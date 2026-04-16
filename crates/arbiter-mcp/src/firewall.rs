//! MCP Firewall — stdio proxy that interposes between an MCP client and server.
//!
//! Architecture:
//!
//! ```text
//!   MCP Client (stdin/stdout)
//!        │         ▲
//!        ▼         │
//!   ┌──────────────────┐
//!   │  Arbiter Firewall │
//!   │  ┌──────────────┐ │
//!   │  │ PolicyEngine │ │   ← deterministic, ~2-4µs
//!   │  └──────────────┘ │
//!   │  ┌──────────────┐ │
//!   │  │  AuditChain  │ │   ← hash-chained log
//!   │  └──────────────┘ │
//!   └──────────────────┘
//!        │         ▲
//!        ▼         │
//!   MCP Server (child process stdin/stdout)
//! ```
//!
//! The firewall:
//! 1. Spawns the downstream MCP server as a child process
//! 2. Reads JSON-RPC messages from the client (our stdin)
//! 3. For `tools/call`: evaluates policy → allow (forward) or refuse (return error)
//! 4. For everything else: passes through transparently
//! 5. Reads responses from the server and forwards them to the client (our stdout)

use anyhow::{Context, Result};
use arbiter_engine::Engine;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use crate::{InterceptResult, Interceptor, JsonRpcRequest, JsonRpcResponse, JsonRpcError};

/// Configuration for the MCP firewall.
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Path to the contract manifest JSON file.
    pub manifest_path: String,
    /// Path to the audit log file.
    pub audit_path: String,
    /// The downstream MCP server command (e.g. "node server.js").
    pub server_command: String,
    /// Arguments for the downstream MCP server.
    pub server_args: Vec<String>,
}

/// The MCP Firewall. Sits between client and server on stdio.
pub struct Firewall {
    interceptor: Interceptor,
    config: FirewallConfig,
}

impl Firewall {
    /// Boot the firewall from a config.
    pub async fn boot(config: FirewallConfig) -> Result<Self> {
        let engine = Engine::boot(
            &config.manifest_path,
            &config.audit_path,
        )
        .await
        .context("booting arbiter engine")?;

        let interceptor = Interceptor::new(engine);

        info!(
            manifest = %config.manifest_path,
            audit = %config.audit_path,
            server = %config.server_command,
            "firewall booted"
        );

        Ok(Firewall {
            interceptor,
            config,
        })
    }

    /// Boot from an already-constructed engine (useful for testing).
    pub fn from_engine(engine: Engine, config: FirewallConfig) -> Self {
        Firewall {
            interceptor: Interceptor::new(engine),
            config,
        }
    }

    /// Run the firewall: spawn the downstream server and proxy messages.
    pub async fn run(&mut self) -> Result<()> {
        // Spawn the downstream MCP server
        let mut child = Command::new(&self.config.server_command)
            .args(&self.config.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // let server errors pass through
            .spawn()
            .context("spawning downstream MCP server")?;

        let child_stdin = child.stdin.take().context("no stdin on child")?;
        let child_stdout = child.stdout.take().context("no stdout on child")?;

        let mut server_writer = child_stdin;
        let mut server_reader = BufReader::new(child_stdout);

        // Read from our stdin (the MCP client)
        let client_stdin = tokio::io::stdin();
        let mut client_reader = BufReader::new(client_stdin);
        let mut client_writer = tokio::io::stdout();

        // Proxy loop: read client → evaluate → forward or refuse
        // Server responses are forwarded back concurrently.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);

        // Task: read server responses and send to client
        let server_to_client = tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match server_reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        if let Err(e) = tx.send(line.trim_end().to_string()).await {
                            warn!("server->client channel closed: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("error reading from server: {e}");
                        break;
                    }
                }
            }
        });

        // Main loop: read client messages
        let mut client_line = String::new();
        loop {
            // Check for server responses to forward
            while let Ok(server_line) = rx.try_recv() {
                client_writer
                    .write_all(server_line.as_bytes())
                    .await
                    .context("writing server response to client")?;
                client_writer
                    .write_all(b"\n")
                    .await
                    .context("writing newline to client")?;
                client_writer.flush().await?;
            }

            client_line.clear();
            let n = client_reader
                .read_line(&mut client_line)
                .await
                .context("reading from client stdin")?;

            if n == 0 {
                // Client closed stdin — shut down
                info!("client disconnected, shutting down");
                break;
            }

            let trimmed = client_line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Try to parse as JSON-RPC
            let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(_) => {
                    // Not valid JSON-RPC — forward as-is
                    server_writer
                        .write_all(client_line.as_bytes())
                        .await
                        .context("forwarding non-JSON to server")?;
                    server_writer.flush().await?;
                    continue;
                }
            };

            // Evaluate through the interceptor
            match self.interceptor.process(&request).await {
                Ok(InterceptResult::Allow { .. }) => {
                    // Forward the original request to the server
                    server_writer
                        .write_all(client_line.as_bytes())
                        .await
                        .context("forwarding allowed request to server")?;
                    server_writer.flush().await?;
                }
                Ok(InterceptResult::Refuse(response)) => {
                    // Send the refusal response directly to the client
                    let response_json = serde_json::to_string(&response)
                        .context("serializing refusal response")?;
                    client_writer
                        .write_all(response_json.as_bytes())
                        .await
                        .context("writing refusal to client")?;
                    client_writer
                        .write_all(b"\n")
                        .await
                        .context("writing newline to client")?;
                    client_writer.flush().await?;

                    warn!(
                        method = %request.method,
                        id = %request.id,
                        "request refused by policy"
                    );
                }
                Err(e) => {
                    // Internal error — send JSON-RPC error to client
                    let error_response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request.id.clone(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32603, // Internal error
                            message: format!("Arbiter internal error: {e}"),
                            data: None,
                        }),
                    };
                    let response_json = serde_json::to_string(&error_response)?;
                    client_writer.write_all(response_json.as_bytes()).await?;
                    client_writer.write_all(b"\n").await?;
                    client_writer.flush().await?;
                }
            }
        }

        // Cleanup
        drop(server_writer);
        server_to_client.abort();
        let _ = child.kill().await;

        Ok(())
    }

    pub fn interceptor(&self) -> &Interceptor {
        &self.interceptor
    }

    pub fn interceptor_mut(&mut self) -> &mut Interceptor {
        &mut self.interceptor
    }
}

/// Process a single JSON-RPC line through an interceptor without stdio transport.
/// Useful for embedding the firewall in custom transports (HTTP, SSE, WebSocket).
pub async fn evaluate_message(
    interceptor: &mut Interceptor,
    message: &str,
) -> Result<EvaluateResult> {
    let request: JsonRpcRequest = serde_json::from_str(message)
        .context("parsing JSON-RPC message")?;

    match interceptor.process(&request).await? {
        InterceptResult::Allow { tool_call, agent_id } => {
            Ok(EvaluateResult::Forward {
                original_message: message.to_string(),
                tool_name: tool_call.name,
                agent_id,
            })
        }
        InterceptResult::Refuse(response) => {
            let response_json = serde_json::to_string(&response)?;
            Ok(EvaluateResult::Block {
                response_json,
            })
        }
    }
}

/// The result of evaluating a single message.
#[derive(Debug)]
pub enum EvaluateResult {
    /// Message should be forwarded to the downstream server.
    Forward {
        original_message: String,
        tool_name: String,
        agent_id: String,
    },
    /// Message was blocked; send this response back to the client.
    Block {
        response_json: String,
    },
}
