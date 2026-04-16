//! Model Context Protocol (MCP) policy interceptor and firewall.
//!
//! Accepts MCP JSON-RPC tool call requests, constructs a `Task` from the
//! tool name and arguments, runs it through the Arbiter policy engine, and
//! returns an allow/refuse response.
//!
//! The `firewall` module provides a stdio proxy that sits between an MCP
//! client and server, enforcing policy on every `tools/call` in transit.
//!
//! This crate provides the core interceptor logic. Transport (stdio/SSE/HTTP)
//! is the caller's responsibility — or use `firewall::Firewall` for stdio.

pub mod compliance;
pub mod firewall;
pub mod http;

use anyhow::{Context, Result};
use arbiter_engine::{Engine, EvalResult};
use arbiter_shared::task::{EgressLogEntry, Task};
use chrono::Utc;
use compliance::ToolRegistry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::instrument;

/// A JSON-RPC 2.0 request (simplified for MCP tool calls).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP tool call extracted from a `tools/call` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// The result of intercepting a tool call.
#[derive(Debug)]
pub enum InterceptResult {
    /// Tool call is allowed. The caller should forward it to the actual tool.
    Allow {
        tool_call: ToolCall,
        agent_id: String,
    },
    /// Tool call is refused by policy. Contains the JSON-RPC error response.
    Refuse(JsonRpcResponse),
}

/// MCP methods that are allowed through without policy evaluation.
/// These are protocol-level handshake and notification methods that
/// carry no security-relevant payload.
const PASSTHROUGH_METHODS: &[&str] = &[
    "ping",
    "initialize",
    "initialized",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
];

/// Check whether a method is on the passthrough allowlist.
///
/// Exact match against `PASSTHROUGH_METHODS`.
fn is_passthrough_method(method: &str) -> bool {
    PASSTHROUGH_METHODS.iter().any(|&m| m == method)
}

/// The MCP policy interceptor. Wraps an Arbiter engine.
#[derive(Clone)]
pub struct Interceptor {
    engine: Engine,
    tool_registry: ToolRegistry,
}

impl Interceptor {
    pub fn new(engine: Engine) -> Self {
        Interceptor {
            engine,
            tool_registry: ToolRegistry::new(),
        }
    }

    /// Return a reference to the tool registry for tool metadata inspection.
    pub fn tool_registry(&self) -> &ToolRegistry {
        &self.tool_registry
    }

    /// Process a raw JSON-RPC request string.
    ///
    /// If the method is `tools/call`, extracts the tool call, evaluates policy,
    /// and returns allow/refuse. For other methods, returns allow (pass-through).
    #[instrument(skip(self, request_json))]
    pub async fn process_raw(&self, request_json: &str) -> Result<InterceptResult> {
        let request: JsonRpcRequest =
            serde_json::from_str(request_json).context("parsing JSON-RPC request")?;

        self.process(&request).await
    }

    /// Process a parsed JSON-RPC request.
    ///
    /// Method handling (default-deny):
    /// - **Passthrough allowlist** (`ping`, `initialize`, `initialized`,
    ///   `notifications/*`): forwarded without policy evaluation.
    /// - **`tools/call`**: tool name + arguments are extracted and evaluated.
    ///   Destructive tools must be in the manifest allowlist.
    /// - **`elicitation/create`**: checked against blocked data types.
    /// - **Everything else** (`resources/read`, `sampling/createMessage`,
    ///   `prompts/get`, etc.): the method name becomes the `task_type` and
    ///   the params become the payload — routed through full policy evaluation.
    pub async fn process(&self, request: &JsonRpcRequest) -> Result<InterceptResult> {
        // 1. Protocol-level methods: pass through without evaluation.
        if is_passthrough_method(&request.method) {
            let tool_call = ToolCall {
                name: request.method.clone(),
                arguments: request.params.clone(),
            };
            return Ok(InterceptResult::Allow {
                tool_call,
                agent_id: "passthrough".to_string(),
            });
        }

        // 2. elicitation/create: check against blocked types.
        if request.method == "elicitation/create" {
            let manifest = self.engine.manifest();
            let entry = compliance::check_elicitation(
                &request.params,
                &manifest.blocked_elicitation_types,
            );
            // Log the elicitation event
            self.engine.audit().await.append(&entry).await?;

            if !entry.allowed {
                let response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: format!("Elicitation blocked: {}", entry.reason),
                        data: None,
                    }),
                };
                return Ok(InterceptResult::Refuse(response));
            }

            let tool_call = ToolCall {
                name: request.method.clone(),
                arguments: request.params.clone(),
            };
            return Ok(InterceptResult::Allow {
                tool_call,
                agent_id: "elicitation".to_string(),
            });
        }

        // 3. tools/call: extract tool name + arguments.
        if request.method == "tools/call" {
            let tool_call = extract_tool_call(&request.params)?;

            // M4.1: Enforce destructive tool policy
            let is_destructive = self.tool_registry.is_destructive(&tool_call.name).await;
            let manifest = self.engine.manifest();
            if let Err(reason) =
                compliance::check_destructive_policy(&tool_call.name, is_destructive, &manifest.destructive_allowlist)
            {
                let response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: format!("Policy violation: {reason}"),
                        data: None,
                    }),
                };
                return Ok(InterceptResult::Refuse(response));
            }

            return self.evaluate_tool_call(tool_call, request).await;
        }

        // 4. Default-deny: route all other methods through policy evaluation.
        //    The method name becomes the task_type; params become the payload.
        let tool_call = ToolCall {
            name: request.method.clone(),
            arguments: request.params.clone(),
        };
        self.evaluate_tool_call(tool_call, request).await
    }

    /// Evaluate a tool call against the policy engine and return allow/refuse.
    async fn evaluate_tool_call(
        &self,
        tool_call: ToolCall,
        request: &JsonRpcRequest,
    ) -> Result<InterceptResult> {

        // Build a Task from the tool call
        let task = Task {
            id: uuid::Uuid::new_v4().to_string(),
            task_type: tool_call.name.clone(),
            payload: tool_call.arguments.clone(),
            submitted_at: Utc::now(),
        };

        // Evaluate policy
        match self.engine.evaluate(&task).await? {
            EvalResult::Allow { agent_id, .. } => {
                tracing::info!(tool = %tool_call.name, "tool call allowed");
                Ok(InterceptResult::Allow {
                    tool_call,
                    agent_id,
                })
            }
            EvalResult::Refuse(refusal) => {
                tracing::warn!(
                    tool = %tool_call.name,
                    boundary = %refusal.boundary_id,
                    "tool call refused"
                );

                let response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600, // Invalid request
                        message: format!("Policy violation: {}", refusal.reason),
                        data: Some(serde_json::to_value(&refusal).unwrap_or_default()),
                    }),
                };

                Ok(InterceptResult::Refuse(response))
            }
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Log a server→client response to the audit chain.
    ///
    /// Records a SHA-256 content hash, the JSON-RPC request ID (if present),
    /// and the response size. Does not block or modify the response.
    ///
    /// Also performs M4 compliance checks:
    /// - Multi-modal content extraction and size enforcement
    /// - Output schema validation (if tool has declared schema)
    pub async fn log_egress(&self, raw_response: &str) -> Result<()> {
        let content_hash = format!(
            "{:x}",
            Sha256::new().chain_update(raw_response.as_bytes()).finalize()
        );
        let parsed = serde_json::from_str::<serde_json::Value>(raw_response).ok();
        let request_id = parsed.as_ref().and_then(|v| v.get("id").cloned());

        let entry = EgressLogEntry {
            timestamp: Utc::now(),
            content_hash,
            request_id: request_id.clone(),
            size_bytes: raw_response.len(),
        };
        self.engine.audit().await.append(&entry).await?;

        // M4.3: Multi-modal content logging
        if let Some(ref resp) = parsed {
            let manifest = self.engine.manifest();
            match compliance::extract_content_blocks(resp, manifest.max_binary_size) {
                Ok((blocks, total_size)) if !blocks.is_empty() => {
                    let mm_entry = compliance::build_multimodal_entry(
                        request_id.clone(),
                        blocks,
                        total_size,
                    );
                    self.engine.audit().await.append(&mm_entry).await?;
                }
                Err(reason) => {
                    tracing::warn!("multi-modal content rejected: {reason}");
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Ingest a `tools/list` response to populate the tool registry.
    ///
    /// Call this when a `tools/list` response passes through the proxy
    /// to register tool annotations and output schemas for M4 compliance.
    pub async fn ingest_tools_list(&self, raw_response: &str) -> Result<()> {
        let response: serde_json::Value =
            serde_json::from_str(raw_response).context("parsing tools/list response")?;
        self.tool_registry.ingest_tools_list(&response).await
    }

    /// Validate a tool response against its declared output schema (M4.2).
    ///
    /// Returns any schema violations found. Logs violations to the audit chain.
    pub async fn validate_tool_response(
        &self,
        tool_name: &str,
        raw_response: &str,
    ) -> Result<Vec<String>> {
        let schema = match self.tool_registry.output_schema(tool_name).await {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let response: serde_json::Value =
            serde_json::from_str(raw_response).context("parsing tool response")?;

        let result_value = response
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let violations = compliance::validate_output_schema(&result_value, &schema);

        if !violations.is_empty() {
            let request_id = response.get("id").cloned();
            let entry = compliance::build_schema_violation(tool_name, request_id, &violations);
            self.engine.audit().await.append(&entry).await?;
        }

        Ok(violations)
    }
}

/// Extract a ToolCall from MCP `tools/call` params.
fn extract_tool_call(params: &serde_json::Value) -> Result<ToolCall> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .context("missing 'name' in tools/call params")?
        .to_string();

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    Ok(ToolCall { name, arguments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_shared::boundary::{BoundaryCategory, PolicyBoundary};
    use arbiter_shared::contract::{AgentContract, ContractManifest, GlobalContract};
    use chrono::Utc;
    use std::collections::HashMap;

    async fn test_interceptor(dir: &std::path::Path) -> Interceptor {
        let mut agents = HashMap::new();
        agents.insert(
            "filesystem".to_string(),
            AgentContract {
                id: "filesystem".to_string(),
                version: 1,
                rules: vec![],
                constraints: vec![],
                capabilities: vec!["read write files filesystem".into()],
            },
        );

        let manifest = ContractManifest {
            version: "1".to_string(),
            compiled_at: Utc::now(),
            global: GlobalContract {
                rules: vec![],
                constraints: vec![],
            },
            agents,
            boundaries: vec![PolicyBoundary {
                id: "BOUNDARY-SEC".to_string(),
                category: BoundaryCategory::Security,
                trigger_patterns: vec![
                    "password".into(),
                    "credential".into(),
                    "secret".into(),
                ],
                protected_subjects: vec![
                    "password".into(),
                    "credential".into(),
                    "secret".into(),
                ],
                source_rule: "Never expose credentials".into(),
                compiled_at: Utc::now(),
                active: true,
            }],
            shadow_tier: None,
            destructive_allowlist: vec![],
            max_binary_size: 10 * 1024 * 1024,
            blocked_elicitation_types: vec!["password".into(), "secret".into(), "credential".into()],
            audit_max_file_size: 50 * 1024 * 1024,
        };

        let log_path = dir.join("mcp_audit.jsonl");
        let engine = Engine::boot_from_manifest(manifest, &log_path)
            .await
            .unwrap();

        Interceptor::new(engine)
    }

    #[tokio::test]
    async fn allows_benign_tool_call() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = test_interceptor(dir.path()).await;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "read_file",
                "arguments": {"path": "/tmp/readme.md"}
            }),
        };

        let result = interceptor.process(&request).await.unwrap();
        assert!(matches!(result, InterceptResult::Allow { .. }));
    }

    #[tokio::test]
    async fn refuses_credential_access() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = test_interceptor(dir.path()).await;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(2),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "read password credential",
                "arguments": {"target": "secret vault password store"}
            }),
        };

        let result = interceptor.process(&request).await.unwrap();
        match result {
            InterceptResult::Refuse(resp) => {
                assert!(resp.error.is_some());
                let err = resp.error.unwrap();
                assert!(err.message.contains("Policy violation"));
            }
            InterceptResult::Allow { .. } => panic!("expected refusal"),
        }
    }

    #[tokio::test]
    async fn passes_through_non_tool_methods() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = test_interceptor(dir.path()).await;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(3),
            method: "initialize".into(),
            params: serde_json::json!({}),
        };

        let result = interceptor.process(&request).await.unwrap();
        assert!(matches!(result, InterceptResult::Allow { .. }));
    }

    #[tokio::test]
    async fn audit_log_valid_after_intercept() {
        let dir = tempfile::tempdir().unwrap();
        let interceptor = test_interceptor(dir.path()).await;

        // One allowed, one refused
        let allow_req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "list_files",
                "arguments": {"path": "/tmp"}
            }),
        };
        interceptor.process(&allow_req).await.unwrap();

        let refuse_req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(2),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "read password credential",
                "arguments": {"target": "secret password file"}
            }),
        };
        interceptor.process(&refuse_req).await.unwrap();

        // Verify audit chain
        let log_path = dir.path().join("mcp_audit.jsonl");
        assert!(arbiter_audit::AuditChain::verify(&log_path).await.unwrap());
    }
}
