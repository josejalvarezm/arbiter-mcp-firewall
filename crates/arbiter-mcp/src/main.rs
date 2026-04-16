//! `arbiter-firewall` — MCP policy firewall CLI.
//!
//! Usage:
//!   arbiter-firewall --manifest contract.json --audit audit.jsonl -- node my-mcp-server.js
//!
//! This binary sits between an MCP client and server on stdio, enforcing
//! policy boundaries on every `tools/call` request.

use anyhow::{bail, Context, Result};
use arbiter_mcp::firewall::{Firewall, FirewallConfig};
use tracing_subscriber::EnvFilter;

fn parse_args() -> Result<FirewallConfig> {
    let args: Vec<String> = std::env::args().collect();

    let mut manifest_path = None;
    let mut audit_path = None;
    let mut server_command = None;
    let mut server_args = Vec::new();
    let mut after_separator = false;

    let mut i = 1;
    while i < args.len() {
        if after_separator {
            if server_command.is_none() {
                server_command = Some(args[i].clone());
            } else {
                server_args.push(args[i].clone());
            }
            i += 1;
            continue;
        }

        match args[i].as_str() {
            "--manifest" | "-m" => {
                i += 1;
                manifest_path = Some(
                    args.get(i)
                        .context("--manifest requires a path")?
                        .clone(),
                );
            }
            "--audit" | "-a" => {
                i += 1;
                audit_path = Some(
                    args.get(i)
                        .context("--audit requires a path")?
                        .clone(),
                );
            }
            "--" => {
                after_separator = true;
            }
            "--help" | "-h" => {
                eprintln!("arbiter-firewall — MCP policy firewall");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("  arbiter-firewall --manifest <path> [--audit <path>] -- <server-command> [args...]");
                eprintln!();
                eprintln!("OPTIONS:");
                eprintln!("  -m, --manifest <path>   Contract manifest JSON (required)");
                eprintln!("  -a, --audit <path>      Audit log path (default: arbiter-audit.jsonl)");
                eprintln!("  -- <command> [args...]   Downstream MCP server command");
                eprintln!();
                eprintln!("ENVIRONMENT:");
                eprintln!("  RUST_LOG                Log level filter (default: arbiter=info)");
                std::process::exit(0);
            }
            other => {
                bail!("unknown argument: {other}. Use --help for usage.");
            }
        }
        i += 1;
    }

    let manifest_path = manifest_path.context(
        "missing --manifest. Usage: arbiter-firewall --manifest contract.json -- <server-command>",
    )?;

    let audit_path = audit_path.unwrap_or_else(|| "arbiter-audit.jsonl".to_string());

    let server_command = server_command.context(
        "missing server command after '--'. Usage: arbiter-firewall --manifest contract.json -- <server-command>",
    )?;

    Ok(FirewallConfig {
        manifest_path,
        audit_path,
        server_command,
        server_args,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("arbiter=info")),
        )
        .with_writer(std::io::stderr) // logs to stderr, stdout is the MCP channel
        .init();

    let config = parse_args()?;

    eprintln!(
        "arbiter-firewall: manifest={} audit={} server={}",
        config.manifest_path, config.audit_path, config.server_command
    );

    let mut firewall = Firewall::boot(config).await?;
    firewall.run().await
}
