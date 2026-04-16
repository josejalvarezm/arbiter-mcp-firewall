//! Latency benchmark for the Arbiter deterministic policy path.
//!
//! Measures:
//! 1. Pure PolicyEngine::evaluate (no I/O) — the deterministic ceiling
//! 2. Full Engine::evaluate (policy + audit append) — end-to-end
//! 3. AuditChain::append in isolation
//!
//! Target: ~118µs for the deterministic path.

use arbiter_audit::AuditChain;
use arbiter_engine::Engine;
use arbiter_engine::policy::PolicyEngine;
use arbiter_shared::boundary::{BoundaryCategory, PolicyBoundary};
use arbiter_shared::contract::{AgentContract, ContractManifest, GlobalContract};
use arbiter_shared::task::{DecisionLogEntry, Task, TaskStatus};
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;

fn make_manifest(boundary_count: usize) -> ContractManifest {
    let mut agents = HashMap::new();
    agents.insert(
        "documenter".to_string(),
        AgentContract {
            id: "documenter".to_string(),
            version: 1,
            rules: vec!["cite sources".into()],
            constraints: vec![],
            capabilities: vec!["generate documentation from source code".into()],
        },
    );
    agents.insert(
        "analyst".to_string(),
        AgentContract {
            id: "analyst".to_string(),
            version: 1,
            rules: vec![],
            constraints: vec![],
            capabilities: vec!["analyse data reports".into()],
        },
    );

    let mut boundaries = Vec::new();
    // Always include the canonical privacy boundary
    boundaries.push(PolicyBoundary {
        id: "BOUNDARY-PII".to_string(),
        category: BoundaryCategory::Privacy,
        trigger_patterns: vec!["access".into(), "read".into(), "fetch".into()],
        protected_subjects: vec!["credentials".into(), "password".into(), "ssn".into()],
        source_rule: "Never expose PII or credentials".into(),
        compiled_at: Utc::now(),
        active: true,
    });

    // Add extra boundaries to simulate realistic load
    for i in 1..boundary_count {
        boundaries.push(PolicyBoundary {
            id: format!("BOUNDARY-{:04}", i),
            category: BoundaryCategory::Security,
            trigger_patterns: vec![format!("trigger_{i}"), format!("action_{i}")],
            protected_subjects: vec![format!("subject_{i}")],
            source_rule: format!("Rule {i}"),
            compiled_at: Utc::now(),
            active: true,
        });
    }

    ContractManifest {
        version: "1".to_string(),
        compiled_at: Utc::now(),
        global: GlobalContract {
            rules: vec!["every output must be traceable".into()],
            constraints: vec![],
        },
        agents,
        boundaries,
    }
}

fn benign_task() -> Task {
    Task {
        id: "bench-benign".into(),
        task_type: "summarise quarterly report".into(),
        payload: serde_json::json!({"text": "summarise the quarterly report"}),
        submitted_at: Utc::now(),
    }
}

fn violating_task() -> Task {
    Task {
        id: "bench-violate".into(),
        task_type: "fetch data".into(),
        payload: serde_json::json!({"query": "access the database credentials password"}),
        submitted_at: Utc::now(),
    }
}

/// Run a timed loop and return (min, median, mean, p95, p99, max) in nanoseconds.
fn stats(durations: &mut Vec<u128>) -> (u128, u128, u128, u128, u128, u128) {
    durations.sort();
    let n = durations.len();
    let min = durations[0];
    let max = durations[n - 1];
    let median = durations[n / 2];
    let mean = durations.iter().sum::<u128>() / n as u128;
    let p95 = durations[(n as f64 * 0.95) as usize];
    let p99 = durations[(n as f64 * 0.99) as usize];
    (min, median, mean, p95, p99, max)
}

fn print_stats(label: &str, durations: &mut Vec<u128>) {
    let (min, median, mean, p95, p99, max) = stats(durations);
    println!(
        "  {label:<45} min={:>7.1}µs  median={:>7.1}µs  mean={:>7.1}µs  p95={:>7.1}µs  p99={:>7.1}µs  max={:>7.1}µs",
        min as f64 / 1000.0,
        median as f64 / 1000.0,
        mean as f64 / 1000.0,
        p95 as f64 / 1000.0,
        p99 as f64 / 1000.0,
        max as f64 / 1000.0,
    );
}

#[tokio::main]
async fn main() {
    let iterations = 10_000;
    let boundary_counts = [1, 10, 50];

    println!("═══════════════════════════════════════════════════════════════════════════════════════");
    println!("  ARBITER LATENCY AUDIT — {} iterations per scenario", iterations);
    println!("═══════════════════════════════════════════════════════════════════════════════════════");

    // ── 1. Pure PolicyEngine::evaluate (deterministic, no I/O) ──────────────
    println!("\n┌─ PHASE 1: Pure PolicyEngine::evaluate (deterministic, zero I/O) ─────────────┐");
    for &bc in &boundary_counts {
        let manifest = make_manifest(bc);
        let engine = PolicyEngine::from_boundaries(manifest.boundaries.clone());
        let task = benign_task();

        // Warmup
        for _ in 0..100 {
            let _ = engine.evaluate(&task);
        }

        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = engine.evaluate(&task);
            durations.push(start.elapsed().as_nanos());
        }
        print_stats(&format!("Allow path  ({bc} boundaries)"), &mut durations);

        // Refused path
        let vtask = violating_task();
        for _ in 0..100 {
            let _ = engine.evaluate(&vtask);
        }
        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = engine.evaluate(&vtask);
            durations.push(start.elapsed().as_nanos());
        }
        print_stats(&format!("Refuse path ({bc} boundaries)"), &mut durations);
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    // ── 2. AuditChain::append in isolation ──────────────────────────────────
    println!("\n┌─ PHASE 2: AuditChain::append (isolated file I/O) ───────────────────────────────┐");
    {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("bench_audit.jsonl");
        let mut chain = AuditChain::open(&log_path).await.unwrap();

        let entry = DecisionLogEntry {
            timestamp: Utc::now(),
            task_id: "bench-audit".into(),
            agent: "documenter".into(),
            rationale: "Matched agent with score 3".into(),
            outcome: Some(TaskStatus::Success),
        };

        // Warmup
        for _ in 0..100 {
            chain.append(&entry).await.unwrap();
        }

        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            chain.append(&entry).await.unwrap();
            durations.push(start.elapsed().as_nanos());
        }
        print_stats("append (single entry)", &mut durations);
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    // ── 3. Full Engine::evaluate (policy + audit) ───────────────────────────
    println!("\n┌─ PHASE 3: Full Engine::evaluate (policy + audit append) ─────────────────────────┐");
    for &bc in &boundary_counts {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("bench_engine.jsonl");
        let manifest = make_manifest(bc);
        let mut engine = Engine::boot_from_manifest(manifest, &log_path).await.unwrap();

        let task = benign_task();
        // Warmup
        for _ in 0..100 {
            let _ = engine.evaluate(&task).await.unwrap();
        }

        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = engine.evaluate(&task).await.unwrap();
            durations.push(start.elapsed().as_nanos());
        }
        print_stats(&format!("Allow path  ({bc} boundaries)"), &mut durations);

        // Reset engine for refuse path
        let dir2 = tempfile::tempdir().unwrap();
        let log_path2 = dir2.path().join("bench_engine_refuse.jsonl");
        let manifest2 = make_manifest(bc);
        let mut engine2 = Engine::boot_from_manifest(manifest2, &log_path2).await.unwrap();

        let vtask = violating_task();
        for _ in 0..100 {
            let _ = engine2.evaluate(&vtask).await.unwrap();
        }
        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = engine2.evaluate(&vtask).await.unwrap();
            durations.push(start.elapsed().as_nanos());
        }
        print_stats(&format!("Refuse path ({bc} boundaries)"), &mut durations);
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    // ── 4. MCP Interceptor process_raw ──────────────────────────────────────
    println!("\n┌─ PHASE 4: MCP Interceptor::process_raw (full stack) ─────────────────────────────┐");
    {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("bench_mcp.jsonl");
        let manifest = make_manifest(10);
        let engine = Engine::boot_from_manifest(manifest, &log_path).await.unwrap();
        let mut interceptor = arbiter_mcp::Interceptor::new(engine);

        let allowed_req = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "summarise_report",
                "arguments": {"text": "quarterly earnings"}
            }
        })).unwrap();

        // Warmup
        for _ in 0..100 {
            let _ = interceptor.process_raw(&allowed_req).await.unwrap();
        }

        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = interceptor.process_raw(&allowed_req).await.unwrap();
            durations.push(start.elapsed().as_nanos());
        }
        print_stats("MCP Allow (10 boundaries)", &mut durations);

        let refused_req = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_secret",
                "arguments": {"query": "access credentials password"}
            }
        })).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let log_path2 = dir2.path().join("bench_mcp_refuse.jsonl");
        let manifest2 = make_manifest(10);
        let engine2 = Engine::boot_from_manifest(manifest2, &log_path2).await.unwrap();
        let mut interceptor2 = arbiter_mcp::Interceptor::new(engine2);

        for _ in 0..100 {
            let _ = interceptor2.process_raw(&refused_req).await.unwrap();
        }

        let mut durations = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = interceptor2.process_raw(&refused_req).await.unwrap();
            durations.push(start.elapsed().as_nanos());
        }
        print_stats("MCP Refuse (10 boundaries)", &mut durations);
    }
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    println!("\n══════════════════════════════════════════════════════════════════════════════════════");
    println!("  TARGET: Deterministic policy path ≤ 118µs (median)");
    println!("  NOTE:   Audit append adds file I/O. If dominating, consider async background flush.");
    println!("══════════════════════════════════════════════════════════════════════════════════════");
}
