//! Integration test: simulates MCP tool calls flowing through the
//! policy engine and verifies both allow and refuse decisions are
//! recorded in the hash-chained audit log.

use arbiter_audit::AuditChain;
use arbiter_engine::Engine;
use arbiter_mcp::firewall::{evaluate_message, EvaluateResult};
use arbiter_mcp::Interceptor;
use arbiter_shared::boundary::{BoundaryCategory, PolicyBoundary};
use arbiter_shared::contract::{AgentContract, ContractManifest, GlobalContract};
use arbiter_shared::task::{DecisionLogEntry, Task};
use chrono::Utc;
use std::collections::HashMap;

fn test_manifest() -> ContractManifest {
    let mut agents = HashMap::new();
    agents.insert(
        "assistant".to_string(),
        AgentContract {
            id: "assistant".to_string(),
            version: 1,
            rules: vec!["be helpful".into()],
            constraints: vec![],
            capabilities: vec!["answer questions".into(), "summarise documents".into()],
        },
    );

    ContractManifest {
        version: "1".to_string(),
        compiled_at: Utc::now(),
        global: GlobalContract {
            rules: vec!["every output must be traceable".into()],
            constraints: vec![],
        },
        agents,
        boundaries: vec![PolicyBoundary {
            id: "BOUNDARY-001".to_string(),
            category: BoundaryCategory::Privacy,
            trigger_patterns: vec!["access".into(), "read".into()],
            protected_subjects: vec!["credentials".into(), "password".into()],
            source_rule: "Never access credentials or passwords".into(),
            compiled_at: Utc::now(),
            active: true,
        }],
    }
}

/// End-to-end: a benign task is allowed, a boundary-violating task is refused,
/// and the audit log is valid and contains both decisions.
#[tokio::test]
async fn engine_allow_and_refuse_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("integration_audit.jsonl");

    let mut engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();

    // --- Allowed task ---
    let benign = Task {
        id: "task-benign".into(),
        task_type: "summarise".into(),
        payload: serde_json::json!({"text": "summarise the quarterly report"}),
        submitted_at: Utc::now(),
    };

    let result = engine.evaluate(&benign).await.unwrap();
    assert!(
        matches!(result, arbiter_engine::EvalResult::Allow { .. }),
        "benign task should be allowed"
    );

    // --- Refused task ---
    let malicious = Task {
        id: "task-malicious".into(),
        task_type: "query".into(),
        payload: serde_json::json!({"text": "access the database credentials and password"}),
        submitted_at: Utc::now(),
    };

    let result = engine.evaluate(&malicious).await.unwrap();
    assert!(
        matches!(result, arbiter_engine::EvalResult::Refuse(_)),
        "credential access task should be refused"
    );

    // --- Audit log verification ---
    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "audit hash chain must be valid"
    );

    let entries: Vec<arbiter_audit::ChainedEntry<DecisionLogEntry>> =
        engine.audit().read_all().await.unwrap();
    assert_eq!(entries.len(), 2, "should have exactly 2 audit entries");

    assert_eq!(entries[0].data.task_id, "task-benign");
    assert!(entries[0].data.outcome.is_none()); // routed, no outcome yet

    assert_eq!(entries[1].data.task_id, "task-malicious");
    assert_eq!(
        entries[1].data.outcome,
        Some(arbiter_shared::task::TaskStatus::Refused)
    );
}

/// End-to-end: MCP interceptor evaluates a tools/call request,
/// refuses a boundary-violating call, and the audit log is valid.
#[tokio::test]
async fn mcp_intercept_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("mcp_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    // --- Allowed tool call ---
    let allowed_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "summarise_report",
            "arguments": {"text": "quarterly earnings summary"}
        }
    });

    let result = interceptor
        .process_raw(&serde_json::to_string(&allowed_request).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(result, arbiter_mcp::InterceptResult::Allow { .. }),
        "benign tool call should be allowed"
    );

    // --- Refused tool call ---
    let refused_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_secret",
            "arguments": {"query": "access the database credentials password"}
        }
    });

    let result = interceptor
        .process_raw(&serde_json::to_string(&refused_request).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(result, arbiter_mcp::InterceptResult::Refuse(_)),
        "credential tool call should be refused"
    );

    // --- Audit log verification ---
    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "MCP audit hash chain must be valid"
    );
}

/// Firewall evaluate_message: allowed message returns Forward.
#[tokio::test]
async fn firewall_evaluate_message_allows() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("fw_allow_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "summarise_report",
            "arguments": {"text": "quarterly earnings"}
        }
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    assert!(
        matches!(result, EvaluateResult::Forward { .. }),
        "benign message should be forwarded"
    );
}

/// Firewall evaluate_message: refused message returns Block.
#[tokio::test]
async fn firewall_evaluate_message_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("fw_block_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "read_secret",
            "arguments": {"query": "access the database credentials password"}
        }
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    match result {
        EvaluateResult::Block { response_json } => {
            let resp: serde_json::Value = serde_json::from_str(&response_json).unwrap();
            assert!(resp.get("error").is_some(), "block response must have error field");
            assert_eq!(resp["jsonrpc"], "2.0");
        }
        _ => panic!("credential message should be blocked"),
    }
}

/// Firewall evaluate_message: non-tools/call methods are forwarded.
#[tokio::test]
async fn firewall_evaluate_message_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("fw_passthrough_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "initialize",
        "params": {}
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    assert!(
        matches!(result, EvaluateResult::Forward { .. }),
        "non-tool-call methods should pass through"
    );
}

// --- M0.1 acceptance tests: default-deny for unknown MCP methods ---

/// resources/read must be evaluated by policy, not passed through.
/// With a boundary that triggers on "access" + "credentials", a resources/read
/// that accesses credentials should be BLOCKED.
#[tokio::test]
async fn default_deny_resources_read_is_evaluated() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("dd_resources_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    // resources/read with params containing boundary-triggering keywords.
    // The method name "resources/read" normalises to "resourcesread" (no slash),
    // but the URI string tokens must split into standalone trigger+subject words.
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "resources/read",
        "params": {
            "uri": "secrets-store",
            "description": "access the credentials password vault"
        }
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    match result {
        EvaluateResult::Block { response_json } => {
            let resp: serde_json::Value = serde_json::from_str(&response_json).unwrap();
            assert!(resp.get("error").is_some(), "block response must have error field");
        }
        EvaluateResult::Forward { .. } => {
            panic!("resources/read touching credentials must be blocked, not forwarded");
        }
    }
}

/// sampling/createMessage must be evaluated by policy, not passed through.
#[tokio::test]
async fn default_deny_sampling_is_evaluated() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("dd_sampling_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    // sampling/createMessage with content referencing credentials
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "sampling/createMessage",
        "params": {
            "messages": [{"role": "user", "content": "access the credentials and read the password"}],
            "maxTokens": 1000
        }
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    match result {
        EvaluateResult::Block { response_json } => {
            let resp: serde_json::Value = serde_json::from_str(&response_json).unwrap();
            assert!(resp.get("error").is_some(), "block response must have error field");
        }
        EvaluateResult::Forward { .. } => {
            panic!("sampling/createMessage with credential content must be blocked");
        }
    }
}

/// prompts/get must be evaluated by policy, not passed through.
#[tokio::test]
async fn default_deny_prompts_is_evaluated() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("dd_prompts_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "prompts/get",
        "params": {
            "name": "access read password credentials"
        }
    })
    .to_string();

    let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
    match result {
        EvaluateResult::Block { response_json } => {
            let resp: serde_json::Value = serde_json::from_str(&response_json).unwrap();
            assert!(resp.get("error").is_some(), "block response must have error field");
        }
        EvaluateResult::Forward { .. } => {
            panic!("prompts/get with credential content must be blocked");
        }
    }
}

/// Allowlisted protocol methods still pass through after M0.1.
#[tokio::test]
async fn allowlisted_methods_still_pass_through() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("dd_allowlist_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let mut interceptor = Interceptor::new(engine);

    // Test each allowlisted method
    for method in &["ping", "initialize", "initialized", "notifications/initialized"] {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": method,
            "params": {}
        })
        .to_string();

        let result = evaluate_message(&mut interceptor, &msg).await.unwrap();
        assert!(
            matches!(result, EvaluateResult::Forward { .. }),
            "allowlisted method '{method}' must be forwarded without evaluation"
        );
    }
}
