//! Integration test: simulates MCP tool calls flowing through the
//! policy engine and verifies both allow and refuse decisions are
//! recorded in the hash-chained audit log.

use arbiter_audit::AuditChain;
use arbiter_engine::Engine;
use arbiter_mcp::firewall::{evaluate_message, log_response, EvaluateResult};
use arbiter_mcp::Interceptor;
use arbiter_shared::boundary::{BoundaryCategory, PolicyBoundary};
use arbiter_shared::contract::{AgentContract, ContractManifest, GlobalContract, ShadowConfig};
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
        shadow_tier: None,
    }
}

/// End-to-end: a benign task is allowed, a boundary-violating task is refused,
/// and the audit log is valid and contains both decisions.
#[tokio::test]
async fn engine_allow_and_refuse_with_audit() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("integration_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
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
        engine.audit().await.read_all().await.unwrap();
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
    let interceptor = Interceptor::new(engine);

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
    let interceptor = Interceptor::new(engine);

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

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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
    let interceptor = Interceptor::new(engine);

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

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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
    let interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "initialize",
        "params": {}
    })
    .to_string();

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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
    let interceptor = Interceptor::new(engine);

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

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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
    let interceptor = Interceptor::new(engine);

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

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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
    let interceptor = Interceptor::new(engine);

    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "prompts/get",
        "params": {
            "name": "access read password credentials"
        }
    })
    .to_string();

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
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

/// M1.4: 100 concurrent evaluations on a shared Engine produce a valid audit chain.
#[tokio::test]
async fn concurrent_evaluations_are_safe() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("concurrent_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..100 {
        let eng = engine.clone();
        handles.push(tokio::spawn(async move {
            let task = Task {
                id: format!("conc-{i}"),
                task_type: "summarise".into(),
                payload: serde_json::json!({"text": "quarterly report"}),
                submitted_at: Utc::now(),
            };
            eng.evaluate(&task).await.unwrap()
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    assert_eq!(results.len(), 100);
    for r in &results {
        assert!(
            matches!(r, arbiter_engine::EvalResult::Allow { .. }),
            "all concurrent benign tasks should be allowed"
        );
    }

    // Audit chain must be intact with exactly 100 entries.
    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "audit hash chain must be valid after concurrent writes"
    );
    let entries: Vec<arbiter_audit::ChainedEntry<arbiter_shared::task::DecisionLogEntry>> =
        engine.audit().await.read_all().await.unwrap();
    assert_eq!(entries.len(), 100, "should have exactly 100 audit entries");
}

/// Allowlisted protocol methods still pass through after M0.1.
#[tokio::test]
async fn allowlisted_methods_still_pass_through() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("dd_allowlist_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let interceptor = Interceptor::new(engine);

    // Test each allowlisted method
    for method in &["ping", "initialize", "initialized", "notifications/initialized"] {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": method,
            "params": {}
        })
        .to_string();

        let result = evaluate_message(&interceptor, &msg).await.unwrap();
        assert!(
            matches!(result, EvaluateResult::Forward { .. }),
            "allowlisted method '{method}' must be forwarded without evaluation"
        );
    }
}

/// M1.3: Egress audit logging — every allowed tools/call that gets a server
/// response should produce an egress log entry in the audit chain.
#[tokio::test]
async fn egress_response_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("egress_audit.jsonl");

    let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
        .await
        .unwrap();
    let interceptor = Interceptor::new(engine.clone());

    // 1. Send an allowed tools/call request
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 50,
        "method": "tools/call",
        "params": {
            "name": "summarise_report",
            "arguments": {"text": "quarterly earnings"}
        }
    })
    .to_string();

    let result = evaluate_message(&interceptor, &msg).await.unwrap();
    assert!(matches!(result, EvaluateResult::Forward { .. }));

    // 2. Simulate the server response and log it
    let server_response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 50,
        "result": {"content": [{"type": "text", "text": "Q3 earnings were strong."}]}
    })
    .to_string();

    log_response(&interceptor, &server_response).await.unwrap();

    // 3. Verify audit chain is intact
    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "audit chain must be valid after egress logging"
    );

    // 4. Read back as generic JSON values to check the mixed-type chain
    let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = raw.trim().lines().collect();
    assert_eq!(lines.len(), 2, "should have 1 decision + 1 egress entry");

    // The second entry should be the egress log with a content_hash field
    let egress: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert!(
        egress.get("content_hash").is_some(),
        "egress entry must contain content_hash"
    );
    assert_eq!(egress["size_bytes"], server_response.len());
    assert_eq!(egress["request_id"], 50);
}

/// M2.2: Shadow evaluation — an allowed request triggers an async shadow
/// classify call to the SetFit service, and the result is logged to the
/// audit chain without blocking the request path.
#[tokio::test]
async fn shadow_evaluation_logs_classify_result() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // 1. Spin up a tiny mock classifier HTTP server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mock_server = tokio::spawn(async move {
        // Handle up to 5 requests then stop
        for _ in 0..5 {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;

            let body = r#"{"label":"safe","confidence":0.92}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    // 2. Boot engine with shadow tier enabled
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("shadow_audit.jsonl");

    let mut manifest = test_manifest();
    manifest.shadow_tier = Some(ShadowConfig {
        enabled: true,
        endpoint: format!("http://127.0.0.1:{port}/classify"),
        confidence_threshold: 0.7,
    });

    let engine = Engine::boot_from_manifest(manifest, &log_path)
        .await
        .unwrap();

    assert!(engine.shadow_enabled(), "shadow tier should be enabled");

    // 3. Evaluate a benign task — should be allowed, shadow eval spawned
    let task = Task {
        id: "shadow-test-1".into(),
        task_type: "summarise".into(),
        payload: serde_json::json!({"text": "quarterly report"}),
        submitted_at: Utc::now(),
    };

    let result = engine.evaluate(&task).await.unwrap();
    assert!(matches!(result, arbiter_engine::EvalResult::Allow { .. }));

    // 4. Wait briefly for the spawned shadow task to complete
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 5. Check the audit log for a shadow entry
    let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = raw.trim().lines().collect();
    assert_eq!(lines.len(), 2, "should have 1 decision + 1 shadow entry");

    let shadow_entry: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(shadow_entry["task_id"], "shadow-test-1");
    assert_eq!(shadow_entry["label"], "safe");
    assert_eq!(shadow_entry["confidence"], 0.92);
    assert_eq!(shadow_entry["would_refuse"], false);

    // 6. Audit chain must still be valid
    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "audit chain must be valid after shadow evaluation"
    );

    mock_server.abort();
}

/// M2.2: Shadow would-refuse — the classifier flags a request that the
/// deterministic policy engine allowed. The request is NOT blocked, but
/// a ShadowLogEntry with would_refuse=true is written to the audit chain.
#[tokio::test]
async fn shadow_would_refuse_is_logged() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Mock classifier returns "unsafe" with high confidence
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mock_server = tokio::spawn(async move {
        for _ in 0..5 {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;

            let body = r#"{"label":"privacy_violation","confidence":0.88}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("shadow_refuse_audit.jsonl");

    let mut manifest = test_manifest();
    manifest.shadow_tier = Some(ShadowConfig {
        enabled: true,
        endpoint: format!("http://127.0.0.1:{port}/classify"),
        confidence_threshold: 0.7,
    });

    let engine = Engine::boot_from_manifest(manifest, &log_path)
        .await
        .unwrap();

    // This task is benign to the deterministic engine, but the shadow
    // classifier will flag it as a privacy violation.
    let task = Task {
        id: "shadow-refuse-1".into(),
        task_type: "summarise".into(),
        payload: serde_json::json!({"text": "quarterly report"}),
        submitted_at: Utc::now(),
    };

    let result = engine.evaluate(&task).await.unwrap();
    assert!(
        matches!(result, arbiter_engine::EvalResult::Allow { .. }),
        "deterministic engine must still allow the request"
    );

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = raw.trim().lines().collect();
    assert_eq!(lines.len(), 2, "should have 1 decision + 1 shadow entry");

    let shadow_entry: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(shadow_entry["task_id"], "shadow-refuse-1");
    assert_eq!(shadow_entry["label"], "privacy_violation");
    assert_eq!(shadow_entry["would_refuse"], true);

    assert!(
        AuditChain::verify(&log_path).await.unwrap(),
        "audit chain must be valid"
    );

    mock_server.abort();
}
