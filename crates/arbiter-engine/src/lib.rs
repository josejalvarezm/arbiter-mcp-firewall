pub mod policy;

use anyhow::{Context, Result};
use arbiter_audit::AuditChain;
use arbiter_shared::boundary::RefusalRecord;
use arbiter_shared::contract::ContractManifest;
use arbiter_shared::task::{DecisionLogEntry, Task, TaskStatus};
use policy::{PolicyEngine, PolicyVerdict};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;

/// The result of an engine evaluation.
#[derive(Debug)]
pub enum EvalResult {
    /// Task is allowed. Contains the best-match agent ID and rationale.
    Allow { agent_id: String, rationale: String },
    /// Task is refused by a policy boundary.
    Refuse(RefusalRecord),
}

/// The Arbiter engine: loads a contract manifest, evaluates tasks against policy
/// boundaries, and logs every decision to a hash-chained audit trail.
///
/// The engine is `Clone + Send + Sync`: policy evaluation is lock-free (read-only),
/// and audit writes are serialized through an internal `Mutex<AuditChain>`.
#[derive(Clone)]
pub struct Engine {
    manifest: ContractManifest,
    policy_engine: Arc<PolicyEngine>,
    audit: Arc<Mutex<AuditChain>>,
}

impl Engine {
    /// Boot the engine from a manifest JSON file and an audit log path.
    ///
    /// If `expected_hash` is `Some`, the SHA-256 of the raw manifest file
    /// content is compared against it. A mismatch is a fatal boot error
    /// (manifest tampering detected).
    #[instrument(skip_all, fields(manifest = %manifest_path.as_ref().display()))]
    pub async fn boot(
        manifest_path: impl AsRef<Path>,
        audit_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let data = tokio::fs::read_to_string(manifest_path.as_ref())
            .await
            .context("reading contract manifest")?;
        let manifest: ContractManifest =
            serde_json::from_str(&data).context("parsing contract manifest")?;

        Self::boot_from_manifest(manifest, audit_path).await
    }

    /// Boot from a manifest file with an integrity check.
    ///
    /// Computes the SHA-256 of the raw manifest and compares it against
    /// `expected_hash`. Returns an error if the hashes do not match.
    #[instrument(skip_all, fields(manifest = %manifest_path.as_ref().display()))]
    pub async fn boot_verified(
        manifest_path: impl AsRef<Path>,
        audit_path: impl AsRef<Path>,
        expected_hash: &str,
    ) -> Result<Self> {
        let data = tokio::fs::read_to_string(manifest_path.as_ref())
            .await
            .context("reading contract manifest")?;

        let actual_hash = compute_sha256(&data);
        if actual_hash != expected_hash {
            anyhow::bail!(
                "manifest integrity check failed: expected {expected_hash}, got {actual_hash}"
            );
        }

        tracing::info!("manifest integrity check passed");

        let manifest: ContractManifest =
            serde_json::from_str(&data).context("parsing contract manifest")?;

        Self::boot_from_manifest(manifest, audit_path).await
    }

    /// Compute the SHA-256 hash of a manifest JSON string.
    ///
    /// Useful for generating the expected hash at build/deploy time.
    pub fn manifest_hash(manifest_json: &str) -> String {
        compute_sha256(manifest_json)
    }

    /// Boot from an in-memory manifest (useful for testing).
    pub async fn boot_from_manifest(
        manifest: ContractManifest,
        audit_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let policy_engine = PolicyEngine::from_boundaries(manifest.boundaries.clone());
        let audit = AuditChain::open(audit_path).await?;

        tracing::info!(
            boundaries = policy_engine.active_count(),
            agents = manifest.agents.len(),
            "engine booted"
        );

        Ok(Engine {
            manifest,
            policy_engine: Arc::new(policy_engine),
            audit: Arc::new(Mutex::new(audit)),
        })
    }

    /// Evaluate a task: enforce policy boundaries, then route.
    ///
    /// Every decision (allow or refuse) is logged to the audit chain.
    /// Policy evaluation is lock-free; only the audit write acquires a mutex.
    #[instrument(skip(self), fields(task_id = %task.id, task_type = %task.task_type))]
    pub async fn evaluate(&self, task: &Task) -> Result<EvalResult> {
        match self.policy_engine.evaluate(task) {
            PolicyVerdict::Refuse(refusal) => {
                let entry = DecisionLogEntry {
                    timestamp: chrono::Utc::now(),
                    task_id: task.id.clone(),
                    agent: "POLICY_ENGINE".to_string(),
                    rationale: refusal.reason.clone(),
                    outcome: Some(TaskStatus::Refused),
                };
                self.audit.lock().await.append(&entry).await?;

                tracing::warn!(
                    boundary = %refusal.boundary_id,
                    "task refused by policy"
                );

                Ok(EvalResult::Refuse(refusal))
            }
            PolicyVerdict::Allow => {
                let (agent_id, rationale) = self.route_task(task);

                let entry = DecisionLogEntry {
                    timestamp: chrono::Utc::now(),
                    task_id: task.id.clone(),
                    agent: agent_id.clone(),
                    rationale: rationale.clone(),
                    outcome: None,
                };
                self.audit.lock().await.append(&entry).await?;

                tracing::info!(agent = %agent_id, "task allowed and routed");

                Ok(EvalResult::Allow { agent_id, rationale })
            }
        }
    }

    /// Simple keyword-overlap agent routing (ported from research prototype).
    fn route_task(&self, task: &Task) -> (String, String) {
        let task_words: Vec<String> = task
            .task_type
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect();

        let mut best_agent = None;
        let mut best_score = 0usize;

        for (id, agent) in &self.manifest.agents {
            let score: usize = agent
                .capabilities
                .iter()
                .map(|cap| {
                    cap.split_whitespace()
                        .filter(|w| task_words.contains(&w.to_lowercase()))
                        .count()
                })
                .sum();

            if score > best_score {
                best_score = score;
                best_agent = Some(id.clone());
            }
        }

        match best_agent {
            Some(id) => {
                let rationale = format!("Matched agent '{id}' with keyword score {best_score}");
                (id, rationale)
            }
            None => (
                "unrouted".to_string(),
                "No agent matched task type".to_string(),
            ),
        }
    }

    pub fn manifest(&self) -> &ContractManifest {
        &self.manifest
    }

    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Access the audit chain (requires async lock).
    pub async fn audit(&self) -> tokio::sync::MutexGuard<'_, AuditChain> {
        self.audit.lock().await
    }
}

/// Compute the SHA-256 hex digest of a string.
fn compute_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_shared::boundary::{BoundaryCategory, PolicyBoundary};
    use arbiter_shared::contract::{AgentContract, ContractManifest, GlobalContract};
    use arbiter_shared::task::Task;
    use chrono::Utc;
    use std::collections::HashMap;

    fn test_manifest() -> ContractManifest {
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
                trigger_patterns: vec![
                    "charity".into(),
                    "donation".into(),
                    "donate".into(),
                ],
                protected_subjects: vec!["political".into(), "party".into(), "voting".into()],
                source_rule: "Never share political affiliation".into(),
                compiled_at: Utc::now(),
                active: true,
            }],
        }
    }

    #[tokio::test]
    async fn allows_benign_task() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
            .await
            .unwrap();

        let task = Task {
            id: "task-1".into(),
            task_type: "generate documentation".into(),
            payload: serde_json::json!({"file": "lib.rs"}),
            submitted_at: Utc::now(),
        };

        let result = engine.evaluate(&task).await.unwrap();
        assert!(matches!(result, EvalResult::Allow { .. }));
    }

    #[tokio::test]
    async fn refuses_boundary_violation() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
            .await
            .unwrap();

        let task = Task {
            id: "task-2".into(),
            task_type: "suggest charity donations".into(),
            payload: serde_json::json!({"context": "user voting and party history"}),
            submitted_at: Utc::now(),
        };

        let result = engine.evaluate(&task).await.unwrap();
        assert!(matches!(result, EvalResult::Refuse(_)));
    }

    #[tokio::test]
    async fn audit_log_is_valid_after_evaluation() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        let engine = Engine::boot_from_manifest(test_manifest(), &log_path)
            .await
            .unwrap();

        let task = Task {
            id: "task-1".into(),
            task_type: "generate documentation".into(),
            payload: serde_json::json!({}),
            submitted_at: Utc::now(),
        };
        engine.evaluate(&task).await.unwrap();

        assert!(AuditChain::verify(&log_path).await.unwrap());
    }

    // --- M0.4 acceptance tests: manifest integrity check ---

    #[tokio::test]
    async fn boot_verified_succeeds_with_correct_hash() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let log_path = dir.path().join("test.jsonl");

        let manifest_json = serde_json::to_string_pretty(&test_manifest()).unwrap();
        let expected_hash = Engine::manifest_hash(&manifest_json);
        tokio::fs::write(&manifest_path, &manifest_json).await.unwrap();

        let engine = Engine::boot_verified(&manifest_path, &log_path, &expected_hash).await;
        assert!(engine.is_ok(), "boot_verified must succeed with correct hash");
    }

    #[tokio::test]
    async fn boot_verified_fails_with_wrong_hash() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let log_path = dir.path().join("test.jsonl");

        let manifest_json = serde_json::to_string_pretty(&test_manifest()).unwrap();
        tokio::fs::write(&manifest_path, &manifest_json).await.unwrap();

        let wrong_hash = "deadbeef".repeat(8); // 64-char bogus hash
        let result = Engine::boot_verified(&manifest_path, &log_path, &wrong_hash).await;
        assert!(result.is_err(), "boot_verified must fail with wrong hash");

        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("manifest integrity check failed"),
            "error must mention integrity check, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn boot_verified_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        let log_path = dir.path().join("test.jsonl");

        // Write original manifest and record its hash
        let manifest_json = serde_json::to_string_pretty(&test_manifest()).unwrap();
        let expected_hash = Engine::manifest_hash(&manifest_json);
        tokio::fs::write(&manifest_path, &manifest_json).await.unwrap();

        // Tamper with the file (change version)
        let tampered = manifest_json.replace("\"1\"", "\"999\"");
        tokio::fs::write(&manifest_path, &tampered).await.unwrap();

        let result = Engine::boot_verified(&manifest_path, &log_path, &expected_hash).await;
        assert!(result.is_err(), "tampered manifest must fail integrity check");
    }
}
