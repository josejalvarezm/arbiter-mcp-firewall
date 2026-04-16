pub mod policy;

use anyhow::{Context, Result};
use arbiter_audit::AuditChain;
use arbiter_shared::boundary::{PolicyBoundary, RefusalRecord};
use arbiter_shared::contract::ContractManifest;
use arbiter_shared::task::{DecisionLogEntry, Task, TaskStatus};
use policy::{PolicyEngine, PolicyVerdict};
use std::path::Path;
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
pub struct Engine {
    manifest: ContractManifest,
    policy_engine: PolicyEngine,
    audit: AuditChain,
}

impl Engine {
    /// Boot the engine from a manifest JSON file and an audit log path.
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
            policy_engine,
            audit,
        })
    }

    /// Evaluate a task: enforce policy boundaries, then route.
    ///
    /// Every decision (allow or refuse) is logged to the audit chain.
    #[instrument(skip(self), fields(task_id = %task.id, task_type = %task.task_type))]
    pub async fn evaluate(&mut self, task: &Task) -> Result<EvalResult> {
        match self.policy_engine.evaluate(task) {
            PolicyVerdict::Refuse(refusal) => {
                let entry = DecisionLogEntry {
                    timestamp: chrono::Utc::now(),
                    task_id: task.id.clone(),
                    agent: "POLICY_ENGINE".to_string(),
                    rationale: refusal.reason.clone(),
                    outcome: Some(TaskStatus::Refused),
                };
                self.audit.append(&entry).await?;

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
                self.audit.append(&entry).await?;

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

    /// Register an additional policy boundary at runtime.
    pub fn add_boundary(&mut self, boundary: PolicyBoundary) {
        self.policy_engine.add_boundary(boundary);
    }

    /// Supersede an existing boundary with a new one.
    pub fn supersede_boundary(
        &mut self,
        old_id: &str,
        new_boundary: PolicyBoundary,
        authorised_by: &str,
        reason: &str,
    ) -> Option<arbiter_shared::boundary::RuleSupersession> {
        self.policy_engine
            .supersede(old_id, new_boundary, authorised_by, reason)
    }

    pub fn manifest(&self) -> &ContractManifest {
        &self.manifest
    }

    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    pub fn audit(&self) -> &AuditChain {
        &self.audit
    }
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

        let mut engine = Engine::boot_from_manifest(test_manifest(), &log_path)
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

        let mut engine = Engine::boot_from_manifest(test_manifest(), &log_path)
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

        let mut engine = Engine::boot_from_manifest(test_manifest(), &log_path)
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
}
