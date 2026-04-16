//! Policy enforcement engine — deterministic, pre-flight boundary evaluation.
//!
//! Ported from the PreFlight research prototype. Preserves exact two-phase
//! matching semantics (trigger ∩ subject) and NFKC Unicode normalization.
//!
//! **Latency Wall**: Boundaries are indexed by trigger keyword in a HashMap.
//! Lookup is O(k) where k = keywords in the task, not O(n) over all boundaries.
//!
//! **Semantic Gap**: NL rules are compiled into PolicyBoundary structs at compile
//! time. Enforcement is pure keyword intersection — no AI inference.
//!
//! **Rigidity Wall**: Rules are superseded, never deleted. RuleSupersession
//! records link old → new.

use arbiter_shared::boundary::{
    AgentDirective, BoundaryCategory, PolicyBoundary, RefusalRecord, RuleSupersession,
};
use arbiter_shared::task::Task;
use chrono::Utc;
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

/// The policy engine. Holds indexed boundaries and evaluates tasks against them.
#[derive(Debug)]
pub struct PolicyEngine {
    boundaries: Vec<PolicyBoundary>,
    /// Keyword → list of boundary indices. Only active boundaries are indexed.
    trigger_index: HashMap<String, Vec<usize>>,
    supersessions: Vec<RuleSupersession>,
}

/// The result of a policy evaluation.
#[derive(Debug)]
pub enum PolicyVerdict {
    Allow,
    Refuse(RefusalRecord),
}

impl PolicyEngine {
    pub fn new() -> Self {
        PolicyEngine {
            boundaries: Vec::new(),
            trigger_index: HashMap::new(),
            supersessions: Vec::new(),
        }
    }

    /// Build from a set of boundaries (e.g. loaded from manifest).
    pub fn from_boundaries(boundaries: Vec<PolicyBoundary>) -> Self {
        let mut engine = PolicyEngine::new();
        for b in boundaries {
            engine.add_boundary(b);
        }
        engine
    }

    /// Add a boundary and index its trigger patterns.
    pub fn add_boundary(&mut self, boundary: PolicyBoundary) {
        let idx = self.boundaries.len();
        if boundary.active {
            for pattern in &boundary.trigger_patterns {
                let normalized: String = pattern.nfkc().collect::<String>().to_lowercase();
                self.trigger_index
                    .entry(normalized)
                    .or_default()
                    .push(idx);
            }
        }
        self.boundaries.push(boundary);
    }

    /// Supersede an existing boundary with a new one.
    pub fn supersede(
        &mut self,
        old_boundary_id: &str,
        new_boundary: PolicyBoundary,
        authorised_by: &str,
        reason: &str,
    ) -> Option<RuleSupersession> {
        let old_idx = self
            .boundaries
            .iter()
            .position(|b| b.id == old_boundary_id && b.active)?;

        self.boundaries[old_idx].active = false;

        let old_patterns: Vec<String> = self.boundaries[old_idx].trigger_patterns.clone();
        for pattern in &old_patterns {
            if let Some(indices) = self.trigger_index.get_mut(pattern) {
                indices.retain(|&i| i != old_idx);
            }
        }

        let record = RuleSupersession {
            old_boundary_id: old_boundary_id.to_string(),
            new_boundary_id: new_boundary.id.clone(),
            authorised_by: authorised_by.to_string(),
            reason: reason.to_string(),
            superseded_at: Utc::now(),
        };
        self.supersessions.push(record.clone());

        self.add_boundary(new_boundary);

        Some(record)
    }

    /// Evaluate a task against all active boundaries.
    ///
    /// Two-phase matching:
    /// 1. Extract keywords → look up trigger index (O(k))
    /// 2. For each candidate boundary, check if task also touches a protected subject
    ///
    /// A boundary fires only when BOTH a trigger AND a subject match.
    pub fn evaluate(&self, task: &Task) -> PolicyVerdict {
        let task_keywords = extract_task_keywords(task);

        // Phase 1: Find candidate boundaries via trigger index
        let mut candidate_indices: Vec<usize> = Vec::new();
        for keyword in &task_keywords {
            if let Some(indices) = self.trigger_index.get(keyword) {
                for &idx in indices {
                    if !candidate_indices.contains(&idx) {
                        candidate_indices.push(idx);
                    }
                }
            }
        }

        // Phase 2: Check protected subjects
        for &idx in &candidate_indices {
            let boundary = &self.boundaries[idx];
            if !boundary.active {
                continue;
            }

            let matched_subjects: Vec<String> = boundary
                .protected_subjects
                .iter()
                .filter(|subj| task_keywords.contains(&normalize_word(subj)))
                .cloned()
                .collect();

            let matched_triggers: Vec<String> = boundary
                .trigger_patterns
                .iter()
                .filter(|pat| task_keywords.contains(&normalize_word(pat)))
                .cloned()
                .collect();

            if !matched_triggers.is_empty() && !matched_subjects.is_empty() {
                let reason = format!(
                    "Refused: High probability of leaking {} data. \
                     Triggers {} matched against subjects {}.",
                    format_category(&boundary.category),
                    format_list(&matched_triggers),
                    format_list(&matched_subjects),
                );

                let directive = match boundary.category {
                    BoundaryCategory::Privacy => AgentDirective::Reformulate {
                        excluded_subjects: boundary.protected_subjects.clone(),
                    },
                    BoundaryCategory::Security => AgentDirective::Terminate,
                    BoundaryCategory::Legal => AgentDirective::EscalateToUser,
                    BoundaryCategory::Custom(_) => AgentDirective::Reformulate {
                        excluded_subjects: boundary.protected_subjects.clone(),
                    },
                };

                return PolicyVerdict::Refuse(RefusalRecord {
                    task_id: task.id.clone(),
                    boundary_id: boundary.id.clone(),
                    category: boundary.category.clone(),
                    reason,
                    matched_patterns: matched_triggers,
                    refused_at: Utc::now(),
                    agent_directive: directive,
                });
            }
        }

        PolicyVerdict::Allow
    }

    pub fn boundaries(&self) -> &[PolicyBoundary] {
        &self.boundaries
    }

    pub fn supersessions(&self) -> &[RuleSupersession] {
        &self.supersessions
    }

    pub fn active_count(&self) -> usize {
        self.boundaries.iter().filter(|b| b.active).count()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a word: NFKC → lowercase → strip non-alphanumeric.
fn normalize_word(word: &str) -> String {
    word.nfkc()
        .collect::<String>()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Extract lowercased, NFKC-normalized keywords from a task.
fn extract_task_keywords(task: &Task) -> Vec<String> {
    let mut keywords = Vec::new();

    for word in task.task_type.split_whitespace() {
        let clean = normalize_word(word);
        if clean.len() > 2 {
            keywords.push(clean);
        }
    }

    extract_payload_keywords(&task.payload, &mut keywords);

    keywords.sort();
    keywords.dedup();
    keywords
}

fn extract_payload_keywords(value: &serde_json::Value, keywords: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            for word in s.split_whitespace() {
                let clean = normalize_word(word);
                if clean.len() > 2 {
                    keywords.push(clean);
                }
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                extract_payload_keywords(v, keywords);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_payload_keywords(v, keywords);
            }
        }
        _ => {}
    }
}

fn format_category(cat: &BoundaryCategory) -> &str {
    match cat {
        BoundaryCategory::Privacy => "privacy",
        BoundaryCategory::Security => "security",
        BoundaryCategory::Legal => "legal",
        BoundaryCategory::Custom(s) => s.as_str(),
    }
}

fn format_list(items: &[String]) -> String {
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_shared::boundary::{AgentDirective, BoundaryCategory, PolicyBoundary};
    use arbiter_shared::task::Task;
    use chrono::Utc;

    fn political_boundary() -> PolicyBoundary {
        PolicyBoundary {
            id: "BOUNDARY-001".to_string(),
            category: BoundaryCategory::Privacy,
            trigger_patterns: vec![
                "charity".into(),
                "donation".into(),
                "donate".into(),
                "align".into(),
                "patterns".into(),
            ],
            protected_subjects: vec!["political".into(), "party".into(), "voting".into()],
            source_rule: "Never share the user's political affiliation.".into(),
            compiled_at: Utc::now(),
            active: true,
        }
    }

    fn security_boundary() -> PolicyBoundary {
        PolicyBoundary {
            id: "BOUNDARY-002".to_string(),
            category: BoundaryCategory::Security,
            trigger_patterns: vec![
                "password".into(),
                "credential".into(),
                "token".into(),
                "secret".into(),
                "key".into(),
            ],
            protected_subjects: vec!["password".into(), "credential".into(), "secret".into()],
            source_rule: "Never expose authentication credentials.".into(),
            compiled_at: Utc::now(),
            active: true,
        }
    }

    fn make_task(id: &str, task_type: &str, payload: serde_json::Value) -> Task {
        Task {
            id: id.into(),
            task_type: task_type.into(),
            payload,
            submitted_at: Utc::now(),
        }
    }

    #[test]
    fn allows_benign_task() {
        let engine = PolicyEngine::from_boundaries(vec![political_boundary()]);
        let task = make_task("t1", "write documentation", serde_json::json!({}));
        assert!(matches!(engine.evaluate(&task), PolicyVerdict::Allow));
    }

    #[test]
    fn refuses_privacy_violation() {
        let engine = PolicyEngine::from_boundaries(vec![political_boundary()]);
        let task = make_task(
            "t2",
            "suggest charity donations",
            serde_json::json!({"context": "user voting and political history"}),
        );
        match engine.evaluate(&task) {
            PolicyVerdict::Refuse(r) => {
                assert_eq!(r.boundary_id, "BOUNDARY-001");
                assert!(matches!(r.agent_directive, AgentDirective::Reformulate { .. }));
            }
            PolicyVerdict::Allow => panic!("expected refusal"),
        }
    }

    #[test]
    fn refuses_security_violation() {
        let engine = PolicyEngine::from_boundaries(vec![security_boundary()]);
        let task = make_task(
            "t3",
            "retrieve password",
            serde_json::json!({"target": "user credential store"}),
        );
        match engine.evaluate(&task) {
            PolicyVerdict::Refuse(r) => {
                assert_eq!(r.boundary_id, "BOUNDARY-002");
                assert_eq!(r.agent_directive, AgentDirective::Terminate);
            }
            PolicyVerdict::Allow => panic!("expected refusal"),
        }
    }

    #[test]
    fn trigger_only_does_not_fire() {
        let engine = PolicyEngine::from_boundaries(vec![political_boundary()]);
        // Has trigger "charity" but no protected subject
        let task = make_task("t4", "list charity events", serde_json::json!({}));
        assert!(matches!(engine.evaluate(&task), PolicyVerdict::Allow));
    }

    #[test]
    fn supersession_deactivates_old_boundary() {
        let mut engine = PolicyEngine::from_boundaries(vec![political_boundary()]);
        assert_eq!(engine.active_count(), 1);

        let new_boundary = PolicyBoundary {
            id: "BOUNDARY-001-v2".to_string(),
            category: BoundaryCategory::Privacy,
            trigger_patterns: vec!["charity".into()],
            protected_subjects: vec!["political".into()],
            source_rule: "Updated rule".into(),
            compiled_at: Utc::now(),
            active: true,
        };

        let record = engine
            .supersede("BOUNDARY-001", new_boundary, "admin", "updated triggers")
            .unwrap();

        assert_eq!(record.old_boundary_id, "BOUNDARY-001");
        assert_eq!(record.new_boundary_id, "BOUNDARY-001-v2");
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.boundaries().len(), 2); // old + new
    }

    #[test]
    fn nfkc_normalization_works() {
        let engine = PolicyEngine::from_boundaries(vec![political_boundary()]);
        // Use fullwidth characters that NFKC should normalize
        let task = make_task(
            "t5",
            "suggest \u{FF43}\u{FF48}\u{FF41}\u{FF52}\u{FF49}\u{FF54}\u{FF59} donations",
            serde_json::json!({"context": "political affiliation"}),
        );
        // "ｃｈａｒｉｔｙ" normalizes to "charity" via NFKC
        assert!(matches!(engine.evaluate(&task), PolicyVerdict::Refuse(_)));
    }
}
