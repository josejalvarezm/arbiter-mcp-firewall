use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Categories of enforceable boundaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BoundaryCategory {
    Privacy,
    Security,
    Legal,
    Custom(String),
}

/// A compiled policy boundary — the boolean form of a natural-language rule.
///
/// Carries `trigger_patterns` (lowercased keywords). If a task's text overlaps
/// with these patterns AND touches a `protected_subject`, the boundary fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBoundary {
    pub id: String,
    pub category: BoundaryCategory,
    /// Lowercased keyword patterns that signal a task *might* touch this boundary.
    pub trigger_patterns: Vec<String>,
    /// Lowercased keywords describing the protected data subject.
    pub protected_subjects: Vec<String>,
    /// The original human-readable rule.
    pub source_rule: String,
    pub compiled_at: DateTime<Utc>,
    /// Superseded boundaries are set to `false` but never deleted.
    pub active: bool,
}

/// A structured refusal returned when a boundary fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalRecord {
    pub task_id: String,
    pub boundary_id: String,
    pub category: BoundaryCategory,
    pub reason: String,
    pub matched_patterns: Vec<String>,
    pub refused_at: DateTime<Utc>,
    pub agent_directive: AgentDirective,
}

/// What happens to the agent after a refusal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentDirective {
    Reformulate {
        excluded_subjects: Vec<String>,
    },
    Terminate,
    EscalateToUser,
}

/// A record of a rule being superseded (append-only; old rule is never deleted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSupersession {
    pub old_boundary_id: String,
    pub new_boundary_id: String,
    pub authorised_by: String,
    pub reason: String,
    pub superseded_at: DateTime<Utc>,
}
