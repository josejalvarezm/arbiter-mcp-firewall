use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::boundary::PolicyBoundary;

/// The compiled contract manifest — single source of truth produced by the compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractManifest {
    pub version: String,
    pub compiled_at: DateTime<Utc>,
    pub global: GlobalContract,
    pub agents: HashMap<String, AgentContract>,
    #[serde(default)]
    pub boundaries: Vec<PolicyBoundary>,
    /// Optional shadow-tier classifier configuration.
    #[serde(default)]
    pub shadow_tier: Option<ShadowConfig>,
    /// Tools explicitly allowed to perform destructive operations.
    /// If empty, ALL destructive tools are blocked by default.
    #[serde(default)]
    pub destructive_allowlist: Vec<String>,
    /// Maximum binary content size in bytes (images/audio).
    /// Default: 10 MiB.
    #[serde(default = "default_max_binary_size")]
    pub max_binary_size: usize,
    /// Elicitation data types that are blocked (e.g., "password", "secret").
    #[serde(default)]
    pub blocked_elicitation_types: Vec<String>,
    /// Audit log rotation: max file size in bytes before rotating.
    /// Default: 50 MiB. 0 = no rotation.
    #[serde(default = "default_audit_max_size")]
    pub audit_max_file_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalContract {
    pub rules: Vec<String>,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContract {
    pub id: String,
    pub version: u32,
    pub rules: Vec<String>,
    pub constraints: Vec<String>,
    pub capabilities: Vec<String>,
}

/// Configuration for the async shadow-tier classifier (SetFit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowConfig {
    /// Whether shadow evaluation is enabled.
    pub enabled: bool,
    /// HTTP endpoint for the classifier service.
    pub endpoint: String,
    /// Confidence threshold above which a "refuse" label triggers a shadow refusal log.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,
}

fn default_confidence_threshold() -> f64 {
    0.7
}

fn default_max_binary_size() -> usize {
    10 * 1024 * 1024 // 10 MiB
}

fn default_audit_max_size() -> usize {
    50 * 1024 * 1024 // 50 MiB
}
