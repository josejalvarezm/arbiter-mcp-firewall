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
