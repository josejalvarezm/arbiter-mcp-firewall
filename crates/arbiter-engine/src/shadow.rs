//! Async shadow-tier classifier client.
//!
//! Sends allowed request payloads to an external classifier (SetFit) for
//! secondary evaluation. Results are logged to the audit chain but never
//! block the request path.

use anyhow::{Context, Result};
use arbiter_shared::contract::ShadowConfig;
use arbiter_shared::task::ShadowLogEntry;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{info, warn};

/// Request body sent to the classifier service.
#[derive(Debug, Serialize)]
struct ClassifyRequest {
    text: String,
}

/// Response body from the classifier service.
#[derive(Debug, Deserialize)]
struct ClassifyResponse {
    label: String,
    confidence: f64,
}

/// HTTP client for the shadow-tier classifier.
#[derive(Clone)]
pub struct ShadowClient {
    http: reqwest::Client,
    config: ShadowConfig,
}

impl ShadowClient {
    /// Create a new shadow client from configuration.
    pub fn new(config: ShadowConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client");

        ShadowClient { http, config }
    }

    /// Classify a text payload. Returns a `ShadowLogEntry` ready for audit.
    pub async fn classify(&self, task_id: &str, text: &str) -> Result<ShadowLogEntry> {
        let start = Instant::now();

        let resp = self
            .http
            .post(&self.config.endpoint)
            .json(&ClassifyRequest {
                text: text.to_string(),
            })
            .send()
            .await
            .context("sending classify request")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("classifier returned HTTP {status}");
        }

        let body: ClassifyResponse = resp
            .json()
            .await
            .context("parsing classifier response")?;

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let would_refuse =
            body.label != "safe" && body.confidence >= self.config.confidence_threshold;

        if would_refuse {
            warn!(
                task_id = %task_id,
                label = %body.label,
                confidence = %body.confidence,
                "shadow tier would refuse"
            );
        } else {
            info!(
                task_id = %task_id,
                label = %body.label,
                confidence = %body.confidence,
                "shadow tier classified"
            );
        }

        Ok(ShadowLogEntry {
            timestamp: Utc::now(),
            task_id: task_id.to_string(),
            label: body.label,
            confidence: body.confidence,
            would_refuse,
            latency_ms,
        })
    }

    /// Whether the shadow tier is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}
