//! Tamper-evident, hash-chained, append-only audit log.
//!
//! Each entry's JSON line is hashed with SHA-256. The next entry
//! carries the previous hash, forming a chain. Modifying or deleting
//! any entry breaks the chain from that point forward.
//!
//! The file handle is opened once and held for the lifetime of the
//! `AuditChain`. Writes are flushed after every append.
//!
//! All I/O is async via Tokio.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::instrument;

/// SHA-256 genesis hash: 64 hex zeros.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute the SHA-256 hex digest of a string.
fn compute_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// A hash-chained entry wrapper. Wraps any serializable payload with chain metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainedEntry<T> {
    /// The actual payload.
    #[serde(flatten)]
    pub data: T,
    /// SHA-256 of the previous entry's JSON line.
    pub prev_hash: String,
}

/// Async, append-only, hash-chained audit log.
///
/// Generic over `T`: any type implementing `Serialize + DeserializeOwned`.
/// The file handle is opened once and held for the lifetime of the chain.
pub struct AuditChain {
    path: PathBuf,
    /// SHA-256 of the last written JSON line (chain head).
    last_hash: String,
    /// Persistent buffered writer — avoids reopening the file on every append.
    writer: BufWriter<File>,
    /// Running byte count of the current file.
    current_size: u64,
    /// Number of rotated files so far.
    rotation_index: u32,
}

impl AuditChain {
    /// Open or create an audit log file. Recovers the chain head from the last line.
    #[instrument(skip_all, fields(path = %path.as_ref().display()))]
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("creating audit log directory")?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .context("opening audit log file")?;

        let current_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let last_hash = recover_last_hash(&path).await?;

        tracing::debug!(last_hash = %last_hash, "audit chain opened");

        Ok(AuditChain {
            path,
            last_hash,
            writer: BufWriter::new(file),
            current_size,
            rotation_index: 0,
        })
    }

    /// Append an entry to the log with hash-chaining.
    #[instrument(skip_all)]
    pub async fn append<T: Serialize>(&mut self, data: &T) -> Result<()> {
        let chained = ChainedEntry {
            data,
            prev_hash: self.last_hash.clone(),
        };

        let mut line =
            serde_json::to_string(&chained).context("serializing audit entry")?;

        self.last_hash = compute_hash(&line);

        line.push('\n');

        let line_bytes = line.len() as u64;
        self.writer
            .write_all(line.as_bytes())
            .await
            .context("writing audit entry")?;

        self.writer
            .flush()
            .await
            .context("flushing audit log")?;

        self.current_size += line_bytes;

        tracing::trace!(hash = %self.last_hash, "entry appended");

        Ok(())
    }

    /// Rotate the log file if it exceeds `max_size` bytes.
    ///
    /// The rotated file is renamed to `<path>.1`, `.2`, etc.
    /// A new file is created and the chain continues (with the current
    /// `last_hash` carried over for cross-file continuity).
    pub async fn rotate_if_needed(&mut self, max_size: usize) -> Result<bool> {
        if max_size == 0 || (self.current_size as usize) < max_size {
            return Ok(false);
        }

        // Flush and drop the current writer
        self.writer.flush().await.context("flushing before rotation")?;

        self.rotation_index += 1;
        let rotated_path = format!("{}.{}", self.path.display(), self.rotation_index);

        // Rename current → rotated
        fs::rename(&self.path, &rotated_path)
            .await
            .context("renaming audit log for rotation")?;

        tracing::info!(
            rotated_to = %rotated_path,
            size = self.current_size,
            "audit log rotated"
        );

        // Open a fresh file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .context("opening new audit log after rotation")?;

        self.writer = BufWriter::new(file);
        self.current_size = 0;
        // last_hash carries over — cross-file chain continuity

        Ok(true)
    }

    /// Return the current file size in bytes.
    pub fn current_size(&self) -> u64 {
        self.current_size
    }

    /// Read all entries from the log.
    pub async fn read_all<T: DeserializeOwned>(&self) -> Result<Vec<ChainedEntry<T>>> {
        let content = fs::read_to_string(&self.path)
            .await
            .context("reading audit log")?;

        let mut entries = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: ChainedEntry<T> =
                serde_json::from_str(line).context("deserializing audit entry")?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Verify the hash chain integrity of the entire log.
    ///
    /// Returns `true` if every entry's `prev_hash` matches the SHA-256
    /// of the preceding JSON line. Returns `false` if tampering is detected.
    pub async fn verify(path: impl AsRef<Path>) -> Result<bool> {
        let content = fs::read_to_string(path.as_ref())
            .await
            .context("reading audit log for verification")?;

        let mut expected_prev = GENESIS_HASH.to_string();

        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            // Parse just to extract prev_hash
            let val: serde_json::Value =
                serde_json::from_str(line).context("parsing line during verification")?;

            let actual_prev = val
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if actual_prev != expected_prev {
                tracing::warn!(
                    expected = %expected_prev,
                    actual = %actual_prev,
                    "hash chain broken"
                );
                return Ok(false);
            }

            expected_prev = compute_hash(line);
        }

        Ok(true)
    }

    /// Return the current chain-head hash.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Return the log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Query audit log entries as raw JSON, filtered by a predicate.
    ///
    /// The predicate receives each raw JSON `Value` and returns `true` to include it.
    /// Useful for searching by session, time range, or decision type without
    /// requiring a concrete deserialization target.
    pub async fn query(
        &self,
        predicate: impl Fn(&serde_json::Value) -> bool,
    ) -> Result<Vec<serde_json::Value>> {
        let content = fs::read_to_string(&self.path)
            .await
            .context("reading audit log for query")?;

        let mut results = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if predicate(&val) {
                    results.push(val);
                }
            }
        }
        Ok(results)
    }

    /// Query by time range (inclusive). Both bounds are optional.
    pub async fn query_by_time_range(
        &self,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<serde_json::Value>> {
        self.query(|val| {
            let ts = val
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            match ts {
                Some(dt) => {
                    let after = from.is_none_or(|f| dt >= f);
                    let before = to.is_none_or(|t| dt <= t);
                    after && before
                }
                None => false,
            }
        })
        .await
    }

    /// List all rotated log files for this chain.
    pub async fn rotated_files(&self) -> Result<Vec<PathBuf>> {
        let parent = self.path.parent().unwrap_or(Path::new("."));
        let stem = self.path.file_name().unwrap_or_default().to_string_lossy();

        let mut files = Vec::new();
        let mut dir = fs::read_dir(parent).await.context("reading audit dir")?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&*stem) && name != *stem {
                files.push(entry.path());
            }
        }
        files.sort();
        Ok(files)
    }
}

/// Recover the chain-head hash from the last non-empty line.
async fn recover_last_hash(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(GENESIS_HASH.to_string());
    }

    let content = fs::read_to_string(path)
        .await
        .context("reading log for chain recovery")?;

    match content.lines().rev().find(|l| !l.trim().is_empty()) {
        Some(line) => Ok(compute_hash(line)),
        None => Ok(GENESIS_HASH.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_shared::task::{DecisionLogEntry, TaskStatus};
    use chrono::Utc;

    fn make_entry(task_id: &str) -> DecisionLogEntry {
        DecisionLogEntry {
            timestamp: Utc::now(),
            task_id: task_id.into(),
            agent: "compiler".into(),
            rationale: "Matched by capability".into(),
            outcome: Some(TaskStatus::Success),
        }
    }

    #[tokio::test]
    async fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let mut chain = AuditChain::open(&log_path).await.unwrap();
        chain.append(&make_entry("task-1")).await.unwrap();
        chain.append(&make_entry("task-2")).await.unwrap();

        let entries: Vec<ChainedEntry<DecisionLogEntry>> =
            chain.read_all().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data.task_id, "task-1");
        assert_eq!(entries[1].data.task_id, "task-2");
    }

    #[tokio::test]
    async fn hash_chain_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let mut chain = AuditChain::open(&log_path).await.unwrap();
        chain.append(&make_entry("task-1")).await.unwrap();
        chain.append(&make_entry("task-2")).await.unwrap();
        chain.append(&make_entry("task-3")).await.unwrap();

        assert!(AuditChain::verify(&log_path).await.unwrap());
    }

    #[tokio::test]
    async fn first_entry_has_genesis_hash() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let mut chain = AuditChain::open(&log_path).await.unwrap();
        chain.append(&make_entry("task-1")).await.unwrap();

        let entries: Vec<ChainedEntry<DecisionLogEntry>> =
            chain.read_all().await.unwrap();
        assert_eq!(entries[0].prev_hash, GENESIS_HASH);
    }

    #[tokio::test]
    async fn append_only_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        {
            let mut chain = AuditChain::open(&log_path).await.unwrap();
            chain.append(&make_entry("task-1")).await.unwrap();
        }

        {
            let mut chain = AuditChain::open(&log_path).await.unwrap();
            chain.append(&make_entry("task-2")).await.unwrap();

            let entries: Vec<ChainedEntry<DecisionLogEntry>> =
                chain.read_all().await.unwrap();
            assert_eq!(entries.len(), 2);
        }

        assert!(AuditChain::verify(&log_path).await.unwrap());
    }

    #[tokio::test]
    async fn tampered_log_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("decisions.jsonl");

        let mut chain = AuditChain::open(&log_path).await.unwrap();
        chain.append(&make_entry("task-1")).await.unwrap();
        chain.append(&make_entry("task-2")).await.unwrap();

        // Tamper: rewrite file with broken hash
        let content = fs::read_to_string(&log_path).await.unwrap();
        let tampered = content.replacen("task-1", "task-X", 1);
        fs::write(&log_path, tampered).await.unwrap();

        assert!(!AuditChain::verify(&log_path).await.unwrap());
    }
}
