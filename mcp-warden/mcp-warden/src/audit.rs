use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub ts: String,
    pub server: &'a str,
    pub tool: &'a str,
    /// "allowed" | "denied" | "pending_approval" | "blocked_injection" | "blocked_rug_pull"
    pub decision: &'a str,
    /// sha256 of the call arguments, NOT the raw arguments - secrets and PII
    /// should never sit in a log file in plaintext.
    pub args_fingerprint: String,
    pub injection_flags: &'a [&'static str],
    pub result_bytes: Option<usize>,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("audit.jsonl"),
        }
    }

    pub fn record(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(event)?)?;
        f.sync_data()?;
        Ok(())
    }

    pub fn now() -> String {
        Utc::now().to_rfc3339()
    }

    pub fn fingerprint_args(args: &serde_json::Value) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(args)?);
        Ok(format!("{:x}", hasher.finalize()))
    }
}
