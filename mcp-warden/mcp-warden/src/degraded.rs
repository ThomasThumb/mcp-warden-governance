use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Deliberately NOT an automatic fail-open or fail-closed policy. When the
/// control plane can't be reached, the gateway refuses to serve *anything*
/// until a human explicitly runs `mcp-warden confirm-degraded` on that
/// specific box, for a specific reason, for a bounded window. That decision
/// is logged locally and (once the control plane is reachable again) should
/// get shipped up as an audit event too - see README "Roadmap".
#[derive(Debug, Serialize, Deserialize)]
pub struct DegradedAck {
    pub reason: String,
    pub confirmed_by: String,
    pub confirmed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn ack_path(state_dir: &Path) -> PathBuf {
    state_dir.join("degraded_ack.json")
}

pub fn write_ack(
    state_dir: &Path,
    reason: &str,
    confirmed_by: &str,
    minutes: i64,
) -> Result<DegradedAck> {
    let now = Utc::now();
    let ack = DegradedAck {
        reason: reason.to_string(),
        confirmed_by: confirmed_by.to_string(),
        confirmed_at: now,
        expires_at: now + Duration::minutes(minutes),
    };
    std::fs::write(ack_path(state_dir), serde_json::to_string_pretty(&ack)?)?;
    Ok(ack)
}

/// Returns Some(ack) only if a confirmation exists AND hasn't expired.
/// An expired or missing ack means: refuse to serve, full stop.
pub fn read_valid_ack(state_dir: &Path) -> Option<DegradedAck> {
    let text = std::fs::read_to_string(ack_path(state_dir)).ok()?;
    let ack: DegradedAck = serde_json::from_str(&text).ok()?;
    if ack.expires_at > Utc::now() {
        Some(ack)
    } else {
        None
    }
}
