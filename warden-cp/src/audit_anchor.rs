use crate::identity::AuditCheckpointSignature;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Clone)]
pub struct AuditAnchor {
    file_path: Option<PathBuf>,
    command: Option<AnchorCommand>,
    required: bool,
}

#[derive(Clone)]
struct AnchorCommand {
    command: crate::external_command::ExternalCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnchorRecord {
    pub seq: i64,
    pub entry_hash: String,
    pub checkpoint_signed_at: String,
    pub checkpoint_sig_b64: String,
    pub checkpoint_ml_dsa_alg: Option<String>,
    pub checkpoint_ml_dsa_sig_b64: Option<String>,
    pub anchored_at: String,
}

impl AuditAnchor {
    pub fn from_env() -> anyhow::Result<Self> {
        let file_path = std::env::var("AUDIT_ANCHOR_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let command = AnchorCommand::from_env()?;
        let required = truthy_env("AUDIT_ANCHOR_REQUIRED");
        if required && file_path.is_none() && command.is_none() {
            anyhow::bail!(
                "AUDIT_ANCHOR_REQUIRED=true needs AUDIT_ANCHOR_FILE or AUDIT_ANCHOR_COMMAND to be set"
            );
        }
        Ok(Self {
            file_path,
            command,
            required,
        })
    }

    pub fn required(&self) -> bool {
        self.required
    }

    pub fn is_enabled(&self) -> bool {
        self.file_path.is_some() || self.command.is_some()
    }

    pub fn publish(&self, record: &AuditAnchorRecord) -> anyhow::Result<()> {
        if let Some(path) = &self.file_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            serde_json::to_writer(&mut file, record)?;
            file.write_all(b"\n")?;
            file.flush()?;
        }
        if let Some(command) = &self.command {
            command.publish(record)?;
        }
        Ok(())
    }

    pub fn latest(&self) -> anyhow::Result<Option<AuditAnchorRecord>> {
        if let Some(command) = &self.command {
            return command.latest();
        }
        let Some(path) = &self.file_path else {
            return Ok(None);
        };
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let reader = BufReader::new(file);
        let mut latest = None;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            latest = Some(serde_json::from_str(&line)?);
        }
        Ok(latest)
    }
}

#[derive(Serialize)]
struct AnchorCommandRequest<'a> {
    version: u8,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<&'a AuditAnchorRecord>,
}

#[derive(Deserialize)]
struct AnchorCommandResponse {
    #[serde(default)]
    record: Option<AuditAnchorRecord>,
}

impl AnchorCommand {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let command = crate::external_command::ExternalCommand::from_env(
            "AUDIT_ANCHOR_COMMAND",
            "AUDIT_ANCHOR_ARGS_JSON",
            "AUDIT_ANCHOR_TIMEOUT_MS",
            5_000,
        )?;
        Ok(command.map(|command| Self { command }))
    }

    fn publish(&self, record: &AuditAnchorRecord) -> anyhow::Result<()> {
        let _: serde_json::Value = self.command.run_json(&AnchorCommandRequest {
            version: 1,
            action: "publish",
            record: Some(record),
        })?;
        Ok(())
    }

    fn latest(&self) -> anyhow::Result<Option<AuditAnchorRecord>> {
        let response: AnchorCommandResponse = self.command.run_json(&AnchorCommandRequest {
            version: 1,
            action: "latest",
            record: None,
        })?;
        Ok(response.record)
    }
}

impl AuditAnchorRecord {
    pub fn new(
        seq: i64,
        entry_hash: String,
        checkpoint_signed_at: String,
        checkpoint: &AuditCheckpointSignature,
    ) -> Self {
        Self {
            seq,
            entry_hash,
            checkpoint_signed_at,
            checkpoint_sig_b64: checkpoint.ed25519_sig_b64.clone(),
            checkpoint_ml_dsa_alg: checkpoint.ml_dsa_alg.clone(),
            checkpoint_ml_dsa_sig_b64: checkpoint.ml_dsa_sig_b64.clone(),
            anchored_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn truthy_env(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}
