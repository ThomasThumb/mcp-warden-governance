use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HashStore {
    /// key: "{server_id}::{tool_name}" -> approved sha256 hex digest of the tool definition
    approved: HashMap<String, String>,
    pub pending: HashMap<String, PendingChange>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PendingChange {
    pub old_hash: Option<String>,
    pub new_hash: String,
    pub new_definition: serde_json::Value,
}

/// Detects "rug pulls": a server that changes a tool's name, description, or
/// input schema after you already approved it. MCP has no protocol-level
/// protection against this - a tool description is trusted text handed
/// straight to the model, so a server author (or someone who compromised
/// their infra) can rewrite it any time after your first approval.
pub struct IntegrityGuard {
    path: PathBuf,
    store: HashStore,
}

impl IntegrityGuard {
    pub fn load(state_dir: &Path) -> anyhow::Result<Self> {
        let path = state_dir.join("tool_hashes.json");
        let store = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&path)?)?
        } else {
            HashStore::default()
        };
        Ok(Self { path, store })
    }

    fn save(&self) -> anyhow::Result<()> {
        std::fs::write(&self.path, serde_json::to_string_pretty(&self.store)?)?;
        Ok(())
    }

    /// Hash the *entire* tool definition (name + description + input schema),
    /// not just the description string. Attackers hide instructions in schema
    /// field names and enum values too, not only the description field.
    pub fn fingerprint(definition: &serde_json::Value) -> anyhow::Result<String> {
        let canonical = serde_json::to_vec(definition)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// true  -> known-good, unchanged since last approval, safe to expose
    /// false -> new or changed since last approval; recorded as pending and
    ///          withheld from the host until a human runs `mcp-warden approve <key>`
    pub fn check_and_record(
        &mut self,
        key: &str,
        definition: &serde_json::Value,
    ) -> anyhow::Result<bool> {
        let new_hash = Self::fingerprint(definition)?;
        let outcome = match self.store.approved.get(key) {
            Some(existing) if *existing == new_hash => true,
            Some(existing) => {
                self.store.pending.insert(
                    key.to_string(),
                    PendingChange {
                        old_hash: Some(existing.clone()),
                        new_hash,
                        new_definition: definition.clone(),
                    },
                );
                false
            }
            None => {
                self.store.pending.insert(
                    key.to_string(),
                    PendingChange {
                        old_hash: None,
                        new_hash,
                        new_definition: definition.clone(),
                    },
                );
                false
            }
        };
        self.save()?;
        Ok(outcome)
    }

    pub fn approve(&mut self, key: &str) -> anyhow::Result<bool> {
        if let Some(pending) = self.store.pending.remove(key) {
            self.store
                .approved
                .insert(key.to_string(), pending.new_hash);
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn list_pending(&self) -> Vec<(String, PendingChange)> {
        self.store
            .pending
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}
