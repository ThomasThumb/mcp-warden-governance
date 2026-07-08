use crate::external_command::ExternalCommand;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, SignatureEncoding, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

const TOKEN_CONTEXT: &str = "warden-cp/token/v2";
const TOKEN_TYP: &str = "warden-cp.token.v2";
const TOKEN_ED25519_ALG: &str = "Ed25519";
const TOKEN_ML_DSA_ALG: &str = "ML-DSA-65";
const AUDIT_CHECKPOINT_CONTEXT: &str = "warden-cp/audit-checkpoint/v1";
const LEGACY_AUDIT_SEAL_CONTEXT: &str = "warden-cp/audit-legacy-seal/v1";

/// SPIFFE ID shape: spiffe://<trust-domain>/<path>. Using this format now -
/// even though these are locally-minted, not SPIRE-issued - means the
/// `agent_sessions.spiffe_id` column and everything downstream (audit
/// records, policy scoping) doesn't need to change shape when you eventually
/// point this at real SPIRE. That's the "expand to enterprise without
/// constraints" part: swap the issuer, keep the identifier format.
pub fn mint_spiffe_id(trust_domain: &str, agent_uuid: &str) -> String {
    format!("spiffe://{trust_domain}/agent/{agent_uuid}")
}

/// Delegation-chain claim, modeled on OAuth 2.0 Token Exchange's `act`
/// (actor) claim (RFC 8693): who is *actually* making this call, and on
/// whose authority. `sub` is the agent session's SPIFFE ID; `act.sub` is the
/// human/service principal that authorized it. Chain further if you ever
/// have agent-delegates-to-sub-agent scenarios - `act` nests.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,     // agent session spiffe_id
    pub act: ActorClaim, // who authorized this agent
    pub cnf: ConfirmationClaim,
    pub aud: String,
    pub server_id: String, // scoped to exactly one upstream server
    pub tool_name: String, // and exactly one tool - not "all tools on this server"
    pub gateway_id: String,
    pub jti: String,
    pub nbf: i64,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActorClaim {
    pub sub: String, // principal id
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    /// Ed25519 verifying key owned by the worker/agent session. Gateways use
    /// this for a per-call proof-of-possession signature, so stealing the
    /// short-lived token alone is not enough to call a tool.
    pub ed25519_public_key_b64: String,
}

pub struct HybridSigner {
    backend: SignerBackend,
}

enum SignerBackend {
    Local(LocalSigner),
    External(ExternalSigner),
}

struct LocalSigner {
    ed25519: Ed25519SigningKey,
    ml_dsa65: Option<MlDsaSigningKey<MlDsa65>>,
}

struct ExternalSigner {
    command: ExternalCommand,
    ed25519_public_key: [u8; 32],
    ml_dsa65_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProtectedHeader {
    typ: String,
    alg: String,
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_dsa_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_dsa_kid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedEnvelope {
    protected_b64: String,
    payload_b64: String,
    ed25519_sig_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_dsa_sig_b64: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditCheckpointSignature {
    pub ed25519_sig_b64: String,
    pub ml_dsa_alg: Option<String>,
    pub ml_dsa_sig_b64: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditSignatureParts<'a> {
    pub ed25519_sig_b64: &'a str,
    pub ml_dsa_alg: Option<&'a str>,
    pub ml_dsa_sig_b64: Option<&'a str>,
    pub require_ml_dsa: bool,
}

#[derive(Serialize)]
struct ExternalSignRequest<'a> {
    version: u8,
    action: &'a str,
    message_b64: String,
    include_ml_dsa: bool,
}

#[derive(Deserialize)]
struct ExternalSignResponse {
    ed25519_sig_b64: String,
    #[serde(default)]
    ml_dsa_alg: Option<String>,
    #[serde(default)]
    ml_dsa_sig_b64: Option<String>,
}

impl HybridSigner {
    /// Loads a production external signer when WARDEN_SIGNER_COMMAND is set.
    /// In that mode, warden-cp never reads or stores the private signing keys;
    /// the configured adapter is expected to talk to KMS, an HSM, Vault, or an
    /// OS keystore and return signatures over the exact bytes supplied here.
    ///
    /// Without WARDEN_SIGNER_COMMAND, this falls back to local development key
    /// files with owner-only permissions. Those files are convenient for dev
    /// and demos, but production should prefer the external signer boundary.
    pub fn load_or_generate(path: &Path, ml_dsa_path: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(external) = ExternalSigner::from_env()? {
            tracing::info!(
                "using external signing command; private signer keys stay out of warden-cp"
            );
            return Ok(Self {
                backend: SignerBackend::External(external),
            });
        }

        let ed25519 = if let Ok(bytes) = std::fs::read(path) {
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key file is the wrong length"))?;
            Ed25519SigningKey::from_bytes(&seed)
        } else {
            let mut csprng = OsRng;
            let signing_key = Ed25519SigningKey::generate(&mut csprng);
            write_secret_key_file(path, &signing_key.to_bytes())?;
            tracing::warn!(
                "generated a new local Ed25519 signing key at {path:?}; use WARDEN_SIGNER_COMMAND \
                 for KMS/HSM/OS-keystore-backed production signing"
            );
            signing_key
        };

        let ml_dsa65 = match ml_dsa_path {
            Some(path) => Some(load_or_generate_ml_dsa(path)?),
            None => None,
        };

        Ok(Self {
            backend: SignerBackend::Local(LocalSigner { ed25519, ml_dsa65 }),
        })
    }

    pub fn ed25519_verifying_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.ed25519_public_key_bytes())
    }

    pub fn ed25519_key_id(&self) -> String {
        key_id(&self.ed25519_public_key_bytes())
    }

    pub fn ml_dsa65_verifying_key_b64(&self) -> Option<String> {
        self.ml_dsa65_public_key_bytes()
            .map(|key| URL_SAFE_NO_PAD.encode(key))
    }

    pub fn ml_dsa65_key_id(&self) -> Option<String> {
        self.ml_dsa65_public_key_bytes()
            .map(|key| key_id(key.as_slice()))
    }

    pub fn sign_token(&self, claims: &TokenClaims) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(claims)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let header = ProtectedHeader {
            typ: TOKEN_TYP.to_string(),
            alg: TOKEN_ED25519_ALG.to_string(),
            kid: self.ed25519_key_id(),
            ml_dsa_alg: self.has_ml_dsa().then(|| TOKEN_ML_DSA_ALG.to_string()),
            ml_dsa_kid: self.ml_dsa65_key_id(),
        };
        let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let signing_input = token_signing_input(&protected_b64, &payload_b64);
        let signatures = self.sign_message(&signing_input, self.has_ml_dsa())?;
        let envelope = SignedEnvelope {
            protected_b64,
            payload_b64,
            ed25519_sig_b64: signatures.ed25519_sig_b64,
            ml_dsa_sig_b64: signatures.ml_dsa_sig_b64,
        };
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope)?))
    }

    #[allow(dead_code)] // Used by online token introspection and future local admin checks.
    pub fn verify_token(&self, token: &str, require_ml_dsa: bool) -> anyhow::Result<TokenClaims> {
        let envelope_bytes = URL_SAFE_NO_PAD.decode(token)?;
        let envelope: SignedEnvelope = serde_json::from_slice(&envelope_bytes)?;
        let header_bytes = URL_SAFE_NO_PAD.decode(&envelope.protected_b64)?;
        let header: ProtectedHeader = serde_json::from_slice(&header_bytes)?;
        if header.typ != TOKEN_TYP || header.alg != TOKEN_ED25519_ALG {
            anyhow::bail!("unsupported token header");
        }
        if header.kid != self.ed25519_key_id() {
            anyhow::bail!("token key id does not match the active signer");
        }
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&envelope.ed25519_sig_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        let signing_input = token_signing_input(&envelope.protected_b64, &envelope.payload_b64);
        self.ed25519_verifying_key()?
            .verify_strict(&signing_input, &sig)?;
        if require_ml_dsa {
            verify_ml_dsa_envelope(
                self.ml_dsa65_public_key_bytes().as_deref(),
                &header,
                &envelope,
                &signing_input,
            )?;
        }
        let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_b64)?;
        let claims: TokenClaims = serde_json::from_slice(&payload)?;
        let now = chrono::Utc::now().timestamp();
        if claims.exp < now {
            anyhow::bail!("token expired");
        }
        if claims.nbf > now + 60 {
            anyhow::bail!("token not yet valid");
        }
        if claims.iat > now + 60 {
            anyhow::bail!("token issued in the future");
        }
        Ok(claims)
    }

    pub fn sign_audit_checkpoint(
        &self,
        seq: i64,
        entry_hash: &str,
        signed_at: &str,
        include_ml_dsa: bool,
    ) -> anyhow::Result<AuditCheckpointSignature> {
        let message = audit_checkpoint_message(seq, entry_hash, signed_at);
        self.sign_message(&message, include_ml_dsa)
    }

    pub fn sign_legacy_audit_seal(
        &self,
        last_entry_hash: &str,
        sealed_at: &str,
    ) -> anyhow::Result<AuditCheckpointSignature> {
        let message = legacy_audit_seal_message(last_entry_hash, sealed_at);
        self.sign_message(&message, true)
    }

    pub fn verify_audit_checkpoint(
        &self,
        seq: i64,
        entry_hash: &str,
        signed_at: &str,
        signature: AuditSignatureParts<'_>,
    ) -> anyhow::Result<()> {
        let message = audit_checkpoint_message(seq, entry_hash, signed_at);
        self.verify_audit_message(&message, signature)
    }

    pub fn verify_legacy_audit_seal(
        &self,
        last_entry_hash: &str,
        sealed_at: &str,
        signature: AuditSignatureParts<'_>,
    ) -> anyhow::Result<()> {
        let message = legacy_audit_seal_message(last_entry_hash, sealed_at);
        self.verify_audit_message(&message, signature)
    }

    fn sign_message(
        &self,
        message: &[u8],
        include_ml_dsa: bool,
    ) -> anyhow::Result<AuditCheckpointSignature> {
        if include_ml_dsa && !self.has_ml_dsa() {
            anyhow::bail!("ML-DSA signing was requested but no ML-DSA signer is configured");
        }
        match &self.backend {
            SignerBackend::Local(local) => local.sign_message(message, include_ml_dsa),
            SignerBackend::External(external) => external.sign_message(message, include_ml_dsa),
        }
    }

    fn verify_audit_message(
        &self,
        message: &[u8],
        signature: AuditSignatureParts<'_>,
    ) -> anyhow::Result<()> {
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature.ed25519_sig_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad audit checkpoint signature length"))?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        self.ed25519_verifying_key()?.verify_strict(message, &sig)?;

        let has_ml_dsa_sig = signature.ml_dsa_alg.is_some() || signature.ml_dsa_sig_b64.is_some();
        if signature.require_ml_dsa || has_ml_dsa_sig {
            verify_ml_dsa_signature(
                self.ml_dsa65_public_key_bytes().as_deref(),
                message,
                signature.ml_dsa_alg,
                signature.ml_dsa_sig_b64,
            )?;
        }

        Ok(())
    }

    fn ed25519_public_key_bytes(&self) -> Vec<u8> {
        match &self.backend {
            SignerBackend::Local(local) => local.ed25519.verifying_key().to_bytes().to_vec(),
            SignerBackend::External(external) => external.ed25519_public_key.to_vec(),
        }
    }

    fn ed25519_verifying_key(&self) -> anyhow::Result<Ed25519VerifyingKey> {
        let key_bytes: [u8; 32] = self
            .ed25519_public_key_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 public key has the wrong length"))?;
        Ok(Ed25519VerifyingKey::from_bytes(&key_bytes)?)
    }

    fn ml_dsa65_public_key_bytes(&self) -> Option<Vec<u8>> {
        match &self.backend {
            SignerBackend::Local(local) => local
                .ml_dsa65
                .as_ref()
                .map(|key| key.verifying_key().to_bytes().as_slice().to_vec()),
            SignerBackend::External(external) => external.ml_dsa65_public_key.clone(),
        }
    }

    fn has_ml_dsa(&self) -> bool {
        self.ml_dsa65_public_key_bytes().is_some()
    }
}

impl LocalSigner {
    fn sign_message(
        &self,
        message: &[u8],
        include_ml_dsa: bool,
    ) -> anyhow::Result<AuditCheckpointSignature> {
        let ed_sig: Ed25519Signature = self.ed25519.sign(message);
        let ml_dsa_sig_b64 = self
            .ml_dsa65
            .as_ref()
            .filter(|_| include_ml_dsa)
            .map(|key| {
                let sig = key.sign(message);
                URL_SAFE_NO_PAD.encode(sig.to_bytes().as_slice())
            });
        Ok(AuditCheckpointSignature {
            ed25519_sig_b64: URL_SAFE_NO_PAD.encode(ed_sig.to_bytes()),
            ml_dsa_alg: ml_dsa_sig_b64
                .as_ref()
                .map(|_| TOKEN_ML_DSA_ALG.to_string()),
            ml_dsa_sig_b64,
        })
    }
}

impl ExternalSigner {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(command) = ExternalCommand::from_env(
            "WARDEN_SIGNER_COMMAND",
            "WARDEN_SIGNER_ARGS_JSON",
            "WARDEN_SIGNER_TIMEOUT_MS",
            5_000,
        )?
        else {
            return Ok(None);
        };

        let ed25519_public_key = decode_env_public_key("WARDEN_SIGNER_ED25519_PUBLIC_KEY_B64")?;
        Ed25519VerifyingKey::from_bytes(&ed25519_public_key)?;

        let ml_dsa65_public_key = std::env::var("WARDEN_SIGNER_ML_DSA65_PUBLIC_KEY_B64")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| decode_public_key_value("WARDEN_SIGNER_ML_DSA65_PUBLIC_KEY_B64", &value))
            .transpose()?;
        if let Some(key) = &ml_dsa65_public_key {
            MlDsaVerifyingKey::<MlDsa65>::new_from_slice(key)?;
        } else if !truthy_env("WARDEN_SIGNER_ALLOW_ED25519_ONLY") {
            anyhow::bail!(
                "WARDEN_SIGNER_COMMAND requires WARDEN_SIGNER_ML_DSA65_PUBLIC_KEY_B64; \
                 set WARDEN_SIGNER_ALLOW_ED25519_ONLY=true only for a documented migration"
            );
        }

        Ok(Some(Self {
            command,
            ed25519_public_key,
            ml_dsa65_public_key,
        }))
    }

    fn sign_message(
        &self,
        message: &[u8],
        include_ml_dsa: bool,
    ) -> anyhow::Result<AuditCheckpointSignature> {
        let response: ExternalSignResponse = self.command.run_json(&ExternalSignRequest {
            version: 1,
            action: "sign",
            message_b64: URL_SAFE_NO_PAD.encode(message),
            include_ml_dsa,
        })?;

        let ed_sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&response.ed25519_sig_b64)?
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("external signer returned a bad Ed25519 signature length")
            })?;
        let ed_sig = Ed25519Signature::from_bytes(&ed_sig_bytes);
        Ed25519VerifyingKey::from_bytes(&self.ed25519_public_key)?
            .verify_strict(message, &ed_sig)?;

        let has_ml_dsa = response.ml_dsa_alg.is_some() || response.ml_dsa_sig_b64.is_some();
        if include_ml_dsa || has_ml_dsa {
            verify_ml_dsa_signature(
                self.ml_dsa65_public_key.as_deref(),
                message,
                response.ml_dsa_alg.as_deref(),
                response.ml_dsa_sig_b64.as_deref(),
            )?;
        }

        Ok(AuditCheckpointSignature {
            ed25519_sig_b64: response.ed25519_sig_b64,
            ml_dsa_alg: response.ml_dsa_alg,
            ml_dsa_sig_b64: response.ml_dsa_sig_b64,
        })
    }
}

fn token_signing_input(protected_b64: &str, payload_b64: &str) -> Vec<u8> {
    format!("{TOKEN_CONTEXT}\n{protected_b64}.{payload_b64}").into_bytes()
}

fn audit_checkpoint_message(seq: i64, entry_hash: &str, signed_at: &str) -> Vec<u8> {
    format!("{AUDIT_CHECKPOINT_CONTEXT}\n{seq}\n{entry_hash}\n{signed_at}").into_bytes()
}

fn legacy_audit_seal_message(last_entry_hash: &str, sealed_at: &str) -> Vec<u8> {
    format!("{LEGACY_AUDIT_SEAL_CONTEXT}\n{last_entry_hash}\n{sealed_at}").into_bytes()
}

fn key_id(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn verify_ml_dsa_envelope(
    key_bytes: Option<&[u8]>,
    header: &ProtectedHeader,
    envelope: &SignedEnvelope,
    signing_input: &[u8],
) -> anyhow::Result<()> {
    if header.ml_dsa_alg.as_deref() != Some(TOKEN_ML_DSA_ALG) {
        anyhow::bail!("token is missing supported ML-DSA algorithm marker");
    }
    let Some(key_bytes) = key_bytes else {
        anyhow::bail!("ML-DSA token verification is required but no verifier key is configured");
    };
    if header.ml_dsa_kid.as_deref() != Some(key_id(key_bytes).as_str()) {
        anyhow::bail!("token ML-DSA key id does not match the active signer");
    }
    let sig_b64 = envelope
        .ml_dsa_sig_b64
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("token is missing ML-DSA signature"))?;
    verify_ml_dsa_signature(
        Some(key_bytes),
        signing_input,
        header.ml_dsa_alg.as_deref(),
        Some(sig_b64),
    )
}

fn verify_ml_dsa_signature(
    key_bytes: Option<&[u8]>,
    message: &[u8],
    alg: Option<&str>,
    sig_b64: Option<&str>,
) -> anyhow::Result<()> {
    let Some(key_bytes) = key_bytes else {
        anyhow::bail!("ML-DSA signature is required but no verifier key is configured");
    };
    if alg != Some(TOKEN_ML_DSA_ALG) {
        anyhow::bail!("missing supported ML-DSA marker");
    }
    let sig_b64 = sig_b64.ok_or_else(|| anyhow::anyhow!("missing ML-DSA signature"))?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes.as_slice())?;
    let key = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(key_bytes)?;
    key.verify(message, &sig)?;
    Ok(())
}

fn decode_env_public_key(name: &str) -> anyhow::Result<[u8; 32]> {
    let value = std::env::var(name).map_err(|_| anyhow::anyhow!("{name} must be set"))?;
    let bytes = decode_public_key_value(name, &value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} has the wrong length"))
}

fn decode_public_key_value(name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| anyhow::anyhow!("{name} must be URL-safe base64 without padding: {e}"))
}

fn truthy_env(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn load_or_generate_ml_dsa(path: &Path) -> anyhow::Result<MlDsaSigningKey<MlDsa65>> {
    if let Ok(bytes) = std::fs::read(path) {
        return Ok(MlDsaSigningKey::<MlDsa65>::new_from_slice(&bytes)?);
    }

    let key = MlDsaSigningKey::<MlDsa65>::generate();
    write_secret_key_file(path, key.to_seed().as_slice())?;
    tracing::warn!(
        "generated a new local ML-DSA-65 signing key at {path:?}; use WARDEN_SIGNER_COMMAND \
         for KMS/HSM/OS-keystore-backed production signing"
    );
    Ok(key)
}

fn write_secret_key_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = secret_key_open_options(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    restrict_key_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn secret_key_open_options(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn secret_key_open_options(path: &Path) -> anyhow::Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?)
}

fn restrict_key_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        restrict_key_file_windows(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_key_file_windows(path: &Path) -> anyhow::Result<()> {
    use std::process::Command;

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let system32 = Path::new(&system_root).join("System32");
    let whoami = Command::new(system32.join("whoami.exe")).output()?;
    if !whoami.status.success() {
        anyhow::bail!("failed to determine current Windows identity for key ACL");
    }
    let owner = String::from_utf8(whoami.stdout)?.trim().to_string();
    if owner.is_empty() {
        anyhow::bail!("empty Windows identity from whoami");
    }
    let owner_grant = format!("{owner}:F");
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("signing key path is not valid UTF-8"))?;
    let status = Command::new(system32.join("icacls.exe"))
        .arg(path_str)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(owner_grant)
        .arg("/grant:r")
        .arg("*S-1-5-18:F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:F")
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to restrict Windows ACL on signing key");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> HybridSigner {
        HybridSigner {
            backend: SignerBackend::Local(LocalSigner {
                ed25519: Ed25519SigningKey::from_bytes(&[11u8; 32]),
                ml_dsa65: Some(MlDsaSigningKey::<MlDsa65>::generate()),
            }),
        }
    }

    fn test_claims(_signer: &HybridSigner) -> TokenClaims {
        let now = chrono::Utc::now().timestamp();
        TokenClaims {
            sub: mint_spiffe_id("warden.local", "550e8400-e29b-41d4-a716-446655440000"),
            act: ActorClaim {
                sub: "principal-1".to_string(),
            },
            cnf: ConfirmationClaim {
                ed25519_public_key_b64: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            },
            aud: "warden-mcp:gw-1:docs:search".to_string(),
            server_id: "docs".to_string(),
            tool_name: "search".to_string(),
            gateway_id: "gw-1".to_string(),
            jti: "token-1".to_string(),
            nbf: now,
            iat: now,
            exp: now + 60,
        }
    }

    #[test]
    fn token_verify_rejects_protected_header_tampering() {
        let signer = test_signer();
        let token = signer.sign_token(&test_claims(&signer)).unwrap();
        signer.verify_token(&token, true).unwrap();

        let envelope_bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes).unwrap();
        let header_b64 = envelope
            .get("protected_b64")
            .and_then(|value| value.as_str())
            .unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        header["kid"] = serde_json::Value::String("wrong-key".to_string());
        envelope["protected_b64"] =
            serde_json::Value::String(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()));
        let tampered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());

        assert!(signer.verify_token(&tampered, true).is_err());
    }

    #[test]
    fn audit_checkpoint_signature_detects_hash_tampering() {
        let signer = test_signer();
        let checkpoint = signer
            .sign_audit_checkpoint(42, "abc123", "2026-07-08T00:00:00Z", true)
            .unwrap();

        signer
            .verify_audit_checkpoint(
                42,
                "abc123",
                "2026-07-08T00:00:00Z",
                AuditSignatureParts {
                    ed25519_sig_b64: &checkpoint.ed25519_sig_b64,
                    ml_dsa_alg: checkpoint.ml_dsa_alg.as_deref(),
                    ml_dsa_sig_b64: checkpoint.ml_dsa_sig_b64.as_deref(),
                    require_ml_dsa: true,
                },
            )
            .unwrap();

        assert!(signer
            .verify_audit_checkpoint(
                42,
                "different",
                "2026-07-08T00:00:00Z",
                AuditSignatureParts {
                    ed25519_sig_b64: &checkpoint.ed25519_sig_b64,
                    ml_dsa_alg: checkpoint.ml_dsa_alg.as_deref(),
                    ml_dsa_sig_b64: checkpoint.ml_dsa_sig_b64.as_deref(),
                    require_ml_dsa: true,
                },
            )
            .is_err());
    }

    #[test]
    fn ed25519_only_checkpoint_is_allowed_when_ml_dsa_not_required() {
        let signer = test_signer();
        let checkpoint = signer
            .sign_audit_checkpoint(43, "abc123", "2026-07-08T00:00:00Z", false)
            .unwrap();
        assert!(checkpoint.ml_dsa_sig_b64.is_none());

        signer
            .verify_audit_checkpoint(
                43,
                "abc123",
                "2026-07-08T00:00:00Z",
                AuditSignatureParts {
                    ed25519_sig_b64: &checkpoint.ed25519_sig_b64,
                    ml_dsa_alg: checkpoint.ml_dsa_alg.as_deref(),
                    ml_dsa_sig_b64: checkpoint.ml_dsa_sig_b64.as_deref(),
                    require_ml_dsa: false,
                },
            )
            .unwrap();
        assert!(signer
            .verify_audit_checkpoint(
                43,
                "abc123",
                "2026-07-08T00:00:00Z",
                AuditSignatureParts {
                    ed25519_sig_b64: &checkpoint.ed25519_sig_b64,
                    ml_dsa_alg: checkpoint.ml_dsa_alg.as_deref(),
                    ml_dsa_sig_b64: checkpoint.ml_dsa_sig_b64.as_deref(),
                    require_ml_dsa: true,
                },
            )
            .is_err());
    }
}
