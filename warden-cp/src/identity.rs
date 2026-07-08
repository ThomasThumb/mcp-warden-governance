use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, SignatureEncoding, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    pub server_id: String, // scoped to exactly one upstream server
    pub tool_name: String, // and exactly one tool - not "all tools on this server"
    pub gateway_id: String,
    pub jti: String,
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
    ed25519: Ed25519SigningKey,
    ml_dsa65: Option<MlDsaSigningKey<MlDsa65>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedEnvelope {
    payload_b64: String,
    ed25519_sig_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_dsa_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_dsa_sig_b64: Option<String>,
}

impl HybridSigner {
    /// Fixes the "restart silently invalidates every token" hole: loads a
    /// persisted 32-byte seed if present, otherwise generates one and writes
    /// it with owner-only permissions (0600 on Unix - Windows ACLs aren't
    /// handled here, flagged honestly rather than pretending they are).
    /// This file is as sensitive as a root password. Treat it that way:
    /// back it up somewhere real, don't commit it, restrict who can read the
    /// host it lives on.
    pub fn load_or_generate(path: &Path, ml_dsa_path: Option<&Path>) -> anyhow::Result<Self> {
        let ed25519 = if let Ok(bytes) = std::fs::read(path) {
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key file is the wrong length"))?;
            Ed25519SigningKey::from_bytes(&seed)
        } else {
            let mut csprng = OsRng;
            let signing_key = Ed25519SigningKey::generate(&mut csprng);
            std::fs::write(path, signing_key.to_bytes())?;
            restrict_key_file(path)?;
            tracing::warn!(
                "generated a new Ed25519 signing key at {path:?} - back this file up now, \
                 losing it invalidates issued tokens"
            );
            signing_key
        };

        let ml_dsa65 = match ml_dsa_path {
            Some(path) => Some(load_or_generate_ml_dsa(path)?),
            None => None,
        };

        Ok(Self { ed25519, ml_dsa65 })
    }

    pub fn ed25519_verifying_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.ed25519.verifying_key().to_bytes())
    }

    pub fn ml_dsa65_verifying_key_b64(&self) -> Option<String> {
        self.ml_dsa65
            .as_ref()
            .map(|key| URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes().as_slice()))
    }

    pub fn sign_token(&self, claims: &TokenClaims) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(claims)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let sig: Ed25519Signature = self.ed25519.sign(payload_b64.as_bytes());
        let (ml_dsa_alg, ml_dsa_sig_b64) = match &self.ml_dsa65 {
            Some(key) => {
                let sig = key.sign(payload_b64.as_bytes());
                (
                    Some("ML-DSA-65".to_string()),
                    Some(URL_SAFE_NO_PAD.encode(sig.to_bytes().as_slice())),
                )
            }
            None => (None, None),
        };
        let envelope = SignedEnvelope {
            payload_b64,
            ed25519_sig_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            ml_dsa_alg,
            ml_dsa_sig_b64,
        };
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope)?))
    }

    #[allow(dead_code)] // Used when gateways start verifying per-call scoped tokens locally.
    pub fn verify_token(
        verifying_key_bytes: &[u8; 32],
        token: &str,
    ) -> anyhow::Result<TokenClaims> {
        let envelope_bytes = URL_SAFE_NO_PAD.decode(token)?;
        let envelope: SignedEnvelope = serde_json::from_slice(&envelope_bytes)?;
        let vk = Ed25519VerifyingKey::from_bytes(verifying_key_bytes)?;
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&envelope.ed25519_sig_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        vk.verify(envelope.payload_b64.as_bytes(), &sig)?;
        let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_b64)?;
        let claims: TokenClaims = serde_json::from_slice(&payload)?;
        if claims.exp < chrono::Utc::now().timestamp() {
            anyhow::bail!("token expired");
        }
        Ok(claims)
    }
}

fn load_or_generate_ml_dsa(path: &Path) -> anyhow::Result<MlDsaSigningKey<MlDsa65>> {
    if let Ok(bytes) = std::fs::read(path) {
        return Ok(MlDsaSigningKey::<MlDsa65>::new_from_slice(&bytes)?);
    }

    let key = MlDsaSigningKey::<MlDsa65>::generate();
    std::fs::write(path, key.to_seed().as_slice())?;
    restrict_key_file(path)?;
    tracing::warn!(
        "generated a new ML-DSA-65 signing key at {path:?} - back this file up with the Ed25519 key"
    );
    Ok(key)
}

fn restrict_key_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
