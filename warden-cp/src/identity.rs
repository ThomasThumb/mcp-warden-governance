use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

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

/// Classical signer, real and working today. The commented-out
/// `ml_dsa_sig_b64` field below is where FIPS 204 (ML-DSA) hybrid signing
/// slots in - RustCrypto's pure-Rust `ml-dsa` crate is the natural fit, but
/// check GHSA-hcp2-x6j4-29j7 (a timing side-channel in its Decompose step,
/// disclosed Jan 2026) is patched in whatever version you pull before
/// relying on it. Shipping Ed25519-only today and adding ML-DSA as a second,
/// separately-verified signature - not a replacement - is the hybrid pattern
/// Cloudflare/AWS use for exactly this "don't trust the new primitive alone
/// yet" reason.
pub struct HybridSigner {
    ed25519: SigningKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedEnvelope {
    payload_b64: String,
    ed25519_sig_b64: String,
    // ml_dsa_sig_b64: Option<String>,  // TODO: wire up RustCrypto `ml-dsa` here
}

impl HybridSigner {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        Self {
            ed25519: SigningKey::generate(&mut csprng),
        }
    }

    /// Fixes the "restart silently invalidates every token" hole: loads a
    /// persisted 32-byte seed if present, otherwise generates one and writes
    /// it with owner-only permissions (0600 on Unix - Windows ACLs aren't
    /// handled here, flagged honestly rather than pretending they are).
    /// This file is as sensitive as a root password. Treat it that way:
    /// back it up somewhere real, don't commit it, restrict who can read the
    /// host it lives on.
    pub fn load_or_generate(path: &std::path::Path) -> anyhow::Result<Self> {
        if let Ok(bytes) = std::fs::read(path) {
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key file is the wrong length"))?;
            return Ok(Self {
                ed25519: SigningKey::from_bytes(&seed),
            });
        }

        let signer = Self::generate();
        std::fs::write(path, signer.ed25519.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::warn!(
            "generated a new signing key at {path:?} - back this file up now, \
             losing it invalidates every token this control plane has ever issued"
        );
        Ok(signer)
    }

    pub fn verifying_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.ed25519.verifying_key().to_bytes())
    }

    pub fn sign_token(&self, claims: &TokenClaims) -> anyhow::Result<String> {
        let payload = serde_json::to_vec(claims)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let sig: Signature = self.ed25519.sign(payload_b64.as_bytes());
        let envelope = SignedEnvelope {
            payload_b64,
            ed25519_sig_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
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
        let vk = VerifyingKey::from_bytes(verifying_key_bytes)?;
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&envelope.ed25519_sig_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(envelope.payload_b64.as_bytes(), &sig)?;
        let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_b64)?;
        let claims: TokenClaims = serde_json::from_slice(&payload)?;
        if claims.exp < chrono::Utc::now().timestamp() {
            anyhow::bail!("token expired");
        }
        Ok(claims)
    }
}
