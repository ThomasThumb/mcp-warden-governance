use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ml_dsa::{
    KeyInit, MlDsa65, Signature as MlDsaSignature, Verifier as MlDsaVerifier,
    VerifyingKey as MlDsaVerifyingKey,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub act: ActorClaim,
    pub cnf: Option<ConfirmationClaim>,
    pub server_id: String,
    pub tool_name: String,
    pub gateway_id: String,
    pub jti: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ActorClaim {
    pub sub: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConfirmationClaim {
    pub ed25519_public_key_b64: String,
}

#[derive(Debug, Deserialize)]
struct SignedEnvelope {
    payload_b64: String,
    ed25519_sig_b64: String,
    ml_dsa_alg: Option<String>,
    ml_dsa_sig_b64: Option<String>,
}

pub fn verify_token(
    verifying_key_b64: &str,
    ml_dsa_key_b64: Option<&str>,
    require_ml_dsa: bool,
    token: &str,
) -> anyhow::Result<TokenClaims> {
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(verifying_key_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer public key has the wrong length"))?;
    let vk = VerifyingKey::from_bytes(&key_bytes)?;

    let envelope_bytes = URL_SAFE_NO_PAD.decode(token)?;
    let envelope: SignedEnvelope = serde_json::from_slice(&envelope_bytes)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&envelope.ed25519_sig_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("token signature has the wrong length"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(envelope.payload_b64.as_bytes(), &sig)?;
    if require_ml_dsa {
        verify_ml_dsa_signature(&envelope, ml_dsa_key_b64)?;
    }
    let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_b64)?;
    let claims: TokenClaims = serde_json::from_slice(&payload)?;
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        anyhow::bail!("token expired");
    }
    if claims.iat > now + 60 {
        anyhow::bail!("token issued in the future");
    }
    Ok(claims)
}

fn verify_ml_dsa_signature(
    envelope: &SignedEnvelope,
    ml_dsa_key_b64: Option<&str>,
) -> anyhow::Result<()> {
    let Some(key_b64) = ml_dsa_key_b64 else {
        anyhow::bail!("ML-DSA token verification is required but no public key is configured");
    };
    if envelope.ml_dsa_alg.as_deref() != Some("ML-DSA-65") {
        anyhow::bail!("token is missing supported ML-DSA algorithm marker");
    }
    let Some(sig_b64) = envelope.ml_dsa_sig_b64.as_deref() else {
        anyhow::bail!("token is missing ML-DSA signature");
    };
    let key_bytes = URL_SAFE_NO_PAD.decode(key_b64)?;
    let vk = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(&key_bytes)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig = MlDsaSignature::<MlDsa65>::try_from(sig_bytes.as_slice())?;
    vk.verify(envelope.payload_b64.as_bytes(), &sig)?;
    Ok(())
}

pub fn agent_session_id_from_spiffe(spiffe_id: &str) -> Option<String> {
    let session_id = spiffe_id.rsplit_once("/agent/")?.1;
    Uuid::parse_str(session_id).ok()?;
    Some(session_id.to_string())
}

pub fn proof_message(token: &str, args_fingerprint: &str) -> String {
    format!("warden-pop-v1\n{token}\n{args_fingerprint}")
}

pub fn verify_agent_proof(
    public_key_b64: &str,
    token: &str,
    args_fingerprint: &str,
    proof_sig_b64: &str,
) -> anyhow::Result<()> {
    let public_key: [u8; 32] = BASE64_STANDARD
        .decode(public_key_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent proof key has the wrong length"))?;
    let signature: [u8; 64] = BASE64_STANDARD
        .decode(proof_sig_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent proof signature has the wrong length"))?;
    let vk = VerifyingKey::from_bytes(&public_key)?;
    let sig = Signature::from_bytes(&signature);
    vk.verify(proof_message(token, args_fingerprint).as_bytes(), &sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ml_dsa::{
        Generate, KeyExport, Keypair, MlDsa65, SignatureEncoding, Signer as MlDsaSigner,
        SigningKey as MlDsaSigningKey,
    };

    #[test]
    fn proof_verifies_against_bound_agent_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key_b64 = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
        let token = "token";
        let args_fingerprint = "args";
        let sig = signing_key.sign(proof_message(token, args_fingerprint).as_bytes());
        let proof = BASE64_STANDARD.encode(sig.to_bytes());

        verify_agent_proof(&public_key_b64, token, args_fingerprint, &proof).unwrap();
        assert!(verify_agent_proof(&public_key_b64, token, "different", &proof).is_err());
    }

    #[test]
    fn hybrid_token_requires_ml_dsa_when_enabled() {
        let ed = SigningKey::from_bytes(&[9u8; 32]);
        let ml = MlDsaSigningKey::<MlDsa65>::generate();
        let claims = serde_json::json!({
            "sub": "spiffe://warden.local/agent/550e8400-e29b-41d4-a716-446655440000",
            "act": { "sub": "principal-1" },
            "cnf": { "ed25519_public_key_b64": BASE64_STANDARD.encode([7u8; 32]) },
            "server_id": "docs",
            "tool_name": "search",
            "gateway_id": "gw-1",
            "jti": "token-1",
            "iat": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 60
        });
        let payload = serde_json::to_vec(&claims).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let ed_sig = ed.sign(payload_b64.as_bytes());
        let ml_sig = ml.sign(payload_b64.as_bytes());
        let envelope = serde_json::json!({
            "payload_b64": payload_b64,
            "ed25519_sig_b64": URL_SAFE_NO_PAD.encode(ed_sig.to_bytes()),
            "ml_dsa_alg": "ML-DSA-65",
            "ml_dsa_sig_b64": URL_SAFE_NO_PAD.encode(ml_sig.to_bytes().as_slice())
        });
        let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());
        let ed_key = URL_SAFE_NO_PAD.encode(ed.verifying_key().to_bytes());
        let ml_key = URL_SAFE_NO_PAD.encode(ml.verifying_key().to_bytes().as_slice());

        verify_token(&ed_key, Some(&ml_key), true, &token).unwrap();
        assert!(verify_token(&ed_key, None, true, &token).is_err());
    }
}
