use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
}

pub fn verify_token(verifying_key_b64: &str, token: &str) -> anyhow::Result<TokenClaims> {
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
}
