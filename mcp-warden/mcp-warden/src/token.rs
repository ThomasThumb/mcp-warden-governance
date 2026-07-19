use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, VerifyingKey};
use ml_dsa::{
    KeyInit, MlDsa65, Signature as MlDsaSignature, Verifier as MlDsaVerifier,
    VerifyingKey as MlDsaVerifyingKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const TOKEN_CONTEXT: &str = "warden-cp/token/v2";
const TOKEN_TYP: &str = "warden-cp.token.v2";
const TOKEN_ED25519_ALG: &str = "Ed25519";
const TOKEN_ML_DSA_ALG: &str = "ML-DSA-65";
const MAX_TOKEN_BYTES: usize = 128 * 1024;
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 3600;

#[derive(Debug, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub act: ActorClaim,
    pub cnf: Option<ConfirmationClaim>,
    pub aud: String,
    pub server_id: String,
    pub tool_name: String,
    pub gateway_id: String,
    pub jti: Option<String>,
    pub nbf: i64,
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
    protected_b64: String,
    payload_b64: String,
    ed25519_sig_b64: String,
    ml_dsa_sig_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtectedHeader {
    typ: String,
    alg: String,
    kid: String,
    ml_dsa_alg: Option<String>,
    ml_dsa_kid: Option<String>,
}

pub fn verify_token(
    verifying_key_b64: &str,
    ml_dsa_key_b64: Option<&str>,
    require_ml_dsa: bool,
    expected_audience: &str,
    token: &str,
) -> anyhow::Result<TokenClaims> {
    if token.len() > MAX_TOKEN_BYTES {
        anyhow::bail!("token exceeds the accepted size limit");
    }
    let decoded_key = URL_SAFE_NO_PAD.decode(verifying_key_b64)?;
    let expected_kid = key_id(&decoded_key);
    let key_bytes: [u8; 32] = decoded_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer public key has the wrong length"))?;
    let vk = VerifyingKey::from_bytes(&key_bytes)?;

    let envelope_bytes = URL_SAFE_NO_PAD.decode(token)?;
    let envelope: SignedEnvelope = serde_json::from_slice(&envelope_bytes)?;
    if envelope.protected_b64.len() > 16 * 1024 || envelope.payload_b64.len() > 64 * 1024 {
        anyhow::bail!("token envelope component exceeds the accepted size limit");
    }
    let header_bytes = URL_SAFE_NO_PAD.decode(&envelope.protected_b64)?;
    let header: ProtectedHeader = serde_json::from_slice(&header_bytes)?;
    if header.typ != TOKEN_TYP || header.alg != TOKEN_ED25519_ALG {
        anyhow::bail!("unsupported token header");
    }
    if header.kid != expected_kid {
        anyhow::bail!("token key id does not match configured signer");
    }
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&envelope.ed25519_sig_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("token signature has the wrong length"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let signing_input = token_signing_input(&envelope.protected_b64, &envelope.payload_b64);

    vk.verify_strict(&signing_input, &sig)?;
    if require_ml_dsa {
        verify_ml_dsa_signature(&envelope, &header, &signing_input, ml_dsa_key_b64)?;
    }
    let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_b64)?;
    let claims: TokenClaims = serde_json::from_slice(&payload)?;
    let now = chrono::Utc::now().timestamp();
    if claims.exp <= now {
        anyhow::bail!("token expired");
    }
    if claims.nbf > now + 60 {
        anyhow::bail!("token not yet valid");
    }
    if claims.iat > now + 60 {
        anyhow::bail!("token issued in the future");
    }
    if claims.exp <= claims.iat
        || claims.nbf > claims.exp
        || claims.exp.saturating_sub(claims.iat) > MAX_TOKEN_LIFETIME_SECONDS
    {
        anyhow::bail!("token has an invalid validity window");
    }
    if [
        claims.sub.as_str(),
        claims.act.sub.as_str(),
        claims.aud.as_str(),
        claims.server_id.as_str(),
        claims.tool_name.as_str(),
        claims.gateway_id.as_str(),
    ]
    .iter()
    .any(|value| value.is_empty() || value.len() > 512)
    {
        anyhow::bail!("token contains an invalid scoped identifier");
    }
    if claims.aud != expected_audience {
        anyhow::bail!("token audience does not match this gateway/server/tool call");
    }
    Ok(claims)
}

fn verify_ml_dsa_signature(
    envelope: &SignedEnvelope,
    header: &ProtectedHeader,
    signing_input: &[u8],
    ml_dsa_key_b64: Option<&str>,
) -> anyhow::Result<()> {
    let Some(key_b64) = ml_dsa_key_b64 else {
        anyhow::bail!("ML-DSA token verification is required but no public key is configured");
    };
    let key_bytes = URL_SAFE_NO_PAD.decode(key_b64)?;
    if header.ml_dsa_alg.as_deref() != Some(TOKEN_ML_DSA_ALG) {
        anyhow::bail!("token is missing supported ML-DSA algorithm marker");
    }
    if header.ml_dsa_kid.as_deref() != Some(key_id(&key_bytes).as_str()) {
        anyhow::bail!("token ML-DSA key id does not match configured signer");
    }
    let Some(sig_b64) = envelope.ml_dsa_sig_b64.as_deref() else {
        anyhow::bail!("token is missing ML-DSA signature");
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(&key_bytes)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    let sig = MlDsaSignature::<MlDsa65>::try_from(sig_bytes.as_slice())?;
    vk.verify(signing_input, &sig)?;
    Ok(())
}

pub fn token_audience(gateway_id: &str, server_id: &str, tool_name: &str) -> String {
    format!(
        "warden-mcp:v2:{}:{gateway_id}:{}:{server_id}:{}:{tool_name}",
        gateway_id.len(),
        server_id.len(),
        tool_name.len()
    )
}

fn token_signing_input(protected_b64: &str, payload_b64: &str) -> Vec<u8> {
    format!("{TOKEN_CONTEXT}\n{protected_b64}.{payload_b64}").into_bytes()
}

fn key_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    URL_SAFE_NO_PAD.encode(&digest[..16])
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
    let public_key: [u8; 32] = decode_base64_either(public_key_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent proof key has the wrong length"))?;
    let signature: [u8; 64] = decode_base64_either(proof_sig_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent proof signature has the wrong length"))?;
    let vk = VerifyingKey::from_bytes(&public_key)?;
    let sig = Signature::from_bytes(&signature);
    vk.verify_strict(proof_message(token, args_fingerprint).as_bytes(), &sig)?;
    Ok(())
}

fn decode_base64_either(value: &str) -> anyhow::Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(Into::into)
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

        let public_key_url_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let proof_url_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        verify_agent_proof(&public_key_url_b64, token, args_fingerprint, &proof_url_b64).unwrap();
    }

    #[test]
    fn hybrid_token_requires_ml_dsa_when_enabled() {
        let ed = SigningKey::from_bytes(&[9u8; 32]);
        let ml = MlDsaSigningKey::<MlDsa65>::generate();
        let audience = token_audience("gw-1", "docs", "search");
        let claims = serde_json::json!({
            "sub": "spiffe://warden.local/agent/550e8400-e29b-41d4-a716-446655440000",
            "act": { "sub": "principal-1" },
            "cnf": { "ed25519_public_key_b64": BASE64_STANDARD.encode([7u8; 32]) },
            "aud": audience,
            "server_id": "docs",
            "tool_name": "search",
            "gateway_id": "gw-1",
            "jti": "token-1",
            "nbf": chrono::Utc::now().timestamp(),
            "iat": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 60
        });
        let payload = serde_json::to_vec(&claims).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let protected = serde_json::json!({
            "typ": TOKEN_TYP,
            "alg": TOKEN_ED25519_ALG,
            "kid": key_id(&ed.verifying_key().to_bytes()),
            "ml_dsa_alg": TOKEN_ML_DSA_ALG,
            "ml_dsa_kid": key_id(ml.verifying_key().to_bytes().as_slice())
        });
        let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
        let signing_input = token_signing_input(&protected_b64, &payload_b64);
        let ed_sig = ed.sign(&signing_input);
        let ml_sig = ml.sign(&signing_input);
        let envelope = serde_json::json!({
            "protected_b64": protected_b64,
            "payload_b64": payload_b64,
            "ed25519_sig_b64": URL_SAFE_NO_PAD.encode(ed_sig.to_bytes()),
            "ml_dsa_sig_b64": URL_SAFE_NO_PAD.encode(ml_sig.to_bytes().as_slice())
        });
        let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());
        let ed_key = URL_SAFE_NO_PAD.encode(ed.verifying_key().to_bytes());
        let ml_key = URL_SAFE_NO_PAD.encode(ml.verifying_key().to_bytes().as_slice());

        verify_token(
            &ed_key,
            Some(&ml_key),
            true,
            &token_audience("gw-1", "docs", "search"),
            &token,
        )
        .unwrap();
        assert!(verify_token(
            &ed_key,
            None,
            true,
            &token_audience("gw-1", "docs", "search"),
            &token
        )
        .is_err());
        assert!(verify_token(
            &ed_key,
            Some(&ml_key),
            true,
            &token_audience("gw-1", "docs", "other"),
            &token
        )
        .is_err());
    }

    #[test]
    fn token_audience_is_tuple_unambiguous() {
        assert_ne!(
            token_audience("gateway", "server:a", "tool"),
            token_audience("gateway", "server", "a:tool")
        );
    }
}
