use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::routes::AppState;

type ApiResult<T> = Result<T, (StatusCode, String)>;

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub allowed_domains: Vec<String>,
    pub default_roles: Vec<String>,
    pub session_ttl_hours: i64,
}

impl OidcConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let issuer_url = match std::env::var("OIDC_ISSUER_URL") {
            Ok(v) if !v.trim().is_empty() => trim_slash(&v),
            _ => return Ok(None),
        };
        let client_id = required_env("OIDC_CLIENT_ID")?;
        let client_secret = required_env("OIDC_CLIENT_SECRET")?;
        let redirect_url = std::env::var("OIDC_REDIRECT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:7878/oidc/callback".to_string());
        let allowed_domains = csv_env("OIDC_ALLOWED_EMAIL_DOMAINS");
        let default_roles = csv_env("OIDC_DEFAULT_ROLES");
        let session_ttl_hours = std::env::var("OIDC_SESSION_TTL_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8)
            .clamp(1, 24);

        Ok(Some(Self {
            issuer_url,
            client_id,
            client_secret,
            redirect_url,
            allowed_domains,
            default_roles,
            session_ttl_hours,
        }))
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: usize,
    iat: Option<usize>,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    preferred_username: Option<String>,
    groups: Option<Vec<String>>,
}

pub async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> ApiResult<Redirect> {
    let cfg = oidc(&state)?;
    let discovery = discover(&cfg).await?;
    let state_value = random_url_token();
    let nonce = random_url_token();
    let code_verifier = random_url_token();
    let code_challenge = pkce_challenge(&code_verifier);
    let now = Utc::now();
    let expires = now + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oidc_login_states
             (state, nonce, code_verifier, return_to, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&state_value)
    .bind(&nonce)
    .bind(&code_verifier)
    .bind(&query.return_to)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    let mut url = Url::parse(&discovery.authorization_endpoint).map_err(bad_gateway)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_url)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state_value)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Redirect::temporary(url.as_str()))
}

pub async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Html<String>> {
    let cfg = oidc(&state)?;
    let state_row = sqlx::query(
        "SELECT nonce, code_verifier, return_to, expires_at
         FROM oidc_login_states WHERE state = ?",
    )
    .bind(&query.state)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;

    sqlx::query("DELETE FROM oidc_login_states WHERE state = ?")
        .bind(&query.state)
        .execute(&state.pool)
        .await
        .map_err(err500)?;

    let Some(state_row) = state_row else {
        return Err((StatusCode::BAD_REQUEST, "unknown OIDC state".into()));
    };
    let expires_at: String = state_row.try_get("expires_at").map_err(err500)?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at).map_err(err500)?;
    if expires_at < Utc::now() {
        return Err((StatusCode::BAD_REQUEST, "expired OIDC state".into()));
    }
    let nonce: String = state_row.try_get("nonce").map_err(err500)?;
    let code_verifier: String = state_row.try_get("code_verifier").map_err(err500)?;

    let discovery = discover(&cfg).await?;
    let token = exchange_code(&cfg, &discovery, &query.code, &code_verifier).await?;
    let claims = verify_id_token(&cfg, &discovery, &token.id_token, &nonce).await?;
    let email = claims.email.clone().or(claims.preferred_username.clone());
    enforce_allowed_domain(&cfg, email.as_deref())?;

    let principal_id = upsert_principal(&state, &cfg, &claims, email.as_deref()).await?;
    sync_oidc_groups(
        &state,
        &discovery.issuer,
        &principal_id,
        claims.groups.as_deref(),
    )
    .await?;
    let (session_token, session_expires_at) =
        create_session(&state, &principal_id, cfg.session_ttl_hours).await?;

    Ok(Html(success_page(
        &principal_id,
        &session_token,
        &session_expires_at,
    )))
}

fn oidc(state: &AppState) -> ApiResult<std::sync::Arc<OidcConfig>> {
    state
        .oidc
        .clone()
        .ok_or((StatusCode::NOT_FOUND, "OIDC is not configured".into()))
}

async fn discover(cfg: &OidcConfig) -> ApiResult<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", cfg.issuer_url);
    let discovery: Discovery = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(bad_gateway)?
        .error_for_status()
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)?;
    if trim_slash(&discovery.issuer) != cfg.issuer_url {
        return Err((StatusCode::BAD_GATEWAY, "OIDC issuer mismatch".into()));
    }
    Ok(discovery)
}

async fn exchange_code(
    cfg: &OidcConfig,
    discovery: &Discovery,
    code: &str,
    code_verifier: &str,
) -> ApiResult<TokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_url.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("code_verifier", code_verifier),
    ];
    reqwest::Client::new()
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(bad_gateway)?
        .error_for_status()
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)
}

async fn verify_id_token(
    cfg: &OidcConfig,
    discovery: &Discovery,
    id_token: &str,
    nonce: &str,
) -> ApiResult<Claims> {
    let header = decode_header(id_token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("bad ID token header: {e}"),
        )
    })?;
    let alg = header.alg;
    if !matches!(alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "only RSA-signed OIDC ID tokens are supported".into(),
        ));
    }
    let jwks: Jwks = reqwest::Client::new()
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(bad_gateway)?
        .error_for_status()
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kty == "RSA" && key.kid.as_deref() == header.kid.as_deref())
        .or_else(|| {
            jwks.keys
                .iter()
                .find(|key| key.kty == "RSA" && key.alg.as_deref() == Some(alg_name(alg)))
        })
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "matching OIDC JWK not found".into(),
        ))?;
    let n = jwk
        .n
        .as_deref()
        .ok_or((StatusCode::UNAUTHORIZED, "JWK missing n".into()))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or((StatusCode::UNAUTHORIZED, "JWK missing e".into()))?;
    let key = DecodingKey::from_rsa_components(n, e)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("bad RSA JWK: {e}")))?;

    let mut validation = Validation::new(alg);
    validation.set_audience(&[cfg.client_id.clone()]);
    validation.set_issuer(&[discovery.issuer.clone()]);
    let data = decode::<Claims>(id_token, &key, &validation).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("ID token verification failed: {e}"),
        )
    })?;
    if data.claims.nonce.as_deref() != Some(nonce) {
        return Err((StatusCode::UNAUTHORIZED, "OIDC nonce mismatch".into()));
    }
    Ok(data.claims)
}

async fn upsert_principal(
    state: &AppState,
    cfg: &OidcConfig,
    claims: &Claims,
    email: Option<&str>,
) -> ApiResult<String> {
    let subject = format!("{}:{}", claims.iss, claims.sub);
    let now = Utc::now().to_rfc3339();
    if let Some(row) = sqlx::query(
        "SELECT principal_id FROM principal_identities
         WHERE provider = 'oidc' AND external_subject = ?",
    )
    .bind(&subject)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    {
        let principal_id: String = row.try_get("principal_id").map_err(err500)?;
        let display_name = display_name(claims, email);
        sqlx::query("UPDATE principals SET display_name = ?, active = 1 WHERE id = ?")
            .bind(&display_name)
            .bind(&principal_id)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
        sqlx::query(
            "UPDATE principal_identities SET email = ?, updated_at = ?
             WHERE provider = 'oidc' AND external_subject = ?",
        )
        .bind(email)
        .bind(&now)
        .bind(&subject)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
        apply_default_roles(state, cfg, &principal_id).await?;
        return Ok(principal_id);
    }

    let principal_id = Uuid::new_v4().to_string();
    let display_name = display_name(claims, email);
    sqlx::query(
        "INSERT INTO principals (id, kind, display_name, external_id, active, created_at)
         VALUES (?, 'human', ?, ?, 1, ?)",
    )
    .bind(&principal_id)
    .bind(&display_name)
    .bind(format!("oidc:{subject}"))
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    sqlx::query(
        "INSERT INTO principal_identities
             (provider, external_subject, principal_id, email, created_at, updated_at)
         VALUES ('oidc', ?, ?, ?, ?, ?)",
    )
    .bind(&subject)
    .bind(&principal_id)
    .bind(email)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    apply_default_roles(state, cfg, &principal_id).await?;
    Ok(principal_id)
}

async fn sync_oidc_groups(
    state: &AppState,
    issuer: &str,
    principal_id: &str,
    groups: Option<&[String]>,
) -> ApiResult<()> {
    let prefix = format!("oidc:{issuer}:");
    let rows = sqlx::query(
        "SELECT group_id FROM group_members
         JOIN groups ON groups.id = group_members.group_id
         WHERE group_members.principal_id = ? AND groups.external_id LIKE ?",
    )
    .bind(principal_id)
    .bind(format!("{prefix}%"))
    .fetch_all(&state.pool)
    .await
    .map_err(err500)?;
    for row in rows {
        let group_id: String = row.try_get("group_id").map_err(err500)?;
        sqlx::query("DELETE FROM group_members WHERE group_id = ? AND principal_id = ?")
            .bind(&group_id)
            .bind(principal_id)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
    }

    let Some(groups) = groups else {
        return Ok(());
    };
    for group in groups.iter().filter(|g| !g.trim().is_empty()) {
        let external_id = format!("{prefix}{group}");
        let group_id = upsert_group(state, group, &external_id).await?;
        sqlx::query(
            "INSERT INTO group_members (group_id, principal_id)
             VALUES (?, ?) ON CONFLICT(group_id, principal_id) DO NOTHING",
        )
        .bind(&group_id)
        .bind(principal_id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    }
    Ok(())
}

async fn upsert_group(
    state: &AppState,
    display_name: &str,
    external_id: &str,
) -> ApiResult<String> {
    if let Some(row) = sqlx::query("SELECT id FROM groups WHERE external_id = ?")
        .bind(external_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?
    {
        let id: String = row.try_get("id").map_err(err500)?;
        sqlx::query("UPDATE groups SET display_name = ?, active = 1 WHERE id = ?")
            .bind(display_name)
            .bind(&id)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
        return Ok(id);
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO groups (id, display_name, external_id, active, created_at)
         VALUES (?, ?, ?, 1, ?)",
    )
    .bind(&id)
    .bind(display_name)
    .bind(external_id)
    .bind(Utc::now().to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok(id)
}

async fn apply_default_roles(
    state: &AppState,
    cfg: &OidcConfig,
    principal_id: &str,
) -> ApiResult<()> {
    for role in &cfg.default_roles {
        if !["root_admin", "security_admin", "gateway_owner"].contains(&role.as_str()) {
            continue;
        }
        sqlx::query(
            "INSERT INTO principal_roles (principal_id, role)
             VALUES (?, ?) ON CONFLICT(principal_id, role) DO NOTHING",
        )
        .bind(principal_id)
        .bind(role)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    }
    Ok(())
}

async fn create_session(
    state: &AppState,
    principal_id: &str,
    ttl_hours: i64,
) -> ApiResult<(String, String)> {
    let token = format!("warden_session_{}", Uuid::new_v4().simple());
    let now = Utc::now();
    let expires = now + Duration::hours(ttl_hours);
    sqlx::query(
        "INSERT INTO auth_sessions
             (id, principal_id, token_hash, source, created_at, expires_at)
         VALUES (?, ?, ?, 'oidc', ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(principal_id)
    .bind(auth::hash_key(&token))
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok((token, expires.to_rfc3339()))
}

fn enforce_allowed_domain(cfg: &OidcConfig, email: Option<&str>) -> ApiResult<()> {
    if cfg.allowed_domains.is_empty() {
        return Ok(());
    }
    let Some(email) = email else {
        return Err((StatusCode::FORBIDDEN, "OIDC email is required".into()));
    };
    let Some(domain) = email.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()) else {
        return Err((StatusCode::FORBIDDEN, "OIDC email is invalid".into()));
    };
    if cfg
        .allowed_domains
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&domain))
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "OIDC email domain is not allowed".into(),
        ))
    }
}

fn display_name(claims: &Claims, email: Option<&str>) -> String {
    claims
        .name
        .clone()
        .or(claims.preferred_username.clone())
        .or_else(|| email.map(ToString::to_string))
        .unwrap_or_else(|| claims.sub.clone())
}

fn success_page(principal_id: &str, token: &str, expires_at: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>warden-cp SSO</title>\
         <body><h1>SSO complete</h1>\
         <p>Principal: <code>{}</code></p>\
         <p>Bearer session expires: <code>{}</code></p>\
         <p>Use this bearer token in the admin dashboard or API client:</p>\
         <textarea rows=\"4\" cols=\"96\" readonly>{}</textarea></body>",
        escape_html(principal_id),
        escape_html(expires_at),
        escape_html(token)
    )
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_url_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name)?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(value)
}

fn csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn trim_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        _ => "unsupported",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn err500(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn bad_gateway(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, e.to_string())
}
