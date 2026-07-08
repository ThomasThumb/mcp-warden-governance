use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Row};
use uuid::Uuid;

use crate::routes::AppState;

pub fn hash_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Resolved caller identity, available to any handler via the
/// `AuthedPrincipal` extractor below. This is what fixes the hole: the
/// approval-decision handler now takes its `decided_by` from here, not from
/// a trust-me field in the request body.
#[derive(Clone, Debug)]
pub struct AuthedPrincipal(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthedPrincipal
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthedPrincipal>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "missing authentication".into()))
    }
}

/// VERIFY-AGAINST-DOCS NOTE: this is axum 0.7's `middleware::from_fn_with_state`
/// shape (State extractor, owned Request, Next). If your resolved axum
/// version renamed anything here, the logic (pull bearer token -> hash ->
/// look up -> stash principal in extensions -> reject if missing) is what
/// matters; the exact extractor plumbing is what to diff against current docs.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let key_hash = hash_key(token);
    let row = sqlx::query(
        "SELECT api_keys.principal_id as principal_id
         FROM api_keys
         JOIN principals ON principals.id = api_keys.principal_id
         WHERE api_keys.key_hash = ?
           AND api_keys.revoked_at IS NULL
           AND principals.active = 1",
    )
    .bind(&key_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match row {
        Some(row) => row,
        None => {
            let now = chrono::Utc::now().to_rfc3339();
            let session = sqlx::query(
                "SELECT auth_sessions.principal_id as principal_id
                 FROM auth_sessions
                 JOIN principals ON principals.id = auth_sessions.principal_id
                 WHERE auth_sessions.token_hash = ?
                   AND auth_sessions.revoked_at IS NULL
                   AND auth_sessions.expires_at > ?
                   AND principals.active = 1",
            )
            .bind(&key_hash)
            .bind(&now)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let Some(session) = session else {
                return Err(StatusCode::UNAUTHORIZED);
            };
            session
        }
    };
    let principal_id: String = row
        .try_get("principal_id")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    req.extensions_mut().insert(AuthedPrincipal(principal_id));

    Ok(next.run(req).await)
}

/// If there are no principals at all yet, mint one root service principal
/// and one API key for it, print the raw key ONCE, and move on. This is the
/// only moment the raw key exists outside the operator's hands - store it
/// somewhere real (a password manager, a vault), because it can't be
/// recovered, only revoked and replaced.
pub async fn bootstrap_root_key_if_needed(pool: &AnyPool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO principal_roles (principal_id, role)
         SELECT id, 'root_admin' FROM principals WHERE display_name = 'root-admin'
         ON CONFLICT(principal_id, role) DO NOTHING",
    )
    .execute(pool)
    .await?;

    let count_row = sqlx::query("SELECT COUNT(*) as c FROM principals")
        .fetch_one(pool)
        .await?;
    let count: i64 = count_row.try_get("c").unwrap_or(0);
    if count > 0 {
        return Ok(());
    }

    let principal_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO principals (id, kind, display_name, external_id, created_at)
         VALUES (?, 'service', 'root-admin', NULL, ?)",
    )
    .bind(&principal_id)
    .bind(&now)
    .execute(pool)
    .await?;

    let raw_key = format!("warden_root_{}", Uuid::new_v4().simple());
    let key_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, principal_id, key_hash, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&key_id)
    .bind(&principal_id)
    .bind(hash_key(&raw_key))
    .bind(&now)
    .execute(pool)
    .await?;

    sqlx::query("INSERT INTO principal_roles (principal_id, role) VALUES (?, 'root_admin')")
        .bind(&principal_id)
        .execute(pool)
        .await?;

    eprintln!("=======================================================================");
    eprintln!(" First run: created root principal {principal_id}");
    eprintln!(" ROOT API KEY (shown once, save it now - it cannot be recovered):");
    eprintln!("   {raw_key}");
    eprintln!(" Every request needs: Authorization: Bearer <key>");
    eprintln!("=======================================================================");
    Ok(())
}
