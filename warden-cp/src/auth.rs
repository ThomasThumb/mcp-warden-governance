use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::db::DbPool;
use uuid::Uuid;

use crate::routes::AppState;

pub fn hash_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn random_bearer_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(bytes))
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

/// Authentication middleware: resolve a bearer token to an active principal
/// and make that identity available to downstream authorization checks.
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
         WHERE api_keys.key_hash = $1
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
                 WHERE auth_sessions.token_hash = $1
                   AND auth_sessions.revoked_at IS NULL
                   AND auth_sessions.expires_at > $2
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
pub async fn bootstrap_root_key_if_needed(pool: &DbPool) -> anyhow::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    // This no-op update obtains a database write lock before the existence
    // checks on both SQLite and Postgres.
    sqlx::query("UPDATE bootstrap_lock SET touched_at = $1 WHERE id = 1")
        .bind(&now)
        .execute(&mut *transaction)
        .await?;
    let count_row = sqlx::query("SELECT COUNT(*) as c FROM principals")
        .fetch_one(&mut *transaction)
        .await?;
    let count: i64 = count_row.try_get("c")?;
    if count > 0 {
        let root_count: i64 =
            sqlx::query("SELECT COUNT(*) AS c FROM principal_roles WHERE role = 'root_admin'")
                .fetch_one(&mut *transaction)
                .await?
                .try_get("c")?;
        if root_count > 0 {
            transaction.commit().await?;
            return Ok(());
        }

        // One-time migration for a pre-role database. Once any root role
        // exists, display names never confer privilege.
        let candidates = sqlx::query(
            "SELECT id FROM principals WHERE display_name = 'root-admin' ORDER BY created_at",
        )
        .fetch_all(&mut *transaction)
        .await?;
        if candidates.len() != 1 {
            anyhow::bail!(
                "database has principals but no root_admin role and {} legacy root-admin candidates; refusing ambiguous privilege migration",
                candidates.len()
            );
        }
        let root_id: String = candidates[0].try_get("id")?;
        sqlx::query("INSERT INTO principal_roles (principal_id, role) VALUES ($1, 'root_admin')")
            .bind(root_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Ok(());
    }

    let principal_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO principals (id, kind, display_name, external_id, created_at)
         VALUES ($1, 'service', 'root-admin', NULL, $2)",
    )
    .bind(&principal_id)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;

    let raw_key = random_bearer_token("warden_root");
    let key_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, principal_id, key_hash, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&key_id)
    .bind(&principal_id)
    .bind(hash_key(&raw_key))
    .bind(&now)
    .execute(&mut *transaction)
    .await?;

    sqlx::query("INSERT INTO principal_roles (principal_id, role) VALUES ($1, 'root_admin')")
        .bind(&principal_id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    eprintln!("=======================================================================");
    eprintln!(" First run: created root principal {principal_id}");
    eprintln!(" ROOT API KEY (shown once, save it now - it cannot be recovered):");
    eprintln!("   {raw_key}");
    eprintln!(" Every request needs: Authorization: Bearer <key>");
    eprintln!("=======================================================================");
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    async fn test_pool() -> DbPool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
        MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    async fn insert_principal(pool: &DbPool, id: &str, name: &str) {
        sqlx::query(
            "INSERT INTO principals (id, kind, display_name, active, created_at)
             VALUES ($1, 'service', $2, 1, $3)",
        )
        .bind(id)
        .bind(name)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn legacy_root_migration_runs_once_and_never_promotes_by_name_again() {
        let pool = test_pool().await;
        insert_principal(&pool, "legacy", "root-admin").await;
        bootstrap_root_key_if_needed(&pool).await.unwrap();

        insert_principal(&pool, "lookalike", "root-admin").await;
        bootstrap_root_key_if_needed(&pool).await.unwrap();

        let rows = sqlx::query(
            "SELECT principal_id FROM principal_roles WHERE role = 'root_admin' ORDER BY principal_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].try_get::<String, _>("principal_id").unwrap(),
            "legacy"
        );
    }

    #[tokio::test]
    async fn ambiguous_legacy_root_migration_fails_closed() {
        let pool = test_pool().await;
        insert_principal(&pool, "first", "root-admin").await;
        insert_principal(&pool, "second", "root-admin").await;
        let error = bootstrap_root_key_if_needed(&pool).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing ambiguous privilege migration"));
    }
}
