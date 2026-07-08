use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{Duration, Utc};
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use uuid::Uuid;

use crate::audit_anchor::AuditAnchorRecord;
use crate::auth::AuthedPrincipal;
use crate::db::{DbPool, DbRow};
use crate::identity::{mint_spiffe_id, ActorClaim, AuditSignatureParts, HybridSigner, TokenClaims};
use crate::models::*;
use crate::notify::Notifier;

#[derive(Clone)]
pub struct AuditChainTail {
    pub seq: i64,
    pub hash: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub signer: Arc<HybridSigner>,
    pub oidc: Option<Arc<crate::oidc::OidcConfig>>,
    pub notifier: Arc<Notifier>,
    pub trust_domain: String,
    /// Tail of the audit hash chain, serialized through a mutex so
    /// concurrent ingests can't fork it. See migrations/0001_init.sql's
    /// audit_events comment for the single-instance caveat.
    pub audit_chain_tail: Arc<tokio::sync::Mutex<AuditChainTail>>,
    /// Optional external/WORM high-water mark sink for rollback/truncation
    /// detection outside the mutable audit_events table.
    pub audit_anchor: Arc<crate::audit_anchor::AuditAnchor>,
    /// Ed25519 signs every audit row; ML-DSA signs every row by default. The
    /// interval exists only for deployments that deliberately accept periodic
    /// PQ checkpoints plus an external anchor at very high volume.
    pub audit_ml_dsa_checkpoint_interval: i64,
    /// Sliding-window rate limiter: principal_id -> request timestamps.
    pub rate_limits: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_CANONICAL_VERSION_V2: i64 = 2;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_PER_WINDOW: u32 = 120;

/// Apply to write-heavy endpoints only (audit ingest, approval/fingerprint
/// creation) - read endpoints stay unlimited in v0.1.
pub async fn rate_limit(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let principal = req
        .extensions()
        .get::<AuthedPrincipal>()
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    {
        let now = Instant::now();
        let cutoff = StdDuration::from_secs(RATE_LIMIT_WINDOW_SECS);
        let mut limits = state.rate_limits.lock().unwrap();
        let hits = limits
            .entry(principal.0.clone())
            .or_insert_with(VecDeque::new);
        while hits
            .front()
            .is_some_and(|hit| now.duration_since(*hit) >= cutoff)
        {
            hits.pop_front();
        }
        if hits.len() as u32 >= RATE_LIMIT_MAX_PER_WINDOW {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        hits.push_back(now);
    }
    Ok(next.run(req).await)
}

pub async fn admin_dashboard() -> Html<&'static str> {
    Html(include_str!("../static/admin.html"))
}

type ApiResult<T> = Result<T, (StatusCode, String)>;

fn err500(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, msg.into())
}

async fn gateway_owner(state: &AppState, gateway_id: &str) -> ApiResult<Option<String>> {
    let row = sqlx::query("SELECT owner_principal_id FROM gateways WHERE id = $1")
        .bind(gateway_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?;

    row.map(|r| r.try_get("owner_principal_id").map_err(err500))
        .transpose()
}

async fn ensure_gateway_owner(
    state: &AppState,
    principal: &AuthedPrincipal,
    gateway_id: &str,
) -> ApiResult<()> {
    match gateway_owner(state, gateway_id).await? {
        Some(owner) if owner == principal.0 => Ok(()),
        Some(_) => Err(forbidden("gateway is owned by another principal")),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("unknown gateway '{gateway_id}'"),
        )),
    }
}

async fn ensure_scope_owner(
    state: &AppState,
    principal: &AuthedPrincipal,
    scope: &str,
) -> ApiResult<()> {
    if scope == principal.0 {
        return Ok(());
    }

    match gateway_owner(state, scope).await? {
        Some(owner) if owner == principal.0 => Ok(()),
        Some(_) => Err(forbidden("scope is owned by another principal")),
        None => Err(forbidden(
            "scope is not owned by the authenticated principal",
        )),
    }
}

async fn ensure_session_owner(
    state: &AppState,
    principal: &AuthedPrincipal,
    session_id: &str,
) -> ApiResult<()> {
    let row = sqlx::query("SELECT principal_id FROM agent_sessions WHERE id = $1")
        .bind(session_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?;

    match row {
        Some(r) => {
            let owner: String = r.try_get("principal_id").map_err(err500)?;
            if owner == principal.0 {
                Ok(())
            } else {
                Err(forbidden("agent session is owned by another principal"))
            }
        }
        None => Err((StatusCode::NOT_FOUND, "unknown agent_session_id".into())),
    }
}

pub async fn principal_has_role(
    state: &AppState,
    principal: &AuthedPrincipal,
    role: &str,
) -> ApiResult<bool> {
    let row = sqlx::query(
        "SELECT 1 FROM principal_roles
         WHERE principal_id = $1 AND role = $2
         UNION
         SELECT 1 FROM group_members
         JOIN groups ON groups.id = group_members.group_id
         JOIN group_roles ON group_roles.group_id = group_members.group_id
         WHERE group_members.principal_id = $3
           AND groups.active = 1
           AND group_roles.role = $4
         LIMIT 1",
    )
    .bind(&principal.0)
    .bind(role)
    .bind(&principal.0)
    .bind(role)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;
    Ok(row.is_some())
}

async fn is_root_admin(state: &AppState, principal: &AuthedPrincipal) -> ApiResult<bool> {
    if principal_has_role(state, principal, "root_admin").await? {
        return Ok(true);
    }

    // Backwards-compatible fallback for pre-role SQLite files.
    let row = sqlx::query("SELECT display_name FROM principals WHERE id = $1")
        .bind(&principal.0)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?;
    Ok(row
        .and_then(|r| r.try_get::<String, _>("display_name").ok())
        .is_some_and(|name| name == "root-admin"))
}

async fn ensure_root_admin(state: &AppState, principal: &AuthedPrincipal) -> ApiResult<()> {
    if is_root_admin(state, principal).await? {
        Ok(())
    } else {
        Err(forbidden("root-admin API key required"))
    }
}

fn validate_roles(roles: &[String]) -> ApiResult<()> {
    let allowed = ["root_admin", "security_admin", "gateway_owner"];
    if roles.is_empty() || roles.iter().any(|role| !allowed.contains(&role.as_str())) {
        return Err((
            StatusCode::BAD_REQUEST,
            "roles must be one or more of root_admin, security_admin, gateway_owner".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Principals + API keys
// ---------------------------------------------------------------------------

pub async fn create_principal(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<CreatePrincipalRequest>,
) -> ApiResult<Json<Principal>> {
    ensure_root_admin(&state, &principal).await?;
    if req.kind != "human" && req.kind != "service" {
        return Err((
            StatusCode::BAD_REQUEST,
            "kind must be human or service".into(),
        ));
    }
    let display_name = req.display_name.trim();
    if display_name.is_empty() || display_name.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "display_name must be 1-128 characters".into(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO principals (id, kind, display_name, external_id, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&req.kind)
    .bind(display_name)
    .bind(&req.external_id)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(Principal {
        id,
        kind: req.kind,
        display_name: display_name.to_string(),
        external_id: req.external_id,
        active: true,
        created_at: now,
    }))
}

pub async fn list_principals(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<Vec<Principal>>> {
    ensure_root_admin(&state, &principal).await?;
    let rows = sqlx::query(
        "SELECT id, kind, display_name, external_id, active, created_at
         FROM principals ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_principal(&r).map_err(err500)?);
    }
    Ok(Json(out))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<CreateApiKeyRequest>,
) -> ApiResult<Json<CreatedApiKey>> {
    ensure_root_admin(&state, &principal).await?;

    let exists = sqlx::query("SELECT id FROM principals WHERE id = $1")
        .bind(&req.principal_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?
        .is_some();
    if !exists {
        return Err((StatusCode::NOT_FOUND, "principal not found".into()));
    }

    let raw_key = crate::auth::random_bearer_token("warden_key");
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO api_keys (id, principal_id, key_hash, created_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(&req.principal_id)
    .bind(crate::auth::hash_key(&raw_key))
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(CreatedApiKey {
        id,
        principal_id: req.principal_id,
        raw_key,
        created_at: now,
    }))
}

pub async fn set_principal_roles(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<SetPrincipalRolesRequest>,
) -> ApiResult<StatusCode> {
    ensure_root_admin(&state, &principal).await?;
    validate_roles(&req.roles)?;
    let exists = sqlx::query("SELECT id FROM principals WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?
        .is_some();
    if !exists {
        return Err((StatusCode::NOT_FOUND, "principal not found".into()));
    }

    sqlx::query("DELETE FROM principal_roles WHERE principal_id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    for role in req.roles {
        sqlx::query("INSERT INTO principal_roles (principal_id, role) VALUES ($1, $2)")
            .bind(&id)
            .bind(role)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
    }
    Ok(StatusCode::OK)
}

pub async fn set_group_roles(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<SetGroupRolesRequest>,
) -> ApiResult<StatusCode> {
    ensure_root_admin(&state, &principal).await?;
    validate_roles(&req.roles)?;
    let exists = sqlx::query("SELECT id FROM groups WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?
        .is_some();
    if !exists {
        return Err((StatusCode::NOT_FOUND, "group not found".into()));
    }

    sqlx::query("DELETE FROM group_roles WHERE group_id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    for role in req.roles {
        sqlx::query("INSERT INTO group_roles (group_id, role) VALUES ($1, $2)")
            .bind(&id)
            .bind(role)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
    }
    Ok(StatusCode::OK)
}

pub async fn list_groups(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<Vec<GroupView>>> {
    ensure_root_admin(&state, &principal).await?;
    let rows = sqlx::query(
        "SELECT groups.id, groups.display_name, groups.external_id, groups.active,
                groups.created_at, COUNT(group_members.principal_id) as member_count
         FROM groups
         LEFT JOIN group_members ON group_members.group_id = groups.id
         GROUP BY groups.id, groups.display_name, groups.external_id, groups.active, groups.created_at
         ORDER BY groups.display_name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let group_id: String = row.try_get("id").map_err(err500)?;
        let role_rows =
            sqlx::query("SELECT role FROM group_roles WHERE group_id = $1 ORDER BY role")
                .bind(&group_id)
                .fetch_all(&state.pool)
                .await
                .map_err(err500)?;
        let mut roles = Vec::with_capacity(role_rows.len());
        for role in role_rows {
            roles.push(role.try_get("role").map_err(err500)?);
        }
        out.push(GroupView {
            id: group_id,
            display_name: row.try_get("display_name").map_err(err500)?,
            external_id: row.try_get("external_id").ok(),
            active: row.try_get::<i64, _>("active").unwrap_or(1) != 0,
            roles,
            member_count: row.try_get("member_count").unwrap_or(0),
            created_at: row.try_get("created_at").map_err(err500)?,
        });
    }
    Ok(Json(out))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    ensure_root_admin(&state, &principal).await?;
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = $1
         WHERE id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "api key not found or already revoked".into(),
        ));
    }
    Ok(StatusCode::OK)
}

fn row_to_principal(r: &DbRow) -> anyhow::Result<Principal> {
    Ok(Principal {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        display_name: r.try_get("display_name")?,
        external_id: r.try_get("external_id").ok(),
        active: r.try_get::<i64, _>("active").unwrap_or(1) != 0,
        created_at: r.try_get("created_at")?,
    })
}

fn row_to_session(r: &DbRow) -> anyhow::Result<AgentSession> {
    Ok(AgentSession {
        id: r.try_get("id")?,
        spiffe_id: r.try_get("spiffe_id")?,
        principal_id: r.try_get("principal_id")?,
        purpose: r.try_get("purpose").ok(),
        public_key_b64: r.try_get("public_key_b64")?,
        issued_at: r.try_get("issued_at")?,
        expires_at: r.try_get("expires_at")?,
        revoked_at: r.try_get("revoked_at").ok(),
    })
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

pub async fn admin_summary(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<AdminSummary>> {
    let now = Utc::now().to_rfc3339();
    let is_admin = is_root_admin(&state, &principal).await?;

    let principals = if is_admin {
        count(&state, "SELECT COUNT(*) as c FROM principals").await?
    } else {
        1
    };
    let gateways = if is_admin {
        count(&state, "SELECT COUNT(*) as c FROM gateways").await?
    } else {
        count_owned(
            &state,
            "SELECT COUNT(*) as c FROM gateways WHERE owner_principal_id = $1",
            &principal.0,
        )
        .await?
    };
    let active_agent_sessions = if is_admin {
        count_bound(
            &state,
            "SELECT COUNT(*) as c FROM agent_sessions WHERE revoked_at IS NULL AND expires_at > $1",
            &now,
        )
        .await?
    } else {
        count_two_bound(&state, "SELECT COUNT(*) as c FROM agent_sessions WHERE principal_id = $1 AND revoked_at IS NULL AND expires_at > $2", &principal.0, &now).await?
    };
    let revoked_agent_sessions = if is_admin {
        count(
            &state,
            "SELECT COUNT(*) as c FROM agent_sessions WHERE revoked_at IS NOT NULL",
        )
        .await?
    } else {
        count_owned(&state, "SELECT COUNT(*) as c FROM agent_sessions WHERE principal_id = $1 AND revoked_at IS NOT NULL", &principal.0).await?
    };
    let pending_approvals = if is_admin {
        count(
            &state,
            "SELECT COUNT(*) as c FROM approval_requests WHERE status = 'pending'",
        )
        .await?
    } else {
        count_owned(
            &state,
            "SELECT COUNT(*) as c FROM approval_requests ar JOIN gateways g ON g.id = ar.gateway_id WHERE g.owner_principal_id = $1 AND ar.status = 'pending'",
            &principal.0,
        ).await?
    };
    let pending_tool_fingerprints = if is_admin {
        count(
            &state,
            "SELECT COUNT(*) as c FROM tool_fingerprints WHERE status = 'pending'",
        )
        .await?
    } else {
        count_owned(
            &state,
            "SELECT COUNT(*) as c FROM tool_fingerprints tf JOIN gateways g ON g.id = tf.gateway_id WHERE g.owner_principal_id = $1 AND tf.status = 'pending'",
            &principal.0,
        ).await?
    };
    let audit_events = if is_admin {
        count(&state, "SELECT COUNT(*) as c FROM audit_events").await?
    } else {
        count_owned(
            &state,
            "SELECT COUNT(*) as c FROM audit_events ae JOIN gateways g ON g.id = ae.gateway_id WHERE g.owner_principal_id = $1",
            &principal.0,
        ).await?
    };

    Ok(Json(AdminSummary {
        principals,
        gateways,
        active_agent_sessions,
        revoked_agent_sessions,
        pending_approvals,
        pending_tool_fingerprints,
        audit_events,
    }))
}

async fn count(state: &AppState, sql: &str) -> ApiResult<i64> {
    let row = sqlx::query(sql)
        .fetch_one(&state.pool)
        .await
        .map_err(err500)?;
    row.try_get("c").map_err(err500)
}

async fn count_bound(state: &AppState, sql: &str, value: &str) -> ApiResult<i64> {
    let row = sqlx::query(sql)
        .bind(value)
        .fetch_one(&state.pool)
        .await
        .map_err(err500)?;
    row.try_get("c").map_err(err500)
}

async fn count_owned(state: &AppState, sql: &str, owner: &str) -> ApiResult<i64> {
    count_bound(state, sql, owner).await
}

async fn count_two_bound(state: &AppState, sql: &str, first: &str, second: &str) -> ApiResult<i64> {
    let row = sqlx::query(sql)
        .bind(first)
        .bind(second)
        .fetch_one(&state.pool)
        .await
        .map_err(err500)?;
    row.try_get("c").map_err(err500)
}

pub async fn list_gateways(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<Vec<GatewayInventory>>> {
    let rows = if is_root_admin(&state, &principal).await? {
        sqlx::query(
            "SELECT id, owner_principal_id, hostname, version, last_heartbeat_at
             FROM gateways ORDER BY last_heartbeat_at DESC",
        )
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, owner_principal_id, hostname, version, last_heartbeat_at
             FROM gateways WHERE owner_principal_id = $1 ORDER BY last_heartbeat_at DESC",
        )
        .bind(&principal.0)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(GatewayInventory {
            id: r.try_get("id").map_err(err500)?,
            owner_principal_id: r.try_get("owner_principal_id").map_err(err500)?,
            hostname: r.try_get("hostname").map_err(err500)?,
            version: r.try_get("version").map_err(err500)?,
            last_heartbeat_at: r.try_get("last_heartbeat_at").map_err(err500)?,
        });
    }
    Ok(Json(out))
}

pub async fn list_agent_sessions(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<Vec<AgentSession>>> {
    let rows = if is_root_admin(&state, &principal).await? {
        sqlx::query(
            "SELECT id, spiffe_id, principal_id, purpose, public_key_b64,
                    issued_at, expires_at, revoked_at
             FROM agent_sessions ORDER BY issued_at DESC",
        )
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, spiffe_id, principal_id, purpose, public_key_b64,
                    issued_at, expires_at, revoked_at
             FROM agent_sessions WHERE principal_id = $1 ORDER BY issued_at DESC",
        )
        .bind(&principal.0)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_session(&r).map_err(err500)?);
    }
    Ok(Json(out))
}

pub async fn list_tool_fingerprints(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
) -> ApiResult<Json<Vec<ToolFingerprintView>>> {
    let rows = if is_root_admin(&state, &principal).await? {
        sqlx::query(
            "SELECT gateway_id, server_id, tool_name, fingerprint, status,
                    first_seen_at, last_seen_at
             FROM tool_fingerprints ORDER BY last_seen_at DESC",
        )
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT tf.gateway_id, tf.server_id, tf.tool_name, tf.fingerprint, tf.status,
                    tf.first_seen_at, tf.last_seen_at
             FROM tool_fingerprints tf JOIN gateways g ON g.id = tf.gateway_id
             WHERE g.owner_principal_id = $1 ORDER BY tf.last_seen_at DESC",
        )
        .bind(&principal.0)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(ToolFingerprintView {
            gateway_id: r.try_get("gateway_id").map_err(err500)?,
            server_id: r.try_get("server_id").map_err(err500)?,
            tool_name: r.try_get("tool_name").map_err(err500)?,
            fingerprint: r.try_get("fingerprint").map_err(err500)?,
            status: r.try_get("status").map_err(err500)?,
            first_seen_at: r.try_get("first_seen_at").map_err(err500)?,
            last_seen_at: r.try_get("last_seen_at").map_err(err500)?,
        });
    }
    Ok(Json(out))
}

pub async fn list_audit_events(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<Vec<AuditEventView>>> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let gateway_filter = params.get("gateway_id").cloned();

    let rows = match (is_root_admin(&state, &principal).await?, gateway_filter) {
        (true, Some(gateway_id)) => {
            sqlx::query(
                "SELECT id, ts, gateway_id, agent_session_id, principal_id, server_id,
                        tool_name, decision, args_fingerprint, injection_flags,
                        result_bytes, prev_hash, entry_hash
                 FROM audit_events WHERE gateway_id = $1 ORDER BY ts DESC LIMIT $2",
            )
            .bind(gateway_id)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (true, None) => {
            sqlx::query(
                "SELECT id, ts, gateway_id, agent_session_id, principal_id, server_id,
                        tool_name, decision, args_fingerprint, injection_flags,
                        result_bytes, prev_hash, entry_hash
                 FROM audit_events ORDER BY ts DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (false, Some(gateway_id)) => {
            sqlx::query(
                "SELECT ae.id, ae.ts, ae.gateway_id, ae.agent_session_id, ae.principal_id,
                        ae.server_id, ae.tool_name, ae.decision, ae.args_fingerprint,
                        ae.injection_flags, ae.result_bytes, ae.prev_hash, ae.entry_hash
                 FROM audit_events ae JOIN gateways g ON g.id = ae.gateway_id
                 WHERE g.owner_principal_id = $1 AND ae.gateway_id = $2
                 ORDER BY ae.ts DESC LIMIT $3",
            )
            .bind(&principal.0)
            .bind(gateway_id)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (false, None) => {
            sqlx::query(
                "SELECT ae.id, ae.ts, ae.gateway_id, ae.agent_session_id, ae.principal_id,
                        ae.server_id, ae.tool_name, ae.decision, ae.args_fingerprint,
                        ae.injection_flags, ae.result_bytes, ae.prev_hash, ae.entry_hash
                 FROM audit_events ae JOIN gateways g ON g.id = ae.gateway_id
                 WHERE g.owner_principal_id = $1 ORDER BY ae.ts DESC LIMIT $2",
            )
            .bind(&principal.0)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_audit_event(&r).map_err(err500)?);
    }
    Ok(Json(out))
}

pub async fn security_anomalies(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<Vec<SecurityAnomaly>>> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let large_result_threshold = params
        .get("large_result_bytes")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1_000_000)
        .max(1);
    let is_admin = is_root_admin(&state, &principal).await?;

    let rows = if is_admin {
        sqlx::query(
            "SELECT id, ts, gateway_id, agent_session_id, principal_id, server_id,
                    tool_name, decision, args_fingerprint, injection_flags,
                    result_bytes, prev_hash, entry_hash
             FROM audit_events
             WHERE decision IN ('blocked_injection', 'allowed_flagged')
                OR COALESCE(result_bytes, 0) >= $1
             ORDER BY ts DESC LIMIT $2",
        )
        .bind(large_result_threshold)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT ae.id, ae.ts, ae.gateway_id, ae.agent_session_id, ae.principal_id,
                    ae.server_id, ae.tool_name, ae.decision, ae.args_fingerprint,
                    ae.injection_flags, ae.result_bytes, ae.prev_hash, ae.entry_hash
             FROM audit_events ae JOIN gateways g ON g.id = ae.gateway_id
             WHERE g.owner_principal_id = $1
               AND (ae.decision IN ('blocked_injection', 'allowed_flagged')
                    OR COALESCE(ae.result_bytes, 0) >= $2)
             ORDER BY ae.ts DESC LIMIT $3",
        )
        .bind(&principal.0)
        .bind(large_result_threshold)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let event = row_to_audit_event(&r).map_err(err500)?;
        let flags = event.injection_flags.clone();
        if event.decision == "blocked_injection" {
            out.push(SecurityAnomaly {
                severity: "high".to_string(),
                kind: "blocked_injection".to_string(),
                description: "Tool call or result matched injection heuristics above the block threshold".to_string(),
                ts: event.ts.clone(),
                gateway_id: event.gateway_id.clone(),
                agent_session_id: event.agent_session_id.clone(),
                principal_id: event.principal_id.clone(),
                server_id: event.server_id.clone(),
                tool_name: event.tool_name.clone(),
                evidence: serde_json::json!({ "injection_flags": flags, "args_fingerprint": event.args_fingerprint }),
            });
        } else if event.decision == "allowed_flagged" {
            out.push(SecurityAnomaly {
                severity: "medium".to_string(),
                kind: "allowed_flagged_result".to_string(),
                description: "Tool result contained suspicious content but did not cross the block threshold".to_string(),
                ts: event.ts.clone(),
                gateway_id: event.gateway_id.clone(),
                agent_session_id: event.agent_session_id.clone(),
                principal_id: event.principal_id.clone(),
                server_id: event.server_id.clone(),
                tool_name: event.tool_name.clone(),
                evidence: serde_json::json!({ "injection_flags": flags, "result_bytes": event.result_bytes }),
            });
        } else if event.result_bytes.unwrap_or(0) >= large_result_threshold {
            out.push(SecurityAnomaly {
                severity: "medium".to_string(),
                kind: "large_result".to_string(),
                description: "Tool returned an unusually large result; review for possible exfiltration".to_string(),
                ts: event.ts.clone(),
                gateway_id: event.gateway_id.clone(),
                agent_session_id: event.agent_session_id.clone(),
                principal_id: event.principal_id.clone(),
                server_id: event.server_id.clone(),
                tool_name: event.tool_name.clone(),
                evidence: serde_json::json!({ "result_bytes": event.result_bytes, "threshold": large_result_threshold }),
            });
        }
    }
    Ok(Json(out))
}

fn row_to_audit_event(r: &DbRow) -> anyhow::Result<AuditEventView> {
    let flags: String = r.try_get("injection_flags")?;
    Ok(AuditEventView {
        id: r.try_get("id")?,
        seq: r.try_get("seq").ok(),
        canonical_version: r.try_get("canonical_version").ok(),
        ts: r.try_get("ts")?,
        gateway_id: r.try_get("gateway_id")?,
        agent_session_id: r.try_get("agent_session_id").ok(),
        principal_id: r.try_get("principal_id").ok(),
        server_id: r.try_get("server_id")?,
        tool_name: r.try_get("tool_name")?,
        decision: r.try_get("decision")?,
        args_fingerprint: r.try_get("args_fingerprint")?,
        injection_flags: serde_json::from_str(&flags).unwrap_or_default(),
        result_bytes: r.try_get("result_bytes").ok(),
        prev_hash: r.try_get("prev_hash")?,
        entry_hash: r.try_get("entry_hash")?,
        checkpoint_signed_at: r.try_get("checkpoint_signed_at").ok(),
    })
}

pub async fn register_gateway(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<RegisterGatewayRequest>,
) -> ApiResult<StatusCode> {
    if req.owner_principal_id != principal.0 {
        return Err(forbidden(
            "gateway owner_principal_id must match the authenticated principal",
        ));
    }
    if let Some(existing_owner) = gateway_owner(&state, &req.gateway_id).await? {
        if existing_owner != principal.0 {
            return Err(forbidden("gateway is already owned by another principal"));
        }
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO gateways (id, owner_principal_id, hostname, version, last_heartbeat_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT(id) DO UPDATE SET last_heartbeat_at = excluded.last_heartbeat_at,
             version = excluded.version, hostname = excluded.hostname",
    )
    .bind(&req.gateway_id)
    .bind(&principal.0)
    .bind(&req.hostname)
    .bind(&req.version)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    for up in &req.upstreams {
        sqlx::query(
            "INSERT INTO upstream_inventory (gateway_id, server_id, transport, reported_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(gateway_id, server_id) DO UPDATE SET
                 transport = excluded.transport, reported_at = excluded.reported_at",
        )
        .bind(&req.gateway_id)
        .bind(&up.server_id)
        .bind(&up.transport)
        .bind(&now)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Policy distribution (centralized allowlists)
// ---------------------------------------------------------------------------

pub async fn get_policy(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(scope): Path<String>,
) -> ApiResult<Json<PolicyBundle>> {
    ensure_scope_owner(&state, &principal, &scope).await?;

    let row = sqlx::query(
        "SELECT scope, version, bundle_json FROM policy_bundles
         WHERE scope = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(&scope)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;

    match row {
        Some(r) => {
            let bundle_json: String = r.try_get("bundle_json").map_err(err500)?;
            Ok(Json(PolicyBundle {
                scope,
                version: r.try_get("version").map_err(err500)?,
                bundle: serde_json::from_str(&bundle_json).map_err(err500)?,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no policy for scope '{scope}'"),
        )),
    }
}

pub async fn put_policy(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<PolicyBundle>,
) -> ApiResult<Json<PolicyBundle>> {
    ensure_scope_owner(&state, &principal, &req.scope).await?;

    let next_version_row =
        sqlx::query("SELECT COALESCE(MAX(version), 0) as v FROM policy_bundles WHERE scope = $1")
            .bind(&req.scope)
            .fetch_one(&state.pool)
            .await
            .map_err(err500)?;
    let next_version: i64 = next_version_row.try_get::<i64, _>("v").unwrap_or(0) + 1;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let bundle_text = serde_json::to_string(&req.bundle).map_err(err500)?;

    sqlx::query(
        "INSERT INTO policy_bundles (id, scope, version, bundle_json, created_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&req.scope)
    .bind(next_version)
    .bind(&bundle_text)
    .bind(&now)
    .bind(&principal.0)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(PolicyBundle {
        scope: req.scope,
        version: next_version,
        bundle: req.bundle,
    }))
}

// ---------------------------------------------------------------------------
// Fleet-wide drift detection (generalizes mcp-warden's local integrity.rs)
// ---------------------------------------------------------------------------

pub async fn report_tool_fingerprint(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<ToolFingerprintReport>,
) -> ApiResult<Json<ToolFingerprintDecision>> {
    ensure_gateway_owner(&state, &principal, &req.gateway_id).await?;

    let now = Utc::now().to_rfc3339();
    let existing = sqlx::query(
        "SELECT fingerprint, status FROM tool_fingerprints
         WHERE gateway_id = $1 AND server_id = $2 AND tool_name = $3",
    )
    .bind(&req.gateway_id)
    .bind(&req.server_id)
    .bind(&req.tool_name)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;

    let status = match existing {
        Some(r) => {
            let old_fp: String = r.try_get("fingerprint").map_err(err500)?;
            let old_status: String = r.try_get("status").map_err(err500)?;
            if old_fp == req.fingerprint && old_status == "approved" {
                "approved".to_string()
            } else if old_fp == req.fingerprint {
                old_status // unchanged, keep whatever it already was (likely "pending")
            } else {
                "pending".to_string() // changed since last report - possible rug pull, needs re-approval
            }
        }
        None => "pending".to_string(),
    };

    sqlx::query(
        "INSERT INTO tool_fingerprints
             (gateway_id, server_id, tool_name, fingerprint, status, first_seen_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT(gateway_id, server_id, tool_name) DO UPDATE SET
             fingerprint = excluded.fingerprint, status = excluded.status,
             last_seen_at = excluded.last_seen_at",
    )
    .bind(&req.gateway_id)
    .bind(&req.server_id)
    .bind(&req.tool_name)
    .bind(&req.fingerprint)
    .bind(&status)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(ToolFingerprintDecision { status }))
}

#[derive(serde::Deserialize)]
pub struct ApproveFingerprintRequest {
    pub gateway_id: String,
    pub server_id: String,
    pub tool_name: String,
}

pub async fn approve_tool_fingerprint(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<ApproveFingerprintRequest>,
) -> ApiResult<StatusCode> {
    ensure_gateway_owner(&state, &principal, &req.gateway_id).await?;

    let result = sqlx::query(
        "UPDATE tool_fingerprints SET status = 'approved'
         WHERE gateway_id = $1 AND server_id = $2 AND tool_name = $3",
    )
    .bind(&req.gateway_id)
    .bind(&req.server_id)
    .bind(&req.tool_name)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "tool fingerprint not found".into()));
    }
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Approvals (KISS: one object + API; Slack/dashboard/CLI are thin surfaces)
// ---------------------------------------------------------------------------

pub async fn create_approval(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<CreateApprovalRequest>,
) -> ApiResult<Json<ApprovalRequest>> {
    ensure_gateway_owner(&state, &principal, &req.gateway_id).await?;
    if let Some(session_id) = &req.agent_session_id {
        ensure_session_owner(&state, &principal, session_id).await?;
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO approval_requests
             (id, gateway_id, agent_session_id, server_id, tool_name, args_fingerprint,
              risk_tier, status, requested_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)",
    )
    .bind(&id)
    .bind(&req.gateway_id)
    .bind(&req.agent_session_id)
    .bind(&req.server_id)
    .bind(&req.tool_name)
    .bind(&req.args_fingerprint)
    .bind(&req.risk_tier)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    let approval = ApprovalRequest {
        id,
        gateway_id: req.gateway_id,
        agent_session_id: req.agent_session_id,
        server_id: req.server_id,
        tool_name: req.tool_name,
        args_fingerprint: req.args_fingerprint,
        risk_tier: req.risk_tier,
        status: "pending".to_string(),
        requested_at: now,
        decided_at: None,
        decided_by: None,
        reason: None,
    };

    state.notifier.notify_pending(&approval).await;
    Ok(Json(approval))
}

pub async fn list_approvals(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<Vec<ApprovalRequest>>> {
    let status_filter = params.get("status").cloned();
    let rows = if let Some(status) = status_filter {
        sqlx::query(
            "SELECT ar.* FROM approval_requests ar
             JOIN gateways g ON g.id = ar.gateway_id
             WHERE g.owner_principal_id = $1 AND ar.status = $2
             ORDER BY ar.requested_at DESC",
        )
        .bind(&principal.0)
        .bind(status)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT ar.* FROM approval_requests ar
             JOIN gateways g ON g.id = ar.gateway_id
             WHERE g.owner_principal_id = $1
             ORDER BY ar.requested_at DESC",
        )
        .bind(&principal.0)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_approval(&r).map_err(err500)?);
    }
    Ok(Json(out))
}

pub async fn get_approval(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<Json<ApprovalRequest>> {
    fetch_approval_for_principal(&state, &principal, &id).await
}

pub async fn decide_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    principal: AuthedPrincipal,
    Json(req): Json<DecideApprovalRequest>,
) -> ApiResult<Json<ApprovalRequest>> {
    let now = Utc::now().to_rfc3339();
    let status = if req.approved { "approved" } else { "denied" };

    let result = sqlx::query(
        "UPDATE approval_requests
         SET status = $1, decided_at = $2, decided_by = $3, reason = $4
         WHERE id = $5 AND status = 'pending'
           AND gateway_id IN (SELECT id FROM gateways WHERE owner_principal_id = $6)",
    )
    .bind(status)
    .bind(&now)
    .bind(&principal.0)
    .bind(&req.reason)
    .bind(&id)
    .bind(&principal.0)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    // BUG FIXED (found in self-review): this used to fall through to
    // get_approval regardless of whether the UPDATE actually changed
    // anything. Two approvers racing - one approves, one denies, a few
    // milliseconds apart - meant the loser got a 200 OK showing the
    // winner's decision, with nothing telling them their own click had no
    // effect. Now they get a clear conflict instead of quiet, misleading
    // success.
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::CONFLICT,
            format!("approval '{id}' was already decided by someone else, or does not exist"),
        ));
    }

    fetch_approval_for_principal(&state, &principal, &id).await
}

async fn fetch_approval_for_principal(
    state: &AppState,
    principal: &AuthedPrincipal,
    id: &str,
) -> ApiResult<Json<ApprovalRequest>> {
    let row = sqlx::query(
        "SELECT ar.* FROM approval_requests ar
         JOIN gateways g ON g.id = ar.gateway_id
         WHERE ar.id = $1 AND g.owner_principal_id = $2",
    )
    .bind(id)
    .bind(&principal.0)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;
    match row {
        Some(r) => Ok(Json(row_to_approval(&r).map_err(err500)?)),
        None => Err((StatusCode::NOT_FOUND, format!("no approval '{id}'"))),
    }
}

fn row_to_approval(r: &DbRow) -> anyhow::Result<ApprovalRequest> {
    Ok(ApprovalRequest {
        id: r.try_get("id")?,
        gateway_id: r.try_get("gateway_id")?,
        agent_session_id: r.try_get("agent_session_id").ok(),
        server_id: r.try_get("server_id")?,
        tool_name: r.try_get("tool_name")?,
        args_fingerprint: r.try_get("args_fingerprint")?,
        risk_tier: r.try_get("risk_tier")?,
        status: r.try_get("status")?,
        requested_at: r.try_get("requested_at")?,
        decided_at: r.try_get("decided_at").ok(),
        decided_by: r.try_get("decided_by").ok(),
        reason: r.try_get("reason").ok(),
    })
}

fn token_audience(gateway_id: &str, server_id: &str, tool_name: &str) -> String {
    format!("warden-mcp:{gateway_id}:{server_id}:{tool_name}")
}

fn agent_session_id_from_spiffe(spiffe_id: &str) -> Option<String> {
    let session_id = spiffe_id.rsplit_once("/agent/")?.1;
    Uuid::parse_str(session_id).ok()?;
    Some(session_id.to_string())
}

struct AuditHashFields<'a> {
    seq: i64,
    prev_hash: &'a str,
    ts: &'a str,
    gateway_id: &'a str,
    agent_session_id: Option<&'a str>,
    principal_id: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    decision: &'a str,
    args_fingerprint: &'a str,
    injection_flags: &'a str,
    result_bytes: Option<i64>,
}

fn audit_entry_hash_v2(fields: AuditHashFields<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"warden-cp.audit-event.v2\0");
    hash_i64(&mut hasher, fields.seq);
    hash_str(&mut hasher, fields.prev_hash);
    hash_str(&mut hasher, fields.ts);
    hash_str(&mut hasher, fields.gateway_id);
    hash_opt_str(&mut hasher, fields.agent_session_id);
    hash_str(&mut hasher, fields.principal_id);
    hash_str(&mut hasher, fields.server_id);
    hash_str(&mut hasher, fields.tool_name);
    hash_str(&mut hasher, fields.decision);
    hash_str(&mut hasher, fields.args_fingerprint);
    hash_str(&mut hasher, fields.injection_flags);
    hash_opt_i64(&mut hasher, fields.result_bytes);
    format!("{:x}", hasher.finalize())
}

fn audit_requires_ml_dsa_checkpoint(seq: i64, interval: i64) -> bool {
    seq == 1 || interval <= 1 || seq % interval == 0
}

fn legacy_audit_entry_hash(fields: AuditHashFields<'_>) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        fields.prev_hash,
        fields.ts,
        fields.gateway_id,
        fields.agent_session_id.unwrap_or(""),
        fields.principal_id,
        fields.server_id,
        fields.tool_name,
        fields.decision,
        fields.args_fingerprint,
        fields.injection_flags,
        fields.result_bytes.unwrap_or(-1)
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_str(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_opt_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_i64(hasher, value);
        }
        None => hasher.update([0]),
    }
}

pub async fn seal_legacy_audit_if_needed(
    pool: &DbPool,
    signer: &HybridSigner,
) -> anyhow::Result<()> {
    let existing = sqlx::query("SELECT id FROM audit_legacy_seals WHERE id = 'legacy-v1'")
        .fetch_optional(pool)
        .await?;
    if existing.is_some() {
        return Ok(());
    }

    let Some(row) = sqlx::query(
        "SELECT entry_hash FROM audit_events
         WHERE canonical_version < $1 OR canonical_version IS NULL
         ORDER BY CASE WHEN seq IS NULL THEN 0 ELSE 1 END DESC, seq DESC, ts DESC
         LIMIT 1",
    )
    .bind(AUDIT_CANONICAL_VERSION_V2)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(());
    };

    let last_entry_hash: String = row.try_get("entry_hash")?;
    let sealed_at = Utc::now().to_rfc3339();
    let seal = signer.sign_legacy_audit_seal(&last_entry_hash, &sealed_at)?;
    sqlx::query(
        "INSERT INTO audit_legacy_seals
             (id, last_entry_hash, sealed_at, seal_sig_b64, seal_ml_dsa_alg, seal_ml_dsa_sig_b64)
         VALUES ('legacy-v1', $1, $2, $3, $4, $5)",
    )
    .bind(&last_entry_hash)
    .bind(&sealed_at)
    .bind(&seal.ed25519_sig_b64)
    .bind(&seal.ml_dsa_alg)
    .bind(&seal.ml_dsa_sig_b64)
    .execute(pool)
    .await?;
    tracing::warn!(
        last_entry_hash = %last_entry_hash,
        "sealed legacy unsigned audit rows; migrate or archive them when practical"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Audit ingest (the "who, what, when, where" ledger)
// ---------------------------------------------------------------------------

pub async fn ingest_audit(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(events): Json<Vec<AuditEventIn>>,
) -> ApiResult<StatusCode> {
    if events.len() > 500 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "audit batch too large".into(),
        ));
    }
    for event in &events {
        ensure_gateway_owner(&state, &principal, &event.gateway_id).await?;
        if let Some(session_id) = &event.agent_session_id {
            ensure_session_owner(&state, &principal, session_id).await?;
        }
        if event
            .principal_id
            .as_ref()
            .is_some_and(|claimed| claimed != &principal.0)
        {
            return Err(forbidden(
                "audit principal_id must match the authenticated principal",
            ));
        }
    }

    // Serialize the whole batch through the chain-tail lock so concurrent
    // ingests can't fork the chain (see AppState doc comment for the
    // single-instance caveat this doesn't solve).
    let mut tail_guard = state.audit_chain_tail.lock().await;
    let mut tail = tail_guard.clone();

    for e in events {
        let now = Utc::now().to_rfc3339();
        let flags_json = serde_json::to_string(&e.injection_flags).map_err(err500)?;
        let id = Uuid::new_v4().to_string();
        let seq = tail.seq + 1;

        let entry_hash = audit_entry_hash_v2(AuditHashFields {
            seq,
            prev_hash: &tail.hash,
            ts: &now,
            gateway_id: &e.gateway_id,
            agent_session_id: e.agent_session_id.as_deref(),
            principal_id: &principal.0,
            server_id: &e.server_id,
            tool_name: &e.tool_name,
            decision: &e.decision,
            args_fingerprint: &e.args_fingerprint,
            injection_flags: &flags_json,
            result_bytes: e.result_bytes,
        });
        let checkpoint_signed_at = now.clone();
        let checkpoint = state
            .signer
            .sign_audit_checkpoint(
                seq,
                &entry_hash,
                &checkpoint_signed_at,
                audit_requires_ml_dsa_checkpoint(seq, state.audit_ml_dsa_checkpoint_interval),
            )
            .map_err(err500)?;
        let anchor_record = AuditAnchorRecord::new(
            seq,
            entry_hash.clone(),
            checkpoint_signed_at.clone(),
            &checkpoint,
        );

        sqlx::query(
            "INSERT INTO audit_events
                 (id, seq, canonical_version, ts, gateway_id, agent_session_id, principal_id,
                  server_id, tool_name, decision, args_fingerprint, injection_flags, result_bytes,
                  prev_hash, entry_hash, checkpoint_signed_at, checkpoint_sig_b64,
                  checkpoint_ml_dsa_alg, checkpoint_ml_dsa_sig_b64)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
        )
        .bind(&id)
        .bind(seq)
        .bind(AUDIT_CANONICAL_VERSION_V2)
        .bind(&now)
        .bind(&e.gateway_id)
        .bind(&e.agent_session_id)
        .bind(&principal.0)
        .bind(&e.server_id)
        .bind(&e.tool_name)
        .bind(&e.decision)
        .bind(&e.args_fingerprint)
        .bind(&flags_json)
        .bind(e.result_bytes)
        .bind(&tail.hash)
        .bind(&entry_hash)
        .bind(&checkpoint_signed_at)
        .bind(&checkpoint.ed25519_sig_b64)
        .bind(&checkpoint.ml_dsa_alg)
        .bind(&checkpoint.ml_dsa_sig_b64)
        .execute(&state.pool)
        .await
        .map_err(err500)?;

        tail = AuditChainTail {
            seq,
            hash: entry_hash,
        };
        if let Err(e) = state.audit_anchor.publish(&anchor_record) {
            *tail_guard = tail.clone();
            if state.audit_anchor.required() {
                return Err(err500(format!(
                    "required audit anchor publish failed after seq {seq}: {e}"
                )));
            }
            tracing::warn!(
                seq,
                error = %e,
                "audit anchor publish failed; database row is still signed but rollback detection may lag"
            );
        }
    }

    *tail_guard = tail;
    Ok(StatusCode::OK)
}

/// Walks the whole chain and recomputes every hash. Returns the id of the
/// first row that doesn't match if the chain's been tampered with, or "ok".
/// This is the entire point of hash-chaining - if you never call this, the
/// chain is just extra columns.
pub async fn verify_audit_chain(State(state): State<AppState>) -> Json<serde_json::Value> {
    let latest_anchor = match state.audit_anchor.latest() {
        Ok(anchor) => anchor,
        Err(e) if state.audit_anchor.required() => {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "failed to read required audit anchor",
                "error": e.to_string()
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to read optional audit anchor");
            None
        }
    };
    if let Some(anchor) = &latest_anchor {
        if let Err(e) = state.signer.verify_audit_checkpoint(
            anchor.seq,
            &anchor.entry_hash,
            &anchor.checkpoint_signed_at,
            AuditSignatureParts {
                ed25519_sig_b64: &anchor.checkpoint_sig_b64,
                ml_dsa_alg: anchor.checkpoint_ml_dsa_alg.as_deref(),
                ml_dsa_sig_b64: anchor.checkpoint_ml_dsa_sig_b64.as_deref(),
                require_ml_dsa: audit_requires_ml_dsa_checkpoint(
                    anchor.seq,
                    state.audit_ml_dsa_checkpoint_interval,
                ),
            },
        ) {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "latest audit anchor signature does not verify",
                "error": e.to_string()
            }));
        }
    }

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_next_seq: Option<i64> = None;
    let mut checked_rows: i64 = 0;
    let mut signed_checkpoints: i64 = 0;
    let mut legacy_unsigned_rows: i64 = 0;
    let mut last_legacy_hash: Option<String> = None;
    let mut anchor_matched_row = latest_anchor.is_none();
    let mut rows = sqlx::query(
        "SELECT id, seq, canonical_version, ts, gateway_id, agent_session_id, principal_id,
                server_id, tool_name, decision, args_fingerprint, injection_flags, result_bytes,
                prev_hash, entry_hash, checkpoint_signed_at, checkpoint_sig_b64,
                checkpoint_ml_dsa_alg, checkpoint_ml_dsa_sig_b64
         FROM audit_events
         ORDER BY CASE WHEN seq IS NULL THEN 0 ELSE 1 END, seq ASC, ts ASC",
    )
    .fetch(&state.pool);

    while let Some(r) = match rows.try_next().await {
        Ok(row) => row,
        Err(e) => {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "failed to stream audit rows",
                "error": e.to_string()
            }))
        }
    } {
        let id: String = match r.try_get("id") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "audit row has an invalid id column",
                    "error": e.to_string()
                }))
            }
        };
        let decode_error = |column: &str, error: sqlx::Error| {
            Json(serde_json::json!({
                "ok": false,
                "broken_at_id": id,
                "reason": format!("audit row has an invalid {column} column"),
                "error": error.to_string()
            }))
        };
        let seq: Option<i64> = match r.try_get("seq") {
            Ok(value) => value,
            Err(e) => return decode_error("seq", e),
        };
        let canonical_version: i64 = match r.try_get("canonical_version") {
            Ok(value) => value,
            Err(e) => return decode_error("canonical_version", e),
        };
        let ts: String = match r.try_get("ts") {
            Ok(value) => value,
            Err(e) => return decode_error("ts", e),
        };
        let gateway_id: String = match r.try_get("gateway_id") {
            Ok(value) => value,
            Err(e) => return decode_error("gateway_id", e),
        };
        let agent_session_id: Option<String> = match r.try_get("agent_session_id") {
            Ok(value) => value,
            Err(e) => return decode_error("agent_session_id", e),
        };
        let principal_id: String = match r.try_get("principal_id") {
            Ok(value) => value,
            Err(e) => return decode_error("principal_id", e),
        };
        let server_id: String = match r.try_get("server_id") {
            Ok(value) => value,
            Err(e) => return decode_error("server_id", e),
        };
        let tool_name: String = match r.try_get("tool_name") {
            Ok(value) => value,
            Err(e) => return decode_error("tool_name", e),
        };
        let decision: String = match r.try_get("decision") {
            Ok(value) => value,
            Err(e) => return decode_error("decision", e),
        };
        let args_fingerprint: String = match r.try_get("args_fingerprint") {
            Ok(value) => value,
            Err(e) => return decode_error("args_fingerprint", e),
        };
        let injection_flags: String = match r.try_get("injection_flags") {
            Ok(value) => value,
            Err(e) => return decode_error("injection_flags", e),
        };
        let result_bytes: Option<i64> = match r.try_get("result_bytes") {
            Ok(value) => value,
            Err(e) => return decode_error("result_bytes", e),
        };
        let prev_hash: String = match r.try_get("prev_hash") {
            Ok(value) => value,
            Err(e) => return decode_error("prev_hash", e),
        };
        let entry_hash: String = match r.try_get("entry_hash") {
            Ok(value) => value,
            Err(e) => return decode_error("entry_hash", e),
        };
        let checkpoint_signed_at: Option<String> = match r.try_get("checkpoint_signed_at") {
            Ok(value) => value,
            Err(e) => return decode_error("checkpoint_signed_at", e),
        };
        let checkpoint_sig_b64: Option<String> = match r.try_get("checkpoint_sig_b64") {
            Ok(value) => value,
            Err(e) => return decode_error("checkpoint_sig_b64", e),
        };
        let checkpoint_ml_dsa_alg: Option<String> = match r.try_get("checkpoint_ml_dsa_alg") {
            Ok(value) => value,
            Err(e) => return decode_error("checkpoint_ml_dsa_alg", e),
        };
        let checkpoint_ml_dsa_sig_b64: Option<String> = match r.try_get("checkpoint_ml_dsa_sig_b64")
        {
            Ok(value) => value,
            Err(e) => return decode_error("checkpoint_ml_dsa_sig_b64", e),
        };

        checked_rows += 1;

        // Check 1: does this row's stored prev_hash actually match the
        // previous row's entry_hash? This is the check the original version
        // of this function was missing entirely - it only re-verified each
        // row in isolation, so a chain that had been quietly forked (two
        // rows both claiming the same prev_hash, or a row's prev_hash
        // pointing at nothing real) would have reported "ok": true.
        if prev_hash != expected_prev {
            return Json(serde_json::json!({
                "ok": false,
                "broken_at_id": id,
                "reason": "prev_hash does not match the preceding entry's hash - chain is forked or a row is missing"
            }));
        }

        // Check 2: does this row's own entry_hash actually match its content?
        let recomputed = if canonical_version >= AUDIT_CANONICAL_VERSION_V2 {
            let Some(seq) = seq else {
                return Json(serde_json::json!({
                    "ok": false,
                    "broken_at_id": id,
                    "reason": "v2 audit row is missing sequence number"
                }));
            };
            if let Some(expected) = expected_next_seq {
                if seq != expected {
                    return Json(serde_json::json!({
                        "ok": false,
                        "broken_at_id": id,
                        "reason": "audit sequence is not contiguous"
                    }));
                }
            }
            expected_next_seq = Some(seq + 1);
            audit_entry_hash_v2(AuditHashFields {
                seq,
                prev_hash: &prev_hash,
                ts: &ts,
                gateway_id: &gateway_id,
                agent_session_id: agent_session_id.as_deref(),
                principal_id: &principal_id,
                server_id: &server_id,
                tool_name: &tool_name,
                decision: &decision,
                args_fingerprint: &args_fingerprint,
                injection_flags: &injection_flags,
                result_bytes,
            })
        } else {
            legacy_unsigned_rows += 1;
            last_legacy_hash = Some(entry_hash.clone());
            legacy_audit_entry_hash(AuditHashFields {
                seq: seq.unwrap_or_default(),
                prev_hash: &prev_hash,
                ts: &ts,
                gateway_id: &gateway_id,
                agent_session_id: agent_session_id.as_deref(),
                principal_id: &principal_id,
                server_id: &server_id,
                tool_name: &tool_name,
                decision: &decision,
                args_fingerprint: &args_fingerprint,
                injection_flags: &injection_flags,
                result_bytes,
            })
        };

        if recomputed != entry_hash {
            return Json(serde_json::json!({
                "ok": false,
                "broken_at_id": id,
                "reason": "entry_hash does not match recomputed hash of this row's own content"
            }));
        }

        if canonical_version >= AUDIT_CANONICAL_VERSION_V2 {
            let Some(seq) = seq else {
                return Json(serde_json::json!({
                    "ok": false,
                    "broken_at_id": id,
                    "reason": "v2 audit row is missing sequence number"
                }));
            };
            let Some(checkpoint_signed_at) = checkpoint_signed_at.as_deref() else {
                return Json(serde_json::json!({
                    "ok": false,
                    "broken_at_id": id,
                    "reason": "v2 audit row is missing signed checkpoint timestamp"
                }));
            };
            let Some(checkpoint_sig_b64) = checkpoint_sig_b64.as_deref() else {
                return Json(serde_json::json!({
                    "ok": false,
                    "broken_at_id": id,
                    "reason": "v2 audit row is missing signed checkpoint"
                }));
            };
            if let Err(e) = state.signer.verify_audit_checkpoint(
                seq,
                &entry_hash,
                checkpoint_signed_at,
                AuditSignatureParts {
                    ed25519_sig_b64: checkpoint_sig_b64,
                    ml_dsa_alg: checkpoint_ml_dsa_alg.as_deref(),
                    ml_dsa_sig_b64: checkpoint_ml_dsa_sig_b64.as_deref(),
                    require_ml_dsa: audit_requires_ml_dsa_checkpoint(
                        seq,
                        state.audit_ml_dsa_checkpoint_interval,
                    ),
                },
            ) {
                return Json(serde_json::json!({
                    "ok": false,
                    "broken_at_id": id,
                    "reason": "audit checkpoint signature does not verify",
                    "error": e.to_string()
                }));
            }
            if let Some(anchor) = &latest_anchor {
                if anchor.seq == seq {
                    if anchor.entry_hash != entry_hash {
                        return Json(serde_json::json!({
                            "ok": false,
                            "broken_at_id": id,
                            "reason": "audit row hash does not match latest external anchor"
                        }));
                    }
                    anchor_matched_row = true;
                }
            }
            signed_checkpoints += 1;
        }

        expected_prev = entry_hash;
    }
    drop(rows);

    let legacy_sealed = if let Some(last_hash) = last_legacy_hash.as_deref() {
        let seal = match sqlx::query(
            "SELECT last_entry_hash, sealed_at, seal_sig_b64, seal_ml_dsa_alg,
                    seal_ml_dsa_sig_b64
             FROM audit_legacy_seals
             WHERE id = 'legacy-v1'",
        )
        .fetch_optional(&state.pool)
        .await
        {
            Ok(row) => row,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "failed to read legacy audit seal",
                    "error": e.to_string()
                }))
            }
        };
        let Some(seal) = seal else {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "legacy unsigned audit rows exist but no signed legacy seal is present"
            }));
        };
        let sealed_hash: String = match seal.try_get("last_entry_hash") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "legacy audit seal has invalid last_entry_hash",
                    "error": e.to_string()
                }))
            }
        };
        if sealed_hash != last_hash {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "legacy audit rows no longer match the signed legacy seal"
            }));
        }
        let sealed_at: String = match seal.try_get("sealed_at") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "legacy audit seal has invalid sealed_at",
                    "error": e.to_string()
                }))
            }
        };
        let seal_sig_b64: String = match seal.try_get("seal_sig_b64") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "legacy audit seal has invalid seal_sig_b64",
                    "error": e.to_string()
                }))
            }
        };
        let seal_ml_dsa_alg: Option<String> = match seal.try_get("seal_ml_dsa_alg") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "legacy audit seal has invalid seal_ml_dsa_alg",
                    "error": e.to_string()
                }))
            }
        };
        let seal_ml_dsa_sig_b64: Option<String> = match seal.try_get("seal_ml_dsa_sig_b64") {
            Ok(value) => value,
            Err(e) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "reason": "legacy audit seal has invalid seal_ml_dsa_sig_b64",
                    "error": e.to_string()
                }))
            }
        };
        if let Err(e) = state.signer.verify_legacy_audit_seal(
            last_hash,
            &sealed_at,
            AuditSignatureParts {
                ed25519_sig_b64: &seal_sig_b64,
                ml_dsa_alg: seal_ml_dsa_alg.as_deref(),
                ml_dsa_sig_b64: seal_ml_dsa_sig_b64.as_deref(),
                require_ml_dsa: true,
            },
        ) {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "legacy audit seal signature does not verify",
                "error": e.to_string()
            }));
        }
        true
    } else {
        false
    };

    let last_seq = expected_next_seq.map(|seq| seq - 1).unwrap_or(0);
    let anchor_status = if let Some(anchor) = &latest_anchor {
        if !anchor_matched_row {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "audit database is missing the row recorded by the latest external anchor",
                "anchor_seq": anchor.seq,
                "db_last_seq": last_seq
            }));
        }
        if state.audit_anchor.required()
            && (anchor.seq != last_seq || anchor.entry_hash != expected_prev)
        {
            return Json(serde_json::json!({
                "ok": false,
                "reason": "required audit anchor does not match the current audit tail",
                "anchor_seq": anchor.seq,
                "db_last_seq": last_seq
            }));
        }
        if anchor.seq == last_seq {
            "matched"
        } else {
            "db_ahead_of_anchor"
        }
    } else if state.audit_anchor.required() {
        return Json(serde_json::json!({
            "ok": false,
            "reason": "required audit anchor is missing"
        }));
    } else if state.audit_anchor.is_enabled() {
        "missing"
    } else {
        "disabled"
    };

    Json(serde_json::json!({
        "ok": true,
        "checked_rows": checked_rows,
        "signed_checkpoints": signed_checkpoints,
        "legacy_unsigned_rows": legacy_unsigned_rows,
        "legacy_sealed": legacy_sealed,
        "audit_anchor": anchor_status
    }))
}

// ---------------------------------------------------------------------------
// Agent identity + scoped token issuance
// ---------------------------------------------------------------------------

pub async fn mint_agent_session(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<MintAgentSessionRequest>,
) -> ApiResult<Json<AgentSession>> {
    if req.principal_id != principal.0 {
        return Err(forbidden(
            "agent session principal_id must match the authenticated principal",
        ));
    }
    let public_key = BASE64_STANDARD.decode(&req.public_key_b64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "public_key_b64 is not valid base64".to_string(),
        )
    })?;
    if public_key.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_b64 must be a 32-byte Ed25519 verifying key".into(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let spiffe_id = mint_spiffe_id(&state.trust_domain, &id);
    let now = Utc::now();
    let ttl_minutes = req.ttl_minutes.clamp(1, 24 * 60);
    let expires = now + Duration::minutes(ttl_minutes);

    sqlx::query(
        "INSERT INTO agent_sessions
             (id, spiffe_id, principal_id, purpose, public_key_b64, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&spiffe_id)
    .bind(&principal.0)
    .bind(&req.purpose)
    .bind(&req.public_key_b64)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(AgentSession {
        id,
        spiffe_id,
        principal_id: principal.0,
        purpose: req.purpose,
        public_key_b64: req.public_key_b64,
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        revoked_at: None,
    }))
}

pub async fn issue_token(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<IssueTokenRequest>,
) -> ApiResult<Json<IssuedToken>> {
    ensure_gateway_owner(&state, &principal, &req.gateway_id).await?;

    let row = sqlx::query(
        "SELECT spiffe_id, principal_id, public_key_b64, expires_at, revoked_at
         FROM agent_sessions WHERE id = $1",
    )
    .bind(&req.agent_session_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;

    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown agent_session_id".into()));
    };
    let revoked_at: Option<String> = row.try_get("revoked_at").ok().flatten();
    if revoked_at.is_some() {
        return Err((StatusCode::FORBIDDEN, "agent session revoked".into()));
    }
    let expires_at: String = row.try_get("expires_at").map_err(err500)?;
    let expires_dt = chrono::DateTime::parse_from_rfc3339(&expires_at).map_err(err500)?;
    if expires_dt < Utc::now() {
        return Err((StatusCode::FORBIDDEN, "agent session expired".into()));
    }

    let spiffe_id: String = row.try_get("spiffe_id").map_err(err500)?;
    let principal_id: String = row.try_get("principal_id").map_err(err500)?;
    let public_key_b64: String = row.try_get("public_key_b64").map_err(err500)?;
    if principal_id != principal.0 {
        return Err(forbidden("agent session is owned by another principal"));
    }

    let now = Utc::now();
    let exp = now + Duration::seconds(req.ttl_seconds.clamp(30, 3600));
    let jti = Uuid::new_v4().to_string();
    let aud = token_audience(&req.gateway_id, &req.server_id, &req.tool_name);

    let claims = TokenClaims {
        sub: spiffe_id,
        act: ActorClaim { sub: principal_id },
        cnf: crate::identity::ConfirmationClaim {
            ed25519_public_key_b64: public_key_b64,
        },
        aud,
        server_id: req.server_id,
        tool_name: req.tool_name,
        gateway_id: req.gateway_id,
        jti: jti.clone(),
        nbf: now.timestamp(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };

    let token = state.signer.sign_token(&claims).map_err(err500)?;
    sqlx::query(
        "INSERT INTO issued_tokens
             (jti, agent_session_id, gateway_id, server_id, tool_name, issued_at, not_before, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&jti)
    .bind(&req.agent_session_id)
    .bind(&claims.gateway_id)
    .bind(&claims.server_id)
    .bind(&claims.tool_name)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(exp.to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok(Json(IssuedToken {
        token,
        expires_at: exp.to_rfc3339(),
    }))
}

pub async fn signer_public_key(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ed25519_public_key_b64": state.signer.ed25519_verifying_key_b64(),
        "ed25519_kid": state.signer.ed25519_key_id(),
        "ml_dsa_alg": "ML-DSA-65",
        "ml_dsa_public_key_b64": state.signer.ml_dsa65_verifying_key_b64(),
        "ml_dsa_kid": state.signer.ml_dsa65_key_id(),
        "hybrid_required_by_default": true
    }))
}

pub async fn introspect_token(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<IntrospectTokenRequest>,
) -> ApiResult<Json<IntrospectTokenResponse>> {
    let claims = match state.signer.verify_token(&req.token, true) {
        Ok(claims) => claims,
        Err(e) => {
            return Ok(Json(inactive_token_response(format!(
                "token signature or claims failed verification: {e}"
            ))))
        }
    };

    ensure_gateway_owner(&state, &principal, &claims.gateway_id).await?;
    let Some(agent_session_id) = agent_session_id_from_spiffe(&claims.sub) else {
        return Ok(Json(inactive_token_response(
            "token subject is not a recognized agent SPIFFE ID",
        )));
    };
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let Some(token_row) = sqlx::query(
        "SELECT used_at, expires_at
         FROM issued_tokens
         WHERE jti = $1 AND agent_session_id = $2 AND gateway_id = $3
           AND server_id = $4 AND tool_name = $5",
    )
    .bind(&claims.jti)
    .bind(&agent_session_id)
    .bind(&claims.gateway_id)
    .bind(&claims.server_id)
    .bind(&claims.tool_name)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    else {
        return Ok(Json(inactive_token_response(
            "token id was not issued by this control plane",
        )));
    };
    let used_at: Option<String> = token_row.try_get("used_at").ok().flatten();
    if used_at.is_some() {
        return Ok(Json(inactive_token_response("token id was already used")));
    }
    let expires_at: String = token_row.try_get("expires_at").map_err(err500)?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at).map_err(err500)?;
    if expires_at < now {
        return Ok(Json(inactive_token_response("token id is expired")));
    }

    let Some(session_row) = sqlx::query(
        "SELECT principal_id, expires_at, revoked_at
         FROM agent_sessions
         WHERE id = $1",
    )
    .bind(&agent_session_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    else {
        return Ok(Json(inactive_token_response(
            "agent session no longer exists",
        )));
    };
    let principal_id: String = session_row.try_get("principal_id").map_err(err500)?;
    if principal_id != claims.act.sub {
        return Ok(Json(inactive_token_response(
            "token actor does not match agent session owner",
        )));
    }
    let session_revoked_at: Option<String> = session_row.try_get("revoked_at").ok().flatten();
    if session_revoked_at.is_some() {
        return Ok(Json(inactive_token_response("agent session is revoked")));
    }
    let session_expires_at: String = session_row.try_get("expires_at").map_err(err500)?;
    let session_expires_at =
        chrono::DateTime::parse_from_rfc3339(&session_expires_at).map_err(err500)?;
    if session_expires_at < now {
        return Ok(Json(inactive_token_response("agent session is expired")));
    }

    let result =
        sqlx::query("UPDATE issued_tokens SET used_at = $1 WHERE jti = $2 AND used_at IS NULL")
            .bind(&now_rfc3339)
            .bind(&claims.jti)
            .execute(&state.pool)
            .await
            .map_err(err500)?;
    if result.rows_affected() == 0 {
        return Ok(Json(inactive_token_response("token id was already used")));
    }

    Ok(Json(IntrospectTokenResponse {
        active: true,
        agent_session_id: Some(agent_session_id),
        principal_id: Some(claims.act.sub),
        gateway_id: Some(claims.gateway_id),
        server_id: Some(claims.server_id),
        tool_name: Some(claims.tool_name),
        jti: Some(claims.jti),
        reason: None,
    }))
}

fn inactive_token_response(reason: impl Into<String>) -> IntrospectTokenResponse {
    IntrospectTokenResponse {
        active: false,
        agent_session_id: None,
        principal_id: None,
        gateway_id: None,
        server_id: None,
        tool_name: None,
        jti: None,
        reason: Some(reason.into()),
    }
}

pub async fn revoke_agent_session(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE agent_sessions SET revoked_at = $1
         WHERE id = $2 AND principal_id = $3 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(&id)
    .bind(&principal.0)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "not found or already revoked".into()));
    }
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Org-authored Rego policy: the "everyone's needs are different" knob.
// ---------------------------------------------------------------------------

pub async fn set_org_policy(
    State(state): State<AppState>,
    Path(scope): Path<String>,
    principal: AuthedPrincipal,
    Json(req): Json<SetOrgPolicyRequest>,
) -> ApiResult<Json<OrgPolicy>> {
    ensure_scope_owner(&state, &principal, &scope).await?;

    // Reject bad Rego at write time, not at eval-in-the-hot-path time.
    // Compilation success does NOT mean the policy is safe - it only means
    // it parses. The floor (see mcp-warden's policy.rs) is what actually
    // keeps a badly-reasoned policy from being able to do damage.
    let mut engine = regorus::Engine::new();
    engine
        .add_policy("org_policy.rego".to_string(), req.rego_source.clone())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("rego does not compile: {e}"),
            )
        })?;

    let next_version_row =
        sqlx::query("SELECT COALESCE(MAX(version), 0) as v FROM org_policies WHERE scope = $1")
            .bind(&scope)
            .fetch_one(&state.pool)
            .await
            .map_err(err500)?;
    let next_version: i64 = next_version_row.try_get::<i64, _>("v").unwrap_or(0) + 1;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO org_policies (id, scope, version, rego_source, created_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&scope)
    .bind(next_version)
    .bind(&req.rego_source)
    .bind(&now)
    .bind(&principal.0)
    .execute(&state.pool)
    .await
    .map_err(err500)?;

    Ok(Json(OrgPolicy {
        scope,
        version: next_version,
        rego_source: req.rego_source,
    }))
}

pub async fn get_org_policy(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(scope): Path<String>,
) -> ApiResult<Json<OrgPolicy>> {
    ensure_scope_owner(&state, &principal, &scope).await?;

    let row = sqlx::query(
        "SELECT scope, version, rego_source FROM org_policies
         WHERE scope = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(&scope)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;

    match row {
        Some(r) => Ok(Json(OrgPolicy {
            scope,
            version: r.try_get("version").map_err(err500)?,
            rego_source: r.try_get("rego_source").map_err(err500)?,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no org policy for scope '{scope}'"),
        )),
    }
}
