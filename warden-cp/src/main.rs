mod audit_anchor;
mod auth;
mod db;
mod external_command;
mod identity;
mod models;
mod notify;
mod oidc;
mod routes;
mod scim;
mod transport;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post, put};
use axum::Router;
use routes::{AppState, AuditChainTail, TransportSecurity};
use sqlx::Row;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn load_chain_tail(pool: &db::DbPool) -> anyhow::Result<AuditChainTail> {
    let row = sqlx::query(
        "SELECT seq, entry_hash FROM audit_events
         ORDER BY CASE WHEN seq IS NULL THEN 0 ELSE 1 END DESC, seq DESC, ts DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some(r) => AuditChainTail {
            seq: r.try_get::<Option<i64>, _>("seq")?.unwrap_or(0),
            hash: r.try_get("entry_hash")?,
        },
        None => AuditChainTail {
            seq: 0,
            hash: GENESIS_HASH.to_string(),
        },
    })
}

fn enforce_transport_security(bind_addr: &str, security: &TransportSecurity) -> anyhow::Result<()> {
    if security.tls_enabled {
        return Ok(());
    }
    if security.require_https && security.trust_proxy_headers && is_loopback_bind(bind_addr) {
        return Ok(());
    }
    if security.require_https {
        anyhow::bail!(
            "WARDEN_CP_REQUIRE_HTTPS=true but TLS_CERT_PATH/TLS_KEY_PATH are not set; \
             enable built-in TLS or terminate HTTPS at a trusted reverse proxy and set \
             WARDEN_CP_TRUST_PROXY_HEADERS=true while binding warden-cp to loopback"
        );
    }
    if is_loopback_bind(bind_addr) || bool_env("WARDEN_CP_ALLOW_INSECURE_NON_LOOPBACK")? {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to bind plaintext warden-cp to non-loopback address {bind_addr}; \
         terminate TLS at a local reverse proxy or set \
         WARDEN_CP_ALLOW_INSECURE_NON_LOOPBACK=true only in a trusted private test network"
    )
}

fn is_loopback_bind(bind_addr: &str) -> bool {
    let host = bind_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(bind_addr)
        .trim_matches(['[', ']']);
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

fn bool_env(name: &str) -> anyhow::Result<bool> {
    bool_env_with_default(name, false)
}

fn bool_env_with_default(name: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => anyhow::bail!("{name} must be one of true, false, 1, 0, yes, or no"),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e.into()),
    }
}

fn audit_ml_dsa_checkpoint_interval() -> anyhow::Result<i64> {
    match std::env::var("AUDIT_ML_DSA_CHECKPOINT_INTERVAL") {
        Ok(value) => {
            let interval = value.parse::<i64>().map_err(|_| {
                anyhow::anyhow!("AUDIT_ML_DSA_CHECKPOINT_INTERVAL must be an integer")
            })?;
            if !(1..=1_000_000).contains(&interval) {
                anyhow::bail!("AUDIT_ML_DSA_CHECKPOINT_INTERVAL must be between 1 and 1000000");
            }
            Ok(interval)
        }
        Err(std::env::VarError::NotPresent) => Ok(1),
        Err(e) => Err(e.into()),
    }
}

fn transport_security_from_env(tls_enabled: bool) -> anyhow::Result<TransportSecurity> {
    Ok(TransportSecurity {
        tls_enabled,
        require_https: bool_env("WARDEN_CP_REQUIRE_HTTPS")?,
        trust_proxy_headers: bool_env("WARDEN_CP_TRUST_PROXY_HEADERS")?,
    })
}

fn tls_paths_from_env() -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    let cert = std::env::var("TLS_CERT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let key = std::env::var("TLS_KEY_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());
    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some((PathBuf::from(cert), PathBuf::from(key)))),
        (None, None) => Ok(None),
        _ => anyhow::bail!("TLS_CERT_PATH and TLS_KEY_PATH must be set together"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://warden-cp.db".to_string());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
    let tls_paths = tls_paths_from_env()?;
    let transport_security = transport_security_from_env(tls_paths.is_some())?;
    enforce_transport_security(&bind_addr, &transport_security)?;
    let webhook_url = std::env::var("APPROVAL_WEBHOOK_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let trust_domain = std::env::var("TRUST_DOMAIN").unwrap_or_else(|_| "warden.local".to_string());
    let signing_key_path = PathBuf::from(
        std::env::var("SIGNING_KEY_PATH").unwrap_or_else(|_| "warden-cp-signing.key".to_string()),
    );
    let ml_dsa_key_path = PathBuf::from(
        std::env::var("ML_DSA_SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "warden-cp-ml-dsa65.key".to_string()),
    );
    let production_postgres_build = cfg!(all(feature = "postgres", not(feature = "sqlite")));
    let require_external_signer =
        bool_env_with_default("WARDEN_REQUIRE_EXTERNAL_SIGNER", production_postgres_build)?;

    let signer = Arc::new(identity::HybridSigner::load_or_generate(
        &signing_key_path,
        Some(&ml_dsa_key_path),
        require_external_signer,
    )?);
    tracing::info!(
        "Ed25519 signer public key (share with gateways for offline token verification): {}",
        signer.ed25519_verifying_key_b64()
    );
    if let Some(key) = signer.ml_dsa65_verifying_key_b64() {
        tracing::info!("ML-DSA-65 signer public key: {key}");
    }

    let pool = db::connect(&database_url).await?;
    auth::bootstrap_root_key_if_needed(&pool).await?;

    routes::seal_legacy_audit_if_needed(&pool, signer.as_ref()).await?;
    let chain_tail = load_chain_tail(&pool).await?;
    let oidc = oidc::OidcConfig::from_env()?.map(Arc::new);
    let audit_anchor = Arc::new(audit_anchor::AuditAnchor::from_env()?);
    let audit_ml_dsa_checkpoint_interval = audit_ml_dsa_checkpoint_interval()?;

    let state = AppState {
        pool,
        signer,
        oidc,
        notifier: Arc::new(notify::Notifier::new(webhook_url)?),
        trust_domain,
        audit_chain_tail: Arc::new(AsyncMutex::new(chain_tail)),
        audit_anchor,
        audit_ml_dsa_checkpoint_interval,
        transport_security,
        rate_limits: Arc::new(Mutex::new(std::collections::HashMap::new())),
    };

    let protected = Router::new()
        .route("/v1/admin/summary", get(routes::admin_summary))
        .route(
            "/v1/principals",
            get(routes::list_principals).post(routes::create_principal),
        )
        .route("/v1/principals/:id/roles", put(routes::set_principal_roles))
        .route("/v1/groups", get(routes::list_groups))
        .route("/v1/groups/:id/roles", put(routes::set_group_roles))
        .route("/v1/api-keys", post(routes::create_api_key))
        .route("/v1/api-keys/:id/revoke", post(routes::revoke_api_key))
        .route("/v1/gateways", get(routes::list_gateways))
        .route("/v1/gateways/register", post(routes::register_gateway))
        .route("/v1/policy/:scope", get(routes::get_policy))
        .route("/v1/policy", put(routes::put_policy))
        .route("/v1/audit", post(routes::ingest_audit))
        .route("/v1/audit/export", get(routes::list_audit_events))
        .route("/v1/audit/events", get(routes::list_audit_events))
        .route("/v1/security/anomalies", get(routes::security_anomalies))
        .route(
            "/v1/tool-fingerprints/approve",
            post(routes::approve_tool_fingerprint),
        )
        .route(
            "/v1/tool-fingerprints",
            get(routes::list_tool_fingerprints).post(routes::report_tool_fingerprint),
        )
        .route(
            "/v1/approvals",
            post(routes::create_approval).get(routes::list_approvals),
        )
        .route("/v1/approvals/:id", get(routes::get_approval))
        .route("/v1/approvals/:id/decide", post(routes::decide_approval))
        .route("/v1/approvals/:id/consume", post(routes::consume_approval))
        .route("/v1/audit/verify", get(routes::verify_audit_chain))
        .route(
            "/v1/agent-sessions",
            get(routes::list_agent_sessions).post(routes::mint_agent_session),
        )
        .route(
            "/v1/agent-sessions/:id/revoke",
            post(routes::revoke_agent_session),
        )
        .route("/v1/token", post(routes::issue_token))
        .route("/v1/token/introspect", post(routes::introspect_token))
        .route("/v1/signer/public-key", get(routes::signer_public_key))
        .route(
            "/v1/org-policy/:scope",
            put(routes::set_org_policy).get(routes::get_org_policy),
        )
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim::service_provider_config),
        )
        .route("/scim/v2/Schemas", get(scim::schemas))
        .route(
            "/scim/v2/Users",
            get(scim::list_users).post(scim::create_user),
        )
        .route(
            "/scim/v2/Users/:id",
            get(scim::get_user)
                .put(scim::replace_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(scim::list_groups).post(scim::create_group),
        )
        .route(
            "/scim/v2/Groups/:id",
            get(scim::get_group)
                .put(scim::replace_group)
                .patch(scim::patch_group)
                .delete(scim::delete_group),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            routes::rate_limit,
        ))
        // Auth applies to everything above - there is no unauthenticated
        // endpoint in this service, on purpose. If you add a health check
        // later, mount it as a separate router WITHOUT this layer.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let app = Router::new()
        .route("/admin", get(routes::admin_dashboard))
        .route("/oidc/login", get(oidc::login))
        .route("/oidc/callback", get(oidc::callback))
        .merge(protected)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            routes::require_https,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            routes::security_headers,
        ))
        .with_state(state);

    transport::serve_app(&bind_addr, app, tls_paths).await
}
