mod auth;
mod db;
mod identity;
mod models;
mod notify;
mod oidc;
mod routes;
mod scim;

use axum::middleware;
use axum::routing::{get, post, put};
use axum::Router;
use routes::AppState;
use sqlx::Row;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn load_chain_tail(pool: &db::DbPool) -> String {
    let row = sqlx::query("SELECT entry_hash FROM audit_events ORDER BY ts DESC LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    match row {
        Some(r) => r
            .try_get::<String, _>("entry_hash")
            .unwrap_or_else(|_| GENESIS_HASH.to_string()),
        None => GENESIS_HASH.to_string(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://warden-cp.db".to_string());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
    let webhook_url = std::env::var("APPROVAL_WEBHOOK_URL").ok();
    let trust_domain = std::env::var("TRUST_DOMAIN").unwrap_or_else(|_| "warden.local".to_string());
    let signing_key_path = PathBuf::from(
        std::env::var("SIGNING_KEY_PATH").unwrap_or_else(|_| "warden-cp-signing.key".to_string()),
    );
    let ml_dsa_key_path = PathBuf::from(
        std::env::var("ML_DSA_SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "warden-cp-ml-dsa65.key".to_string()),
    );

    let pool = db::connect(&database_url).await?;
    auth::bootstrap_root_key_if_needed(&pool).await?;

    let signer = Arc::new(identity::HybridSigner::load_or_generate(
        &signing_key_path,
        Some(&ml_dsa_key_path),
    )?);
    tracing::info!(
        "Ed25519 signer public key (share with gateways for offline token verification): {}",
        signer.ed25519_verifying_key_b64()
    );
    if let Some(key) = signer.ml_dsa65_verifying_key_b64() {
        tracing::info!("ML-DSA-65 signer public key: {key}");
    }

    let chain_tail = load_chain_tail(&pool).await;
    let oidc = oidc::OidcConfig::from_env()?.map(Arc::new);

    let state = AppState {
        pool,
        signer,
        oidc,
        notifier: Arc::new(notify::Notifier::new(webhook_url)),
        trust_domain,
        audit_chain_tail: Arc::new(AsyncMutex::new(chain_tail)),
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
        .with_state(state);

    tracing::info!("warden-cp listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
