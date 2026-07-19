mod audit;
mod config;
mod control_plane;
mod degraded;
mod gateway;
mod injection_filter;
mod integrity;
mod policy;
mod rego_policy;
mod token;
mod upstream;

use control_plane::CpClient;

use config::WardenConfig;
use gateway::Gateway;
use integrity::IntegrityGuard;
use rmcp::transport::stdio;
use rmcp::ServiceExt;
use std::path::{Path, PathBuf};
use upstream::Upstream;

fn default_config_path() -> PathBuf {
    PathBuf::from(std::env::var("MCP_WARDEN_CONFIG").unwrap_or_else(|_| "warden.toml".to_string()))
}

fn cli_config() -> anyhow::Result<Option<WardenConfig>> {
    let path = default_config_path();
    if path.exists() {
        return WardenConfig::load(&path).map(Some);
    }
    if std::env::var_os("MCP_WARDEN_CONFIG").is_some() {
        anyhow::bail!("MCP_WARDEN_CONFIG points to missing file {path:?}");
    }
    Ok(None)
}

fn cli_state_dir(config: Option<&WardenConfig>) -> &Path {
    config
        .map(|value| value.state_dir.as_path())
        .unwrap_or_else(|| Path::new("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr) // stdout is reserved for MCP JSON-RPC frames
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("approve") => {
            let key = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: mcp-warden approve <server::tool>"))?;
            let config = cli_config()?;
            let fallback_state = config::default_state_dir();
            let state_dir = config
                .as_ref()
                .map(|value| value.state_dir.as_path())
                .unwrap_or(fallback_state.as_path());
            let mut guard = IntegrityGuard::load(state_dir)?;
            if guard.approve(&key)? {
                println!("approved: {key}");
            } else {
                println!("no pending change found for: {key}");
            }
            Ok(())
        }
        Some("list-pending") => {
            let config = cli_config()?;
            let fallback_state = config::default_state_dir();
            let state_dir = config
                .as_ref()
                .map(|value| value.state_dir.as_path())
                .unwrap_or(fallback_state.as_path());
            let guard = IntegrityGuard::load(state_dir)?;
            let pending = guard.list_pending();
            if pending.is_empty() {
                println!("no pending tool changes");
            } else {
                for (key, change) in pending {
                    println!(
                        "{key}\n  old_hash: {:?}\n  new_hash: {}\n  definition: {}\n",
                        change.old_hash, change.new_hash, change.new_definition
                    );
                }
            }
            Ok(())
        }
        Some("confirm-degraded") => {
            let mut reason = String::new();
            let config = cli_config()?;
            let cp = config
                .as_ref()
                .and_then(|value| value.control_plane.as_ref())
                .ok_or_else(|| anyhow::anyhow!("confirm-degraded requires a configured control plane"))?;
            let mut confirmed_by = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into());
            let mut minutes: i64 = cp.max_degraded_minutes;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--reason" => {
                        reason = args
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("--reason requires a value"))?
                    }
                    "--by" => {
                        confirmed_by = args
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("--by requires a value"))?
                    }
                    "--minutes" => {
                        minutes = args
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("--minutes requires a value"))?
                            .parse()
                            .map_err(|_| anyhow::anyhow!("--minutes must be an integer"))?
                    }
                    other => anyhow::bail!("unrecognized confirm-degraded flag '{other}'"),
                }
            }
            if reason.is_empty() {
                anyhow::bail!(
                    "usage: mcp-warden confirm-degraded --reason \"why\" [--by you] [--minutes 60]"
                );
            }
            let state_dir = cli_state_dir(config.as_ref());
            std::fs::create_dir_all(state_dir)?;
            let ack = degraded::write_ack(
                state_dir,
                &reason,
                &confirmed_by,
                minutes,
                cp.max_degraded_minutes,
            )?;
            println!(
                "degraded mode confirmed by {} until {} - reason: {}",
                ack.confirmed_by, ack.expires_at, ack.reason
            );
            println!(
                "the gateway will run on cached/local policy only until then - re-run this \
                 command to extend, it will NOT renew itself"
            );
            Ok(())
        }
        Some("serve") | None => {
            let config_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(default_config_path);
            let mut config = WardenConfig::load(&config_path)?;

            let mut cp_client = None;
            let mut degraded_until = None;
            if let Some(cp_cfg) = config.control_plane.clone() {
                let api_key = config
                    .control_plane_api_key()?
                    .ok_or_else(|| anyhow::anyhow!("control plane API key is unavailable"))?;
                let client = CpClient::new(
                    cp_cfg.url.clone(),
                    cp_cfg.gateway_id.clone(),
                    api_key,
                )?;
                let reachable = client
                    .register(
                        &cp_cfg.owner_principal_id,
                        env!("CARGO_PKG_VERSION"),
                        &config.servers,
                    )
                    .await;

                match reachable {
                    Ok(()) => {
                        tracing::info!("registered with control plane at {}", cp_cfg.url);
                        if cp_cfg.signer_public_key_b64.is_none()
                            || (cp_cfg.require_ml_dsa_token_signature
                                && cp_cfg.ml_dsa_public_key_b64.is_none())
                        {
                            match client.fetch_signer_public_key().await {
                                Ok(keys) => {
                                    if let Some(cfg) = config.control_plane.as_mut() {
                                        cfg.signer_public_key_b64 =
                                            Some(keys.ed25519_public_key_b64);
                                        cfg.ml_dsa_public_key_b64 = keys.ml_dsa_public_key_b64;
                                        if cfg.require_ml_dsa_token_signature
                                            && cfg.ml_dsa_public_key_b64.is_none()
                                        {
                                            anyhow::bail!(
                                                "control plane did not return an ML-DSA public key"
                                            );
                                        }
                                    }
                                }
                                Err(e) if cp_cfg.require_agent_token => {
                                    anyhow::bail!(
                                        "control plane is reachable but signer public key fetch failed: {e}"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "failed to fetch signer public key; per-call tokens are not required"
                                    );
                                }
                            }
                        }
                        cp_client = Some(client);
                    }
                    Err(e) => {
                        // This is the go/no-go gate: no silent fail-open, no
                        // silent fail-closed. A human on THIS box has to have
                        // already said "yes, run degraded" - or has to say so
                        // right now - before a single upstream server spawns.
                        match degraded::read_valid_ack(
                            &config.state_dir,
                            cp_cfg.max_degraded_minutes,
                        ) {
                            Some(ack) => {
                                if cp_cfg.require_agent_token
                                    && cp_cfg.signer_public_key_b64.is_none()
                                {
                                    anyhow::bail!(
                                        "degraded mode requires a configured signer_public_key_b64"
                                    );
                                }
                                if cp_cfg.require_ml_dsa_token_signature
                                    && cp_cfg.ml_dsa_public_key_b64.is_none()
                                {
                                    anyhow::bail!(
                                        "degraded mode requires a configured ml_dsa_public_key_b64"
                                    );
                                }
                                tracing::warn!(
                                    "control plane unreachable ({e}) - running DEGRADED on \
                                     cached/local policy until {}, confirmed by {} ({})",
                                    ack.expires_at, ack.confirmed_by, ack.reason
                                );
                                degraded_until = Some(ack.expires_at);
                            }
                            None => {
                                eprintln!(
                                    "control plane at {} is unreachable: {e}\n\n\
                                     Refusing to serve. This gateway will not fall back to \
                                     cached/local policy without an explicit human decision.\n\
                                     Run:\n  mcp-warden confirm-degraded --reason \"why\" \
                                     --minutes {}\nthen retry.",
                                    cp_cfg.url, cp_cfg.max_degraded_minutes
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }

            let mut upstreams = Vec::new();
            for server_config in config.servers.clone() {
                match Upstream::connect(server_config.clone()).await {
                    Ok(up) => upstreams.push(up),
                    Err(e) => {
                        tracing::error!(server = %server_config.id, error = %e, "failed to connect upstream, skipping");
                    }
                }
            }

            let integrity = IntegrityGuard::load(&config.state_dir)?;

            let rego = match &config.rego_policy_path {
                Some(path) => {
                    let source = std::fs::read_to_string(path)?;
                    Some(rego_policy::RegoPolicy::compile(&source)?)
                }
                None => None,
            };

            let gateway = Gateway::new(
                config,
                upstreams,
                integrity,
                rego,
                cp_client,
                degraded_until,
            );

            let service = gateway.serve(stdio()).await?;
            service.waiting().await?;
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!(
            "unknown subcommand '{other}' - try: serve [config.toml] | approve <server::tool> | list-pending | confirm-degraded"
        )),
    }
}
