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
use std::path::PathBuf;
use upstream::Upstream;

fn default_state_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".mcp-warden")
}

fn default_config_path() -> PathBuf {
    PathBuf::from(std::env::var("MCP_WARDEN_CONFIG").unwrap_or_else(|_| "warden.toml".to_string()))
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
            let mut guard = IntegrityGuard::load(&default_state_dir())?;
            if guard.approve(&key)? {
                println!("approved: {key}");
            } else {
                println!("no pending change found for: {key}");
            }
            Ok(())
        }
        Some("list-pending") => {
            let guard = IntegrityGuard::load(&default_state_dir())?;
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
            let mut confirmed_by = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
            let mut minutes: i64 = 60;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--reason" => reason = args.next().unwrap_or_default(),
                    "--by" => confirmed_by = args.next().unwrap_or(confirmed_by),
                    "--minutes" => {
                        minutes = args
                            .next()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(60)
                    }
                    other => tracing::warn!("ignoring unrecognized flag '{other}'"),
                }
            }
            if reason.is_empty() {
                anyhow::bail!(
                    "usage: mcp-warden confirm-degraded --reason \"why\" [--by you] [--minutes 60]"
                );
            }
            let state_dir = default_state_dir();
            std::fs::create_dir_all(&state_dir)?;
            let ack = degraded::write_ack(&state_dir, &reason, &confirmed_by, minutes)?;
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
            if let Some(cp_cfg) = config.control_plane.clone() {
                let client = CpClient::new(
                    cp_cfg.url.clone(),
                    cp_cfg.gateway_id.clone(),
                    cp_cfg.api_key.clone(),
                );
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
                        if cp_cfg.signer_public_key_b64.is_none() {
                            match client.fetch_signer_public_key().await {
                                Ok(key) => {
                                    if let Some(cfg) = config.control_plane.as_mut() {
                                        cfg.signer_public_key_b64 = Some(key);
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
                        match degraded::read_valid_ack(&config.state_dir) {
                            Some(ack) => {
                                tracing::warn!(
                                    "control plane unreachable ({e}) - running DEGRADED on \
                                     cached/local policy until {}, confirmed by {} ({})",
                                    ack.expires_at, ack.confirmed_by, ack.reason
                                );
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

            let gateway = Gateway::new(config, upstreams, integrity, rego, cp_client);

            let service = gateway.serve(stdio()).await?;
            service.waiting().await?;
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!(
            "unknown subcommand '{other}' - try: serve [config.toml] | approve <server::tool> | list-pending"
        )),
    }
}
