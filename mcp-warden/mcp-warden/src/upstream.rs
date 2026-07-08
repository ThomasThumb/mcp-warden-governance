use crate::config::{
    OAuthClientCredentials, SandboxConfig, SandboxMode, Transport, UpstreamConfig,
};
use anyhow::{bail, Context, Result};
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::service::{RoleClient, RunningService, ServiceExt};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::process::Command;

// ---------------------------------------------------------------------------
// A note on API stability: rmcp is under active development (it went from
// 0.1 to 2.x with several breaking changes along the way - see the project's
// migration guides). The shapes below (RunningService<RoleClient, ()>,
// ServiceExt::serve, list_all_tools, call_tool/CallToolRequestParam) are
// confirmed against the SDK's published docs and README examples at the time
// this was written. If your `cargo check` complains about a renamed type or
// method, run `cargo doc -p rmcp --open` (or check docs.rs/rmcp/latest) - the
// concepts here (spawn a child, .serve() it, list_all_tools, call_tool) will
// still be there, just possibly renamed.
// ---------------------------------------------------------------------------

pub struct Upstream {
    pub config: UpstreamConfig,
    conn: UpstreamConn,
}

enum UpstreamConn {
    Stdio(RunningService<RoleClient, ()>),
    Http(HttpUpstream),
}

struct HttpUpstream {
    url: String,
    token_env: Option<String>,
    oauth: Option<OAuthClientCredentials>,
    http: reqwest::Client,
    next_id: AtomicU64,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

impl Upstream {
    pub async fn connect(config: UpstreamConfig) -> Result<Self> {
        match config.transport.clone() {
            Transport::Stdio {
                command,
                args,
                env,
                sandbox,
            } => {
                let cmd_args = args.clone();
                let env_vars = env.clone();
                let child = TokioChildProcess::new(
                    build_stdio_command(&command, &cmd_args, &env_vars, sandbox.as_ref())?
                        .configure(move |cmd| {
                            cmd.args(&cmd_args);
                            for (k, v) in &env_vars {
                                cmd.env(k, v);
                            }
                        }),
                )?;
                let service = ().serve(child).await?;
                Ok(Self {
                    config,
                    conn: UpstreamConn::Stdio(service),
                })
            }
            Transport::Http {
                url,
                token_env,
                oauth,
            } => Ok(Self {
                config,
                conn: UpstreamConn::Http(HttpUpstream {
                    url,
                    token_env,
                    oauth,
                    http: reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .build()
                        .context("building HTTP upstream client")?,
                    next_id: AtomicU64::new(1),
                }),
            }),
        }
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        match &self.conn {
            UpstreamConn::Stdio(svc) => Ok(svc.list_all_tools().await?),
            UpstreamConn::Http(http) => http.list_tools().await,
        }
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult> {
        match &self.conn {
            UpstreamConn::Stdio(svc) => {
                let mut request = CallToolRequestParams::new(name.to_string());
                if let Some(arguments) = arguments {
                    request = request.with_arguments(arguments);
                }
                Ok(svc.call_tool(request).await?)
            }
            UpstreamConn::Http(http) => http.call_tool(name, arguments).await,
        }
    }
}

impl HttpUpstream {
    async fn bearer_token(&self) -> Result<Option<String>> {
        if let Some(env_name) = &self.token_env {
            let token = std::env::var(env_name)
                .with_context(|| format!("missing upstream token env var {env_name}"))?;
            return Ok(Some(token));
        }
        let Some(oauth) = &self.oauth else {
            return Ok(None);
        };
        let client_id = std::env::var(&oauth.client_id_env)
            .with_context(|| format!("missing OAuth client id env var {}", oauth.client_id_env))?;
        let client_secret = std::env::var(&oauth.client_secret_env).with_context(|| {
            format!(
                "missing OAuth client secret env var {}",
                oauth.client_secret_env
            )
        })?;
        let token: OAuthTokenResponse = self
            .http
            .post(&oauth.token_url)
            .basic_auth(client_id, Some(client_secret))
            .form(&[
                ("grant_type", "client_credentials"),
                ("resource", oauth.resource.as_str()),
                ("scope", oauth.scope.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Some(token.access_token))
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = self.http.post(&self.url).json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        if let Some(token) = self.bearer_token().await? {
            request = request.bearer_auth(token);
        }
        let value: serde_json::Value = request.send().await?.error_for_status()?.json().await?;
        if let Some(error) = value.get("error") {
            bail!("upstream HTTP RPC {method} failed: {error}");
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("upstream HTTP RPC {method} returned no result"))
    }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        let result = self.rpc("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tools/list response missing tools"))?;
        Ok(serde_json::from_value(tools)?)
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult> {
        let result = self
            .rpc(
                "tools/call",
                json!({
                    "name": name,
                    "arguments": arguments.unwrap_or_default(),
                }),
            )
            .await?;
        Ok(serde_json::from_value(result)?)
    }
}

fn build_stdio_command(
    command: &str,
    _args: &[String],
    env: &std::collections::HashMap<String, String>,
    sandbox: Option<&SandboxConfig>,
) -> Result<Command> {
    let Some(sandbox) = sandbox else {
        return Ok(Command::new(command));
    };
    match sandbox.mode {
        SandboxMode::None => Ok(Command::new(command)),
        SandboxMode::Bubblewrap => {
            let mut cmd = Command::new("bwrap");
            cmd.arg("--die-with-parent")
                .arg("--unshare-all")
                .arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--ro-bind")
                .arg("/")
                .arg("/");
            if !sandbox.allow_network {
                cmd.arg("--unshare-net");
            }
            if let Some(workspace) = &sandbox.workspace {
                cmd.arg("--bind")
                    .arg(workspace)
                    .arg("/workspace")
                    .arg("--chdir")
                    .arg("/workspace");
            }
            cmd.args(&sandbox.extra_args).arg("--").arg(command);
            Ok(cmd)
        }
        SandboxMode::Firejail => {
            let mut cmd = Command::new("firejail");
            cmd.arg("--quiet");
            if !sandbox.allow_network {
                cmd.arg("--net=none");
            }
            if let Some(workspace) = &sandbox.workspace {
                cmd.arg(format!("--private={}", workspace.display()));
            }
            cmd.args(&sandbox.extra_args).arg("--").arg(command);
            Ok(cmd)
        }
        SandboxMode::Docker => {
            let image = sandbox
                .docker_image
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("docker sandbox requires docker_image"))?;
            let mut cmd = Command::new("docker");
            cmd.args(["run", "--rm", "-i"]);
            if !sandbox.allow_network {
                cmd.args(["--network", "none"]);
            }
            cmd.arg("--read-only");
            if let Some(workspace) = &sandbox.workspace {
                cmd.arg("-v")
                    .arg(format!("{}:/workspace:rw", workspace.display()))
                    .args(["-w", "/workspace"]);
            }
            for (key, value) in env {
                cmd.arg("-e").arg(format!("{key}={value}"));
            }
            cmd.args(&sandbox.extra_args).arg(image).arg(command);
            Ok(cmd)
        }
    }
}
