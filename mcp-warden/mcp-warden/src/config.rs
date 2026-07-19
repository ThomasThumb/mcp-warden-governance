use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_DEGRADED_MINUTES: i64 = 24 * 60;

#[derive(Debug, Deserialize, Clone)]
pub struct WardenConfig {
    #[serde(default)]
    pub servers: Vec<UpstreamConfig>,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub injection_filter: InjectionFilterConfig,
    #[serde(default)]
    pub control_plane: Option<ControlPlaneConfig>,
    /// Path to an org-authored Rego policy (see rego_policy.rs). Optional -
    /// omit it and every RequireApproval tool stays exactly that, no
    /// auto-approve path exists at all. This is deliberately opt-in.
    #[serde(default)]
    pub rego_policy_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ControlPlaneConfig {
    pub url: String,
    pub gateway_id: String,
    pub owner_principal_id: String,
    /// Environment variable containing the bearer token this gateway uses to
    /// authenticate to warden-cp. Keeping the secret out of TOML prevents it
    /// from being copied into source control or configuration backups.
    pub api_key_env: String,
    #[serde(default = "default_grace_minutes")]
    pub max_degraded_minutes: i64,
    /// Control-plane Ed25519 public key used to verify short-lived,
    /// per-tool-call agent tokens locally at the gateway. If omitted and the
    /// control plane is reachable at startup, the gateway fetches it from
    /// /v1/signer/public-key before serving.
    #[serde(default)]
    pub signer_public_key_b64: Option<String>,
    /// Control-plane ML-DSA-65 public key used to verify the hybrid
    /// post-quantum token signature. Fetched from /v1/signer/public-key when
    /// omitted and the control plane is reachable.
    #[serde(default)]
    pub ml_dsa_public_key_b64: Option<String>,
    /// Zero-trust default for new deployments: require both Ed25519 and
    /// ML-DSA-65 signatures on scoped tokens. Set false only during migration
    /// from an older control plane that cannot yet issue hybrid envelopes.
    #[serde(default = "default_true")]
    pub require_ml_dsa_token_signature: bool,
    /// Zero-trust default: when a control plane is configured, every tool call
    /// must carry a scoped token in `_meta.warden_token` (or, for older MCP
    /// clients, `arguments.__warden_token`, which is stripped before upstream).
    #[serde(default = "default_true")]
    pub require_agent_token: bool,
    /// Requires an Ed25519 proof-of-possession signature from the worker key
    /// bound into the token's `cnf` claim. This makes a stolen scoped token
    /// insufficient on its own.
    #[serde(default = "default_true")]
    pub require_agent_proof: bool,
    /// Ask the control plane to re-check each token id before forwarding the
    /// tool call. This enforces revocation and one-time `jti` semantics instead
    /// of relying only on the gateway's offline signature verification.
    #[serde(default = "default_true")]
    pub require_token_introspection: bool,
}

fn default_grace_minutes() -> i64 {
    60
}

pub fn default_state_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".mcp-warden")
}

/// How the gateway reaches a given upstream MCP server.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum Transport {
    /// Local server, spawned as a child process and spoken to over stdio.
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        /// Map child variable names to parent variable names. This is the
        /// preferred way to pass secrets: only explicitly named values cross
        /// the process boundary and the secret never appears in TOML.
        #[serde(default)]
        env_from: HashMap<String, String>,
        /// Optional local process sandbox wrapper. Use this for stdio servers
        /// that touch files, shells, browsers, or network-capable CLIs.
        #[serde(default)]
        sandbox: Option<SandboxConfig>,
    },
    /// Remote server reachable over JSON-RPC-over-HTTP. The gateway owns the
    /// upstream credential; it never forwards the host's bearer token.
    Http {
        url: String,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default)]
        oauth: Option<OAuthClientCredentials>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthClientCredentials {
    pub token_url: String,
    pub client_id_env: String,
    pub client_secret_env: String,
    /// RFC 8707 resource indicator. Set this to the exact upstream MCP
    /// resource URL/audience so a token for one upstream cannot be replayed
    /// against another.
    pub resource: String,
    #[serde(default = "default_oauth_scope")]
    pub scope: String,
}

fn default_oauth_scope() -> String {
    "mcp:call".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct SandboxConfig {
    #[serde(default)]
    pub mode: SandboxMode,
    /// Directory mounted as the worker workspace where supported.
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub allow_network: bool,
    /// Required for `mode = "docker"`.
    #[serde(default)]
    pub docker_image: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    #[default]
    None,
    Bubblewrap,
    Firejail,
    Docker,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    /// Short id used to namespace this server's tools, e.g. "github", "filesystem".
    pub id: String,
    #[serde(flatten)]
    pub transport: Transport,
    /// Risk tier applied to any tool from this server that isn't listed explicitly
    /// under `tools` below. Default is RequireApproval - zero trust by default.
    #[serde(default)]
    pub default_risk: RiskTier,
    #[serde(default)]
    pub tools: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Every call is queued for a human decision before it runs. The safe default.
    #[default]
    RequireApproval,
    /// Runs immediately, no confirmation. Reserve for genuinely read-only tools
    /// you've reviewed - e.g. "search_docs", not "delete_repo".
    ReadOnly,
    /// Never runs. The gateway returns an error to the host without touching upstream.
    Blocked,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ToolPolicy {
    #[serde(default)]
    pub risk: Option<RiskTier>,
    #[serde(default)]
    pub blocked: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InjectionFilterConfig {
    #[serde(default = "default_true")]
    pub scan_tool_descriptions: bool,
    #[serde(default = "default_true")]
    pub scan_results: bool,
    /// Number of heuristic rule hits before content is blocked outright rather
    /// than just flagged. Tune this once you've seen your own false-positive rate.
    #[serde(default = "default_threshold")]
    pub block_threshold: u32,
}

impl Default for InjectionFilterConfig {
    fn default() -> Self {
        Self {
            scan_tool_descriptions: true,
            scan_results: true,
            block_threshold: default_threshold(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_threshold() -> u32 {
    3
}

impl WardenConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path:?}: {e}"))?;
        let base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let cfg = Self::parse(&text, base_dir)?;
        secure_state_dir(&cfg.state_dir)?;
        Ok(cfg)
    }

    fn parse(text: &str, base_dir: &Path) -> anyhow::Result<Self> {
        let mut unknown = Vec::new();
        let deserializer = toml::Deserializer::new(text);
        let mut cfg: WardenConfig = serde_ignored::deserialize(deserializer, |path| {
            unknown.push(path.to_string());
        })?;
        if !unknown.is_empty() {
            unknown.sort();
            unknown.dedup();
            anyhow::bail!("unknown configuration field(s): {}", unknown.join(", "));
        }

        cfg.state_dir = resolve_config_path(&cfg.state_dir, base_dir)?;
        cfg.rego_policy_path = cfg
            .rego_policy_path
            .as_deref()
            .map(|path| resolve_config_path(path, base_dir))
            .transpose()?;

        let mut server_ids = HashSet::new();
        for server in &mut cfg.servers {
            validate_identifier("server id", &server.id)?;
            if !server_ids.insert(server.id.clone()) {
                anyhow::bail!("duplicate server id '{}'", server.id);
            }
            if let Transport::Stdio {
                command,
                env,
                env_from,
                sandbox,
                ..
            } = &mut server.transport
            {
                if command.trim().is_empty() {
                    anyhow::bail!("server '{}' has an empty stdio command", server.id);
                }
                for name in env.keys().chain(env_from.keys()).chain(env_from.values()) {
                    validate_env_name(name)?;
                }
                if let Some(duplicate) = env.keys().find(|name| env_from.contains_key(*name)) {
                    anyhow::bail!(
                        "server '{}' defines child environment variable '{}' in both env and env_from",
                        server.id,
                        duplicate
                    );
                }
                if let Some(sandbox) = sandbox {
                    sandbox.workspace = sandbox
                        .workspace
                        .as_deref()
                        .map(|path| resolve_config_path(path, base_dir))
                        .transpose()?;
                    if sandbox.mode == SandboxMode::Docker {
                        let image = sandbox.docker_image.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "server '{}' uses the docker sandbox without docker_image",
                                server.id
                            )
                        })?;
                        let Some((_, digest)) = image.rsplit_once("@sha256:") else {
                            anyhow::bail!(
                                "server '{}' docker_image must be pinned by sha256 digest",
                                server.id
                            );
                        };
                        if digest.len() != 64
                            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            anyhow::bail!(
                                "server '{}' docker_image has an invalid sha256 digest",
                                server.id
                            );
                        }
                    }
                }
            }
            if let Transport::Http {
                url,
                token_env,
                oauth,
            } = &server.transport
            {
                validate_secure_url("upstream URL", url)?;
                if let Some(token_env) = token_env {
                    validate_env_name(token_env)?;
                }
                if let Some(oauth) = oauth {
                    validate_secure_url("OAuth token URL", &oauth.token_url)?;
                    validate_env_name(&oauth.client_id_env)?;
                    validate_env_name(&oauth.client_secret_env)?;
                    if oauth.resource.trim().is_empty() {
                        anyhow::bail!("OAuth resource must not be empty");
                    }
                }
            }
        }

        if let Some(cp) = &cfg.control_plane {
            validate_secure_url("control-plane URL", &cp.url)?;
            validate_identifier("gateway id", &cp.gateway_id)?;
            validate_identifier("owner principal id", &cp.owner_principal_id)?;
            validate_env_name(&cp.api_key_env)?;
            if !(1..=MAX_DEGRADED_MINUTES).contains(&cp.max_degraded_minutes) {
                anyhow::bail!("max_degraded_minutes must be between 1 and {MAX_DEGRADED_MINUTES}");
            }
            if cp.require_agent_proof && !cp.require_token_introspection {
                anyhow::bail!(
                    "require_agent_proof=true requires require_token_introspection=true; \
                     proof-of-possession without one-time token introspection is replayable"
                );
            }
        }
        Ok(cfg)
    }

    pub fn control_plane_api_key(&self) -> anyhow::Result<Option<String>> {
        self.control_plane
            .as_ref()
            .map(|cp| {
                std::env::var(&cp.api_key_env).map_err(|_| {
                    anyhow::anyhow!(
                        "control-plane API key environment variable '{}' is not set",
                        cp.api_key_env
                    )
                })
            })
            .transpose()
    }
}

fn validate_identifier(label: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("{label} must be 1-128 ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_env_name(value: &str) -> anyhow::Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        anyhow::bail!("environment variable name must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!("invalid environment variable name '{value}'");
    }
    Ok(())
}

fn validate_secure_url(label: &str, value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|e| anyhow::anyhow!("invalid {label} '{value}': {e}"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("{label} must use HTTPS (HTTP is allowed only for loopback development)");
    }
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("{label} must not contain embedded credentials");
    }
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

fn resolve_config_path(path: &Path, base_dir: &Path) -> anyhow::Result<PathBuf> {
    let raw = path.to_string_lossy();
    let expanded = if raw == "~" {
        home_dir().ok_or_else(|| anyhow::anyhow!("cannot expand '~': HOME/USERPROFILE is unset"))?
    } else if raw.starts_with("~/") || raw.starts_with("~\\") {
        home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot expand '~': HOME/USERPROFILE is unset"))?
            .join(&raw[2..])
    } else if raw.starts_with('~') {
        anyhow::bail!("unsupported home-directory syntax '{raw}'");
    } else {
        path.to_path_buf()
    };
    Ok(if expanded.is_relative() {
        base_dir.join(expanded)
    } else {
        expanded
    })
}

fn secure_state_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_security_field() {
        let text = r#"
state_dir = "state"
[control_plane]
url = "https://cp.example.com"
gateway_id = "gateway-1"
owner_principal_id = "owner-1"
api_key_env = "CP_KEY"
require_agent_tokn = false
"#;
        let error = WardenConfig::parse(text, Path::new("C:/config"))
            .expect_err("misspelled security field must fail closed");
        assert!(error.to_string().contains("require_agent_tokn"));
    }

    #[test]
    fn resolves_relative_paths_and_rejects_insecure_remote_urls() {
        let text = r#"
state_dir = "state"
[[servers]]
id = "remote"
transport = "http"
url = "http://example.com/rpc"
"#;
        let error = WardenConfig::parse(text, Path::new("C:/config"))
            .expect_err("remote plaintext HTTP must fail closed");
        assert!(error.to_string().contains("HTTPS"));

        let text = text.replace("http://example.com", "http://127.0.0.1:7878");
        let config = WardenConfig::parse(&text, Path::new("C:/config")).unwrap();
        assert_eq!(config.state_dir, PathBuf::from("C:/config/state"));
    }

    #[test]
    fn rejects_duplicate_environment_sources() {
        let text = r#"
[[servers]]
id = "local"
transport = "stdio"
command = "server"
env = { TOKEN = "literal" }
env_from = { TOKEN = "SECRET_TOKEN" }
"#;
        let error = WardenConfig::parse(text, Path::new("."))
            .expect_err("ambiguous environment sources must fail closed");
        assert!(error.to_string().contains("both env and env_from"));
    }

    #[test]
    fn docker_sandbox_requires_an_immutable_image_digest() {
        let text = r#"
[[servers]]
id = "local"
transport = "stdio"
command = "server"
[servers.sandbox]
mode = "docker"
docker_image = "registry.example/worker:latest"
"#;
        let error = WardenConfig::parse(text, Path::new("."))
            .expect_err("mutable Docker tags must fail closed");
        assert!(error.to_string().contains("pinned by sha256 digest"));

        let digest = "a".repeat(64);
        let pinned = text.replace(
            "registry.example/worker:latest",
            &format!("registry.example/worker@sha256:{digest}"),
        );
        WardenConfig::parse(&pinned, Path::new(".")).unwrap();
    }
}
