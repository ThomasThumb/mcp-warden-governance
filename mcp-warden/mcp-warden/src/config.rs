use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    /// Bearer token this gateway authenticates to warden-cp with. Mint one
    /// via warden-cp's root key (or a per-gateway key once you build proper
    /// key issuance) - do NOT reuse the control plane's own signing key here,
    /// that's a different secret with a different purpose.
    pub api_key: String,
    #[serde(default = "default_grace_minutes")]
    pub max_degraded_minutes: i64,
    /// Control-plane Ed25519 public key used to verify short-lived,
    /// per-tool-call agent tokens locally at the gateway. If omitted and the
    /// control plane is reachable at startup, the gateway fetches it from
    /// /v1/signer/public-key before serving.
    #[serde(default)]
    pub signer_public_key_b64: Option<String>,
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
}

fn default_grace_minutes() -> i64 {
    60
}

fn default_state_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".mcp-warden")
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
    #[serde(default)]
    pub extra_args: Vec<String>,
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
        let cfg: WardenConfig = toml::from_str(&text)?;
        std::fs::create_dir_all(&cfg.state_dir)?;
        Ok(cfg)
    }
}
