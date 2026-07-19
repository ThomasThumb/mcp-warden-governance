use crate::config::UpstreamConfig;
use anyhow::Result;
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SignerPublicKeys {
    pub ed25519_public_key_b64: String,
    pub ml_dsa_public_key_b64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenIntrospection {
    pub active: bool,
    pub agent_session_id: Option<String>,
    pub principal_id: Option<String>,
    pub gateway_id: Option<String>,
    pub server_id: Option<String>,
    pub tool_name: Option<String>,
    pub jti: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalState {
    pub id: String,
    pub status: String,
}

#[derive(Clone)]
pub struct CpClient {
    base_url: String,
    gateway_id: String,
    api_key: String,
    http: reqwest::Client,
}

impl CpClient {
    pub fn new(base_url: String, gateway_id: String, api_key: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| anyhow::anyhow!("building control-plane HTTP client: {e}"))?;
        Ok(Self {
            base_url,
            gateway_id,
            api_key,
            http,
        })
    }

    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// BUG FIXED (found in self-review, not by an external report): every
    /// call in this file used to go out with no Authorization header at
    /// all. That was fine right up until the auth middleware got added to
    /// warden-cp - at which point every one of these calls started silently
    /// failing with 401, and I didn't catch it in the same pass that added
    /// the auth. Adding auth to one side of an integration and not
    /// re-checking the other side is exactly the kind of gap a red team
    /// finds in ten seconds, so it's the first thing fixed here.
    fn authed(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(&self.api_key)
    }

    pub async fn register(
        &self,
        owner_principal_id: &str,
        version: &str,
        servers: &[UpstreamConfig],
    ) -> Result<()> {
        let upstreams: Vec<_> = servers
            .iter()
            .map(|s| {
                let transport = match &s.transport {
                    crate::config::Transport::Stdio { .. } => "stdio",
                    crate::config::Transport::Http { .. } => "http",
                };
                json!({ "server_id": s.id, "transport": transport })
            })
            .collect();

        let body = json!({
            "gateway_id": self.gateway_id,
            "owner_principal_id": owner_principal_id,
            "hostname": hostname(),
            "version": version,
            "upstreams": upstreams,
        });

        self.authed(
            self.http
                .post(format!("{}/v1/gateways/register", self.base_url)),
        )
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }

    pub async fn fetch_policy(&self, scope: &str) -> Result<Option<serde_json::Value>> {
        let resp = self
            .authed(
                self.http
                    .get(format!("{}/v1/policy/{}", self.base_url, scope)),
            )
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        let v: serde_json::Value = response_json_limited(resp, 4 * 1024 * 1024).await?;
        Ok(v.get("bundle").cloned())
    }

    pub async fn report_fingerprint(
        &self,
        server_id: &str,
        tool_name: &str,
        fingerprint: &str,
    ) -> Result<String> {
        let body = json!({
            "gateway_id": self.gateway_id,
            "server_id": server_id,
            "tool_name": tool_name,
            "fingerprint": fingerprint,
        });
        let resp = self
            .authed(
                self.http
                    .post(format!("{}/v1/tool-fingerprints", self.base_url)),
            )
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = response_json_limited(resp, 1024 * 1024).await?;
        Ok(v.get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("pending")
            .to_string())
    }

    pub async fn submit_audit(&self, events: &[serde_json::Value]) -> Result<()> {
        self.authed(self.http.post(format!("{}/v1/audit", self.base_url)))
            .json(events)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn fetch_signer_public_key(&self) -> Result<SignerPublicKeys> {
        let resp = self
            .authed(
                self.http
                    .get(format!("{}/v1/signer/public-key", self.base_url)),
            )
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = response_json_limited(resp, 1024 * 1024).await?;
        let ed25519_public_key_b64 = v
            .get("ed25519_public_key_b64")
            .and_then(|s| s.as_str())
            .map(ToString::to_string)
            .ok_or_else(|| {
                anyhow::anyhow!("control plane did not return ed25519_public_key_b64")
            })?;
        let ml_dsa_public_key_b64 = v
            .get("ml_dsa_public_key_b64")
            .and_then(|s| s.as_str())
            .map(ToString::to_string);
        Ok(SignerPublicKeys {
            ed25519_public_key_b64,
            ml_dsa_public_key_b64,
        })
    }

    pub async fn introspect_token(&self, token: &str) -> Result<TokenIntrospection> {
        let body = json!({ "token": token });
        let resp = self
            .authed(
                self.http
                    .post(format!("{}/v1/token/introspect", self.base_url)),
            )
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        response_json_limited(resp, 1024 * 1024).await
    }

    pub async fn create_approval(
        &self,
        agent_session_id: Option<&str>,
        server_id: &str,
        tool_name: &str,
        args_fingerprint: &str,
        risk_tier: &str,
    ) -> Result<ApprovalState> {
        let body = json!({
            "gateway_id": self.gateway_id,
            "agent_session_id": agent_session_id,
            "server_id": server_id,
            "tool_name": tool_name,
            "args_fingerprint": args_fingerprint,
            "risk_tier": risk_tier,
        });
        let resp = self
            .authed(self.http.post(format!("{}/v1/approvals", self.base_url)))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        response_json_limited(resp, 1024 * 1024).await
    }

    pub async fn consume_approval(&self, id: &str) -> Result<ApprovalState> {
        let resp = self
            .authed(
                self.http
                    .post(format!("{}/v1/approvals/{}/consume", self.base_url, id)),
            )
            .send()
            .await?
            .error_for_status()?;
        response_json_limited(resp, 1024 * 1024).await
    }
}

async fn response_json_limited<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("control-plane response exceeds the {limit}-byte limit");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            anyhow::bail!("control-plane response exceeds the {limit}-byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(Into::into)
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string())
}
