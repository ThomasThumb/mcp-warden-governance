use crate::models::ApprovalRequest;
use serde_json::json;

/// KISS on purpose: rather than building separate Slack/email/dashboard
/// integrations, there's exactly one mechanism - POST a JSON blob to a
/// configured URL - and every "channel" is just a different receiver of that
/// same POST:
///   - Slack: paste a Slack "Incoming Webhook" URL into WEBHOOK_URL. Slack's
///     webhook endpoint accepts a `{"text": "..."}` body directly.
///   - A web dashboard: point WEBHOOK_URL at your own ingestion endpoint,
///     which is free to store it, push it over websockets, whatever.
///   - CLI-only: leave WEBHOOK_URL unset. `mcp-warden-cp approvals list` /
///     `approve` hit the same GET/POST /v1/approvals endpoints directly -
///     there's nothing extra to stand up.
pub struct Notifier {
    webhook_url: Option<String>,
    client: reqwest::Client,
}

impl Notifier {
    pub fn new(webhook_url: Option<String>) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn notify_pending(&self, req: &ApprovalRequest) {
        let Some(url) = &self.webhook_url else {
            return; // CLI-only mode - nothing to push
        };
        let text = format!(
            "mcp-warden approval needed: {}::{} on gateway {} (risk: {}). \
             Decide: POST /v1/approvals/{}/decide",
            req.server_id, req.tool_name, req.gateway_id, req.risk_tier, req.id
        );
        // Slack-compatible body ({"text": ...}); a custom dashboard endpoint
        // can just read whichever field it cares about and ignore the rest.
        let body = json!({ "text": text, "approval": req });
        if let Err(e) = self.client.post(url).json(&body).send().await {
            tracing::warn!(error = %e, "failed to deliver approval notification");
        }
    }
}
