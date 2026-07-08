use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(dead_code)] // Reserved for principal listing/detail APIs and admin dashboard views.
pub struct Principal {
    pub id: String,
    pub kind: String, // "human" | "service"
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreatePrincipalRequest {
    pub kind: String,
    pub display_name: String,
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateApiKeyRequest {
    pub principal_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SetPrincipalRolesRequest {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CreatedApiKey {
    pub id: String,
    pub principal_id: String,
    pub raw_key: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentSession {
    pub id: String,
    pub spiffe_id: String,
    pub principal_id: String,
    pub purpose: Option<String>,
    pub public_key_b64: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct GatewayInventory {
    pub id: String,
    pub owner_principal_id: String,
    pub hostname: String,
    pub version: String,
    pub last_heartbeat_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ToolFingerprintView {
    pub gateway_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub fingerprint: String,
    pub status: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditEventView {
    pub id: String,
    pub ts: String,
    pub gateway_id: String,
    pub agent_session_id: Option<String>,
    pub principal_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub decision: String,
    pub args_fingerprint: String,
    pub injection_flags: Vec<String>,
    pub result_bytes: Option<i64>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AdminSummary {
    pub principals: i64,
    pub gateways: i64,
    pub active_agent_sessions: i64,
    pub revoked_agent_sessions: i64,
    pub pending_approvals: i64,
    pub pending_tool_fingerprints: i64,
    pub audit_events: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct SecurityAnomaly {
    pub severity: String,
    pub kind: String,
    pub description: String,
    pub ts: String,
    pub gateway_id: String,
    pub agent_session_id: Option<String>,
    pub principal_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegisterGatewayRequest {
    pub gateway_id: String,
    pub owner_principal_id: String,
    pub hostname: String,
    pub version: String,
    pub upstreams: Vec<UpstreamReport>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamReport {
    pub server_id: String,
    pub transport: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolFingerprintReport {
    pub gateway_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ToolFingerprintDecision {
    pub status: String, // "approved" | "pending"
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyBundle {
    pub scope: String,
    pub version: i64,
    /// Same shape as mcp-warden's local warden.toml `[servers.tools.*]`
    /// entries, just centrally authored and versioned instead of a local file.
    pub bundle: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateApprovalRequest {
    pub gateway_id: String,
    pub agent_session_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub args_fingerprint: String,
    pub risk_tier: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub gateway_id: String,
    pub agent_session_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub args_fingerprint: String,
    pub risk_tier: String,
    pub status: String,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DecideApprovalRequest {
    pub approved: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditEventIn {
    pub gateway_id: String,
    pub agent_session_id: Option<String>,
    pub principal_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub decision: String,
    pub args_fingerprint: String,
    pub injection_flags: Vec<String>,
    pub result_bytes: Option<i64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MintAgentSessionRequest {
    pub principal_id: String,
    pub purpose: Option<String>,
    pub public_key_b64: String,
    pub ttl_minutes: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IssueTokenRequest {
    pub agent_session_id: String,
    pub gateway_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct IssuedToken {
    pub token: String, // header.payload.signature, base64url each segment
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SetOrgPolicyRequest {
    pub rego_source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrgPolicy {
    pub scope: String,
    pub version: i64,
    pub rego_source: String,
}
