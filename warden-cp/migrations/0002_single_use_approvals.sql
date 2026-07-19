ALTER TABLE approval_requests ADD COLUMN used_at TEXT;

-- Earlier gateways created a new row on every retry. Preserve the newest open
-- request and expire older duplicates before installing the invariant.
UPDATE approval_requests
SET status = 'expired'
WHERE status IN ('pending', 'approved')
  AND EXISTS (
      SELECT 1
      FROM approval_requests AS newer
      WHERE newer.status IN ('pending', 'approved')
        AND newer.gateway_id = approval_requests.gateway_id
        AND COALESCE(newer.agent_session_id, '') = COALESCE(approval_requests.agent_session_id, '')
        AND newer.server_id = approval_requests.server_id
        AND newer.tool_name = approval_requests.tool_name
        AND newer.args_fingerprint = approval_requests.args_fingerprint
        AND newer.risk_tier = approval_requests.risk_tier
        AND (
            newer.requested_at > approval_requests.requested_at
            OR (newer.requested_at = approval_requests.requested_at AND newer.id > approval_requests.id)
        )
  );

-- At most one pending/approved request can exist for the same exact call.
-- COALESCE makes the optional agent-session component compare consistently
-- on SQLite and Postgres, where NULL values are otherwise all distinct.
CREATE UNIQUE INDEX idx_approvals_open_call
ON approval_requests (
    gateway_id,
    COALESCE(agent_session_id, ''),
    server_id,
    tool_name,
    args_fingerprint,
    risk_tier
)
WHERE status IN ('pending', 'approved');
