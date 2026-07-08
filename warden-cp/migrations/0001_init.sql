-- Written to be portable across SQLite (default, small teams) and Postgres
-- (enterprise scale) - plain types, no backend-specific extensions. TEXT is
-- used for timestamps (RFC3339 strings) rather than native DATETIME so the
-- same schema and queries work unmodified on either backend.

CREATE TABLE IF NOT EXISTS principals (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,      -- 'human' | 'service'
    display_name    TEXT NOT NULL,
    external_id     TEXT,               -- SSO subject / email / service account id
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

-- Real authentication. Every write endpoint requires a valid, unrevoked key.
-- key_hash is sha256(raw key) - the raw key is shown exactly once, at
-- creation time, and never stored or logged in plaintext again.
CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES principals(id),
    key_hash        TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_id    TEXT NOT NULL REFERENCES principals(id),
    role            TEXT NOT NULL,      -- 'root_admin' | 'security_admin' | 'gateway_owner'
    PRIMARY KEY (principal_id, role)
);

CREATE TABLE IF NOT EXISTS principal_identities (
    provider            TEXT NOT NULL,  -- 'oidc' | 'scim'
    external_subject    TEXT NOT NULL,
    principal_id        TEXT NOT NULL REFERENCES principals(id),
    email               TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    PRIMARY KEY (provider, external_subject)
);

CREATE TABLE IF NOT EXISTS groups (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    external_id     TEXT,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id        TEXT NOT NULL REFERENCES groups(id),
    principal_id    TEXT NOT NULL REFERENCES principals(id),
    PRIMARY KEY (group_id, principal_id)
);

CREATE TABLE IF NOT EXISTS group_roles (
    group_id        TEXT NOT NULL REFERENCES groups(id),
    role            TEXT NOT NULL,      -- 'root_admin' | 'security_admin' | 'gateway_owner'
    PRIMARY KEY (group_id, role)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES principals(id),
    token_hash      TEXT NOT NULL UNIQUE,
    source          TEXT NOT NULL,      -- 'oidc'
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS oidc_login_states (
    state           TEXT PRIMARY KEY,
    nonce           TEXT NOT NULL,
    code_verifier   TEXT NOT NULL,
    return_to       TEXT,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

-- A per-agent, short-lived, cryptographically verifiable identity - the
-- "who is this specific agent session, delegated from which human" record.
-- spiffe_id follows the SPIFFE URI shape (warden://<trust-domain>/agent/<id>)
-- so this table can be pointed at real SPIRE-issued SVIDs later without a
-- schema change - just start populating spiffe_id from SPIRE instead of
-- minting it locally.
CREATE TABLE IF NOT EXISTS agent_sessions (
    id              TEXT PRIMARY KEY,
    spiffe_id       TEXT NOT NULL UNIQUE,
    principal_id    TEXT NOT NULL REFERENCES principals(id),
    purpose         TEXT,
    public_key_b64  TEXT NOT NULL,      -- agent's own keypair, for token binding (cnf-style)
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS gateways (
    id                  TEXT PRIMARY KEY,
    owner_principal_id  TEXT NOT NULL REFERENCES principals(id),
    hostname            TEXT NOT NULL,
    version             TEXT NOT NULL,
    last_heartbeat_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upstream_inventory (
    gateway_id      TEXT NOT NULL REFERENCES gateways(id),
    server_id       TEXT NOT NULL,
    transport       TEXT NOT NULL,
    reported_at     TEXT NOT NULL,
    PRIMARY KEY (gateway_id, server_id)
);

-- Fleet-wide generalization of the single-gateway integrity.rs hash pinning:
-- the same tool on the same server, reported by different gateways, should
-- fingerprint identically. If it doesn't, that's drift worth flagging even if
-- each individual gateway thinks its own copy is "approved".
CREATE TABLE IF NOT EXISTS tool_fingerprints (
    gateway_id      TEXT NOT NULL,
    server_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    status          TEXT NOT NULL,      -- 'approved' | 'pending'
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    PRIMARY KEY (gateway_id, server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS policy_bundles (
    id              TEXT PRIMARY KEY,
    scope           TEXT NOT NULL,      -- a gateway id, or a client/app label
    version         INTEGER NOT NULL,
    bundle_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL REFERENCES principals(id)
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id                  TEXT PRIMARY KEY,
    gateway_id          TEXT NOT NULL,
    agent_session_id    TEXT REFERENCES agent_sessions(id),
    server_id           TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    args_fingerprint    TEXT NOT NULL,
    risk_tier           TEXT NOT NULL,
    status              TEXT NOT NULL,  -- 'pending' | 'approved' | 'denied' | 'expired'
    requested_at        TEXT NOT NULL,
    decided_at          TEXT,
    decided_by          TEXT REFERENCES principals(id),
    reason              TEXT
);

-- The "who, what, when, where" ledger. principal_id and agent_session_id
-- together give you the full delegation chain (mirrors the `act` claim
-- pattern from OAuth 2.0 Token Exchange, RFC 8693) for every single call.
-- entry_hash = sha256(prev_hash || canonical event fields) - a tamper-evident
-- chain: editing or deleting any past row breaks every entry_hash after it.
-- Caveat, stated plainly: this chain is maintained by a single in-process
-- mutex (see main.rs) and only guarantees tamper-evidence for a single
-- warden-cp instance. A multi-replica HA deployment needs a different
-- chaining strategy (per-shard chains, or an external append-only log) -
-- that's on the backlog, not solved here.
CREATE TABLE IF NOT EXISTS audit_events (
    id                  TEXT PRIMARY KEY,
    ts                  TEXT NOT NULL,
    gateway_id          TEXT NOT NULL,      -- where
    agent_session_id    TEXT,                -- who (agent)
    principal_id        TEXT,                -- who (human, via delegation)
    server_id           TEXT NOT NULL,       -- where (upstream)
    tool_name           TEXT NOT NULL,       -- what
    decision            TEXT NOT NULL,
    args_fingerprint    TEXT NOT NULL,
    injection_flags     TEXT NOT NULL,       -- JSON array, stored as text for portability
    result_bytes        INTEGER,
    prev_hash           TEXT NOT NULL,
    entry_hash          TEXT NOT NULL
);

-- Per-scope, org-authored Rego policy (see mcp-warden's rego_policy.rs for
-- how it's enforced). Versioned so you can see who changed what auto-approve
-- rule and when - that history is itself a compliance artifact.
CREATE TABLE IF NOT EXISTS org_policies (
    id              TEXT PRIMARY KEY,
    scope           TEXT NOT NULL,
    version         INTEGER NOT NULL,
    rego_source     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL REFERENCES principals(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_principal_roles_role ON principal_roles(role);
CREATE INDEX IF NOT EXISTS idx_principal_identities_principal ON principal_identities(principal_id);
CREATE INDEX IF NOT EXISTS idx_group_members_principal ON group_members(principal_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_role ON group_roles(role);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash ON auth_sessions(token_hash);
