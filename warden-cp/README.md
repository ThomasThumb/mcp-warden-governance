# warden-cp

The control plane for `mcp-warden`. Gateways (data plane, one per machine)
register here; this is where policy, identity, drift, and approvals actually
live.

## What this gives you, mapped to what you asked for

- **Inventory** - `POST /v1/gateways/register`: which gateways exist, who
  owns them, which upstream servers each one reports running.
- **Allowlists + drift** - `POST /v1/tool-fingerprints`: every gateway
  reports each tool's hash on every connect; a changed hash flips back to
  `pending` fleet-wide, not just on the one machine that happened to see it.
- **Scoped auth** - `POST /v1/agent-sessions` mints a short-lived,
  SPIFFE-shaped identity per agent session, delegated from a human/service
  principal; `POST /v1/token` issues a token scoped to exactly one
  (gateway, server, tool) triple with a delegation-chain (`act`) claim - see
  "Identity model" below.
- **Audit + approvals** - `POST /v1/audit` ingests the who/what/when/where
  ledger; `POST /v1/approvals` + `GET/POST /v1/approvals/:id` is the
  step-up-approval workflow, KISS-notified (see `notify.rs`).
- **Admin/security visibility** - root can create non-root principals and
  API keys, revoke keys, and read summary, gateway, session, fingerprint, and
  audit-event views without connecting directly to the database.

## Identity model

Every call gets attributed to two things, not one:
- `agent_sessions.spiffe_id` - *which agent session* made the call
  (`spiffe://<trust-domain>/agent/<uuid>`, short-lived, its own keypair)
- the `act` claim inside the issued token - *which human or service
  principal* authorized that agent session to exist

This mirrors OAuth 2.0 Token Exchange's actor-chain pattern (RFC 8693) and
the SPIFFE ID shape on purpose. Neither is fully wired to the real
ecosystem tools yet in this v0.1:
- Real SPIFFE/SPIRE would replace `mint_agent_session`'s local minting with
  actual SVID issuance - the column stays `spiffe_id`, only the issuer changes.
- A real OAuth Token Exchange endpoint would replace `issue_token`'s
  hand-rolled signing - the `act` claim shape carries over.

Point being: adopting the real infrastructure later is a swap, not a
rewrite, because the identifiers and claims are already shaped like it.

## Storage: SQLite for dev, Postgres for production

Use SQLite for local development, single-machine demos, and throwaway tests.
Use Postgres for anything you care about: multiple gateways, durable audit
history, backups, reporting, HA planning, or admin/security review.

`DATABASE_URL=sqlite://warden-cp.db` (default) or
`DATABASE_URL=postgres://user:pass@host/db` - same code path either way via
sqlx's `Any` driver. The honest tradeoff: hand-written SQL instead of sqlx's
`query!` compile-time checking. Once Postgres is the only production backend,
split `db.rs` into a real repository trait with a Postgres-specific
implementation to get compile-time-checked queries and database-native
migrations back. The handler code in `routes.rs` should not need to change.

### Postgres quick start

The repo includes a minimal Postgres deployment under `deploy/postgres/`.
It keeps both Postgres and `warden-cp` bound to localhost by default.

```bash
cd deploy/postgres
cp .env.example .env
# edit POSTGRES_PASSWORD, TRUST_DOMAIN, and WARDEN_CP_BIND as needed
docker compose --env-file .env up --build
```

For non-local deployment, put `warden-cp` behind a TLS 1.3 reverse proxy or
private network ingress. Prefer a provider/stack with hybrid ML-KEM key
establishment where available. Postgres should be backed up with normal
database tooling (`pg_dump`, managed-service PITR, or storage snapshots) and
monitored like production security infrastructure.

TLS/private-ingress examples live in `deploy/caddy/`. The Caddy example keeps
`warden-cp` on localhost behind HTTPS and documents the Go TLS hybrid
ML-KEM behavior to verify in your chosen Caddy build.

## PQC posture

Ed25519 signing is real and wired up today (`identity.rs`). It authenticates
short-lived scoped tokens, but it is not a post-quantum signature. The hybrid
ML-DSA (FIPS 204) slot is intentionally not guessed at: adding it for real
means pulling in a vetted ML-DSA implementation, checking current
side-channel advisories, and requiring both Ed25519 and ML-DSA signatures to
verify during the migration window.

For "harvest now, decrypt later" risk, transport confidentiality is the
priority. Use a TLS 1.3 reverse proxy or TLS provider that supports a
NIST-standard or standards-track hybrid classical + ML-KEM key exchange
(FIPS 203). Do not hand-roll KEM combiners in this service. Data at rest
should be protected by a real database/volume/vault encryption layer using
strong symmetric encryption; PQC mainly changes asymmetric key establishment
and signatures.

## Security hardening (this round)

Two holes from v0.1 are fixed:
- **Every endpoint now requires `Authorization: Bearer <key>`.** First run
  prints a root key once (`auth.rs::bootstrap_root_key_if_needed`) - save it,
  it can't be recovered, only revoked. `decide_approval`'s `decided_by` now
  comes from that authenticated identity, not a field in the request body.
- **The signing key persists** (`SIGNING_KEY_PATH`, default
  `warden-cp-signing.key`, written with 0600 permissions on Unix). Restarting
  the service no longer invalidates every token it's ever issued.

Plus: agent-session revocation (`POST /v1/agent-sessions/:id/revoke`),
hash-chained audit log with a verify endpoint (`GET /v1/audit/verify`), a
coarse fixed-window rate limiter on write endpoints, and org-authored Rego
policy storage/versioning (`PUT/GET /v1/org-policy/:scope` - the enforcement
side lives in `mcp-warden`'s `rego_policy.rs`, this is just the source of
truth and version history).

See `COMPLIANCE.md` for how these map to SOC 2 / ISO 42001 / EU AI Act.

## Explicit gaps - not built, not pretended

- **No TLS.** `axum::serve` here is plain HTTP. Bearer tokens, approval
  decisions, and Rego policy source all cross the wire in the clear the
  moment `BIND_ADDR` is anything other than localhost. This is arguably the
  single most urgent gap in the whole system once you have gateways on a
  different machine than the control plane - terminate TLS in front of this,
  and prefer hybrid ML-KEM key establishment where your TLS stack supports it.
  Not implemented here because certificate management is a deployment
  decision, not something to guess at blind.
- **Coarse RBAC, not enterprise IAM.** Non-root principals and API keys are
  now real, with owner-scoped access for gateways, sessions, approvals,
  policy, fingerprints, and audit reads. Root-admin can create principals,
  keys, and assign coarse roles. What is not here yet: SSO/OIDC login,
  per-scope delegated administrators, or SCIM lifecycle sync.
- **Secrets vault for local server credentials.** Nothing in this round
  touches the fact that a GitHub PAT sitting in a stdio server's env var on
  the gateway machine is still a plaintext secret on that machine. This is a
  deployment-specific decision (HashiCorp Vault vs. OS keychain vs. cloud
  KMS) that needs to be made deliberately, not defaulted.
- **Backup/DR automation.** Postgres is now the recommended production
  backend and a compose deployment is included, but backup schedules,
  restore drills, retention rules, and managed-service PITR are still
  operator responsibilities.
- **Approval fatigue, longer-term.** The Rego auto-approve mechanism helps
  today. If a team is still drowning in approvals six months in, that's a
  signal to write narrower Rego rules for the specific noisy tools, not to
  raise the default risk tier globally.

## Setup

```bash
# Same toolchain note as mcp-warden: needs Rust 1.85+ (edition 2024).
# Unlike rmcp, everything here (axum, sqlx, ed25519-dalek) is a mainstream,
# slow-moving crate, so `cargo check` should need little to no adjustment -
# the risk profile here is much lower than the gateway's rmcp dependency.

export DATABASE_URL="sqlite://warden-cp.db"
export BIND_ADDR="127.0.0.1:7878"
export TRUST_DOMAIN="acme.corp"
export SIGNING_KEY_PATH="warden-cp-signing.key"   # back this file up - see below
export APPROVAL_WEBHOOK_URL="https://hooks.slack.com/services/..."  # optional, omit for CLI-only

cargo run
# First run prints a root API key ONCE. Every request after that needs:
#   curl -H "Authorization: Bearer <key>" http://localhost:7878/v1/...
```

First thing it logs is the Ed25519 public key. Gateways can either fetch it
from `/v1/signer/public-key` at startup or pin it in `warden.toml` as
`control_plane.signer_public_key_b64` for degraded/offline verification.

## Admin/API key quick start

Root creates non-root principals and API keys; raw keys are returned once:

```bash
curl -H "Authorization: Bearer $ROOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind":"service","display_name":"gateway-laptop-jane"}' \
  http://localhost:7878/v1/principals

curl -H "Authorization: Bearer $ROOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"<principal-id>"}' \
  http://localhost:7878/v1/api-keys

curl -X PUT -H "Authorization: Bearer $ROOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"roles":["gateway_owner"]}' \
  http://localhost:7878/v1/principals/<principal-id>/roles
```

Security/admin visibility endpoints:

- `GET /v1/admin/summary`
- `GET /admin`
- `GET /v1/gateways`
- `GET /v1/agent-sessions`
- `GET /v1/tool-fingerprints`
- `GET /v1/approvals?status=pending`
- `GET /v1/audit/events?limit=100&gateway_id=<id>`
- `GET /v1/audit/export?limit=500`
- `GET /v1/security/anomalies?limit=100`

Backup/restore helpers:

- `scripts/backup_postgres.ps1`
- `scripts/restore_postgres.ps1`
- `scripts/verify_restore.ps1`

## NullClaw worker integration

NullClaw can be used as a lightweight autonomous worker, but not as the
authority layer. Register each NullClaw instance as its own service principal
and agent session, issue short-lived scoped tokens through `warden-cp`, and
force tool calls through `mcp-warden`. That gives each worker a revocation
path and keeps `warden-cp` as the source of truth for audit and approvals.

The gateway-side setup guide lives in the `mcp-warden` checkout at
`integrations/nullclaw/README.md`.

NullClaw attribution: NullClaw is an external MIT-licensed project by the
nullclaw contributors. See `THIRD_PARTY_NOTICES.md`.

## Roadmap

1. OIDC/SSO and SCIM lifecycle sync on top of the role model.
2. Real SPIRE integration behind the `agent_sessions` table.
3. Real ML-DSA hybrid signing once the crate's had more runway post-advisory.
4. Richer dashboard workflows for approval decisions and policy editing.
