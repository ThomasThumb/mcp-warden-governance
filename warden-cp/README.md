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
  (gateway, server, tool) triple with a delegation-chain (`act`) claim and a
  one-time token id - see "Identity model" below.
- **Audit + approvals** - `POST /v1/audit` ingests the who/what/when/where
  ledger with hash chaining plus signed checkpoints; `POST /v1/approvals` +
  `GET/POST /v1/approvals/:id` is the step-up-approval workflow,
  KISS-notified (see `notify.rs`). Approved requests are atomically consumed
  before the gateway calls an upstream, so one approval cannot be replayed.
- **Admin/security visibility** - root can create non-root principals and
  API keys, revoke keys, and read summary, gateway, session, fingerprint, and
  audit-event views without connecting directly to the database.
- **Enterprise identity hooks** - OIDC Authorization Code + PKCE login can
  mint expiring bearer sessions, and SCIM 2.0 Users/Groups can lifecycle-sync
  principals and group membership.

## Identity model

Every call gets attributed to two things, not one:
- `agent_sessions.spiffe_id` - *which agent session* made the call
  (`spiffe://<trust-domain>/agent/<uuid>`, short-lived, its own keypair)
- the `act` claim inside the issued token - *which human or service
  principal* authorized that agent session to exist

This mirrors OAuth 2.0 Token Exchange's actor-chain pattern (RFC 8693) and
the SPIFFE ID shape on purpose.
- OIDC login maps verified ID-token subjects into `principal_identities` and
  can sync group claims into `groups`/`group_members`.
- SCIM lifecycle sync can create, update, deactivate, and group users; a
  deactivated principal has API keys, OIDC sessions, and agent sessions
  revoked.
- Real SPIFFE/SPIRE would replace `mint_agent_session`'s local minting with
  actual SVID issuance - the column stays `spiffe_id`, only the issuer changes.
- A real OAuth Token Exchange endpoint could still replace `issue_token`'s
  local scoped-token endpoint later - the `act` claim shape carries over.

Point being: adopting the real infrastructure later is a swap, not a
rewrite, because the identifiers and claims are already shaped like it.

## Storage: SQLite for dev, Postgres for production

Use SQLite for local development, single-machine demos, and throwaway tests.
Use Postgres for anything you care about: multiple gateways, durable audit
history, backups, reporting, HA planning, or admin/security review.

The binary is built for exactly one SQL backend at a time. The default feature
is SQLite for local development:

```bash
DATABASE_URL=sqlite://warden-cp.db cargo run
```

Production builds should use the Postgres feature:

```bash
DATABASE_URL=postgres://user:pass@host/db \
  cargo run --no-default-features --features postgres
```

This is deliberate. SQLx's runtime `Any` driver resolves unused optional
drivers into `Cargo.lock`, which makes dependency-audit output noisy and less
trustworthy. Feature-specific builds keep the lockfile and binary surface to
SQLite/Postgres only; MySQL/RSA is not pulled in.

### Postgres quick start

The repo includes a minimal Postgres deployment under `deploy/postgres/`.
It keeps Postgres on an internal-only network and binds `warden-cp` to
localhost by default. The deployment preserves PostgreSQL 17 data compatibility
while compiling out unused XML/XSLT support and rebuilding its small `gosu`
privilege-drop helper with a fixed, digest-pinned Go toolchain. PostgreSQL's
source archive is checksum-verified; CI scans both resulting images and fails
on any vulnerability or embedded secret.

```bash
cd deploy/postgres
cp .env.example .env
# edit POSTGRES_PASSWORD, TRUST_DOMAIN, WARDEN_CP_BIND, and signer settings
docker compose --env-file .env up --build
```

For non-local deployment, run `warden-cp` with built-in TLS or keep it bound
to localhost behind a TLS 1.3 reverse proxy/private ingress. The binary refuses
non-loopback plaintext binds unless `WARDEN_CP_ALLOW_INSECURE_NON_LOOPBACK=true`
is set explicitly for a trusted private test network. Prefer a provider/stack
with hybrid ML-KEM key establishment where available. Postgres should be backed
up with normal database tooling (`pg_dump`, managed-service PITR, or storage
snapshots) and monitored like production security infrastructure.

TLS/private-ingress examples live in `deploy/caddy/`. The Caddy example keeps
`warden-cp` on localhost behind HTTPS and documents the Go TLS hybrid
ML-KEM behavior to verify in your chosen Caddy build.

### Transport encryption and HTTPS enforcement

Local development can use plaintext loopback:

```bash
export BIND_ADDR="127.0.0.1:7878"
```

Production should use built-in Rustls TLS:

```bash
export BIND_ADDR="0.0.0.0:7878"
export TLS_CERT_PATH="/etc/warden-cp/tls/fullchain.pem"
export TLS_KEY_PATH="/etc/warden-cp/tls/privkey.pem"
export WARDEN_CP_REQUIRE_HTTPS=true
```

Or terminate HTTPS at a trusted local reverse proxy:

```bash
export BIND_ADDR="127.0.0.1:7878"
export WARDEN_CP_REQUIRE_HTTPS=true
export WARDEN_CP_TRUST_PROXY_HEADERS=true
```

When `WARDEN_CP_REQUIRE_HTTPS=true`, requests must arrive over built-in TLS or
carry trusted reverse-proxy `Forwarded: proto=https` / `X-Forwarded-Proto:
https` metadata. Only enable `WARDEN_CP_TRUST_PROXY_HEADERS` when direct client
traffic cannot reach `warden-cp`; otherwise a client could spoof those headers.

## Verification

Run the dependency/build checks without advisory ignores:

```powershell
.\scripts\verify_audit_clean.ps1
```

That checks the default SQLite control-plane build, the production Postgres
control-plane build, raw `cargo audit` for `warden-cp`, and raw `cargo audit`
for the gateway.

Run the concrete Caddy hybrid-PQ TLS proof:

```powershell
.\scripts\verify_caddy_hybrid_pq_tls.ps1
```

The proof starts a disposable Caddy container, uses a Go 1.26 client restricted
to `X25519MLKEM768`, and fails unless the negotiated TLS group is exactly
`X25519MLKEM768`.

Supply-chain CI and release provenance are documented in the repository root
`SUPPLY_CHAIN.md`. Release images should be verified with GitHub artifact
attestations, Sigstore/cosign, and SLSA provenance before deployment.

### Audit anchoring and rollback detection

New audit rows are signed and hash-chained in the database. To detect database
rollback/truncation, publish each signed high-water mark to storage that
`warden-cp` cannot rewrite:

```bash
export AUDIT_ANCHOR_FILE="/mnt/worm/warden-cp/audit-anchor.jsonl"
export AUDIT_ANCHOR_REQUIRED="true"
```

`AUDIT_ANCHOR_FILE` is append-only JSONL. Put it on WORM/object-lock storage,
a protected remote mount, or another append-only sink; a normal local file on
the same compromised host is only operational evidence, not a hard boundary.
When `AUDIT_ANCHOR_REQUIRED=true`, `/v1/audit/verify` requires the latest
anchor to match the current DB tail and audit ingest fails closed if anchoring
cannot be written.

For production WORM/object-lock anchoring, prefer `AUDIT_ANCHOR_COMMAND`.
The command adapter contract and an S3 Object Lock adapter are documented in
`docs/external-integrations.md`.

Existing pre-v2 audit rows are sealed once at startup in `audit_legacy_seals`.
If legacy rows exist and the seal no longer matches, `/v1/audit/verify` fails.

Ed25519 signs every audit row. By default, ML-DSA-65 also signs every audit
row when the ML-DSA signer is configured:

```bash
export AUDIT_ML_DSA_CHECKPOINT_INTERVAL=1
```

Raise the interval only for very high-volume deployments where you have
accepted periodic PQ checkpoints and also publish to an external anchor.

## PQC posture

Scoped tokens are hybrid signed by default: Ed25519 remains the mature
classical anchor, and ML-DSA-65 adds the FIPS 204 post-quantum signature.
Gateways should require both signatures during the migration window. The
implementation uses RustCrypto `ml-dsa`; its upstream docs still warn that
the crate has not been independently audited, so do not remove Ed25519 or
treat ML-DSA as your sole trust anchor yet.

For production key custody, set `WARDEN_SIGNER_COMMAND` and keep the Ed25519
and ML-DSA private keys in KMS, HSM, Vault Transit, PKCS#11, Windows
CNG/DPAPI, or another managed key boundary. The command protocol is documented
in `docs/external-integrations.md`; `warden-cp` verifies returned signatures
against configured public keys before accepting them. Also set
`WARDEN_REQUIRE_EXTERNAL_SIGNER=true` so a missing or incomplete external
signer fails startup before database bootstrap and can never fall back to
generating local keys. Strict mode requires both Ed25519 and ML-DSA-65. The
production container image enables strict mode by default; local binary
development does not. The Postgres-only production build also defaults to
strict mode when run outside the container.

For "harvest now, decrypt later" risk, transport confidentiality is the
priority. Use a TLS 1.3 reverse proxy or TLS provider that supports a
NIST-standard or standards-track hybrid classical + ML-KEM key exchange
(FIPS 203). Do not hand-roll KEM combiners in this service. Data at rest
should be protected by a real database/volume/vault encryption layer using
strong symmetric encryption; PQC mainly changes asymmetric key establishment
and signatures.

## Security hardening (this round)

Key holes from v0.1 are fixed:
- **Every control-plane API endpoint requires `Authorization: Bearer <key>`.**
  The static admin shell and OIDC login/callback must remain reachable before
  API authentication, but they expose no protected API data. First run prints
  a root key once (`auth.rs::bootstrap_root_key_if_needed`) - save it; it can't
  be recovered, only revoked. `decide_approval`'s `decided_by` now comes from
  that authenticated identity, not a field in the request body.
- **The signing key persists for local dev** (`SIGNING_KEY_PATH`, default
  `warden-cp-signing.key`, written with owner-only permissions). Production
  should set both `WARDEN_SIGNER_COMMAND` and
  `WARDEN_REQUIRE_EXTERNAL_SIGNER=true` so private signing keys stay outside
  the process in a KMS/HSM/OS-keystore-backed adapter and startup fails closed.
- **Scoped tokens are signed as protected envelopes.** The signed input now
  includes the token header, algorithm, key IDs, audience, `nbf`, `jti`, and
  payload. Gateways use strict Ed25519 verification and require ML-DSA-65 by
  default.
- **Token IDs are online-checked.** `/v1/token/introspect` verifies the
  envelope, enforces agent-session revocation/expiry, and marks the token id
  used so replayed calls fail closed.
- **Audit rows are canonicalized and signed.** New audit rows use
  domain-separated, length-prefixed hashing with a monotonic sequence number
  and a control-plane-signed checkpoint. `/v1/audit/verify` streams rows and
  verifies both the chain and the signatures.
- **Transport now has explicit HTTPS controls.** `warden-cp` supports built-in
  Rustls TLS and can require HTTPS either directly or through trusted
  reverse-proxy headers.

Plus: agent-session revocation (`POST /v1/agent-sessions/:id/revoke`),
hash-chained audit log with a verify endpoint (`GET /v1/audit/verify`), a
sliding-window rate limiter on write endpoints, and org-authored Rego
policy storage/versioning (`PUT/GET /v1/org-policy/:scope` - the enforcement
side lives in `mcp-warden`'s `rego_policy.rs`, this is just the source of
truth and version history).

OIDC/SSO:

```bash
export OIDC_ISSUER_URL="https://idp.example.com"
export OIDC_CLIENT_ID="warden-cp"
export OIDC_CLIENT_SECRET="..."
export OIDC_REDIRECT_URL="https://warden-cp.example.com/oidc/callback"
export OIDC_ALLOWED_EMAIL_DOMAINS="example.com"
export OIDC_DEFAULT_ROLES="security_admin"
```

Then open `/oidc/login`. The callback verifies issuer, audience, expiry,
nonce, and the provider JWKS before creating an expiring `warden_session_*`
bearer token.

SCIM:

- `GET /scim/v2/ServiceProviderConfig`
- `GET/POST /scim/v2/Users`
- `GET/PUT/PATCH/DELETE /scim/v2/Users/:id`
- `GET/POST /scim/v2/Groups`
- `GET/PUT/PATCH/DELETE /scim/v2/Groups/:id`

SCIM endpoints require a bearer token whose principal has `root_admin` or
`security_admin`, either directly or through group role inheritance.

See `COMPLIANCE.md` for how these map to SOC 2 / ISO 42001 / EU AI Act.

## Explicit gaps - not built, not pretended

- **No built-in TLS.** `axum::serve` here is plain HTTP and refuses
  non-loopback binds by default. For anything beyond same-host development,
  terminate TLS in front of this and prefer hybrid ML-KEM key establishment
  where your TLS stack supports it. Certificate management is still a
  deployment decision, not something this binary guesses at blind.
- **OIDC/SCIM are protocol plumbing, not IdP magic.** OIDC login and SCIM
  Users/Groups are implemented, including group-backed role inheritance and
  lifecycle revocation. You still need to configure the IdP app, redirect URI,
  SCIM bearer principal, group-role mapping, and offboarding policy.
- **Secrets vault for local server credentials.** Nothing in this round
  touches the fact that a GitHub PAT sitting in a stdio server's env var on
  the gateway machine is still a plaintext secret on that machine. This is a
  deployment-specific decision (HashiCorp Vault vs. OS keychain vs. cloud
  KMS) that needs to be made deliberately, not defaulted.
- **Backup/DR automation exists, scheduling does not.** Postgres backup,
  restore, and restore-verification scripts are included, but schedules,
  retention rules, managed-service PITR, and periodic restore drills are still
  operator responsibilities.
- **Approval fatigue, longer-term.** The Rego auto-approve mechanism helps
  today. If a team is still drowning in approvals six months in, that's a
  signal to write narrower Rego rules for the specific noisy tools, not to
  raise the default risk tier globally.

## Setup

```bash
# The workspace pins Rust 1.95 in ../rust-toolchain.toml.

export DATABASE_URL="sqlite://warden-cp.db"
export BIND_ADDR="127.0.0.1:7878"
export TRUST_DOMAIN="acme.corp"
export SIGNING_KEY_PATH="warden-cp-signing.key"   # back this file up - see below
export ML_DSA_SIGNING_KEY_PATH="warden-cp-ml-dsa65.key" # back this up too
export AUDIT_ANCHOR_FILE="/mnt/worm/warden-cp/audit-anchor.jsonl" # optional but recommended
export AUDIT_ANCHOR_REQUIRED="true" # fail closed if the external anchor is unavailable
export AUDIT_ML_DSA_CHECKPOINT_INTERVAL=1
export APPROVAL_WEBHOOK_URL="https://hooks.slack.com/services/..."  # optional, omit for CLI-only

cargo run
# First run prints a root API key ONCE. Every request after that needs:
#   curl -H "Authorization: Bearer <key>" http://localhost:7878/v1/...
```

First thing it logs is the Ed25519 public key. Gateways can either fetch it
from `/v1/signer/public-key` at startup or pin it in `warden.toml` as
`control_plane.signer_public_key_b64` for degraded/offline verification.
That endpoint also returns `ml_dsa_public_key_b64`; new gateways require that
second signature by default.

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
- `GET /v1/groups`
- `PUT /v1/groups/<group-id>/roles`
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

1. Real SPIRE integration behind the `agent_sessions` table.
2. Richer dashboard workflows for approval decisions, SCIM status, and policy editing.
3. FIPS 140-3 validated crypto provider option for deployments that require formal validation.
4. Consensus-backed or per-shard audit sequencing for multi-replica HA deployments.
