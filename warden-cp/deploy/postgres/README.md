# warden-cp Postgres Deployment

This profile runs `warden-cp` against Postgres instead of the local SQLite
default. It is suitable for a small production pilot when fronted by TLS and
backed up properly.

The Dockerfile builds `warden-cp` with `--no-default-features --features
postgres`, so the production image does not include the SQLite backend or
SQLx's runtime `Any` driver.

The database image preserves PostgreSQL 17 on-disk compatibility but builds
17.10 from its checksum-verified upstream source with only the OpenSSL and zlib
features this service needs. Unused XML/XSLT, ICU, LDAP, GSSAPI, LLVM, and
language-extension runtimes are omitted. Its `gosu` helper is also rebuilt from
an immutable upstream revision with a patched Go toolchain and `x/sys`.

## Start

```bash
cp .env.example .env
# edit POSTGRES_PASSWORD, TRUST_DOMAIN, WARDEN_CP_BIND, and signer settings
docker compose --env-file .env up --build
```

The compose file binds:

- Postgres only to the internal Docker network; it has no host-published port
- `warden-cp` to `${WARDEN_CP_BIND}`, default `127.0.0.1:7878`

Keep that localhost bind unless a TLS reverse proxy, VPN, private subnet, or
other trusted ingress is in front of it.

## Back Up

For a local compose deployment:

```bash
../../scripts/backup_postgres.ps1
```

For managed Postgres, prefer the provider's PITR and snapshot tooling, then
run a restore drill before trusting the backup plan.

## Restore Drill

At least once before production use:

1. Restore a backup into an empty database.
2. Start `warden-cp` against the restored database.
3. Verify `GET /v1/audit/verify` returns `{"ok":true}`.
4. Confirm principals, gateways, approvals, fingerprints, and recent audit
   events are present via the admin endpoints.

## Production Notes

- Set `WARDEN_REQUIRE_EXTERNAL_SIGNER=true`. Production startup then fails
  before database bootstrap unless `WARDEN_SIGNER_COMMAND` and valid Ed25519
  plus ML-DSA-65 public verification keys are configured. The Ed25519-only
  migration exception is deliberately unavailable in this mode. The production
  image and Postgres-only binary default to `true`; the checked-in
  `.env.example` explicitly selects `false` only so its localhost development
  quick start remains usable.
- Mount the signer adapter read-only at its absolute in-container path and use
  `WARDEN_SIGNER_ENV_FROM_JSON` to expose only the exact KMS/HSM/Vault settings
  it needs. The child process inherits no other environment variables.
- Keep `.env` outside source control. A local-only deployment with
  `WARDEN_REQUIRE_EXTERNAL_SIGNER=false` must also protect and back up
  `warden-cp-signing.key` and `warden-cp-ml-dsa65.key`; losing them invalidates
  issued hybrid tokens.
- Configure OIDC/SCIM through environment and a dedicated admin principal
  before connecting an enterprise IdP.
- Monitor disk usage, connection count, slow queries, and failed auth.
- Do not expose either Postgres or `warden-cp` directly to the internet.

Code-signing certificates, TLS certificates, and runtime signer keys solve
different problems. A code-signing certificate identifies the software
publisher, and a TLS certificate authenticates the network endpoint. Neither
persists or protects the Ed25519/ML-DSA keys used to sign Warden tokens and
audit checkpoints; those keys belong in the managed signer configured above.
