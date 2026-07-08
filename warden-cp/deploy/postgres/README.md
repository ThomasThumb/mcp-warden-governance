# warden-cp Postgres Deployment

This profile runs `warden-cp` against Postgres instead of the local SQLite
default. It is suitable for a small production pilot when fronted by TLS and
backed up properly.

## Start

```bash
cp .env.example .env
# edit POSTGRES_PASSWORD, TRUST_DOMAIN, WARDEN_CP_BIND
docker compose --env-file .env up --build
```

The compose file binds:

- Postgres to `127.0.0.1:5432`
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

- Store `.env` and `warden-cp-signing.key` outside source control.
- Back up `warden-cp-signing.key`; losing it invalidates issued tokens.
- Monitor disk usage, connection count, slow queries, and failed auth.
- Do not expose either Postgres or `warden-cp` directly to the internet.
