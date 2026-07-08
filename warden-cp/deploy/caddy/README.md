# TLS / Private Ingress

`warden-cp` itself intentionally serves plain HTTP so certificate lifecycle
can stay in deployment tooling. Put it behind a reverse proxy or private
ingress before any gateway talks to it across a network.

This directory includes a minimal Caddy example:

```bash
caddy run --config Caddyfile
```

Keep `warden-cp` bound to `127.0.0.1:7878` behind Caddy on the same host, or
bind it only on a private interface/VPN. Do not expose `warden-cp` or Postgres
directly to the public internet.

## Hybrid ML-KEM Note

Caddy uses Go's TLS stack. Go's `crypto/tls` defaults include the
`X25519MLKEM768` hybrid post-quantum key exchange starting in Go 1.24 when it
is not explicitly disabled. That gives the practical HNDL mitigation target:
TLS 1.3 plus hybrid classical/PQ key establishment, without custom crypto in
this service.

Operationally:

- Run a current Caddy build.
- Do not set `GODEBUG=tlsmlkem=0`.
- Verify negotiated groups with an external TLS scanner that understands
  hybrid PQ groups.
- Keep certificates classical for now unless your PKI/TLS stack has a
  deliberate, tested post-quantum certificate plan.
