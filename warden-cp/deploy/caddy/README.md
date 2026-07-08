# TLS / Private Ingress

`warden-cp` itself intentionally serves plain HTTP so certificate lifecycle
can stay in deployment tooling. Put it behind a reverse proxy or private
ingress before any gateway talks to it across a network.

This directory includes a minimal Caddy example:

```bash
caddy build-info
caddy adapt --config Caddyfile --validate
caddy run --config Caddyfile
```

Keep `warden-cp` bound to `127.0.0.1:7878` behind Caddy on the same host, or
bind it only on a private interface/VPN. Do not expose `warden-cp` or Postgres
directly to the public internet.

## Hybrid ML-KEM Note

Caddy uses Go's TLS stack. Go's `crypto/tls` defaults include the
`X25519MLKEM768` hybrid post-quantum key exchange starting in Go 1.24 when it
is not explicitly disabled. Caddy's `tls` directive also exposes
`x25519mlkem768` in the `curves` list. The example config intentionally sets
only `x25519mlkem768`, so clients that cannot negotiate the hybrid group fail
closed instead of falling back to classical X25519.

Operationally:

- Run a current Caddy build and record `caddy build-info` so you know which
  Go runtime produced the binary.
- Do not set `GODEBUG=tlsmlkem=0`.
- Validate config with `caddy adapt --config Caddyfile --validate`.
- Verify negotiated groups with `..\..\scripts\verify_caddy_hybrid_pq_tls.ps1`
  or an equivalent Go 1.26+ TLS client restricted to `X25519MLKEM768`.
- Keep certificates classical for now unless your PKI/TLS stack has a
  deliberate, tested post-quantum certificate plan.

For a local proof, the script temporarily serves `localhost:8443` with
`tls internal` and `curves x25519mlkem768`, then connects with a Go client
whose only offered key exchange is `tls.X25519MLKEM768`. Save the output line
`curve=X25519MLKEM768` with your deployment records. If a gateway, browser, or
admin client cannot connect to the hybrid-only endpoint, upgrade that client
rather than adding a classical fallback by default.
