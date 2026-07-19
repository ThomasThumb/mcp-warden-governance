# MCP Warden Governance

MCP Warden Governance is a zero-trust governance layer for Model Context
Protocol deployments. It is built for teams that want visibility and control
over what AI agents can call, what tools changed, who approved the action, and
what actually happened afterward.

This repository has two main components:

- `mcp-warden/` - the gateway that sits between MCP hosts and upstream MCP
  servers.
- `warden-cp/` - the control plane for identity, policy, approvals, inventory,
  audit, OIDC/SCIM, and release-grade governance workflows.

## What It Can Do

- Proxy MCP hosts to real upstream MCP servers through a governed gateway.
- Namespace tools so one server cannot shadow another server's tool names.
- Fingerprint tool definitions and hold changed tools for review.
- Enforce default-deny tool policy with allow, block, read-only, and
  require-approval decisions.
- Route approvals through the control plane.
- Issue short-lived, per-tool, per-gateway agent tokens.
- Require proof-of-possession so a stolen token alone is not enough.
- Consume each token ID online through introspection to stop replay.
- Keep a who/what/when/where audit trail without storing raw tool arguments.
- Sign and hash-chain audit rows, then verify the chain later.
- Anchor audit high-water marks outside the database through file or command
  adapters.
- Support OIDC login and SCIM user/group lifecycle sync.
- Run on SQLite for local development or Postgres for production.
- Keep control-plane and upstream secrets out of TOML through explicit
  environment-variable mappings; spawned adapters and stdio servers inherit
  an empty environment unless a value is allowlisted.
- Serve `warden-cp` over built-in Rustls TLS or enforce HTTPS behind a trusted
  reverse proxy.
- Build signed/provenance-backed release images through GitHub Actions,
  Sigstore/cosign, GitHub artifact attestations, and SLSA provenance.

## What It Cannot Do

- It cannot magically prove a brand-new tool is safe before review.
- It cannot fully solve prompt injection with regex. The heuristic filter is
  useful for obvious cases, but the real defense is layered policy, approval,
  scoping, audit, token limits, sandboxing, and revocation.
- It cannot protect secrets from a fully compromised host by itself.
- It cannot make an unsafe local stdio tool safe if you run that tool
  unsandboxed with powerful credentials.
- It cannot provide hard rollback protection unless audit anchors live
  somewhere the database host cannot rewrite.
- It is not a replacement for SIEM, EDR, DLP, or a secrets vault.

## Security And Encryption

The project is security-first: default-deny policy, tool fingerprinting,
short-lived scoped tokens, proof-of-possession, hybrid Ed25519 + ML-DSA
signatures, audit-chain verification, external audit anchoring, built-in TLS /
HTTPS enforcement, and production hooks for KMS/HSM/OS-keystore-backed signing.

Current cryptographic posture:

- **Transport:** `warden-cp` supports built-in Rustls TLS using `TLS_CERT_PATH`
  and `TLS_KEY_PATH`. It can also require HTTPS behind a trusted reverse proxy
  with `WARDEN_CP_REQUIRE_HTTPS=true`.
- **Post-quantum transport:** for network deployments, prefer TLS 1.3 stacks or
  providers that support hybrid classical + ML-KEM key establishment where
  available. Do not hand-roll transport crypto in this service.
- **Token signatures:** scoped agent tokens are hybrid signed with Ed25519 and
  ML-DSA-65 by default.
- **Audit signatures:** audit rows are Ed25519 signed, with ML-DSA-65 enabled
  by default when the ML-DSA signer is configured.
- **Data at rest:** use Postgres, volume, or managed database encryption. The
  app does not replace database/storage encryption.
- **Key custody:** local owner-only key files are supported for development.
  Production can use the external signer command contract to keep private keys
  in KMS, HSM, Vault, PKCS#11, Windows CNG/DPAPI, or another managed boundary.

## Quick Start

Start with the component READMEs:

- `mcp-warden/mcp-warden/README.md`
- `warden-cp/README.md`

For production image provenance, see `SUPPLY_CHAIN.md`.

## Open Source License

This repository is licensed under the Apache License 2.0. See `LICENSE` and
`NOTICE`.

NullClaw is an optional external MIT-licensed agent runtime referenced by the
integration documentation. NullClaw source code is not vendored here;
attribution is retained in each component's `THIRD_PARTY_NOTICES.md`.

## Security Reports

Please report vulnerabilities privately through GitHub Security Advisories. See
`SECURITY.md`.
