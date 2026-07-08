# MCP Warden Governance

MCP Warden Governance is a zero-trust governance layer for Model Context
Protocol deployments.

- `mcp-warden/` is the gateway that sits between MCP hosts and upstream MCP
  servers.
- `warden-cp/` is the control plane for identity, policy, approvals, inventory,
  audit, OIDC/SCIM, and release-grade governance workflows.

The project is security-first: default-deny tool policy, tool fingerprinting,
short-lived per-tool tokens, proof-of-possession, hybrid Ed25519 + ML-DSA
signatures, audit-chain verification, external audit anchoring, and production
hooks for KMS/HSM/OS-keystore-backed signing.

## Quick Start

Start with the component READMEs:

- `mcp-warden/mcp-warden/README.md`
- `warden-cp/README.md`

For production image provenance, see `SUPPLY_CHAIN.md`.

## Open Source License

This repository is licensed under the Apache License 2.0. See `LICENSE` and
`NOTICE`.

NullClaw is an optional external MIT-licensed agent runtime referenced by the
integration documentation. NullClaw source code is not vendored here; attribution
is retained in each component's `THIRD_PARTY_NOTICES.md`.

## Security

Please report vulnerabilities privately through GitHub Security Advisories. See
`SECURITY.md`.
