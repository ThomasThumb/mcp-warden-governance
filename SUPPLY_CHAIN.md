# Supply Chain Provenance

This repository uses GitHub Actions for three supply-chain controls:

- `.github/workflows/security.yml` runs warning-denying Clippy, tests,
  `cargo audit`, the full Cargo Deny advisory/license/ban/source policy, and a
  fail-on-any-finding Trivy vulnerability/secret scans of both production
  container images for `warden-cp` and its pinned PostgreSQL 17 deployment,
  including the production Postgres feature graph on Linux and Windows.
- `.github/workflows/release-provenance.yml` builds the `warden-cp` Postgres
  Docker image, pushes it to GHCR, signs the image digest with Sigstore/cosign
  keyless signing through GitHub OIDC, and publishes GitHub artifact
  attestations.
- The same release workflow calls SLSA's container provenance generator for an
  additional non-forgeable in-toto/SLSA provenance statement.

## Published Image

Release tags publish:

```text
ghcr.io/ThomasThumb/mcp-warden-governance/warden-cp:<tag>
```

The image is built with `cargo build --release --no-default-features --features
postgres`.

## Verify GitHub Artifact Attestation

GitHub stores the attestation with the repository and release workflow identity.
Verify the container image with:

```bash
docker login ghcr.io
gh attestation verify \
  oci://ghcr.io/ThomasThumb/mcp-warden-governance/warden-cp:<tag> \
  --repo ThomasThumb/mcp-warden-governance
```

## Verify Sigstore/Cosign Signature

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ThomasThumb/mcp-warden-governance/.github/workflows/release-provenance.yml@refs/(tags|heads)/.*$' \
  ghcr.io/ThomasThumb/mcp-warden-governance/warden-cp:<tag>
```

## Verify SLSA Provenance

```bash
slsa-verifier verify-image \
  ghcr.io/ThomasThumb/mcp-warden-governance/warden-cp:<tag> \
  --source-uri github.com/ThomasThumb/mcp-warden-governance \
  --source-tag <tag>
```

The verification should show that the image was built by this repository's
GitHub Actions workflow using GitHub's OIDC identity. Treat missing,
unexpected, or mismatched provenance as a release-blocking incident.

## SLSA Posture

GitHub artifact attestations and SLSA provenance prove build origin and digest
binding. They do not, by themselves, prove the source is safe or that
dependencies are vulnerability-free; keep the security workflow green and
review dependency changes before release.

## Operator Rules

- Do not bypass the release workflow for images you ship to admins or agents.
- Do not store private signing keys in the repo for provenance; use keyless
  Sigstore/GitHub OIDC.
- Keep `cargo audit`, `cargo deny`, and the production-image Trivy scan clean
  before publishing a release.
- Verify provenance during deployment, not only during incident response.
