# External Security Integrations

This file documents the two extension points that keep production deployments
from depending on mutable local host state.

## Audit Anchor Command

Use `AUDIT_ANCHOR_COMMAND` when the audit high-water mark must live outside the
database host's rewrite control. The command receives one JSON object on stdin
and returns one JSON object on stdout.

Environment:

```bash
export AUDIT_ANCHOR_REQUIRED=true
export AUDIT_ANCHOR_COMMAND="pwsh"
export AUDIT_ANCHOR_ARGS_JSON='["-File","warden-cp/scripts/audit_anchor_s3_object_lock_adapter.ps1"]'
export AUDIT_ANCHOR_TIMEOUT_MS=5000
```

Request shapes:

```json
{"version":1,"action":"publish","record":{"seq":1,"entry_hash":"..."}}
{"version":1,"action":"latest"}
```

`publish` must durably store the exact record. `latest` must return:

```json
{"record":{"seq":1,"entry_hash":"..."}}
```

or:

```json
{"record":null}
```

The included `audit_anchor_s3_object_lock_adapter.ps1` writes one immutable
object per sequence number. Use it only with an S3 bucket that has Object Lock
enabled, versioning enabled, least-privilege IAM, and retention policy reviewed
by security. Required environment:

```bash
export AUDIT_ANCHOR_S3_BUCKET="my-warden-audit-anchors"
export AUDIT_ANCHOR_S3_PREFIX="prod/warden-cp/audit-anchor"
export AUDIT_ANCHOR_S3_RETENTION_DAYS=365
```

## External Signer Command

Use `WARDEN_SIGNER_COMMAND` when signing keys must stay in KMS, HSM, Vault
Transit, PKCS#11, Windows CNG/DPAPI, or another managed key boundary. In this
mode `warden-cp` does not read local private key files. It sends exact bytes to
the command and verifies the returned signatures against configured public keys
before accepting them.

Environment:

```bash
export WARDEN_SIGNER_COMMAND="/opt/warden/signers/prod-signer"
export WARDEN_SIGNER_ARGS_JSON='["--profile","prod"]'
export WARDEN_SIGNER_TIMEOUT_MS=5000
export WARDEN_SIGNER_ED25519_PUBLIC_KEY_B64="..."
export WARDEN_SIGNER_ML_DSA65_PUBLIC_KEY_B64="..."
```

Request:

```json
{
  "version": 1,
  "action": "sign",
  "message_b64": "URL_SAFE_NO_PAD_BYTES",
  "include_ml_dsa": true
}
```

Response:

```json
{
  "ed25519_sig_b64": "...",
  "ml_dsa_alg": "ML-DSA-65",
  "ml_dsa_sig_b64": "..."
}
```

The service rejects malformed signatures, wrong public keys, missing ML-DSA when
required, command failures, and command timeouts. If an external signer can only
provide Ed25519 during a migration, `WARDEN_SIGNER_ALLOW_ED25519_ONLY=true`
allows startup, but this should be treated as a temporary exception and logged
in the deployment risk register.
