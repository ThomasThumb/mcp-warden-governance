# NullClaw Governed Worker Integration

NullClaw is a good fit as a lightweight autonomous worker, but it should not
be the authority layer. Keep this shape:

```text
NullClaw worker -> mcp-warden -> upstream MCP servers
                    |
                    v
                 warden-cp
```

`warden-cp` owns identity, policy, approvals, audit, and revocation.
`mcp-warden` is the only path to real tools. NullClaw is the worker that asks
for work to be done.

## Hard Rules

- Do not give NullClaw direct upstream credentials for GitHub, filesystem,
  email, Slack, or other sensitive services.
- Do not let NullClaw approve its own actions.
- Do not let NullClaw bypass `mcp-warden` for MCP tools.
- Do run NullClaw with its own service principal, agent session, workspace,
  sandbox, and revocation path.
- Treat NullClaw's own logs as useful telemetry, not the system of record.
  `warden-cp` audit events are the governance record.

## Setup Flow

Create a service principal for the worker:

```bash
curl -H "Authorization: Bearer $ROOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind":"service","display_name":"nullclaw-edge-01"}' \
  http://localhost:7878/v1/principals
```

Create a one-time-visible API key for that principal:

```bash
curl -H "Authorization: Bearer $ROOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"<nullclaw-principal-id>"}' \
  http://localhost:7878/v1/api-keys
```

Mint an agent session for the running NullClaw instance. Use NullClaw's own
public key when available; otherwise generate an instance key and keep it
local to that worker until token binding is fully enforced:

```bash
curl -H "Authorization: Bearer $NULLCLAW_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id":"<nullclaw-principal-id>",
    "purpose":"nullclaw governed worker edge-01",
    "public_key_b64":"<worker-public-key-b64>",
    "ttl_minutes":480
  }' \
  http://localhost:7878/v1/agent-sessions
```

For each tool call, request a short-lived token scoped to the exact gateway,
server, and tool:

```bash
curl -H "Authorization: Bearer $NULLCLAW_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_session_id":"<agent-session-id>",
    "gateway_id":"<gateway-id>",
    "server_id":"filesystem",
    "tool_name":"read_file",
    "ttl_seconds":300
  }' \
  http://localhost:7878/v1/token
```

Pass the token to `mcp-warden` in MCP request metadata when the client can set
`_meta`. Also pass `warden_proof`, a base64 Ed25519 signature by the
NullClaw worker key over `warden-pop-v1\n<token>\n<args_fingerprint>`:

```json
{
  "name": "filesystem::read_file",
  "_meta": {
    "warden_token": "<issued-token>",
    "warden_proof": "<proof-signature>"
  },
  "arguments": {
    "path": "README.md"
  }
}
```

If NullClaw cannot set MCP `_meta`, put the token in
`arguments.__warden_token` and `arguments.__warden_proof`. `mcp-warden`
strips those fields before forwarding the call upstream:

```json
{
  "name": "filesystem::read_file",
  "arguments": {
    "path": "README.md",
    "__warden_token": "<issued-token>",
    "__warden_proof": "<proof-signature>"
  }
}
```

## Recommended NullClaw Posture

- Bind NullClaw's local gateway to `127.0.0.1`.
- Use NullClaw's sandbox backend where available, preferably Landlock or
  Bubblewrap on Linux, Docker otherwise.
- Give each worker a dedicated workspace directory.
- Keep NullClaw channel credentials separate from upstream tool credentials.
- Configure high-risk MCP tools in `warden.toml` as `require_approval`.
- Use `POST /v1/agent-sessions/:id/revoke` as the kill switch for one worker.

## NullClaw Attribution

NullClaw is an external MIT-licensed project by the nullclaw contributors.
This repository does not vendor NullClaw source code; it only documents a
governed integration pattern.

- Project: https://nullclaw.org/
- Repository: https://github.com/nullclaw/nullclaw
- License: MIT License

## What This Does Not Solve Yet

- Full DPoP-style HTTP standardization is not implemented. The gateway now
  enforces a compact Ed25519 proof over the issued token and argument
  fingerprint, which is the local worker-binding layer.
- NullClaw native MCP client behavior may vary by version. If it cannot attach
  `_meta` or `__warden_token`, add a tiny local token-injecting MCP shim rather
  than relaxing `mcp-warden` token requirements.
- NullClaw's own audit trail is separate from `warden-cp`'s tamper-evident
  audit chain. Keep both, but report from `warden-cp`.
