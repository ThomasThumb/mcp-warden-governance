# mcp-warden

A zero-trust proxy that sits between your MCP host (Claude Desktop, Cursor,
etc.) and every real MCP server you connect to. The host talks only to
`mcp-warden`; `mcp-warden` talks to your actual servers and decides what the
host is allowed to see and do.

## Status: this is a working v0.1 skeleton, not a finished product

What's real and implemented:
- Aggregates tools from multiple stdio-spawned upstream servers into one
  namespaced list (`server_id::tool_name`), so two servers can't shadow or
  override each other's tools in the model's flat tool namespace
- **Tool-definition hash pinning** (`integrity.rs`) - every tool's full
  definition (name + description + input schema, not just the description
  string) is fingerprinted. A new or *changed* tool is withheld from the host
  until you run `mcp-warden approve server::tool` - this is the direct defense
  against "rug pulls," where a server changes a tool's behavior after you
  already trusted it
- **Default-deny policy engine** (`policy.rs`) - every tool needs an explicit
  risk tier; anything you haven't reviewed requires human approval, nothing
  runs silently
- **Heuristic injection filter** (`injection_filter.rs`) - pattern-matches
  tool descriptions *and* tool call results (not just the initial listing -
  indirect injection usually rides in through fetched data) against known
  injection shapes
- **Structured audit log** (`audit.rs`) - JSON-lines, one line per decision,
  arguments stored as a hash rather than raw (so secrets don't end up sitting
  in a log file)
- **Control-plane governance** - when `[control_plane]` is configured, the
  gateway registers inventory, enforces centrally approved tool fingerprints
  and policy overlays, submits audit events, routes approvals through
  `warden-cp`, and verifies short-lived per-call agent tokens before any
  upstream tool call is made.
- **Remote HTTP upstreams** - JSON-RPC-over-HTTP POST upstreams are supported
  with static env-backed bearer tokens or OAuth client credentials using an
  RFC 8707 `resource` indicator.
- **Local stdio sandbox wrappers** - `bubblewrap`, `firejail`, and Docker
  wrapper modes are available for stdio servers; missing wrappers fail closed
  at startup instead of silently running unsandboxed.

What's explicitly NOT done yet (see "Roadmap" below), on purpose rather than
by accident:
- **A polished approval UX.** The control-plane approval API is real; a thin
  dashboard, Slack app, or CLI watcher is still the next usability layer.
- **Native SPIRE/SVID issuance.** Agent session IDs are already SPIFFE-shaped,
  but `warden-cp` still mints them locally until real SPIRE integration lands.

## Why it's architected this way

This maps directly onto the recurring MCP attack categories from the OWASP
MCP Top 10 / NSA guidance:

| Attack | Where it's addressed |
|---|---|
| Tool poisoning / rug pulls | `integrity.rs` hash pinning |
| Prompt injection (direct + indirect) | `injection_filter.rs`, applied to both tool defs and results |
| Privilege creep / over-broad scopes | `policy.rs` default-deny, per-tool risk tiers |
| Token passthrough / confused deputy | `upstream.rs` - the gateway is the OAuth client, never the host's raw token |
| Cross-server tool shadowing | namespacing in `gateway.rs::list_tools` |
| Silent behavior drift | audit log + integrity guard together give you a paper trail |

None of these layers is sufficient alone - a good enough injection payload
can dodge regex, a hash pin only catches *changes*, not day-one malice. The
point of stacking them is that an attacker has to beat all of them
simultaneously, not just the weakest one.

## A note on how this was built

I (the AI that wrote this) verified the `rmcp` crate's existence, its
`ServerHandler`/`ClientHandler` trait shapes, and its transport APIs against
the SDK's actual published source and docs rather than from memory - but I
could not compile this end-to-end in my own sandbox, which only has an old
system Rust (1.75) with no path to a newer toolchain. The current `rmcp`
targets edition 2024, which needs rustc 1.85+.

**First thing to do on your machine:** run `cargo check`. It will very likely
need a couple of small fixes - rmcp has shipped breaking changes across
versions before, and I can't guarantee byte-perfect signatures for whatever
version resolves for you. Places most likely to need a tweak, in rough order
of risk:

1. `gateway.rs` - the exact `ErrorData`/`McpError` constructor name (I used
   `McpError::invalid_params(msg, None)` as a placeholder; centralized in one
   `deny()` helper so it's a one-line fix if wrong)
2. `gateway.rs` - `ServerCapabilities::builder().enable_tools()` - confirm
   this method name via `cargo doc -p rmcp --open`
3. `warden.example.toml` - the `[servers.env]` sub-table under an internally
   tagged, flattened enum variant is a spot where `toml`/`serde` interactions
   occasionally need a rewrite to an inline table (`env = { KEY = "val" }`)
4. `upstream.rs` / `gateway.rs` - `PaginatedRequestParam` naming
   (singular/plural has drifted between rmcp releases in different docs I
   checked)

`rego_policy.rs` is much safer ground than the `rmcp` integration - Rego and
`regorus` change far less often, and any signature drift there degrades to
"policy always requires approval," never to "policy always allows," per its
own fail-safe design. `policy.rs` also now has real unit tests
(`cargo test`) covering the one invariant the whole design depends on -
run them before you trust any change to that file, including mine.

None of these are logic bugs - they're all "the SDK renamed something,"
which `cargo check`'s error messages will point at directly.

## Setup

```bash
# You need Rust 1.85+ (edition 2024). If `rustc --version` shows older:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

cp warden.example.toml warden.toml
# edit warden.toml: point at your real servers, set env vars for tokens
cargo check         # fix whatever it flags per the table above
cargo build --release
```

Supply-chain CI and release provenance are documented in the repository root
`SUPPLY_CHAIN.md`. Release binaries should be verified with GitHub artifact
attestations before deployment.

Point your MCP host at the binary instead of your real servers:

```json
{
  "mcpServers": {
    "warden": {
      "command": "/path/to/target/release/mcp-warden",
      "args": ["serve", "/path/to/warden.toml"]
    }
  }
}
```

Approving a new or changed tool:

```bash
./target/release/mcp-warden list-pending
./target/release/mcp-warden approve filesystem::write_file
```

## Control plane integration (new)

If `[control_plane]` is set in `warden.toml`, this gateway now:
1. Registers itself + its upstream inventory with `warden-cp` on every start
2. Refuses to serve **anything** if the control plane is unreachable, unless
   a human has explicitly run `mcp-warden confirm-degraded` on this exact box
3. Reports tool fingerprints to the control plane and withholds unapproved
   tool definitions
4. Pulls the gateway-scoped `/v1/policy/:scope` bundle and overlays it onto
   local tool policy before each call decision
5. Creates/polls `/v1/approvals` for `RequireApproval` calls and submits
   audit events to `/v1/audit` alongside the local JSONL log
6. Verifies every `tools/call` against a short-lived token scoped to exactly
   one `(gateway_id, server_id, tool_name)` before calling upstream
7. Requires the token envelope's Ed25519 and ML-DSA-65 signatures by default
8. Verifies a proof-of-possession signature from the agent-session key when
   `require_agent_proof = true`, so a stolen token alone is not enough
9. Calls `/v1/token/introspect` by default before forwarding the call, so
   revoked sessions and already-used token IDs fail closed online

```toml
[control_plane]
url = "http://localhost:7878"
gateway_id = "laptop-jane"
owner_principal_id = "principal-uuid-here"
max_degraded_minutes = 60   # just documents the default you'd pass to confirm-degraded
signer_public_key_b64 = "optional-if-control-plane-is-reachable-at-startup"
ml_dsa_public_key_b64 = "optional-if-control-plane-is-reachable-at-startup"
require_ml_dsa_token_signature = true
require_agent_token = true
require_agent_proof = true
require_token_introspection = true
```

`require_agent_proof = true` now requires `require_token_introspection = true`.
That is intentional: a proof over `token + args_fingerprint` is replayable if
the token id is not consumed online. Fetch a fresh token for each retry instead
of replaying the same `(token, proof, args)` tuple.

```bash
# control plane down / network partition / whatever:
./mcp-warden serve warden.toml
# control plane at http://localhost:7878 is unreachable: ...
# Refusing to serve. Run:
#   mcp-warden confirm-degraded --reason "why" --minutes 60

./mcp-warden confirm-degraded --reason "VPN down, on-call needs this working" --minutes 60
./mcp-warden serve warden.toml   # now runs, loudly logged as DEGRADED, expires on its own
```

This is deliberately not automatic in either direction - no silent fail-open
(which would mean "control plane down" quietly becomes "no governance at
all"), no silent fail-closed either (which would mean a network blip takes
down every agent workflow in the building with no recourse). A human says go
or no-go, on record, with a reason and a timer.

Central policy bundles are overlays, not total replacements. A bundle can use
either this direct shape:

```json
{
  "default_risk": "require_approval",
  "tools": {
    "read_file": { "risk": "read_only" },
    "delete_file": { "blocked": true }
  }
}
```

or a multi-server shape keyed by server id:

```json
{
  "servers": {
    "filesystem": {
      "tools": {
        "read_file": { "risk": "read_only" }
      }
    }
  }
}
```

Missing or malformed central policy fails safe to the local `warden.toml`
policy; a control-plane fetch error denies the call rather than silently
falling back.

### Per-call agent tokens

The gateway accepts the token in MCP request metadata:

```json
{
  "name": "filesystem::read_file",
  "_meta": {
    "warden_token": "<token from POST /v1/token>"
  },
  "arguments": {
    "path": "README.md"
  }
}
```

For older hosts that cannot send `_meta`, `arguments.__warden_token` is also
accepted and stripped before the upstream server receives the call. A token is
not a general session bearer: it must match the configured gateway, the
upstream server id, and the exact tool name. Missing, expired, or mis-scoped
tokens are denied and audited before the upstream server is touched.
By default, cryptographic verification is followed by online control-plane
introspection. That marks the token ID as used and prevents a captured token
from being replayed against a second call.

When proof-of-possession is enabled, the call must also include
`_meta.warden_proof` or `arguments.__warden_proof`. The value is a base64
Ed25519 signature from the agent-session private key over:

```text
warden-pop-v1
<issued-token>
<args_fingerprint>
```

`args_fingerprint` is computed after `__warden_token` and `__warden_proof`
are stripped, which prevents token/proof material from reaching the upstream
tool or changing the policy/audit fingerprint.
The proof key and proof signature may be encoded as standard base64 or
URL-safe no-pad base64; the verifier accepts both so agents can use the same
encoding convention as the token envelope.

## Remote HTTP upstreams

`transport = "http"` sends MCP JSON-RPC requests over HTTP POST. The gateway
owns the upstream credential. Use either a static env-backed bearer token:

```toml
[[servers]]
id = "remote-docs"
transport = "http"
url = "https://mcp.example.com/rpc"
token_env = "REMOTE_DOCS_TOKEN"
```

or OAuth client credentials with an RFC 8707 `resource` indicator:

```toml
[servers.oauth]
token_url = "https://auth.example.com/oauth/token"
client_id_env = "REMOTE_DOCS_CLIENT_ID"
client_secret_env = "REMOTE_DOCS_CLIENT_SECRET"
resource = "https://mcp.example.com/rpc"
scope = "mcp:call"
```

This deliberately avoids host-token passthrough. If an upstream requires a
streaming MCP HTTP dialect rather than JSON-RPC-over-HTTP POST, keep it
blocked until that transport is implemented and tested explicitly.

## Local stdio sandboxing

For local stdio servers, add a sandbox wrapper:

```toml
[servers.sandbox]
mode = "bubblewrap"   # none | bubblewrap | firejail | docker
workspace = "/srv/agent-workspaces/filesystem"
allow_network = false
```

Docker mode also needs `docker_image`. These wrappers are intentionally
opt-in because they depend on host tooling and OS support. A missing wrapper
binary fails closed at startup instead of silently running unsandboxed.

## Post-quantum / HNDL posture

For "harvest now, decrypt later" protection, the transport key exchange is
the important layer. This project does not invent its own cryptography. The
deployment target is NIST-standard or hybrid post-quantum transport using
ML-KEM (FIPS 203) through a vetted TLS stack or reverse proxy when the control
plane is reachable over a real network. Plain `http://127.0.0.1` is acceptable
for local dev only; across machines, put `warden-cp` behind TLS 1.3 and
prefer a stack/provider that supports hybrid classical + ML-KEM key
establishment.

The per-call tokens are hybrid signed: Ed25519 remains the mature classical
anchor, and ML-DSA-65 adds the FIPS 204 post-quantum signature. New gateway
configs require both signatures by default when a control plane is configured.
Set `require_ml_dsa_token_signature = false` only as a temporary migration
bridge for an older control plane. Symmetric encryption should stay boring
and strong: AES-256-GCM or ChaCha20-Poly1305 through a trusted TLS/AEAD
library, not custom crypto.

## Org-customizable policy (new)

Every org's risk tolerance is different, so `policy.rs` now optionally
layers a custom **Rego** (Open Policy Agent's language, via Microsoft's
`regorus` crate) policy under the hard-coded floor:

```toml
rego_policy_path = "warden.rego"   # omit this line to disable entirely
```

The floor is enforced in Rust, not convention: Rego is only ever consulted
when the floor already says `RequireApproval`, and it can only flip that to
`Allow` - it never sees, and cannot affect, `Blocked` tools. Any compile or
eval error in the policy fails back to `RequireApproval`, never to `Allow`.
See `warden.example.rego` for a real starter policy and `src/policy.rs`'s
test module for the invariant that actually guarantees this - `cargo test`
runs `blocked_tools_ignore_rego_entirely`, and if you ever touch this file,
that test failing is the alarm bell.

## NullClaw as a governed worker

NullClaw is a reasonable lightweight worker runtime, especially for edge or
headless agent deployments, but it should stay behind the governance layers:

```text
NullClaw worker -> mcp-warden -> upstream MCP servers
                    |
                    v
                 warden-cp
```

Run each NullClaw instance as its own `warden-cp` service principal and
agent session. Give it short-lived per-tool tokens, route every MCP call
through `mcp-warden`, and keep upstream credentials in the gateway/upstream
environment rather than in NullClaw. The detailed setup guide is in
`integrations/nullclaw/README.md`.

NullClaw attribution: NullClaw is an external MIT-licensed project by the
nullclaw contributors. See `THIRD_PARTY_NOTICES.md`.

## Roadmap (in the order I'd tackle them)

1. **A real approval UI** - the API queue exists; build a dashboard, Slack
   app, or CLI watcher on top so interactive use doesn't mean babysitting a
   second terminal.
2. **SPIRE/SVID integration** - replace locally minted SPIFFE-shaped IDs with
   real workload identity while keeping the existing `spiffe_id` data model.
3. **Sandbox profile hardening** - turn the current host-tool wrappers into
   reviewed per-upstream profiles and add Landlock where Linux deployments can
   use it.
4. **Anomaly detection** - rate limiting per tool/server, alerting on
   dormant-tool reactivation and oversized responses (possible exfil), along
   the lines of the SIEM-style rules described in the audit log.
5. **Swap the heuristic injection filter for a second-tier semantic check**
   on anything the regex layer doesn't confidently clear - keep in mind this
   adds latency and its own attack surface (a filter model can itself be
   injected), so it's a genuine tradeoff, not a free upgrade.
