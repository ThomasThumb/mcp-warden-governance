# Contributing

Thanks for helping improve MCP Warden Governance.

Before opening a pull request:

1. Keep changes narrowly scoped and security-first.
2. Do not commit secrets, local databases, scan output, release zips, or
   generated `target/` directories.
3. Run the relevant checks:

```bash
cargo fmt --manifest-path warden-cp/Cargo.toml --check
cargo clippy --manifest-path warden-cp/Cargo.toml -- -D warnings
cargo test --manifest-path warden-cp/Cargo.toml
cargo fmt --manifest-path mcp-warden/mcp-warden/Cargo.toml --check
cargo clippy --manifest-path mcp-warden/mcp-warden/Cargo.toml -- -D warnings
cargo test --manifest-path mcp-warden/mcp-warden/Cargo.toml
```

For security-sensitive changes, include the threat model, the invariant being
enforced, and the exact validation command or test that proves it.
