# Contributing

Thanks for helping improve MCP Warden Governance.

Before opening a pull request:

1. Keep changes narrowly scoped and security-first.
2. Do not commit secrets, local databases, scan output, release zips, or
   generated `target/` directories.
3. Run the checks CI enforces. The repo is a cargo workspace, so one
   invocation covers both crates. With [just](https://github.com/casey/just)
   installed:

```bash
just ci
```

Or by hand:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p warden-cp --no-default-features --features postgres --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p warden-cp --no-default-features --features postgres --locked
cargo audit
cargo deny check
```

The toolchain is pinned in `rust-toolchain.toml`; rustup picks it up
automatically. Always pass `--locked` so you build exactly the committed
`Cargo.lock`.

## Building on Windows

The crates build with the stock MSVC toolchain. If the build fails asking for
Spectre-mitigated libraries, that requirement is injected by your local Visual
Studio configuration (a `/Qspectre`-style policy), not by this repository:
install the "MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs" component
in the Visual Studio Installer, or remove the policy. CI runs a
`windows-latest` leg to keep the stock-toolchain path working.

For security-sensitive changes, include the threat model, the invariant being
enforced, and the exact validation command or test that proves it.
