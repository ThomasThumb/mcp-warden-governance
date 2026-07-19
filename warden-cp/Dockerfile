# Build from the REPO ROOT (workspace context), not warden-cp/:
#   docker build -f warden-cp/Dockerfile -t warden-cp .
#
# Base images are digest-pinned so the signed release image is built by a
# known compiler and runs on a known minimal userspace.
# Dependabot's docker ecosystem keeps the digests fresh.
FROM rust:1.97-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS build
WORKDIR /src

# Dependency layer: manifests + lockfile only, so editing source doesn't
# recompile ~300 dependencies. Both member manifests must be present for
# cargo to parse the workspace.
COPY Cargo.toml Cargo.lock ./
COPY warden-cp/Cargo.toml warden-cp/Cargo.toml
COPY mcp-warden/mcp-warden/Cargo.toml mcp-warden/mcp-warden/Cargo.toml
RUN mkdir -p warden-cp/src mcp-warden/mcp-warden/src \
    && echo 'fn main() {}' > warden-cp/src/main.rs \
    && echo 'fn main() {}' > mcp-warden/mcp-warden/src/main.rs \
    && cargo build --release --locked -p warden-cp --no-default-features --features postgres \
    && rm -rf warden-cp/src mcp-warden/mcp-warden/src

COPY warden-cp warden-cp
COPY mcp-warden mcp-warden
# touch so cargo notices the real sources are newer than the stub build
RUN touch warden-cp/src/main.rs \
    && cargo build --release --locked -p warden-cp --no-default-features --features postgres

# Chainguard's minimal Wolfi runtime provides only the dynamic C runtime and
# CA roots needed by the Rust binary: no package manager, shell, Perl, or
# login tools. Its stable nonroot identity is 65532:65532. Keep both the tag
# (so Dependabot can identify the image) and immutable multi-platform digest.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:7ff79e2caef2b8a137ddaf9940fb790e91148482092363760d6661e4591fd54c
COPY --chown=65532:65532 LICENSE /var/lib/warden-cp/LICENSE
WORKDIR /var/lib/warden-cp
COPY --from=build --chown=65532:65532 /src/target/release/warden-cp /usr/local/bin/warden-cp
# Production images fail closed if managed signing is omitted. Local binary
# development retains its convenient file-backed default; Compose must make
# any local-only override explicit.
ENV WARDEN_REQUIRE_EXTERNAL_SIGNER=true
USER 65532:65532
EXPOSE 7878
# No HEALTHCHECK on purpose: the service intentionally exposes no
# unauthenticated endpoint (see main.rs). If a /healthz is added later on a
# separate unauthenticated router, add the HEALTHCHECK alongside it.
ENTRYPOINT ["warden-cp"]
