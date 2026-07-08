FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --no-default-features --features postgres

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --home /var/lib/warden-cp --create-home --shell /usr/sbin/nologin warden-cp
WORKDIR /var/lib/warden-cp
COPY --from=build /src/target/release/warden-cp /usr/local/bin/warden-cp
USER warden-cp
EXPOSE 7878
ENTRYPOINT ["warden-cp"]
