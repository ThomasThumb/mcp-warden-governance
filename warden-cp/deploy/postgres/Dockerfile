# PostgreSQL 17.10 remains on the official, digest-pinned database image for
# storage compatibility. Its bundled gosu 1.19 helper was built with a Go
# runtime that now has fixed high/critical advisories, so rebuild only that
# small privilege-drop helper from the immutable upstream source revision.
FROM golang:1.25.11-alpine@sha256:523c3effe300580ed375e43f43b1c9b091b68e935a7c3a92bfcc4e7ed55b18c2 AS gosu-build
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
RUN go install -trimpath -ldflags="-s -w -buildid=" \
    github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513

FROM postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193 AS postgres-rootfs
RUN rm /usr/local/bin/gosu

# Copy the merged filesystem, not the base-image layers, so the superseded Go
# binary is absent even from dormant image history that layer-aware scanners
# inspect. Reproduce the official image's runtime configuration explicitly.
FROM scratch
COPY --from=postgres-rootfs / /
COPY --from=gosu-build /go/bin/gosu /usr/local/bin/gosu
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GOSU_VERSION=1.19 \
    LANG=en_US.utf8 \
    PG_MAJOR=17 \
    PG_VERSION=17.10 \
    PG_SHA256=078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90 \
    DOCKER_PG_LLVM_DEPS="llvm21-dev \t\tclang21" \
    PGDATA=/var/lib/postgresql/data
VOLUME ["/var/lib/postgresql/data"]
EXPOSE 5432
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
STOPSIGNAL SIGINT
