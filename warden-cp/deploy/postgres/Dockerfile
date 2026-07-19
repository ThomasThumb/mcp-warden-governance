# Build the tiny privilege-drop helper from an immutable upstream revision.
# gosu's upstream module pins an old x/sys; requiring the fixed version in
# this main module makes Go's minimal-version selection use it without a fork.
FROM golang:1.25.12-alpine3.24@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS gosu-build
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src
RUN go mod init build.local/gosu \
    && go get github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513 \
    && go get golang.org/x/sys@v0.44.0 \
    && go build -trimpath -ldflags="-s -w -buildid=" \
        -o /go/bin/gosu github.com/tianon/gosu

# PostgreSQL's XML/XSLT features are not used by Warden. Build the same 17.10
# storage engine without those optional native parsers, reducing both runtime
# packages and attack surface. BuildKit verifies the upstream source archive
# before extraction.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS postgres-build
RUN apk add --no-cache \
        build-base \
        bison \
        bzip2 \
        flex \
        linux-headers \
        openssl-dev \
        perl \
        tzdata \
        zlib-dev
ADD --checksum=sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90 \
    https://ftp.postgresql.org/pub/source/v17.10/postgresql-17.10.tar.bz2 \
    /tmp/postgresql.tar.bz2
RUN mkdir /src \
    && tar -xjf /tmp/postgresql.tar.bz2 --strip-components=1 -C /src \
    && cd /src \
    && ./configure \
        --prefix=/usr/local \
        --disable-rpath \
        --enable-integer-datetimes \
        --with-openssl \
        --with-system-tzdata=/usr/share/zoneinfo \
        --with-zlib \
        --without-icu \
        --without-readline \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make install DESTDIR=/postgres-root

# Retain the battle-tested Docker Official Image entrypoint behavior while
# supplying our smaller server build and runtime filesystem.
FROM postgres:17.10-alpine3.24@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193 AS entrypoint-source

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS postgres-runtime
RUN apk add --no-cache \
        bash \
        ca-certificates \
        libssl3 \
        nss_wrapper \
        tzdata \
        zlib \
    && addgroup -g 70 -S postgres \
    && adduser -u 70 -S -D -G postgres -H -h /var/lib/postgresql -s /bin/sh postgres
COPY --from=postgres-build /postgres-root/ /
COPY --from=gosu-build /go/bin/gosu /usr/local/bin/gosu
COPY --from=entrypoint-source /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /docker-entrypoint-initdb.d /var/lib/postgresql/data /var/run/postgresql \
    && sed -ri "s!^#?(listen_addresses)[[:space:]]*=.*!\\1 = '*'!" \
        /usr/local/share/postgresql/postgresql.conf.sample \
    && grep -Fx "listen_addresses = '*'" \
        /usr/local/share/postgresql/postgresql.conf.sample \
    && chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql \
    && chmod 1777 /var/lib/postgresql/data \
    && chmod 3777 /var/run/postgresql \
    && gosu postgres postgres --version \
    && rm -f /sbin/apk \
    && rm -rf /etc/apk /var/cache/apk

# Flatten the prepared filesystem so deleted package-manager files are absent
# from every final-image layer. Retain Alpine's installed-package database so
# vulnerability scanners can still identify and assess every runtime package.
FROM scratch
COPY --from=postgres-runtime / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GOSU_VERSION=1.19 \
    LANG=en_US.utf8 \
    PG_MAJOR=17 \
    PG_VERSION=17.10 \
    PGDATA=/var/lib/postgresql/data
VOLUME ["/var/lib/postgresql/data"]
EXPOSE 5432
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
STOPSIGNAL SIGINT
