#!/usr/bin/env bash
# Exercise the production entrypoint and volume under the Compose restrictions.
set -euo pipefail

image="${1:-warden-postgres:security}"
name="warden-postgres-smoke-$$-${RANDOM}"
volume="${name}-data"
password="$(openssl rand -hex 24)"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        docker logs "$name" || true
    fi
    docker rm -fv "$name" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
docker run -d --name "$name" \
    --read-only --init --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --cap-add SETGID --cap-add SETUID --pids-limit 256 \
    --tmpfs /var/run/postgresql:rw,noexec,nosuid,nodev,size=16m,mode=0775 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
    -e POSTGRES_USER=warden_smoke -e POSTGRES_DB=warden_smoke \
    -e POSTGRES_PASSWORD="$password" \
    -v "$volume:/var/lib/postgresql/data" "$image" >/dev/null

wait_ready() {
    for _ in $(seq 1 60); do
        # TCP readiness waits for the final server, not initdb's socket-only one.
        if docker exec "$name" pg_isready -h 127.0.0.1 -U warden_smoke -d warden_smoke; then
            return 0
        fi
        sleep 1
    done
    return 1
}
sql() {
    docker exec -e PGPASSWORD="$password" "$name" \
        psql -h 127.0.0.1 -U warden_smoke -d warden_smoke -v ON_ERROR_STOP=1 -Atc "$1"
}

wait_ready
docker exec "$name" sh -ec 'test "$(id -u postgres)" = 70; test "$(gosu postgres id -u)" = 70'
# The process following the init shim must have dropped root privileges.
docker exec "$name" sh -ec 'pid=$(head -n1 "$PGDATA/postmaster.pid"); grep -Eq "^Uid:[[:space:]]+70[[:space:]]+70[[:space:]]+70[[:space:]]+70$" "/proc/$pid/status"'
if docker exec -e PGPASSWORD=incorrect "$name" \
    psql -h 127.0.0.1 -U warden_smoke -d warden_smoke -c 'SELECT 1'; then
    echo 'PostgreSQL accepted an incorrect TCP password' >&2
    exit 1
fi
sql 'CREATE TABLE smoke_test (value integer NOT NULL); INSERT INTO smoke_test VALUES (42);'
test "$(sql 'SHOW server_version;')" = 17.10
test "$(sql 'SHOW password_encryption;')" = scram-sha-256
docker restart "$name" >/dev/null
wait_ready
test "$(sql 'SELECT value FROM smoke_test;')" = 42
echo 'PostgreSQL initialization, privilege drop, authentication, and persistent restart passed'
