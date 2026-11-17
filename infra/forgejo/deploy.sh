#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

SOURCE_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
FORGEJO_CONF=/usr/local/etc/forgejo/conf/app.ini
TLS_DIR=${FORGEJO_TLS_DIR:-/usr/local/etc/ssl/n100-tls}
STEP_ROOT_CA=${FORGEJO_CA_CERT:-/usr/local/etc/step/ca/certs/root_ca.crt}
SECRET_DIR=/root/.secrets
BOOTSTRAP_ENV=${SECRET_DIR}/forgejo-bootstrap.env
DATASET=tank/forgejo

pkg install -y forgejo15

if ! zfs list -H "$DATASET" >/dev/null 2>&1; then
    if [ -d /var/db/forgejo ]; then
        if [ -n "$(find /var/db/forgejo \( -type f -o -type l \) -print -quit 2>/dev/null)" ]; then
            echo "/var/db/forgejo contains data; refusing to hide it with a dataset" >&2
            exit 1
        fi
        rmdir /var/db/forgejo/data /var/db/forgejo/forgejo-repositories 2>/dev/null || true
        rmdir /var/db/forgejo
    fi
    zfs create -o mountpoint=/var/db/forgejo -o compression=zstd "$DATASET"
fi

install -d -o git -g git -m 0750 \
    /var/db/forgejo \
    /var/db/forgejo/data \
    /var/db/forgejo/forgejo-repositories \
    /var/db/forgejo/indexers \
    /var/db/forgejo/tmp \
    /var/log/forgejo
install -d -o root -g git -m 0750 /usr/local/etc/forgejo/conf
[ -d "$SECRET_DIR" ] || install -d -o root -g wheel -m 0700 "$SECRET_DIR"
[ -d "$TLS_DIR" ] || install -d -o root -g wheel -m 0755 "$TLS_DIR"

if [ ! -f "$BOOTSTRAP_ENV" ]; then
    umask 077
    admin_password=$(openssl rand -base64 30 | tr -d '\n')
    runner_secret=$(openssl rand -hex 20)
    {
        printf 'FORGEJO_ADMIN_USER=%s\n' 'operator'
        printf 'FORGEJO_ADMIN_PASSWORD=%s\n' "$admin_password"
        printf 'FORGEJO_RUNNER_SECRET=%s\n' "$runner_secret"
    } > "$BOOTSTRAP_ENV"
fi

if grep -qx 'APP_NAME = GateBSD Forge' "$FORGEJO_CONF" 2>/dev/null; then
    sed -i '' 's/^APP_NAME = GateBSD Forge$/APP_NAME = Home Forge/' "$FORGEJO_CONF"
elif ! grep -qx 'APP_NAME = Home Forge' "$FORGEJO_CONF" 2>/dev/null; then
    if [ -f "$FORGEJO_CONF" ]; then
        cp -p "$FORGEJO_CONF" "${FORGEJO_CONF}.before-gatebsd-$(date +%Y%m%d-%H%M%S)"
    fi
    internal_token=$(openssl rand -hex 64)
    secret_key=$(openssl rand -hex 32)
    jwt_secret=$(openssl rand -hex 32)
    awk \
        -v internal_token="$internal_token" \
        -v secret_key="$secret_key" \
        -v jwt_secret="$jwt_secret" '
        { gsub(/%%INTERNAL_TOKEN%%/, internal_token) }
        { gsub(/%%SECRET_KEY%%/, secret_key) }
        { gsub(/%%JWT_SECRET%%/, jwt_secret) }
        { print }
    ' "$SOURCE_DIR/app.ini.sample" > "${FORGEJO_CONF}.tmp"
    install -o root -g git -m 0640 "${FORGEJO_CONF}.tmp" "$FORGEJO_CONF"
    rm -f "${FORGEJO_CONF}.tmp"
fi

if [ ! -s "$TLS_DIR/server.crt" ] || [ ! -s "$TLS_DIR/server.key" ]; then
    if [ ! -f "$TLS_DIR/ca.key" ]; then
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
            -subj '/CN=Home Lab CA' \
            -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt"
        chmod 0600 "$TLS_DIR/ca.key"
        chmod 0644 "$TLS_DIR/ca.crt"
    fi
    temp=$(mktemp -d "${TLS_DIR}/.bootstrap-tls.XXXXXX")
    trap 'rm -rf "$temp"' EXIT HUP INT TERM
    openssl req -new -newkey rsa:3072 -sha256 -nodes \
        -subj '/CN=buildhost.example.lan' \
        -keyout "$TLS_DIR/server.key" -out "$temp/server.csr"
    printf '%s\n' \
        'subjectAltName=DNS:git.example.lan,DNS:mirror.example.lan,DNS:buildhost.example.lan' \
        'extendedKeyUsage=serverAuth' \
        'keyUsage=digitalSignature,keyEncipherment' > "$temp/server.ext"
    openssl x509 -req -sha256 -days 825 \
        -in "$temp/server.csr" \
        -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
        -extfile "$temp/server.ext" -out "$TLS_DIR/server.crt"
    chmod 0600 "$TLS_DIR/server.key"
    chmod 0644 "$TLS_DIR/server.crt"
    rm -rf "$temp"
    trap - EXIT HUP INT TERM
fi

install -o root -g wheel -m 0644 \
    "$SOURCE_DIR/nginx-forgejo.conf.sample" \
    /usr/local/etc/nginx/conf.d/forgejo.conf

sysrc forgejo_enable=YES >/dev/null
nginx -t
# Forgejo may normalize or add derived secrets during the first migration.
# It loses write access again immediately after bootstrap.
chmod 0660 "$FORGEJO_CONF"
service forgejo restart || service forgejo start
service nginx reload

count=0
until curl --fail --silent http://127.0.0.1:3000/api/healthz >/dev/null 2>&1; do
    count=$((count + 1))
    [ "$count" -lt 30 ] || { echo 'Forgejo did not become healthy in 30 seconds' >&2; exit 1; }
    sleep 1
done

. "$BOOTSTRAP_ENV"
if ! su -m git -c "/usr/local/sbin/forgejo --work-path /var/db/forgejo --config '$FORGEJO_CONF' admin user list" \
    | awk 'NR > 1 {print $2}' | grep -qx "$FORGEJO_ADMIN_USER"; then
    su -m git -c "/usr/local/sbin/forgejo --work-path /var/db/forgejo --config '$FORGEJO_CONF' admin user create --username '$FORGEJO_ADMIN_USER' --password '$FORGEJO_ADMIN_PASSWORD' --email 'gatebsd@example.invalid' --admin --must-change-password=false"
fi
chmod 0640 "$FORGEJO_CONF"

VERIFY_CA="$STEP_ROOT_CA"
if [ ! -s "$VERIFY_CA" ] && [ -s /usr/local/etc/step/certs/root_ca.crt ]; then
    VERIFY_CA=/usr/local/etc/step/certs/root_ca.crt
elif [ ! -s "$VERIFY_CA" ]; then
    VERIFY_CA="$TLS_DIR/ca.crt"
fi
openssl verify -CAfile "$VERIFY_CA" "$TLS_DIR/server.crt"
curl --fail --silent --show-error \
    --cacert "$VERIFY_CA" \
    https://git.example.lan/forgejo/api/healthz

echo "Forgejo deployed"
echo "URL: https://git.example.lan/forgejo/"
echo "Bootstrap credentials: $BOOTSTRAP_ENV"
echo "Local CA certificate: $VERIFY_CA"
