#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }

SOURCE_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
VERSION=12.7.3
ARCH=amd64
BASE_URL="https://code.forgejo.org/forgejo/runner/releases/download/v${VERSION}"
BINARY="forgejo-runner-${VERSION}-linux-${ARCH}"
FINGERPRINT=EB114F5E6C0DC2BCDD183550A4B61A2DC5923710

export DEBIAN_FRONTEND=noninteractive
apt-get update
# nodejs is required by any JavaScript action; unzip by the source-archive
# reproducibility test; zstd to read Forgejo's compressed job logs.
apt-get install -y --no-install-recommends \
    ca-certificates curl git gnupg nodejs unzip zstd

if ! id forgejo-runner >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/forgejo-runner \
        --shell /usr/sbin/nologin forgejo-runner
fi
install -d -o forgejo-runner -g forgejo-runner -m 0750 \
    /var/lib/forgejo-runner /var/lib/forgejo-runner/work
install -d -o root -g forgejo-runner -m 0750 /etc/forgejo-runner

temp=$(mktemp -d /tmp/forgejo-runner.XXXXXX)
trap 'rm -rf "$temp"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 \
    -o "$temp/forgejo-runner" "$BASE_URL/$BINARY"
curl --fail --location --proto '=https' --tlsv1.2 \
    -o "$temp/forgejo-runner.asc" "$BASE_URL/${BINARY}.asc"
GNUPGHOME="$temp/gnupg"
export GNUPGHOME
install -d -m 0700 "$GNUPGHOME"
gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$FINGERPRINT"
[ "$(gpg --batch --with-colons --fingerprint "$FINGERPRINT" | awk -F: '$1 == "fpr" {print $10; exit}')" = "$FINGERPRINT" ]
gpg --batch --verify "$temp/forgejo-runner.asc" "$temp/forgejo-runner"

install -o root -g root -m 0755 "$temp/forgejo-runner" /usr/local/bin/forgejo-runner
install -o root -g root -m 0644 "$SOURCE_DIR/forgejo-runner.service" /etc/systemd/system/forgejo-runner.service
systemctl daemon-reload
/usr/local/bin/forgejo-runner --version

echo 'Forgejo runner binary installed; registration config is still required.'
