#!/bin/sh
# Provision the SSH material a Forgejo runner needs. Run as root on the runner
# host, after install.sh.
#
# Why this file exists: install.sh put the binary, the unit and the user in
# place and ended with "registration config is still required", and the five
# files below were made by hand every time. On 15 August 2026 that cost three
# consecutive failed pipeline runs on a fresh runner -- each one surfaced
# exactly one missing file, because a job stops at the first thing it cannot
# find. The workflow depends on all five and named none of them anywhere else
# in the tree.
#
# What the workflow (.forgejo/workflows/ci.yml) actually opens:
#
#   ~/.ssh/forgejo_deploy         key for cloning over ssh://git@FORGE:2222
#   ~/.ssh/forgejo_known_hosts    host key for that clone -- NOT known_hosts
#   ~/.ssh/n100_ci_config         ssh alias `n100-ci` for the build host
#   ~/.ssh/n100_ci                key that alias authenticates with
#   ~/.ssh/n100_ci_known_hosts    host key for that alias
#
# Those three names come from KEY_STEM and BUILD_HOST_ALIAS below; the values
# shown are the defaults, which is what every provisioned runner carries.
#
# `known_hosts` and `forgejo_known_hosts` are different files. Installing only
# the first looks right and fails: checkout reads the second. That mistake cost
# its own pipeline run.
#
# Host keys are never taken on trust. Both fingerprints must be supplied and are
# compared against what keyscan returns; a mismatch installs nothing. Read them
# on the target hosts themselves, not from this machine:
#
#   build host: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
#   forge:      ssh-keyscan -p 2222 -t rsa 127.0.0.1 | ssh-keygen -lf -
set -eu

RUNNER_USER=${RUNNER_USER:-forgejo-runner}
RUNNER_HOME=${RUNNER_HOME:-/var/lib/forgejo-runner}
SSH_DIR="${RUNNER_HOME}/.ssh"

# Defaults are the internal Hyper-V segment: inter-VM service traffic stays off
# the LAN. The alias keeps a name rather than an address on purpose -- TLS and
# host-key checking are both name-bound.
BUILD_HOST=${BUILD_HOST:-198.51.100.11}
FORGE_HOST=${FORGE_HOST:-git.example.lan}
FORGE_PORT=${FORGE_PORT:-2222}
BUILD_USER=${BUILD_USER:-ci_deployer}

# The build host is named by its role in the pipeline, not by the model of the
# machine filling it. These defaults are the names already on every provisioned
# runner and the ones .forgejo/workflows/ci.yml opens, so nothing on disk is
# renamed -- the machine's name simply stops being spelled into four files.
BUILD_HOST_ALIAS=${BUILD_HOST_ALIAS:-n100-ci}
KEY_STEM=${KEY_STEM:-n100_ci}

BUILD_FP=${BUILD_FP:-}
FORGE_FP=${FORGE_FP:-}

[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
id "$RUNNER_USER" >/dev/null 2>&1 || {
    echo "No such user: ${RUNNER_USER}. Run install.sh first." >&2
    exit 1
}
[ -n "$BUILD_FP" ] && [ -n "$FORGE_FP" ] || {
    echo 'BUILD_FP and FORGE_FP are required. See the header for how to read' >&2
    echo 'them on the hosts themselves; keyscan alone proves nothing.' >&2
    exit 1
}

# `install -d` re-applies ownership to a directory that already exists, and
# that has broken shared runtime directories here before. Create it only when
# it is absent; otherwise check what is there and leave it alone.
if [ -d "$SSH_DIR" ]; then
    _owner=$(stat -c '%U' "$SSH_DIR" 2>/dev/null || stat -f '%Su' "$SSH_DIR")
    [ "$_owner" = "$RUNNER_USER" ] || {
        echo "${SSH_DIR} belongs to ${_owner}, expected ${RUNNER_USER}." >&2
        echo 'Refusing to re-own a directory this script did not create.' >&2
        exit 1
    }
else
    install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0700 "$SSH_DIR"
fi

# Keys are generated here and never copied between machines: one runner, one
# revocable identity. Existing keys are kept -- rerunning this must not orphan
# a key already registered with the forge.
for key in "$KEY_STEM" forgejo_deploy; do
    if [ -f "${SSH_DIR}/${key}" ]; then
        echo "keeping existing ${key}"
    else
        su -s /bin/sh -c "ssh-keygen -t ed25519 -N '' -q -f ${SSH_DIR}/${key} \
            -C ${key}@$(hostname)" "$RUNNER_USER"
        echo "generated ${key}"
    fi
done

# verify_host_key <scan-command> <expected> <destination>
verify_host_key()
{
    _scan=$1; _expect=$2; _dest=$3
    _tmp="${SSH_DIR}/.scan.$$"
    # shellcheck disable=SC2086
    $_scan > "$_tmp" 2>/dev/null || true
    [ -s "$_tmp" ] || { rm -f "$_tmp"; echo "keyscan returned nothing for ${_dest}" >&2; exit 1; }
    _got=$(ssh-keygen -lf "$_tmp" | cut -d' ' -f2)
    if [ "$_got" != "$_expect" ]; then
        rm -f "$_tmp"
        echo "Host key mismatch for ${_dest}" >&2
        echo "  expected ${_expect}" >&2
        echo "  got      ${_got}" >&2
        exit 1
    fi
    install -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0600 "$_tmp" "$_dest"
    rm -f "$_tmp"
    echo "verified host key -> $(basename "$_dest")"
}

verify_host_key "ssh-keyscan -t ed25519 ${BUILD_HOST}" \
    "$BUILD_FP" "${SSH_DIR}/${KEY_STEM}_known_hosts"
verify_host_key "ssh-keyscan -p ${FORGE_PORT} -t rsa ${FORGE_HOST}" \
    "$FORGE_FP" "${SSH_DIR}/forgejo_known_hosts"

# checkout reads forgejo_known_hosts; known_hosts is kept as a copy only so an
# interactive `ssh` from this host behaves the same way.
install -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0644 \
    "${SSH_DIR}/forgejo_known_hosts" "${SSH_DIR}/known_hosts"

cat > "${SSH_DIR}/${KEY_STEM}_config" <<EOF
Host ${BUILD_HOST_ALIAS}
    HostName ${BUILD_HOST}
    User ${BUILD_USER}
    IdentityFile ~/.ssh/${KEY_STEM}
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/${KEY_STEM}_known_hosts
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 2
EOF
chown "$RUNNER_USER:$RUNNER_USER" "${SSH_DIR}/${KEY_STEM}_config"
chmod 0600 "${SSH_DIR}/${KEY_STEM}_config"

echo
echo '=== register these two public keys, then the runner is complete ==='
echo
echo "1. build host ${BUILD_HOST}, append to the ${BUILD_USER} authorized_keys"
echo "   (restrict the source -- this host reaches it from the internal leg):"
echo
printf '   from="<this host internal address>" %s\n' "$(cat "${SSH_DIR}/${KEY_STEM}.pub")"
echo
echo '2. forge: add as a READ-ONLY deploy key on the project repository:'
echo
printf '   %s\n' "$(cat "${SSH_DIR}/forgejo_deploy.pub")"
echo
echo 'Verify before trusting it, from this host, as the runner user:'
echo "   sudo -u ${RUNNER_USER} env HOME=${RUNNER_HOME} \\"
echo "       ssh -F ${SSH_DIR}/${KEY_STEM}_config ${BUILD_HOST_ALIAS} health"
