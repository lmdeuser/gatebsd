#!/bin/sh
# Keep the stand's TLS certificate alive.
#
# nginx serves both Forgejo and the mirror with one leaf issued by the local
# step-ca (CN=buildhost.example.lan, ~30 day lifetime). Nothing renewed it: the certificate
# was minted by hand and the CA trusted by hand, so the pipeline died in July
# when it lapsed and was set to die again on 29 August 2026. The root and
# intermediate are good until 2036 -- only the leaf needs attention, and only
# the leaf is touched here.
#
# What renewal does NOT do is change the names in the certificate.
#
# `step ca renew` reissues the same identity: same CN, same SAN list. A wrong
# name in there is therefore not something that ages out -- it is reissued every
# thirty days for as long as this runs, and no amount of renewal will remove it.
#
# That was not hypothetical. Until 16 August 2026 the leaf asserted two
# addresses for things that had ceased to exist: the physical stand, by then
# reformatted, and a libvirt bridge the VM never had. Renewal had been faithfully
# carrying both forward. They were dropped by a fresh issuance -- a CSR made from
# the existing private key, so the key never changed and the previous certificate
# stayed valid as a rollback -- and the addresses actually in use were added in
# the same pass.
#
# The lesson to keep: fixing a name here takes an issuance, not a renewal, and
# every DNS name in the current SAN must survive it. The runner's checkout
# resolves `git.example.lan` and delivery resolves `mirror.example.lan`; a leaf that drops either
# locks out the pipeline that would fix it. Verify against the existing key, the
# chain and `nginx -t` before replacing the live file, and keep the old one.
#
# Renewal authenticates over mTLS with the certificate being replaced, so this
# must run while that certificate is still valid. Hence a wide window: at
# fifteen days there are fourteen more chances before anything breaks, and
# `step ca renew --expires-in` adds its own jitter and is a no-op outside it.
#
# The running TLS configuration is only ever replaced by something that has
# been checked first: the new certificate must parse, must expire later than
# the one it replaces, must match the private key already in use, and nginx
# must accept the result. Any of those failing leaves the old certificate in
# place -- a stand serving an expiring certificate is recoverable, a stand
# serving a broken one locks out the very pipeline that would fix it.
set -eu

PATH=${STAND_TLS_PATH:-/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin}
export PATH

CERT=${STAND_TLS_CERT:-/usr/local/etc/ssl/n100-tls/server.crt}
KEY=${STAND_TLS_KEY:-/usr/local/etc/ssl/n100-tls/server.key}
CA_URL=${STAND_TLS_CA_URL:-https://127.0.0.1:9000}
CA_ROOT=${STAND_TLS_CA_ROOT:-/usr/local/etc/step/ca/certs/root_ca.crt}
EXPIRES_IN=${STAND_TLS_EXPIRES_IN:-360h}
STEP=${STAND_TLS_STEP:-/usr/local/bin/step}
OPENSSL=${STAND_TLS_OPENSSL:-/usr/bin/openssl}
NGINX=${STAND_TLS_NGINX:-/usr/local/sbin/nginx}
RELOAD=${STAND_TLS_RELOAD:-service nginx reload}

log() { printf '[renew-stand-tls] %s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

not_after() { "$OPENSSL" x509 -in "$1" -noout -enddate | sed 's/^notAfter=//'; }

# Production is FreeBSD, where date(1) parses with -j -f; the regression harness
# runs on Linux, where it parses with -d. Without both forms the lifetime
# comparison below silently fails to parse and every renewal is refused -- which
# is safe, but it also made two tests pass for the wrong reason.
not_after_epoch() {
    _stamp=$(not_after "$1")
    date -j -f '%b %e %T %Y %Z' "$_stamp" '+%s' 2>/dev/null \
        || date -d "$_stamp" '+%s' 2>/dev/null
}

file_mode() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null; }

# Replace the live certificate without re-owning it. This project has already
# paid for `install -o root -g wheel` applied to something that existed: it
# re-applies ownership, and both shared runtime directories were broken that
# way. The certificate is already owned correctly; copy alongside, match the
# mode that is actually there, and rename over it in one step so nginx can
# never read a half-written file.
put_in_place() {
    _staged="${CERT}.renew.$$"
    cp "$1" "$_staged" || die "cannot stage the certificate next to $CERT"
    _mode=$(file_mode "$CERT")
    case "${_mode:-}" in
        ''|*[!0-7]*) _mode=0644 ;;
    esac
    chmod "$_mode" "$_staged" || die "cannot set the certificate mode"
    mv -f "$_staged" "$CERT" || die "cannot move the certificate into place"
}

for _f in "$CERT" "$KEY" "$CA_ROOT"; do
    [ -f "$_f" ] && [ ! -L "$_f" ] || die "missing or unsafe file: $_f"
done
[ -x "$STEP" ] || die "step CLI is unavailable: $STEP"

current_end=$(not_after "$CERT")
log "current certificate expires $current_end"

work=$(mktemp -d "${TMPDIR:-/var/tmp}/renew-stand-tls.XXXXXX") || die "cannot create a work directory"
trap 'rm -rf "$work"' EXIT HUP INT TERM
candidate="$work/server.crt"

# --expires-in makes this a no-op while there is still plenty of time. step
# leaves no output file in that case, which is how "not yet" is told apart from
# "failed" -- a distinction worth making explicitly, because a renewal script
# that cries wolf nightly stops being read.
if ! "$STEP" ca renew --force --expires-in "$EXPIRES_IN" \
        --ca-url "$CA_URL" --root "$CA_ROOT" \
        --out "$candidate" "$CERT" "$KEY" >"$work/step.log" 2>&1; then
    sed 's/^/  /' "$work/step.log" >&2 || true
    die "step ca renew failed"
fi
if [ ! -s "$candidate" ]; then
    log "not due for renewal yet (window ${EXPIRES_IN}); nothing to do"
    exit 0
fi

"$OPENSSL" x509 -in "$candidate" -noout >/dev/null 2>&1 \
    || die "the renewed file is not a certificate"

new_epoch=$(not_after_epoch "$candidate" || true)
old_epoch=$(not_after_epoch "$CERT" || true)
case "${new_epoch:-}${old_epoch:-}" in
    ''|*[!0-9]*) die "cannot compare certificate lifetimes" ;;
esac
[ "$new_epoch" -gt "$old_epoch" ] \
    || die "the renewed certificate does not outlive the current one"

# The private key is reused by `step ca renew`, but proving it rather than
# assuming it costs one comparison and rules out serving a certificate no
# client can complete a handshake against.
new_pub=$("$OPENSSL" x509 -in "$candidate" -noout -pubkey) || die "cannot read the new public key"
key_pub=$("$OPENSSL" pkey -in "$KEY" -pubout) || die "cannot read the private key"
[ "$new_pub" = "$key_pub" ] || die "the renewed certificate does not match the private key"

backup="$work/previous.crt"
cp -p "$CERT" "$backup"
put_in_place "$candidate"

if [ -x "$NGINX" ] && ! "$NGINX" -t >"$work/nginx.log" 2>&1; then
    put_in_place "$backup"
    sed 's/^/  /' "$work/nginx.log" >&2 || true
    die "nginx rejected the renewed certificate; the previous one was restored"
fi

log "renewed: $current_end -> $(not_after "$CERT")"

# The reload comes last and its failure is reported but not fatal: the new
# certificate on disk is correct either way, and the next run of this script --
# or a human -- can reload. Undoing a good renewal because a reload hiccuped
# would be the worse trade.
if [ -n "$RELOAD" ]; then
    if $RELOAD >"$work/reload.log" 2>&1; then
        log "nginx reloaded"
    else
        sed 's/^/  /' "$work/reload.log" >&2 || true
        log "WARNING: the certificate was renewed but nginx was not reloaded"
    fi
fi
