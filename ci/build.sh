#!/bin/sh
# Canonical GateBSD package builder for FreeBSD.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")
APP_VERSION=${1:-$(cat "$REPO_DIR/VERSION")}
case "$APP_VERSION" in
    ''|*[!A-Za-z0-9+_.-]*|[.-]*|*..*) echo "Invalid GateBSD version: $APP_VERSION" >&2; exit 2 ;;
esac
REVISION=${PKG_REVISION:-$(cat "$REPO_DIR/PKG_REVISION" 2>/dev/null || printf '0')}
case "$REVISION" in
    0|'') PKG_VERSION=$APP_VERSION ;;
    *[!0-9]*) echo "Invalid PKG_REVISION: $REVISION" >&2; exit 2 ;;
    *) PKG_VERSION="${APP_VERSION}_${REVISION}" ;;
esac
STAGE=${STAGE:-/tank/packages/gatebsd-build/stage}
DIST=${DIST:-/tank/packages/gatebsd-build/dist}
LOCALBASE=${LOCALBASE:-/usr/local}

canonical_build_path() {
    _value=$1
    case "$_value" in /*) ;; *) echo "Build path must be absolute: $_value" >&2; exit 2 ;; esac
    [ ! -L "$_value" ] || { echo "Build path must not be a symlink: $_value" >&2; exit 2; }
    _parent=$(dirname "$_value")
    _base=$(basename "$_value")
    case "$_base" in ''|.|..) echo "Unsafe build path: $_value" >&2; exit 2 ;; esac
    _resolved_parent=$(realpath "$_parent" 2>/dev/null) || { echo "Build parent is unavailable: $_parent" >&2; exit 2; }
    printf '%s/%s\n' "$_resolved_parent" "$_base"
}
STAGE=$(canonical_build_path "$STAGE")
DIST=$(canonical_build_path "$DIST")
REPO_DIR=$(realpath "$REPO_DIR")
case "$STAGE" in /|/usr|/usr/local|/var|/tmp|"$REPO_DIR") echo "Unsafe STAGE: $STAGE" >&2; exit 2;; esac
case "$DIST" in /|/usr|/usr/local|/var|/tmp|"$REPO_DIR") echo "Unsafe DIST: $DIST" >&2; exit 2;; esac
[ "$STAGE" != "$DIST" ] || { echo "STAGE and DIST must differ" >&2; exit 2; }
case "$LOCALBASE" in /*) ;; *) echo "LOCALBASE must be absolute" >&2; exit 2 ;; esac
command -v pkg >/dev/null 2>&1 || { echo "pkg is required" >&2; exit 2; }

# The source tree never selects a Python minor version.  Resolve one installed
# versioned interpreter that can import sqlite3 and generate a stable launcher.
eval "$(LOCALBASE="$LOCALBASE" "$SCRIPT_DIR/resolve-python.sh")"

pkg_field() {
    _name=$1
    _format=$2
    _value=$(pkg query -e "%n = \"$_name\"" "$_format" 2>/dev/null | head -n 1)
    [ -n "$_value" ] || { echo "Required package is not installed or lacks metadata: $_name" >&2; exit 2; }
    case "$_value" in
        *[!A-Za-z0-9_./+,:@~=%-]*)
            echo "Unsafe package metadata for $_name: $_value" >&2
            exit 2
            ;;
    esac
    printf '%s' "$_value"
}

package_metadata() {
    _prefix=$1
    _name=$2
    eval "${_prefix}_VERSION=\$(pkg_field \"$_name\" '%v')"
    eval "${_prefix}_ORIGIN=\$(pkg_field \"$_name\" '%o')"
}

package_metadata PYTHON_PACKAGE_META "$PYTHON_PACKAGE"
package_metadata PYTHON_SQLITE "$PYTHON_SQLITE_PACKAGE"
package_metadata NGINX nginx
package_metadata ACME_SH acme.sh
package_metadata AMNEZIA_TOOLS amnezia-tools
package_metadata AMNEZIA_KMOD amnezia-kmod
# amnezia-kmod 3.1 carries profiles by default. Keep userspace for explicit
# `UserLand = true` and for H1..H4 <= 4, which the kernel rejects; both backends
# remain package dependencies so every accepted profile works after an upgrade.
package_metadata AMNEZIAWG_GO amneziawg-go
package_metadata MPD5 mpd5
package_metadata DHCPD isc-dhcp44-server
package_metadata UNBOUND unbound
package_metadata NUT nut
package_metadata SMARTMONTOOLS smartmontools
PYTHON_PACKAGE_VERSION=$PYTHON_PACKAGE_META_VERSION
PYTHON_PACKAGE_ORIGIN=$PYTHON_PACKAGE_META_ORIGIN

echo "=== Building GateBSD $PKG_VERSION with $PYTHON_CMD ($PYTHON_FLAVOR) ==="
rm -rf "$STAGE" "$DIST"
mkdir -p \
    "$STAGE/usr/local/share/gatebsd/webui/backend" \
    "$STAGE/usr/local/share/gatebsd/webui/frontend" \
    "$STAGE/usr/local/share/gatebsd/etc/gatebsd" \
    "$STAGE/usr/local/share/gatebsd/etc/nginx" \
    "$STAGE/usr/local/share/gatebsd/etc/unbound" \
    "$STAGE/usr/local/share/gatebsd/etc/amnezia" \
    "$STAGE/usr/local/share/gatebsd/etc/pkg/repos" \
    "$STAGE/usr/local/share/gatebsd/etc/pkg/keys" \
    "$STAGE/usr/local/libexec" \
    "$STAGE/usr/local/sbin" \
    "$STAGE/usr/local/etc/rc.d" \
    "$STAGE/usr/local/etc/gatebsd" \
    "$STAGE/usr/local/etc/cron.d" \
    "$STAGE/usr/local/etc/newsyslog.conf.d" \
    "$STAGE/boot/loader.conf.d" \
    "$DIST"

cp -R "$REPO_DIR/webui/backend/gatebsd_ui" "$STAGE/usr/local/share/gatebsd/webui/backend/"
cp "$REPO_DIR"/webui/frontend/*.html "$REPO_DIR"/webui/frontend/*.js "$REPO_DIR"/webui/frontend/*.css \
   "$STAGE/usr/local/share/gatebsd/webui/frontend/"
# The asset URLs carry the release version, so a browser holding an immutable
# copy of the previous one is asked for a different URL and actually updates.
"$REPO_DIR/scripts/stamp-frontend-version.sh" \
    "$STAGE/usr/local/share/gatebsd/webui/frontend" "$PKG_VERSION"
cp "$REPO_DIR/VERSION" "$STAGE/usr/local/share/gatebsd/VERSION"

install -m 0640 "$REPO_DIR/etc/gatebsd.conf" "$STAGE/usr/local/share/gatebsd/etc/gatebsd.conf.sample"
install -m 0600 "$REPO_DIR/etc/gatebsd/failover.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/gatebsd/failover.conf.sample"
install -m 0600 "$REPO_DIR/etc/gatebsd/duckdns.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/gatebsd/duckdns.conf.sample"
install -m 0644 "$REPO_DIR/etc/gatebsd/repo-sources.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/gatebsd/repo-sources.conf.sample"
install -m 0600 "$REPO_DIR/etc/gatebsd/split-dns.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/gatebsd/split-dns.conf.sample"
install -m 0644 "$REPO_DIR/etc/nginx/gatebsd.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/nginx/gatebsd.conf.sample"
[ ! -f "$REPO_DIR/etc/nginx/nginx.conf.sample" ] || install -m 0644 "$REPO_DIR/etc/nginx/nginx.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/nginx/nginx.conf.sample"
install -d -m 0755 "$STAGE/etc/ssh/sshd_config.d"
install -m 0644 "$REPO_DIR/etc/ssh/sshd_config.d/gatebsd.conf" "$STAGE/etc/ssh/sshd_config.d/gatebsd.conf"
install -d -m 0755 "$STAGE/usr/local/etc/nginx/conf.d" "$STAGE/usr/local/etc/sudoers.d"
install -m 0644 "$REPO_DIR/etc/nginx/gatebsd-limits.conf" "$STAGE/usr/local/etc/nginx/conf.d/gatebsd-limits.conf"
install -m 0440 "$REPO_DIR/etc/sudoers.d/gatebsd-agent" "$STAGE/usr/local/etc/sudoers.d/gatebsd-agent"
install -m 0644 "$REPO_DIR/etc/unbound/unbound.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/unbound/unbound.conf.sample"
install -m 0600 "$REPO_DIR/etc/amnezia/gateway.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/amnezia/gateway.conf.sample"
install -m 0600 "$REPO_DIR/etc/amnezia/direct-exceptions.conf.sample" "$STAGE/usr/local/share/gatebsd/etc/amnezia/direct-exceptions.conf.sample"
mkdir -p "$STAGE/usr/local/share/gatebsd/etc/nut"
for file in nut.conf ups.conf upsd.conf upsd.users upsmon.conf; do
    install -m 0640 "$REPO_DIR/etc/nut/$file.sample" "$STAGE/usr/local/share/gatebsd/etc/nut/$file.sample"
done

# The package repository config and the stand's public key. These are not
# samples and they are not device state: they are what makes a device take its
# packages from this project instead of upstream quarterly, and both delivery
# paths have to agree on them or the versions stop meaning anything. They are
# carried under share/ rather than installed straight into /usr/local/etc/pkg
# because gatebsd-repo-bootstrap owns that destination -- a bare device runs it
# before this package exists, and post-install runs it again afterwards, so
# there is one writer instead of two.
# The DoH endpoint list is a pf table file, not a sample: pf refuses to load a
# persist table whose file is missing and fails the entire ruleset doing it, so
# this has to be on the device before the rule that names it.
install -m 0644 "$REPO_DIR/etc/gatebsd/doh-endpoints" "$STAGE/usr/local/etc/gatebsd/doh-endpoints"
install -m 0644 "$REPO_DIR/etc/gatebsd/adblock-extra" "$STAGE/usr/local/etc/gatebsd/adblock-extra"

install -m 0644 "$REPO_DIR/etc/pkg/repos/gatebsd.conf" "$STAGE/usr/local/share/gatebsd/etc/pkg/repos/gatebsd.conf"
install -m 0444 "$REPO_DIR/etc/pkg/keys/gatebsd-stand.pub" "$STAGE/usr/local/share/gatebsd/etc/pkg/keys/gatebsd-stand.pub"

cat > "$STAGE/usr/local/share/gatebsd/etc/gatebsd/required-packages" <<EOF
$PYTHON_PACKAGE
$PYTHON_SQLITE_PACKAGE
nginx
acme.sh
amnezia-tools
amnezia-kmod
amneziawg-go
mpd5
isc-dhcp44-server
unbound
nut
smartmontools
EOF
chmod 0644 "$STAGE/usr/local/share/gatebsd/etc/gatebsd/required-packages"

sed "s|%%PYTHON_CMD%%|$PYTHON_CMD|g" "$REPO_DIR/libexec/gatebsd-python.in" > "$STAGE/usr/local/libexec/gatebsd-python"
chmod 0755 "$STAGE/usr/local/libexec/gatebsd-python"

for file in gatewayctl gatebsd-route-op gatebsd-port-forward gatebsd-watchdog.sh gatebsd-healthcheck.sh gatebsd-backup.sh \
    gatebsd-adblock-update.sh gatebsd-ups-health.sh gatebsd-ups-test.sh gatebsd-ups-bootstrap \
    gatebsd-renew-ssl ru-routes.sh ru-bypass-update.sh gatebsd-passwd gatebsd-install \
    gatebsd-upgrade gatebsd-config-guard gatebsd-firstboot gatebsd-scan gatebsd-collect gatebsd-failoverctl \
    gatebsd-config-migrate gatebsd-lock-cleanup gatebsd-repo-bootstrap gatebsd-agentctl \
    gatebsd-reverse-ssh gatebsd-sms-monitor gatebsd-state-value; do
    [ ! -f "$REPO_DIR/sbin/$file" ] || install -m 0755 "$REPO_DIR/sbin/$file" "$STAGE/usr/local/sbin/$file"
done
for file in gatebsd_firstboot gatebsd_lock_cleanup gatebsd gatebsd_failover ru_bypass gatewayctl_apply gatebsd_reverse_ssh; do
    [ ! -f "$REPO_DIR/rc.d/$file" ] || install -m 0755 "$REPO_DIR/rc.d/$file" "$STAGE/usr/local/etc/rc.d/$file"
done
for file in gatebsd-healthcheck gatebsd-adblock gatebsd-ups-health gatebsd-ups-test gatebsd-ssl-renew gatebsd-sms-monitor ru-bypass; do
    [ ! -f "$REPO_DIR/etc/cron.d/$file" ] || install -m 0644 "$REPO_DIR/etc/cron.d/$file" "$STAGE/usr/local/etc/cron.d/$file"
done
[ ! -f "$REPO_DIR/etc/newsyslog.conf.d/gatebsd.conf" ] || install -m 0644 "$REPO_DIR/etc/newsyslog.conf.d/gatebsd.conf" "$STAGE/usr/local/etc/newsyslog.conf.d/gatebsd.conf"
# Loader settings live outside PREFIX; the package owns the file, not the
# operator's /boot/loader.conf. Takes effect on the next boot, by design. Same
# installer the make path uses -- one implementation, not two.
"$REPO_DIR/scripts/install-loader-conf.sh" -s "$REPO_DIR/etc/loader.conf.d/gatebsd.conf" "$STAGE/boot/loader.conf.d"

find "$STAGE" -name '*.pyc' -delete
find "$STAGE" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

"$SCRIPT_DIR/verify-python-tree.sh" \
    "$REPO_DIR/webui/backend" \
    "$STAGE/usr/local/share/gatebsd/webui/backend" \
    "$STAGE/usr/local/libexec/gatebsd-python"

# Fail the build if runtime scripts bypass the stable launcher.
if grep -RInE '/usr/local/bin/python3([.][0-9]+)?|#!/usr/bin/env python3' \
    "$STAGE/usr/local/etc" "$STAGE/usr/local/sbin" "$STAGE/usr/local/share/gatebsd/webui/backend" >/dev/null 2>&1; then
    echo "Runtime Python invocation bypasses /usr/local/libexec/gatebsd-python" >&2
    grep -RInE '/usr/local/bin/python3([.][0-9]+)?|#!/usr/bin/env python3' \
        "$STAGE/usr/local/etc" "$STAGE/usr/local/sbin" "$STAGE/usr/local/share/gatebsd/webui/backend" >&2 || true
    exit 2
fi

if find "$STAGE" -type f | sed "s|^$STAGE/||" | grep -q '[^A-Za-z0-9_./+@,:=-]'; then
    echo "Staged package contains a filename unsafe for manifest generation" >&2
    exit 2
fi

# Walk the whole stage, not $STAGE/usr/local. The package prefix is
# /usr/local, but not everything this product installs lives under it:
# /boot/loader.conf.d/gatebsd.conf is staged and would otherwise be dropped
# here without a word -- staged, never packaged, and the defect only visible
# on the device. Whatever the stage holds is what the package carries.
FILES_LIST=$(cd "$STAGE" && find . -type f | sed 's|^\./||' | sort | while IFS= read -r file; do
    permissions='""'
    case "$file" in
        usr/local/sbin/*|usr/local/libexec/gatebsd-python|usr/local/etc/rc.d/*) permissions='"0755"' ;;
    esac
    printf '    /%s: %s\n' "$file" "$permissions"
done)

cat > "$DIST/manifest.ucl" <<MANEOF
name: gatebsd
version: "$PKG_VERSION"
origin: local/gatebsd
comment: "FreeBSD router management web UI"
maintainer: "gatebsd@example.invalid"
prefix: /usr/local
licenselogic: single
licenses: [proprietary]
www: "https://gatebsd.local"
desc: "GateBSD - web UI for managing a FreeBSD-based home router."

deps: {
    $PYTHON_PACKAGE: { origin: "$PYTHON_PACKAGE_ORIGIN", version: "$PYTHON_PACKAGE_VERSION" }
    $PYTHON_SQLITE_PACKAGE: { origin: "$PYTHON_SQLITE_ORIGIN", version: "$PYTHON_SQLITE_VERSION" }
    nginx: { origin: "$NGINX_ORIGIN", version: "$NGINX_VERSION" }
    acme.sh: { origin: "$ACME_SH_ORIGIN", version: "$ACME_SH_VERSION" }
    amnezia-tools: { origin: "$AMNEZIA_TOOLS_ORIGIN", version: "$AMNEZIA_TOOLS_VERSION" }
    amnezia-kmod: { origin: "$AMNEZIA_KMOD_ORIGIN", version: "$AMNEZIA_KMOD_VERSION" }
    amneziawg-go: { origin: "$AMNEZIAWG_GO_ORIGIN", version: "$AMNEZIAWG_GO_VERSION" }
    mpd5: { origin: "$MPD5_ORIGIN", version: "$MPD5_VERSION" }
    isc-dhcp44-server: { origin: "$DHCPD_ORIGIN", version: "$DHCPD_VERSION" }
    unbound: { origin: "$UNBOUND_ORIGIN", version: "$UNBOUND_VERSION" }
    nut: { origin: "$NUT_ORIGIN", version: "$NUT_VERSION" }
    smartmontools: { origin: "$SMARTMONTOOLS_ORIGIN", version: "$SMARTMONTOOLS_VERSION" }
}

files: {
$FILES_LIST
}

scripts: {
    post-install: <<EOS
#!/bin/sh
set -eu
safe_dir() {
    _dir=\$1; _owner=\$2; _group=\$3; _mode=\$4
    if [ -e "\$_dir" ] || [ -L "\$_dir" ]; then
        [ -d "\$_dir" ] && [ ! -L "\$_dir" ] || { echo "Unsafe GateBSD directory: \$_dir" >&2; exit 1; }
    fi
    install -d -o "\$_owner" -g "\$_group" -m "\$_mode" "\$_dir"
}
safe_sample() {
    _source=\$1; _destination=\$2; _mode=\$3
    if [ -e "\$_destination" ] || [ -L "\$_destination" ]; then
        [ -f "\$_destination" ] && [ ! -L "\$_destination" ] || { echo "Unsafe GateBSD config: \$_destination" >&2; exit 1; }
        return 0
    fi
    install -o root -g wheel -m "\$_mode" "\$_source" "\$_destination"
}
pw groupshow gatebsd >/dev/null 2>&1 || pw groupadd gatebsd
if pw usershow gatebsd >/dev/null 2>&1; then
    [ "\$(id -gn gatebsd)" = gatebsd ] || { echo "Existing gatebsd user has the wrong primary group" >&2; exit 1; }
    _shell=\$(pw usershow gatebsd | awk -F: '{print \$10}')
    [ "\$_shell" = /usr/sbin/nologin ] || { echo "Existing gatebsd user has an interactive shell" >&2; exit 1; }
else
    pw useradd gatebsd -g gatebsd -d /nonexistent -s /usr/sbin/nologin -c "GateBSD service account"
fi
pw groupshow gatebsd-agent >/dev/null 2>&1 || pw groupadd gatebsd-agent
if pw usershow gatebsd-agent >/dev/null 2>&1; then
    [ "\$(id -gn gatebsd-agent)" = gatebsd-agent ] || { echo "Existing gatebsd-agent user has the wrong primary group" >&2; exit 1; }
    _agent_shell=\$(pw usershow gatebsd-agent | awk -F: '{print \$10}')
    [ "\$_agent_shell" = /bin/sh ] || { echo "Existing gatebsd-agent user has an unexpected shell" >&2; exit 1; }
else
    pw useradd gatebsd-agent -g gatebsd-agent -d /home/gatebsd-agent -m -s /bin/sh -c "GateBSD limited automation"
fi
pw groupshow gatebsd-forward >/dev/null 2>&1 || pw groupadd gatebsd-forward
if pw usershow gatebsd-forward >/dev/null 2>&1; then
    [ "\$(id -gn gatebsd-forward)" = gatebsd-forward ] || { echo "Existing gatebsd-forward user has the wrong primary group" >&2; exit 1; }
    _forward_shell=\$(pw usershow gatebsd-forward | awk -F: '{print \$10}')
    [ "\$_forward_shell" = /usr/sbin/nologin ] || { echo "Existing gatebsd-forward user has an interactive shell" >&2; exit 1; }
else
    pw useradd gatebsd-forward -g gatebsd-forward -d /nonexistent -s /usr/sbin/nologin -c "GateBSD reverse SSH account"
fi
prune_cron_leftovers() {
    # cron(8) on FreeBSD parses *every* file in /usr/local/etc/cron.d, dotted
    # names included -- unlike sudoers' @includedir, which skips them. A single
    # leftover therefore registers the same job twice, and two copies of the
    # adblock updater running at 04:00 corrupted the generated blocklist on the
    # production router until unbound would no longer start from it. Only names
    # derived from files this package owns are touched.
    for _base in gatebsd-healthcheck gatebsd-adblock gatebsd-ups-health gatebsd-ups-test gatebsd-ssl-renew gatebsd-sms-monitor ru-bypass; do
        for _suffix in pkgsave pkgnew bak old orig save disabled; do
            _stale="/usr/local/etc/cron.d/\${_base}.\${_suffix}"
            [ -f "\$_stale" ] && [ ! -L "\$_stale" ] || continue
            echo "Removing duplicate cron entry: \$_stale" >&2
            rm -f "\$_stale"
        done
    done
}
prune_cron_leftovers

retire_legacy_ru_crontab() {
    # Before the update schedule belonged to the package, two hand-written
    # registrations accumulated on the production router: first cron.d/ru-bypass,
    # then the same command in /etc/crontab.  The package now owns the former.
    # Remove only the exact legacy system-crontab registration; similar operator
    # jobs, comments and differently scheduled commands are not ours to touch.
    _crontab=/etc/crontab
    [ -e "\$_crontab" ] || return 0
    [ -f "\$_crontab" ] && [ ! -L "\$_crontab" ] || {
        echo "Unsafe system crontab: \$_crontab" >&2
        exit 1
    }
    _uid=\$(stat -f '%u' "\$_crontab" 2>/dev/null || printf '%s' -1)
    _mode=\$(stat -f '%Lp' "\$_crontab" 2>/dev/null || printf '%s' 777)
    [ "\$_uid" = "\$(id -u)" ] || { echo "System crontab is not root-owned" >&2; exit 1; }
    case "\$_mode" in
        *[2367][0-7]|*[0-7][2367]) echo "System crontab is group/world writable" >&2; exit 1 ;;
    esac

    _cron_dir=\${_crontab%/*}
    _candidate="\$_cron_dir/.gatebsd-crontab.candidate.\$\$"
    _published="\$_cron_dir/.gatebsd-crontab.publish.\$\$"
    trap 'rm -f "\$_candidate" "\$_published"' EXIT HUP INT TERM
    umask 077
    awk '
        NF == 10 &&
        \$1 == "0" && \$2 == "3" && \$3 == "*" && \$4 == "*" && \$5 == "*" &&
        \$6 == "root" &&
        \$7 == "/usr/local/sbin/ru-bypass-update.sh" &&
        \$8 == ">>" && \$9 == "/var/log/ru-bypass.log" && \$10 == "2>&1" {
            removed++
            next
        }
        { print }
    ' "\$_crontab" > "\$_candidate"
    if cmp -s "\$_crontab" "\$_candidate"; then
        rm -f "\$_candidate"
        trap - EXIT HUP INT TERM
        return 0
    fi
    # cp -p carries the existing owner, group and mode to a sibling path; the
    # following write changes only its contents, and rename publishes atomically.
    cp -p "\$_crontab" "\$_published"
    cat "\$_candidate" > "\$_published"
    mv -f "\$_published" "\$_crontab"
    rm -f "\$_candidate"
    trap - EXIT HUP INT TERM
    echo "Removed legacy RU update from /etc/crontab; package cron.d entry is authoritative" >&2
}
retire_legacy_ru_crontab

quarantine_rc_leftovers() {
    # rcorder(8) walks *every* file in the local startup directory -- it has no
    # extension filter at all, unlike nginx's \`include conf.d/*.conf\`, which is
    # why an orphaned copy there is inert and an orphaned copy here is not.
    # A hand-made backup named gatebsd.before-python-flavor-fix-20260718-142222
    # therefore kept its \`PROVIDE: gatebsd\` and ran at every boot ahead of the
    # real script, starting the UI under the pre-migration \`www\` identity while
    # the real script then handed the agent socket to \`gatebsd\`. The panel
    # answered "agent unavailable" from boot until someone noticed.
    #
    # Only siblings of the rc scripts this package owns are considered, and only
    # when no package owns them. They are moved rather than deleted: they are the
    # evidence of how the device drifted.
    _quarantine=/var/backups/gatebsd-rc
    for _name in gatebsd gatebsd_failover gatebsd_firstboot gatebsd_lock_cleanup ru_bypass gatewayctl_apply gatebsd_reverse_ssh; do
        for _stale in "/usr/local/etc/rc.d/\${_name}."* "/usr/local/etc/rc.d/\${_name}-"*; do
            [ -f "\$_stale" ] && [ ! -L "\$_stale" ] || continue
            pkg which -q "\$_stale" >/dev/null 2>&1 && continue
            install -d -o root -g wheel -m 0750 "\$_quarantine"
            echo "Quarantining shadowing rc script: \$_stale" >&2
            mv -f "\$_stale" "\$_quarantine/" || { echo "Failed to quarantine \$_stale" >&2; exit 1; }
        done
    done
}
quarantine_rc_leftovers

safe_dir /var/db/gatebsd gatebsd gatebsd 0750
safe_dir /var/db/gatebsd-system root wheel 0750
safe_dir /var/run/gatebsd root gatebsd 0750
safe_dir /usr/local/etc/gatebsd root wheel 0750
safe_dir /usr/local/etc/nginx/conf.d root wheel 0755
safe_dir /usr/local/etc/unbound root wheel 0755
safe_dir /usr/local/etc/amnezia root wheel 0750
safe_sample /usr/local/share/gatebsd/etc/amnezia/direct-exceptions.conf.sample /usr/local/etc/amnezia/direct-exceptions.conf 0600
safe_sample /usr/local/share/gatebsd/etc/gatebsd/failover.conf.sample /usr/local/etc/gatebsd/failover.conf 0600
# Fills a gap, never overwrites: this file is the operator's choice of package
# source, and an upgrade that reset it would drag a device off the mirror it
# was deliberately pointed at. A device without one is not broken -- the
# bootstrap falls back to the shipped default -- but an explicit file is what
# the panel edits, so it goes down before the bootstrap below reads it.
safe_sample /usr/local/share/gatebsd/etc/gatebsd/repo-sources.conf.sample /usr/local/etc/gatebsd/repo-sources.conf 0644
safe_sample /usr/local/share/gatebsd/etc/gatebsd/split-dns.conf.sample /usr/local/etc/gatebsd/split-dns.conf 0600
safe_sample /usr/local/share/gatebsd/etc/gatebsd.conf.sample /usr/local/etc/gatebsd/gatebsd.conf 0640
safe_sample /usr/local/share/gatebsd/etc/nginx/gatebsd.conf.sample /usr/local/etc/nginx/conf.d/gatebsd.conf 0644
safe_sample /usr/local/share/gatebsd/etc/unbound/unbound.conf.sample /usr/local/etc/unbound/unbound.conf 0644
# Converge the package repository config and the stand's trust key. Not a
# sample: a device pointing anywhere else stops being the product, so this
# overwrites rather than filling a gap -- and keeps what it overwrote under
# /var/backups/gatebsd-pkg. pkg has already read its own configuration by the
# time this runs, so the new content takes effect on the next pkg invocation,
# which is the same deal /boot/loader.conf.d gets.
/usr/local/sbin/gatebsd-repo-bootstrap
/usr/local/sbin/gatebsd-config-migrate
env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin HOME=/root LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/usr/local/share/gatebsd/webui/backend \
    /usr/local/libexec/gatebsd-python -m gatebsd_ui.integrity
env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin HOME=/root LANG=C.UTF-8 \
    PYTHONPATH=/usr/local/share/gatebsd/webui/backend /usr/local/libexec/gatebsd-python -m gatebsd_ui.storage
# Nothing is started from here, and that is not an oversight.
#
# pkg acquires a reaper for the processes its scripts spawn and SIGKILLs
# whatever is still alive when the script returns. Traced on the rig with
# DTrace on 2026-07-31, after the same thing had happened twice on the router:
#
#   pkg[61669] -> python3.12[61927] sig=9   the agent
#   pkg[61669] -> daemon[61925]     sig=9   its supervisor
#   pkg[61669] -> sh[62030]         sig=9   the failover watchdog
#   pkg[61669] -> lockf[62014]      sig=9
#
# So the previous version of this script started three services and pkg killed
# all three seconds later, leaving stale pidfiles and a router with no failover.
# setsid does not help: daemon(8) detaches from the terminal, not from the
# reaper, which is inherited. Nothing a package script starts can outlive it.
#
# Processes that existed *before* pkg ran are not descendants and are not
# touched, which is what makes the two working paths work:
#
#   - \`gatebsd-upgrade\`, which the web UI uses, restarts the services after pkg
#     has returned and gates the result on a health check. No gap;
#   - a bare \`pkg upgrade\` leaves them down, and gatebsd-healthcheck.sh restores
#     them from cron within a minute. That is the bound on how long a device can
#     be without failover after an upgrade done by hand.
printf '%s\n' 'GateBSD installed. Use the web UI to update and enable DNS ad blocking.'
EOS
    pre-deinstall: <<EOS
#!/bin/sh
set -u
service gatebsd stop 2>/dev/null || true
service gatebsd_failover stop 2>/dev/null || true
service gatebsd_reverse_ssh stop 2>/dev/null || true
EOS
}
MANEOF

pkg create -M "$DIST/manifest.ucl" -r "$STAGE" -o "$DIST"
MAIN_PACKAGE="$DIST/gatebsd-$PKG_VERSION.pkg"
[ -f "$MAIN_PACKAGE" ] || { echo "Main package was not created" >&2; exit 2; }
mv "$MAIN_PACKAGE" "$DIST/gatebsd-$PKG_VERSION-main.pkg"
pkg info -F "$DIST/gatebsd-$PKG_VERSION-main.pkg" >/dev/null

cat > "$DIST/manifest-nodeps.ucl" <<MANEOF
name: gatebsd
version: "$PKG_VERSION"
origin: local/gatebsd
comment: "GateBSD test package without dependencies"
maintainer: "gatebsd@example.invalid"
prefix: /usr/local
licenselogic: single
licenses: [proprietary]
www: "https://gatebsd.local"
desc: "GateBSD - dependency-free build used only for jail smoke tests."
files: {
$FILES_LIST
}
MANEOF
pkg create -M "$DIST/manifest-nodeps.ucl" -r "$STAGE" -o "$DIST"
mv "$DIST/gatebsd-$PKG_VERSION.pkg" "$DIST/gatebsd-$PKG_VERSION-nodeps.pkg"
mv "$DIST/gatebsd-$PKG_VERSION-main.pkg" "$DIST/gatebsd-$PKG_VERSION.pkg"
rm -f "$DIST/manifest.ucl" "$DIST/manifest-nodeps.ucl"

printf 'Built %s\n' "$DIST/gatebsd-$PKG_VERSION.pkg"
sha256 "$DIST/gatebsd-$PKG_VERSION.pkg"
