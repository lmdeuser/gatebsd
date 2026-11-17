#!/bin/sh
# What counts as a leftover beside a managed file -- defined once.
#
# Two programs need this answer and must never give different ones: the
# verifier that reports leftovers, and the installer that retires them. A
# retirer with a narrower rule leaves behind exactly what the verifier keeps
# complaining about; a wider one carries off a file the verifier considers
# legitimate. That is the archetype this project keeps paying for -- the same
# name judged by different rules in different tools -- so the rule lives in one
# file that both source.
#
# Not a standalone script: source it.
#
#     . "$SCRIPT_DIR/leftovers.sh"
#     leftovers_beside /usr/local/sbin/mirror-health-check

# Print every path in a managed file's directory that is a leftover of it, one
# per line, sorted. The managed file itself is never printed. Prints nothing if
# the directory does not exist.
#
# A leftover is a sibling whose name is the managed name plus a suffix that
# marks it as another generation:
#
#     mirror-health-check.bak                         base + "."
#     mirror-health-check.before-review-20260730Z     base + "."
#     mirror-health-check-v2                          base + "-v"
#     .freebsd-local-repo                             a hidden copy of base
#
# The leading dot earns no exemption. cron(8) reads every file in a cron.d
# directory whatever it is called, and rcorder(8) reads every file in the
# startup directory the same way -- a dotted copy is not hidden from the
# program that runs it, only from the operator listing the directory. Both of
# those have already caused an outage here.
#
# KNOWN GAP -- read this before renaming a managed file.
#
# The rule is "sibling of a name still in the manifest". It therefore says
# nothing about a file whose manifest row was RENAMED: the old deployed copy is
# no longer any managed file's sibling, so it is not a leftover by this
# definition and both the verifier and the retirer report the directory clean.
#
# That happened on 16 August 2026, renaming n100_network_ready to
# stand_network_ready. `install-ci-host.sh --dry-run` printed "No leftovers
# beside managed files" while the previous script sat in rc.d with a live
# PROVIDE line -- two scripts at boot, and nothing would have said so. The old
# file was carried out by hand into the same retirement tree this pass uses.
#
# So: renaming a row here is a two-part change, and the second part is not
# automated. Move the old deployed file out yourself, and check the directory
# the way the program that reads it does -- `rcorder` for rc.d, the file list
# for cron.d. Widening this rule to cover it needs the previous manifest, which
# is in git and not in either program's hands; until that is built, this comment
# is the guard.
#
# One exemption, and it is not about the name: a file that pkg(8) registers to
# an installed package is that package's, not an older generation of ours.
# /usr/local/etc/poudriere.conf.sample belongs to poudriere-3.4.8 and matches
# `base + "."` exactly as a dated backup does. Carrying it off would leave
# `pkg check -s` reporting the port as damaged, and the next `pkg upgrade`
# would put it back -- so the retirer would move it again, every run, forever.
# Asking pkg who owns a file is cheap and is the only thing that distinguishes
# the two cases; the name cannot.
leftover_is_packaged() {
    command -v pkg >/dev/null 2>&1 || return 1
    pkg which -q -- "$1" >/dev/null 2>&1
}

# The same question one step wider, for verify-deployment.sh's scan of whole
# directories: does this file have a package behind it at all?
#
# Asking `pkg which` about the live file is not enough there. A FreeBSD port
# that ships editable configuration does not install it -- it installs a copy
# under one of four conventional names and lets the first install put it in
# place, so the live file belongs to no package while the port plainly
# accounts for it:
#
#     /usr/local/etc/poudriere.conf   <- poudriere.conf.sample   (@sample)
#     /usr/local/etc/nginx/nginx.conf <- nginx.conf-dist
#     /usr/local/etc/sudoers          <- sudoers.dist
#     /usr/local/etc/pam.d/sudo       <- sudo.default
#
# Without this, /usr/local/etc reports every configuration file on the machine
# and the handful that are actually ours are lost among them -- a verifier
# nobody can read is one nobody runs.
path_has_package_source() {
    if leftover_is_packaged "$1"; then
        return 0
    fi
    for _ps_suffix in .sample -dist .dist .default; do
        if leftover_is_packaged "$1$_ps_suffix"; then
            return 0
        fi
    done
    return 1
}

leftovers_beside() {
    _lb_target=$1
    _lb_dir=$(dirname "$_lb_target")
    _lb_base=$(basename "$_lb_target")

    [ -d "$_lb_dir" ] || return 0

    # Every branch below ends in a command that succeeds, and the function ends
    # in `return 0`. Callers run under `set -e`, and a loop whose final
    # iteration happens to end on a false test would otherwise abort them.
    find "$_lb_dir" -mindepth 1 -maxdepth 1 2>/dev/null | sort |
    while IFS= read -r _lb_path; do
        [ -n "$_lb_path" ] || continue
        [ "$_lb_path" != "$_lb_target" ] || continue

        # Before the name is judged at all: another package's file is not ours
        # to retire, whatever it happens to be called.
        if leftover_is_packaged "$_lb_path"; then
            continue
        fi

        _lb_name=$(basename "$_lb_path")
        _lb_dotted=0
        case "$_lb_name" in
            .*) _lb_name=${_lb_name#.}; _lb_dotted=1 ;;
        esac

        if [ "$_lb_name" = "Makefile.version" ]; then
            continue
        fi

        case "$_lb_name" in
            "$_lb_base".*|"$_lb_base"-v*)
                printf '%s\n' "$_lb_path"
                ;;
            "$_lb_base")
                # Only reachable for a dotted name: the undotted one is the
                # managed file, already excluded above.
                if [ "$_lb_dotted" -eq 1 ]; then
                    printf '%s\n' "$_lb_path"
                fi
                ;;
        esac
    done

    return 0
}
