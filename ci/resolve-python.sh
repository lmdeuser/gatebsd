#!/bin/sh
# Resolve one coherent Python 3 runtime/flavor for GateBSD package generation.
# No Python minor release is selected in the source tree.  The chosen runtime
# must satisfy GateBSD's syntax baseline and import every required stdlib module.
set -eu

LOCALBASE=${LOCALBASE:-/usr/local}

fail() {
    echo "resolve-python: $*" >&2
    exit 2
}

parse_version() {
    _version=$1
    _major=${_version%%.*}
    _minor=${_version#*.}
    [ "$_major" != "$_version" ] || return 1
    case "$_major:$_minor" in
        *[!0-9:]*|:|*:) return 1 ;;
    esac
    [ -n "$_major" ] && [ -n "$_minor" ] || return 1
    PY_MAJOR=$_major
    PY_MINOR=$_minor
}

flavor_from_command() {
    _base=${1##*/}
    case "$_base" in
        python[0-9]*.[0-9]*) ;;
        *) return 1 ;;
    esac
    _version=${_base#python}
    parse_version "$_version" || return 1
    printf 'py%s%s\n' "$PY_MAJOR" "$PY_MINOR"
}

version_from_flavor() {
    _flavor=$1
    case "$_flavor" in
        py3[0-9]*) ;;
        *) return 1 ;;
    esac
    _abi=${_flavor#py}
    _major=$(printf '%s' "$_abi" | cut -c1)
    _minor=$(printf '%s' "$_abi" | cut -c2-)
    case "$_major:$_minor" in
        *[!0-9:]*|:|*:) return 1 ;;
    esac
    printf '%s.%s\n' "$_major" "$_minor"
}

runtime_ok() {
    "$1" -c '
import sys
if sys.version_info < (3, 10):
    raise SystemExit(1)
import base64, ctypes, fcntl, hashlib, hmac, http.server, ipaddress
import json, mimetypes, multiprocessing, os, pathlib, pty, selectors
import signal, socket, sqlite3, ssl, subprocess, tempfile, threading
' >/dev/null 2>&1
}

if [ -n "${PYTHON_FLAVOR:-}" ]; then
    PYTHON_VERSION=$(version_from_flavor "$PYTHON_FLAVOR") || fail "invalid PYTHON_FLAVOR: $PYTHON_FLAVOR"
fi

if [ -n "${PYTHON_CMD:-}" ]; then
    case "$PYTHON_CMD" in
        /*) ;;
        *) fail "PYTHON_CMD must be an absolute path" ;;
    esac
    case "$PYTHON_CMD" in
        *[!A-Za-z0-9_./+-]*) fail "PYTHON_CMD contains unsafe characters" ;;
    esac
    [ -x "$PYTHON_CMD" ] || fail "PYTHON_CMD is not executable: $PYTHON_CMD"
    _command_flavor=$(flavor_from_command "$PYTHON_CMD") || fail "PYTHON_CMD must end in pythonX.Y: $PYTHON_CMD"
    if [ -n "${PYTHON_FLAVOR:-}" ] && [ "$PYTHON_FLAVOR" != "$_command_flavor" ]; then
        fail "PYTHON_CMD and PYTHON_FLAVOR disagree"
    fi
    PYTHON_FLAVOR=$_command_flavor
    PYTHON_VERSION=${PYTHON_CMD##*python}
fi

if [ -z "${PYTHON_CMD:-}" ] && [ -n "${PYTHON_FLAVOR:-}" ]; then
    PYTHON_CMD="$LOCALBASE/bin/python$PYTHON_VERSION"
fi

if [ -z "${PYTHON_CMD:-}" ]; then
    _selected=
    _selected_score=-1
    for _candidate in "$LOCALBASE"/bin/python3.*; do
        [ -e "$_candidate" ] || continue
        [ -x "$_candidate" ] || continue
        _flavor=$(flavor_from_command "$_candidate" 2>/dev/null) || continue
        _version=${_candidate##*python}
        parse_version "$_version" || continue
        runtime_ok "$_candidate" || continue
        _score=$((PY_MAJOR * 10000 + PY_MINOR))
        if [ "$_score" -gt "$_selected_score" ]; then
            _selected=$_candidate
            _selected_score=$_score
        fi
    done
    [ -n "$_selected" ] || fail "no supported versioned Python 3 runtime found under $LOCALBASE/bin"
    PYTHON_CMD=$_selected
    PYTHON_VERSION=${PYTHON_CMD##*python}
    PYTHON_FLAVOR=$(flavor_from_command "$PYTHON_CMD")
fi

[ -x "$PYTHON_CMD" ] || fail "resolved interpreter does not exist: $PYTHON_CMD"
runtime_ok "$PYTHON_CMD" || fail "$PYTHON_CMD is older than Python 3.10 or lacks required standard modules"
PYTHON_ABI=${PYTHON_FLAVOR#py}
PYTHON_PACKAGE=python${PYTHON_ABI}
PYTHON_SQLITE_PACKAGE=${PYTHON_FLAVOR}-sqlite3

# Shell-safe output. Values are constrained above to absolute paths and tokens.
printf 'PYTHON_FLAVOR=%s\n' "$PYTHON_FLAVOR"
printf 'PYTHON_ABI=%s\n' "$PYTHON_ABI"
printf 'PYTHON_VERSION=%s\n' "$PYTHON_VERSION"
printf 'PYTHON_CMD=%s\n' "$PYTHON_CMD"
printf 'PYTHON_PACKAGE=%s\n' "$PYTHON_PACKAGE"
printf 'PYTHON_SQLITE_PACKAGE=%s\n' "$PYTHON_SQLITE_PACKAGE"
