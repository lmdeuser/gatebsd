#!/bin/sh
# Compatibility entrypoint.  All package generation is owned by ci/build.sh.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VERSION=${1:-$(cat "$ROOT/VERSION")}
STAGE=${STAGE:-$ROOT/pkg/stage}
DIST=${DIST:-$ROOT/dist}
exec env STAGE="$STAGE" DIST="$DIST" "$ROOT/ci/build.sh" "$VERSION"
