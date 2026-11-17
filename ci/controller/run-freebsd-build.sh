#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
COMMIT_SHA=${1:-$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)}

printf '%s' "$COMMIT_SHA" | grep -qE '^[0-9a-f]{40}$' || {
    echo 'A full lowercase Git commit SHA is required.' >&2
    exit 64
}

# Named by role, not by the model of the machine filling it. The defaults are
# the names provision-keys.sh writes on the runner, so this reaches exactly the
# host it always did.
BUILD_HOST_ALIAS=${BUILD_HOST_ALIAS:-n100-ci}
BUILD_SSH_CONFIG=${BUILD_SSH_CONFIG:-n100_ci_config}

exec ssh -F "$HOME/.ssh/${BUILD_SSH_CONFIG}" "$BUILD_HOST_ALIAS" ci-build "$COMMIT_SHA"
