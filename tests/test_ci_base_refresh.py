from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ci" / "host" / "prepare-gatebsd-build-jail.sh"


class CiBaseRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.log = self.root / "zfs.log"
        self.zfs = self.root / "zfs"
        self.zfs.write_text(
            """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$LOG"
case "$*" in
    "get -H -o value origin $JAIL_DATASET")
        if [ "$ORIGIN" = "$PRISTINE_SNAPSHOT" ] && [ ! -f "$STATE/promoted" ]; then
            printf '%s\n' "$PRISTINE_SNAPSHOT"
        else
            printf '%s\n' '-'
        fi
        ;;
    "promote $JAIL_DATASET")
        [ "$ORIGIN" = "$PRISTINE_SNAPSHOT" ] || exit 1
        : > "$STATE/promoted"
        ;;
    "destroy $PRISTINE_SNAPSHOT")
        if [ "$ORIGIN" = "$PRISTINE_SNAPSHOT" ] && [ ! -f "$STATE/promoted" ]; then
            echo "cannot destroy snapshot: dataset has clones" >&2
            exit 1
        fi
        : > "$STATE/pristine-destroyed"
        ;;
    "list -H $PRISTINE_SNAPSHOT")
        [ ! -f "$STATE/pristine-destroyed" ] || exit 1
        ;;
    "snapshot $PRISTINE_SNAPSHOT")
        if [ ! -f "$STATE/promoted" ] && [ ! -f "$STATE/pristine-destroyed" ]; then
            echo "cannot create snapshot: dataset already exists" >&2
            exit 1
        fi
        ;;
    "destroy -r $STAGING_DATASET") ;;
    "send $PRISTINE_SNAPSHOT") printf 'snapshot-stream\n' ;;
    "receive $STAGING_DATASET") cat >/dev/null; : > "$STATE/independent" ;;
    "set mountpoint=$STAGING_ROOT $STAGING_DATASET") ;;
    "clone -o mountpoint=$STAGING_ROOT $PRISTINE_SNAPSHOT $STAGING_DATASET")
        : > "$STATE/dependent"
        ;;
    *) echo "unexpected zfs call: $*" >&2; exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        self.zfs.chmod(0o755)
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("STAGING_DATASET=${JAIL_DATASET}-new")
        end = source.index("JAIL_DATASET_FINAL=", start)
        self.segment = source[start:end]

    def run_segment(self, origin: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.root}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "LOG": str(self.log),
            "STATE": str(self.state),
            "ORIGIN": origin,
            "JAIL_DATASET": "tank/ci/base/freebsd_151_amd64",
            "JAIL_ROOT": "/tank/ci/base/freebsd_151_amd64",
            "PRISTINE_SNAPSHOT": "tank/packages/poudriere/jails/freebsd_151_amd64@gatebsd-pristine",
            "STAGING_DATASET": "tank/ci/base/freebsd_151_amd64-new",
            "STAGING_ROOT": "/tank/ci/base/freebsd_151_amd64-new",
        })
        return subprocess.run(
            ["/bin/sh", "-eu", "-c", self.segment],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def assert_independent_staging(self, origin: str) -> None:
        pristine = "tank/packages/poudriere/jails/freebsd_151_amd64@gatebsd-pristine"
        result = self.run_segment(origin)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        operations = self.log.read_text(encoding="utf-8").splitlines()
        self.assertIn(f"send {pristine}", operations)
        self.assertIn("receive tank/ci/base/freebsd_151_amd64-new", operations)
        self.assertNotIn("promote tank/ci/base/freebsd_151_amd64", operations)
        self.assertNotIn(
            f"clone -o mountpoint=/tank/ci/base/freebsd_151_amd64-new {pristine} "
            "tank/ci/base/freebsd_151_amd64-new",
            operations,
        )
        self.assertTrue((self.state / "independent").exists())
        self.assertFalse((self.state / "dependent").exists())

    def test_refresh_detaches_staging_from_the_previous_base_origin(self) -> None:
        self.assert_independent_staging(
            "tank/packages/poudriere/jails/freebsd_151_amd64@gatebsd-pristine"
        )

    def test_an_independent_previous_base_also_gets_independent_staging(self) -> None:
        self.assert_independent_staging("-")


    def test_poudriere_jail_updated_before_staging_and_verified_pristine(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        update_pos = script.find('poudriere jail -u -j "$JAIL_NAME"')
        staging_pos = script.find("STAGING_DATASET=${JAIL_DATASET}-new")
        self.assertNotEqual(update_pos, -1)
        self.assertNotEqual(staging_pos, -1)
        self.assertLess(
            update_pos,
            staging_pos,
            "poudriere jail -u must update the jail BEFORE creating the staging clone",
        )
        post_update = script[update_pos:staging_pos]
        self.assertIn(
            'pkg -r "$POUDRIERE_JAIL_ROOT" info',
            post_update,
            "jail cleanliness must be re-checked after poudriere jail -u",
        )


if __name__ == "__main__":
    unittest.main()
