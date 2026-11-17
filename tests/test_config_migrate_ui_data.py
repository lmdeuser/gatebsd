"""The web UI's data must follow the account the web UI runs as.

The defect these exist for: the UI used to run as ``www`` and wrote its state
with that identity. When it moved to its own unprivileged account, nothing
converted what was already on disk. On an *upgraded* device -- never on a fresh
one, which is why it survived so long -- ``/var/db/gatebsd`` was left holding
``auth.hash`` and ``session.secret`` owned by ``www`` while the UI ran as
``gatebsd``. The UI could not read its own credentials: login answered 503
"agent unavailable", and once past that every authenticated request died on the
session revocation file and nginx returned 502.

Every test runs ``sbin/gatebsd-config-migrate``.
"""
from __future__ import annotations

import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "sbin" / "gatebsd-config-migrate"


def three_distinct_accounts() -> tuple[str, str, str]:
    """Service account, legacy account, and an unrelated third."""
    names: list[str] = []
    for entry in pwd.getpwall():
        if entry.pw_uid == 0 or entry.pw_name in names:
            continue
        names.append(entry.pw_name)
        if len(names) == 3:
            break
    if len(names) < 3:
        raise unittest.SkipTest("need three non-root accounts")
    return names[0], names[1], names[2]


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class ConfigMigrateUiDataTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("migration chowns files; needs root")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.db = self.root / "db"
        self.db.mkdir(mode=0o750)

        self.service, self.legacy, self.foreign = three_distinct_accounts()
        self.service_uid = pwd.getpwnam(self.service).pw_uid
        self.legacy_uid = pwd.getpwnam(self.legacy).pw_uid
        self.foreign_uid = pwd.getpwnam(self.foreign).pw_uid
        self.service_gid = pwd.getpwnam(self.service).pw_gid

        # `pw` does not exist on the test host; the script only uses it to look
        # an account up, so a stub that answers from the real passwd database
        # keeps the behaviour honest.
        self._write(
            "pw",
            """#!/bin/sh
case "$1" in
  usershow) getent passwd "$2" ;;
  groupshow) getent group "$2" >/dev/null 2>&1 || getent passwd "$2" >/dev/null ;;
  *) exit 1 ;;
esac
""",
        )
        self._write(
            "stat",
            """#!/bin/sh
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') exec /usr/bin/stat -c '%u' "$@" ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
""",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def make_file(self, name: str, uid: int) -> Path:
        path = self.db / name
        path.write_text("x", encoding="ascii")
        os.chown(path, uid, uid)
        return path

    def run_migrate(self) -> subprocess.CompletedProcess[str]:
        path = f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin"
        return subprocess.run(
            ["sh", str(MIGRATE)],
            check=False,
            capture_output=True,
            text=True,
            env={
                "PATH": path,
                "GATEBSD_PATH": path,
                # Keep the migration away from anything real on the test host.
                "GATEBSD_MAIN_CONF": str(self.root / "absent-gatebsd.conf"),
                "GATEBSD_FAILOVER_CONF": str(self.root / "absent-failover.conf"),
                "GATEBSD_GATEWAY_CONF": str(self.root / "absent-gateway.conf"),
                "GATEBSD_LEGACY_RU_STATE": str(self.root / "absent-legacy-ru"),
                "RU_STATE_FILE": str(self.root / "absent-ru"),
                "GATEBSD_DB_DIR": str(self.db),
                "GATEBSD_SERVICE_USER": self.service,
                "GATEBSD_SERVICE_GROUP": self.service,
                "GATEBSD_LEGACY_UI_USER": self.legacy,
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def owner_of(self, path: Path) -> int:
        return path.stat().st_uid

    # -- the fix -----------------------------------------------------------
    def test_legacy_owned_credentials_are_handed_to_the_service_account(self) -> None:
        auth = self.make_file("auth.hash", self.legacy_uid)
        secret = self.make_file("session.secret", self.legacy_uid)

        result = self.run_migrate()
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertEqual(self.owner_of(auth), self.service_uid, result.stderr)
        self.assertEqual(self.owner_of(secret), self.service_uid, result.stderr)

    def test_root_owned_state_is_handed_over_too(self) -> None:
        """The agent writes some of this as root; the UI still has to read it."""
        report = self.make_file("last-recovery.json", 0)
        self.run_migrate()
        self.assertEqual(self.owner_of(report), self.service_uid)

    def test_the_directory_itself_becomes_traversable(self) -> None:
        os.chown(self.db, 0, 0)
        self.run_migrate()
        self.assertEqual(self.owner_of(self.db), self.service_uid)
        self.assertEqual(self.db.stat().st_gid, self.service_gid)

    def test_running_twice_changes_nothing_the_second_time(self) -> None:
        auth = self.make_file("auth.hash", self.legacy_uid)
        self.assertEqual(self.run_migrate().returncode, 0)
        first = self.owner_of(auth)
        self.assertEqual(self.run_migrate().returncode, 0)
        self.assertEqual(self.owner_of(auth), first)

    # -- refusals ----------------------------------------------------------
    def test_a_file_owned_by_nobody_we_know_is_left_alone(self) -> None:
        """Re-owning a stranger's file would hand it to the service account."""
        planted = self.make_file("planted", self.foreign_uid)
        result = self.run_migrate()
        self.assertEqual(self.owner_of(planted), self.foreign_uid, result.stderr)

    def test_a_symlink_is_never_followed(self) -> None:
        target = self.root / "outside"
        target.write_text("x", encoding="ascii")
        os.chown(target, self.foreign_uid, self.foreign_uid)
        (self.db / "auth.hash").symlink_to(target)

        self.run_migrate()

        self.assertEqual(
            self.owner_of(target),
            self.foreign_uid,
            "a planted symlink redirected the chown outside the data directory",
        )

    # -- reintroduction ----------------------------------------------------
    def test_without_the_migration_the_ui_cannot_read_its_credentials(self) -> None:
        """The shipped state: run the migration with the UI step removed.

        Proves the assertions above are measuring the migration and not some
        incidental ownership the test set up itself.
        """
        auth = self.make_file("auth.hash", self.legacy_uid)
        source = MIGRATE.read_text(encoding="utf-8")
        patched = source.replace("\nmigrate_ui_data_dir\n", "\n")
        self.assertNotEqual(patched, source, "reintroduction point not found")
        defective = self.root / "config-migrate-defective"
        defective.write_text(patched, encoding="utf-8")
        defective.chmod(0o755)

        path = f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin"
        subprocess.run(
            ["sh", str(defective)],
            check=False,
            capture_output=True,
            text=True,
            env={
                "PATH": path,
                "GATEBSD_PATH": path,
                "GATEBSD_MAIN_CONF": str(self.root / "absent-gatebsd.conf"),
                "GATEBSD_FAILOVER_CONF": str(self.root / "absent-failover.conf"),
                "GATEBSD_GATEWAY_CONF": str(self.root / "absent-gateway.conf"),
                "GATEBSD_LEGACY_RU_STATE": str(self.root / "absent-legacy-ru"),
                "RU_STATE_FILE": str(self.root / "absent-ru"),
                "GATEBSD_DB_DIR": str(self.db),
                "GATEBSD_SERVICE_USER": self.service,
                "GATEBSD_SERVICE_GROUP": self.service,
                "GATEBSD_LEGACY_UI_USER": self.legacy,
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

        self.assertEqual(
            self.owner_of(auth),
            self.legacy_uid,
            "the credentials stayed with the legacy account, as they did in the field",
        )


if __name__ == "__main__":
    unittest.main()
