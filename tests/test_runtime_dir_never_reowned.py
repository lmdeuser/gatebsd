"""No tool may re-own the shared runtime directory it merely locks inside.

``/var/run/gatebsd`` holds the agent's unix socket. The web UI runs as the
unprivileged service account and needs the group's traverse bit to reach that
socket, so the directory's group is load-bearing: lose it and every panel
request answers 503 "agent unavailable" while the agent itself is perfectly
healthy.

Five tools put their lock file in that directory and created it with
``install -d -o root -g wheel -m 0750 "$(dirname "$LOCK_FILE")"``. ``install -d``
re-applies owner, group and mode to a directory that *already exists*, so each
of them silently reset the group on every run. Measured on the router on
3 August 2026: the 2.9.49 package restart at 02:39 left the group ``gatebsd``,
``ru-bypass-update.sh`` ran from cron at 03:01, and from that minute the panel
was dead. ``gatebsd-failoverctl`` was fixed for exactly this in an earlier
release -- see ``tests/test_failoverctl_runtime_dir.py`` -- and the same call
survived in five more places.

Every test here *runs* the real script. The reintroduction tests run a copy with
the old ``install -d`` restored and assert the directory really does get
re-owned, so the guards are known to be measuring something.
"""
from __future__ import annotations

import grp
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBIN = ROOT / "sbin"

# `stat -f` is BSD; the harness also runs on Linux, where the same information
# comes out of `stat -c`.
STAT_STUB = """#!/bin/sh
if /usr/bin/stat -f '%u' / >/dev/null 2>&1; then
  exec /usr/bin/stat "$@"
fi
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') exec /usr/bin/stat -c '%u' "$@" ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    '%z') exec /usr/bin/stat -c '%s' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
"""

# The scripts re-exec themselves under lockf. Stopping at that point keeps the
# test to the one thing it is about: the directory call always happens before
# the re-exec, and letting the real work start would touch the live system.
LOCKF_STUB = "#!/bin/sh\nexit 0\n"
TRUE_STUB = "#!/bin/sh\nexit 0\n"
FALSE_STUB = "#!/bin/sh\nexit 1\n"


def two_distinct_groups() -> tuple[str, str]:
    """Two real groups on this host, neither of them root."""
    unique: list[str] = []
    for entry in grp.getgrall():
        if entry.gr_gid == 0 or entry.gr_name in unique:
            continue
        unique.append(entry.gr_name)
        if len(unique) == 2:
            break
    if len(unique) < 2:
        raise unittest.SkipTest("need two non-root groups to observe re-owning")
    return unique[0], unique[1]


@unittest.skipUnless(hasattr(os, "geteuid"), "POSIX only")
class RuntimeDirNeverReownedTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("re-owning a directory requires root")
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()

        self.owned_group, self.other_group = two_distinct_groups()

        # The shared runtime directory as the package's post-install leaves it.
        self.run_dir = self.root / "run"
        self.run_dir.mkdir(mode=0o750)
        os.chown(self.run_dir, 0, grp.getgrnam(self.owned_group).gr_gid)

        for name in ("lockf", "logger", "service", "zfs", "gzip", "zstreamdump"):
            self._write(name, LOCKF_STUB if name == "lockf" else TRUE_STUB)
        self._write("stat", STAT_STUB)
        # No network in the harness, and none wanted: a failed download ends
        # ru-bypass-update after the directory calls it is being judged on.
        self._write("fetch", FALSE_STUB)
        self._write("helper", TRUE_STUB)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    @property
    def _path(self) -> str:
        return f"{self.bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    def group_of(self, path: Path) -> str:
        return grp.getgrgid(path.stat().st_gid).gr_name

    # -- the five callers --------------------------------------------------
    #
    # Each entry is (script, extra environment, argv). The lock file is always
    # put inside the shared runtime directory, which is where the production
    # defaults put it.
    def cases(self) -> list[tuple[str, dict[str, str], list[str]]]:
        helper = str(self.bin / "helper")
        return [
            (
                "ru-bypass-update.sh",
                {
                    "GATEBSD_GATEWAY_CONF": str(self.root / "absent.conf"),
                    "RU_TABLE": str(self.root / "amnezia" / "ru_bypass.table"),
                    "GATEBSD_RU_UPDATE_LOCK": str(self.run_dir / "ru-bypass-update.lock"),
                    "GATEBSD_PYTHON_LAUNCHER": helper,
                    "GATEBSD_RU_ROUTES_HELPER": helper,
                },
                [],
            ),
            (
                "gatebsd-backup.sh",
                {
                    "GATEBSD_IMAGE_BACKUP_LOCK": str(self.run_dir / "image-backup.lock"),
                    "GATEBSD_IMAGE_BACKUP_DIR": str(self.root / "backups"),
                    "GATEBSD_VERSION_FILE": str(self.root / "VERSION"),
                },
                [],
            ),
            (
                "gatebsd-upgrade",
                {
                    "GATEBSD_UPGRADE_LOCK": str(self.run_dir / "upgrade.lock"),
                    # Both re-execs skipped: the directory call precedes them,
                    # and with no package argument the script stops at usage.
                    "GATEBSD_UPGRADE_LOCK_HELD": "1",
                    "GATEBSD_UPGRADE_CONFIG_LOCKS_HELD": "1",
                },
                [],
            ),
            (
                "gatebsd-ups-test.sh",
                {"GATEBSD_UPS_TEST_LOCK": str(self.run_dir / "ups-test.lock")},
                [],
            ),
            (
                "gatebsd-install",
                {"GATEBSD_INSTALL_LOCK": str(self.run_dir / "install.lock")},
                ["--dry-run"],
            ),
        ]

    def run_script(
        self,
        script: Path,
        extra: dict[str, str],
        argv: list[str],
        service_group: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": self._path,
            "GATEBSD_PATH": self._path,
            "HOME": str(self.root),
            "LANG": "C",
            "TMPDIR": str(self.root),
            **extra,
        }
        if service_group is not None:
            env["GATEBSD_SERVICE_GROUP"] = service_group
        return subprocess.run(
            ["sh", str(script), *argv],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_no_tool_reowns_the_shared_runtime_directory(self) -> None:
        for name, extra, argv in self.cases():
            with self.subTest(script=name):
                os.chown(self.run_dir, 0, grp.getgrnam(self.owned_group).gr_gid)
                result = self.run_script(SBIN / name, extra, argv)
                self.assertEqual(
                    self.group_of(self.run_dir),
                    self.owned_group,
                    f"{name} re-owned the agent socket's directory "
                    f"(exit {result.returncode}): {result.stderr}",
                )

    def test_ru_bypass_update_leaves_the_table_directory_alone(self) -> None:
        """The second `install -d` in the same script, on the config directory."""
        table_dir = self.root / "amnezia"
        table_dir.mkdir(mode=0o750)
        os.chown(table_dir, 0, grp.getgrnam(self.other_group).gr_gid)
        helper = str(self.bin / "helper")

        self.run_script(
            SBIN / "ru-bypass-update.sh",
            {
                "GATEBSD_GATEWAY_CONF": str(self.root / "absent.conf"),
                "RU_TABLE": str(table_dir / "ru_bypass.table"),
                "GATEBSD_RU_UPDATE_LOCK": str(self.run_dir / "ru-bypass-update.lock"),
                # Holding the lock skips the re-exec, so execution reaches the
                # table directory in this same process.
                "GATEBSD_RU_UPDATE_LOCK_HELD": "1",
                "GATEBSD_PYTHON_LAUNCHER": helper,
                "GATEBSD_RU_ROUTES_HELPER": helper,
            },
            [],
        )
        self.assertEqual(self.group_of(table_dir), self.other_group)

    def test_a_missing_runtime_directory_is_still_created(self) -> None:
        """Guarding an existing directory must not stop a fresh one being made."""
        for name, extra, argv in self.cases():
            with self.subTest(script=name):
                fresh = self.root / f"fresh-{name}"
                relocated = {
                    key: value.replace(str(self.run_dir), str(fresh))
                    for key, value in extra.items()
                }
                self.run_script(
                    SBIN / name, relocated, argv, service_group=self.owned_group
                )
                self.assertTrue(fresh.is_dir(), f"{name} did not create {fresh}")
                self.assertEqual(self.group_of(fresh), self.owned_group)
                self.assertEqual(fresh.stat().st_mode & 0o777, 0o750)

    # -- reintroduction ----------------------------------------------------
    def test_reintroducing_the_reowning_install_locks_the_ui_out(self) -> None:
        old_call = (
            f'install -d -o root -g {self.other_group} -m 0750 '
            '"$(dirname "$LOCK_FILE")"'
        )
        patterns = {
            "ru-bypass-update.sh": (
                r'ensure_private_root_dir "\$\(dirname "\$LOCK_FILE"\)" '
                r'"\$\{GATEBSD_SERVICE_GROUP:-gatebsd\}"',
                old_call,
            ),
            "gatebsd-backup.sh": (
                r'ensure_runtime_dir "\$\(dirname "\$LOCK_FILE"\)"', old_call
            ),
            "gatebsd-upgrade": (
                r'^ensure_runtime_dir "\$\(dirname "\$LOCK_FILE"\)"', old_call
            ),
            "gatebsd-ups-test.sh": (
                r'    ensure_runtime_dir "\$\(dirname "\$LOCK_FILE"\)"',
                "    " + old_call,
            ),
            "gatebsd-install": (
                r'    ensure_runtime_dir "\$\(dirname "\$LOCK_FILE"\)"',
                "    " + old_call,
            ),
        }
        by_name = {name: (extra, argv) for name, extra, argv in self.cases()}
        for name, (pattern, replacement) in patterns.items():
            with self.subTest(script=name):
                os.chown(self.run_dir, 0, grp.getgrnam(self.owned_group).gr_gid)
                extra, argv = by_name[name]
                flags = re.M if pattern.startswith("^") else 0
                source = (SBIN / name).read_text(encoding="utf-8")
                patched, count = re.subn(pattern, replacement, source, flags=flags)
                self.assertEqual(
                    count, 1, f"reintroduction pattern did not match once in {name}"
                )
                script = self.root / f"{name}-defective"
                script.write_text(patched, encoding="utf-8")
                script.chmod(0o755)

                self.run_script(script, extra, argv)
                self.assertEqual(
                    self.group_of(self.run_dir),
                    self.other_group,
                    f"the reintroduced defect in {name} did not re-own the "
                    "directory; the guard would be measuring nothing",
                )


class NonRootRuntimeDirInstallGuardTests(unittest.TestCase):
    """Run even when unprivileged: install -d must never run on existing dirs."""

    def test_h5_m5_existing_dirs_never_trigger_install_d(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            calls = root / "install.calls"
            existing_run = root / "run"
            existing_run.mkdir(mode=0o750)
            existing_db_sys = root / "db-sys"
            existing_db_sys.mkdir(mode=0o750)
            legacy_ru = root / "legacy-ru"
            legacy_ru.write_text("192.0.2.0/24\n", encoding="ascii")

            stubs = {
                "id": "#!/bin/sh\necho 0\n",
                "stat": (
                    "#!/bin/sh\n"
                    'if [ "$1" = -f ]; then\n'
                    '  fmt=$2; shift 2\n'
                    '  case "$fmt" in\n'
                    '    "%u") echo 0; exit 0 ;;\n'
                    '    "%Lp") exec /usr/bin/stat -c %a "$@" ;;\n'
                    '  esac\n'
                    'fi\n'
                    'exec /usr/bin/stat "$@"\n'
                ),
                "install": (
                    "#!/bin/sh\n"
                    f'printf "install %s\\n" "$*" >> "{calls}"\n'
                    'if [ "${1:-}" = -d ]; then exit 0; fi\n'
                    'while [ "$#" -gt 2 ]; do\n'
                    '  case "$1" in -o|-g|-m) shift 2 ;; *) break ;; esac\n'
                    'done\n'
                    'cp "$1" "$2"\n'
                ),
                "chown": "#!/bin/sh\nexit 0\n",
                "chmod": "#!/bin/sh\nexec /bin/chmod \"$@\"\n",
                "lockf": "#!/bin/sh\nexit 0\n",
                "service": "#!/bin/sh\nexit 1\n",
            }
            for name, body in stubs.items():
                p = bin_dir / name
                p.write_text(body, encoding="ascii")
                p.chmod(0o755)

            # 1. gatebsd-config-migrate: existing RU state parent dir must not trigger `install -d`.
            env_migrate = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_MAIN_CONF": str(root / "absent-main"),
                "GATEBSD_FAILOVER_CONF": str(root / "absent-failover"),
                "GATEBSD_GATEWAY_CONF": str(root / "absent-gateway"),
                "GATEBSD_UNBOUND_CONF": str(root / "absent-unbound"),
                "GATEBSD_PF_CONF": str(root / "absent-pf"),
                "GATEBSD_NGINX_CONF": str(root / "absent-nginx"),
                "GATEBSD_RC_DIR": str(root / "absent-rc"),
                "GATEBSD_SSHD_CONF": str(root / "absent-sshd"),
                "GATEBSD_SUDOERS_CONF": str(root / "absent-sudoers"),
                "GATEBSD_DB_DIR": str(root / "absent-ui-db"),
                "GATEBSD_LEGACY_RU_STATE": str(legacy_ru),
                "RU_STATE_FILE": str(existing_db_sys / "ru-routes.applied"),
            }
            res = subprocess.run(
                ["sh", str(SBIN / "gatebsd-config-migrate")],
                env=env_migrate, capture_output=True, text=True, check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)

            # 2. gatebsd-watchdog.sh ensure_root_dir on existing run_dir & existing db_sys.
            env_wd = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_FAILOVER_CONF": str(root / "absent-failover"),
                "GATEBSD_RUN_DIR": str(existing_run),
                "GATEBSD_ALLOW_TEST_RUN_DIR": "1",
                "RU_STATE_FILE": str(existing_db_sys / "ru-routes.applied"),
            }
            res_wd = subprocess.run(
                ["sh", str(SBIN / "gatebsd-watchdog.sh")],
                env=env_wd, capture_output=True, text=True, check=False,
            )
            self.assertEqual(res_wd.returncode, 0, res_wd.stderr)

            # 3. rc.d/gatebsd_failover _prepare_runtime_dir on existing run_dir.
            rc_src = (ROOT / "rc.d" / "gatebsd_failover").read_text(encoding="utf-8")
            fn_start = rc_src.index("_prepare_runtime_dir() {")
            fn_end = rc_src.index("\n}", fn_start) + 2
            rc_fn = rc_src[fn_start:fn_end]
            res_rc = subprocess.run(
                ["sh", "-eu", "-c", f'PATH="{bin_dir}:/usr/bin:/bin"; pidfile="{existing_run}/watchdog.pid"; {rc_fn}; _prepare_runtime_dir'],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(res_rc.returncode, 0, res_rc.stderr)

            logged = calls.read_text(encoding="utf-8") if calls.exists() else ""
            install_d_lines = [line for line in logged.splitlines() if line.startswith("install -d")]
            self.assertEqual(install_d_lines, [], f"install -d ran on existing directories: {install_d_lines}")


if __name__ == "__main__":
    unittest.main()
