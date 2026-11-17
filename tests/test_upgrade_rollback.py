"""Functional regression tests for the gatebsd-upgrade rollback path.

The defect these exist for is behavioural, not textual: ``rollback()`` returned
at the first failing step. A rollback that stops after ``pkg add`` leaves the
*new* configuration tree on disk against the *old* package, GateBSD and the
failover watchdog stopped, and no default route. On a box that is the site's
only internet uplink and has no out-of-band access, that state is unrecoverable
remotely -- strictly worse than a partial recovery.

Rather than assert on source text, these tests extract the shell functions from
``sbin/gatebsd-upgrade`` and execute them against stubbed ``service``, ``pkg``,
``pfctl``, ``route`` and ``gatewayctl`` commands, so a future refactor that
reintroduces an early return fails here.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPGRADE = ROOT / "sbin" / "gatebsd-upgrade"

# Functions lifted out of the script and exercised directly. Everything before
# them in the file is argument validation and package staging, which needs a
# real signed package and is covered by the pipeline's in-jail install test.
EXTRACTED = (
    "restart_previously_running",
    "restore_database",
    "health_gate",
    "ui_port",
    "restore_networking",
    "rollback",
)


def extract_function(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{$", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{name}() not found in sbin/gatebsd-upgrade")
    end = source.index("\n}", match.start())
    return source[match.start() : end + 2]


class UpgradeRollbackHarness:
    """Runs the extracted rollback functions with every external tool stubbed."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.calls = root / "calls.log"
        self.backup = root / "backup"
        self.backup.mkdir(exist_ok=True)
        self.source = UPGRADE.read_text(encoding="utf-8")

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {self.calls}\n{body}\n", encoding="ascii")
        path.chmod(0o755)

    def build(
        self,
        *,
        pkg_add_ok: bool = True,
        config_tar_ok: bool = True,
        service_restart_ok: bool = True,
        health_ok: bool = True,
        pf_parses: bool = True,
        gatewayctl_apply_ok: bool = True,
        gatewayctl_bypass_ok: bool = True,
        has_default_route: bool = True,
    ) -> None:
        self.stub("pkg", f"""
case "$1" in
  add) exit {0 if pkg_add_ok else 1} ;;
  query) printf '%s\\n' 2.9.3; exit 0 ;;
esac
exit 0
""")
        self.stub("service", f"""
case "$2" in
  onestatus) exit 0 ;;
  restart|start) exit {0 if service_restart_ok else 1} ;;
esac
exit 0
""")
        self.stub("pfctl", f"""
case "$1" in
  -nf) exit {0 if pf_parses else 1} ;;
esac
exit 0
""")
        self.stub("route", f"exit {0 if has_default_route else 1}")
        self.stub("gatewayctl", f"""
case "$1" in
  apply) exit {0 if gatewayctl_apply_ok else 1} ;;
  bypass|bypass-transient) exit {0 if gatewayctl_bypass_ok else 1} ;;
esac
exit 0
""")
        self.stub("timeout", 'shift\nexec "$@"')
        self.stub("fetch", "exit 0")
        # The real rollback extracts into /. Stub tar so the test never writes
        # outside its temporary directory, while still reporting the configured
        # success or failure of the extraction step.
        self.stub("tar", f"exit {0 if config_tar_ok else 1}")
        # health_gate runs the storage module through the Python launcher.
        launcher = self.bin / "gatebsd-python"
        launcher.write_text(
            f"#!/bin/sh\nprintf 'python %s\\n' \"$*\" >> {self.calls}\nexit {0 if health_ok else 1}\n",
            encoding="ascii",
        )
        launcher.chmod(0o755)
        # rollback only extracts the archive when it exists on disk.
        (self.backup / "config.tar").write_bytes(b"stub archive\n")
        # restore_networking only touches pf when the ruleset is a regular file.
        (self.root / "pf.conf").write_text("pass all\n", encoding="ascii")
        for name in ("sh", "printf", "sed", "awk", "date", "cat", "rm", "install", "mktemp", "mv", "chmod", "id", "ps"):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

    def run_rollback(self, *, gatebsd_running: int = 1, failover_running: int = 1, nginx_running: int = 1) -> subprocess.CompletedProcess[str]:
        functions = "\n".join(extract_function(self.source, name) for name in EXTRACTED)
        script = f"""
PATH={self.bin}:/usr/bin:/bin
export PATH
old_version=2.9.3
old_pkg={self.root}/old.pkg
backup={self.backup}
PYTHON_LAUNCHER={self.bin}/gatebsd-python
BACKEND={self.root}/backend
PF_CONF={self.root}/pf.conf
GATEWAYCTL={self.bin}/gatewayctl
GATEBSD_WAS_RUNNING={gatebsd_running}
FAILOVER_WAS_RUNNING={failover_running}
NGINX_WAS_RUNNING={nginx_running}
ROLLBACK_DB_TMP=
{functions}
rollback
printf 'rollback exit=%s\\n' "$?"
"""
        (self.root / "old.pkg").write_text("stub", encoding="ascii")
        return subprocess.run(
            ["sh", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )

    def call_log(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""


class RollbackCompletesEveryStepTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = UpgradeRollbackHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_failed_package_restore_still_restarts_services_and_network(self) -> None:
        """The regression this file exists for.

        With ``pkg add`` failing, the old implementation returned immediately:
        services stayed stopped and no default route was reinstated.
        """
        self.harness.build(pkg_add_ok=False)
        result = self.harness.run_rollback()
        calls = self.harness.call_log()

        self.assertIn("rollback exit=1", result.stdout)
        self.assertIn("could not restore: package", result.stderr)
        # Every later step must still have been attempted.
        self.assertIn("service gatebsd restart", calls)
        self.assertIn("service gatebsd_failover restart", calls)
        self.assertIn("service nginx restart", calls)
        self.assertIn("pfctl", calls)
        self.assertIn("gatewayctl apply", calls)

    def test_failed_service_restart_does_not_skip_the_remaining_services(self) -> None:
        self.harness.build(service_restart_ok=False)
        self.harness.run_rollback()
        calls = self.harness.call_log()
        for service in ("nginx", "gatebsd", "gatebsd_failover"):
            with self.subTest(service=service):
                self.assertIn(f"service {service} restart", calls)

    def test_successful_rollback_reports_success_and_skips_recovery(self) -> None:
        self.harness.build()
        result = self.harness.run_rollback()
        self.assertIn("rollback exit=0", result.stdout)
        # No last-resort networking recovery is needed when the health gate passes.
        self.assertNotIn("gatewayctl apply", self.harness.call_log())

    def test_failed_health_gate_triggers_networking_recovery(self) -> None:
        self.harness.build(health_ok=False)
        result = self.harness.run_rollback()
        self.assertIn("rollback exit=1", result.stdout)
        self.assertIn("did not pass the health gate", result.stderr)
        self.assertIn("gatewayctl apply", self.harness.call_log())

    def test_unparseable_pf_ruleset_fails_open_to_stay_reachable(self) -> None:
        # A ruleset that does not parse leaves pf enforcing whatever is loaded.
        # Disabling pf is the lesser evil: a reachable router beats a locked-out
        # one when there is no out-of-band access.
        self.harness.build(pkg_add_ok=False, pf_parses=False)
        result = self.harness.run_rollback()
        calls = self.harness.call_log()
        self.assertIn("disabling pf to stay reachable", result.stderr)
        self.assertIn("pfctl -d", calls)
        self.assertNotIn("pfctl -f", calls)

    def test_failed_vpn_apply_falls_back_to_the_raw_wan_default(self) -> None:
        self.harness.build(pkg_add_ok=False, gatewayctl_apply_ok=False)
        result = self.harness.run_rollback()
        calls = self.harness.call_log()
        self.assertIn("gatewayctl bypass-transient", calls)
        self.assertIn("raw WAN default is active", result.stderr)

    def test_no_recoverable_default_route_is_reported_critically(self) -> None:
        self.harness.build(
            pkg_add_ok=False,
            gatewayctl_apply_ok=False,
            gatewayctl_bypass_ok=False,
            has_default_route=False,
        )
        result = self.harness.run_rollback()
        self.assertIn("no default route could be restored", result.stderr)


class RollbackSourceContractTests(unittest.TestCase):
    """Cheap guards against the specific shape of the original defect."""

    def setUp(self) -> None:
        self.source = UPGRADE.read_text(encoding="utf-8")

    def test_rollback_body_has_no_early_return_before_networking_recovery(self) -> None:
        body = extract_function(self.source, "rollback")
        # `|| return 1` after a restore step is exactly the original defect.
        self.assertNotRegex(
            body,
            r"(pkg add|tar -xpf|restore_database|restart_previously_running)[^\n]*\|\| return 1",
            "a failing rollback step must record the failure and continue, not "
            "return and leave the router without networking",
        )

    def test_rollback_always_reaches_the_networking_recovery(self) -> None:
        body = extract_function(self.source, "rollback")
        self.assertEqual(
            body.count("restore_networking"),
            2,
            "both the failed-step path and the failed-health-gate path must run "
            "the last-resort networking recovery",
        )

    def test_networking_recovery_bounds_every_external_wait(self) -> None:
        body = extract_function(self.source, "restore_networking")
        # Match an actual invocation, not the `-x` existence test or a comment.
        invocation = re.compile(r'"\$GATEWAYCTL"\s+\w')
        found = False
        for line in body.splitlines():
            if line.strip().startswith("#") or not invocation.search(line):
                continue
            found = True
            with self.subTest(line=line.strip()):
                self.assertIn(
                    "_bound",
                    line,
                    "gatewayctl must be invoked under a timeout so rollback "
                    "cannot hang forever",
                )
        self.assertTrue(found, "the recovery no longer reinstates a default route")


class MigrationLockH5Tests(unittest.TestCase):
    """H5: gatebsd-config-migrate must take unbound.conf/pf.conf locks when writing."""

    def _run_with_lock_probe(self, target: str) -> None:
        import fcntl
        import os
        import sys
        import time

        migrate = ROOT / "sbin" / "gatebsd-config-migrate"
        backend = ROOT / "webui" / "backend"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "id").write_text("#!/bin/sh\necho 0\n", encoding="ascii")
            (bin_dir / "stat").write_text(
                "#!/bin/sh\n"
                'if [ "$1" = -f ]; then\n'
                '  case "$2" in "%u") echo 0; exit 0 ;; "%Lp") exec /usr/bin/stat -c %a "$3" ;; esac\n'
                'fi\nexec /usr/bin/stat "$@"\n',
                encoding="ascii",
            )
            (bin_dir / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (bin_dir / "chmod").write_text('#!/bin/sh\nexec /bin/chmod "$@"\n', encoding="ascii")
            (bin_dir / "service").write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
            (bin_dir / "sysrc").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (bin_dir / "su").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (bin_dir / "unbound-checkconf").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            (bin_dir / "pfctl").write_text(
                '#!/bin/sh\ncase "$1" in -s) exit 1 ;; esac\nexit 0\n', encoding="ascii"
            )
            for p in bin_dir.iterdir():
                p.chmod(0o755)

            unbound_conf = root / "unbound.conf"
            unbound_conf.write_text(
                'server:\n    username: unbound\n    local-zone: "use-application-dns.net" always_nxdomain\n',
                encoding="utf-8",
            )
            unbound_conf.chmod(0o644)
            pf_conf = root / "pf.conf"
            pf_conf.write_text(
                'wan_if="ng0"\nlan_if="re1"\nlan_net="10.88.0.0/24"\n'
                'table <local_nets> const { 10.0.0.0/8 }\n'
                'nat on $wan_if from $lan_net to any -> ($wan_if)\n'
                'block in all\n'
                'pass in quick on $lan_if from $lan_net to any keep state\n',
                encoding="utf-8",
            )
            pf_conf.chmod(0o600)
            endpoints = root / "doh-endpoints"
            endpoints.write_text("1.1.1.1/32\n", encoding="ascii")

            if target == "unbound":
                lock_path = Path(f"{unbound_conf}.gatebsd.lock")
                pf_conf = root / "absent-pf.conf"
            else:
                lock_path = Path(f"{pf_conf}.gatebsd.lock")
                unbound_conf = root / "absent-unbound.conf"

            env = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PATH": f"{bin_dir}:/usr/bin:/bin",
                "GATEBSD_PYTHON_LAUNCHER": sys.executable,
                "GATEBSD_BACKEND": str(backend),
                "GATEBSD_UNBOUND_CONF": str(unbound_conf),
                "GATEBSD_UNBOUND_STATE_DIR": str(root / "unbound-state"),
                "GATEBSD_PF_CONF": str(pf_conf),
                "GATEBSD_DOH_ENDPOINTS": str(endpoints),
                "GATEBSD_MAIN_CONF": str(root / "absent-main.conf"),
                "GATEBSD_FAILOVER_CONF": str(root / "absent-failover.conf"),
                "GATEBSD_GATEWAY_CONF": str(root / "absent-gateway.conf"),
                "GATEBSD_NGINX_CONF": str(root / "absent-nginx.conf"),
                "GATEBSD_RC_DIR": str(root / "absent-rc"),
                "GATEBSD_SSHD_CONF": str(root / "absent-sshd"),
                "GATEBSD_SUDOERS_CONF": str(root / "absent-sudoers"),
                "GATEBSD_DB_DIR": str(root / "absent-db"),
                "GATEBSD_LEGACY_RU_STATE": str(root / "absent-ru"),
                "RU_STATE_FILE": str(root / "absent-ru-new"),
                "HOME": str(root),
                "LANG": "C",
            }

            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                with subprocess.Popen(
                    ["sh", str(migrate)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ) as proc:
                    try:
                        with self.assertRaises(subprocess.TimeoutExpired):
                            proc.wait(timeout=1.5)
                        # Verify target file has not yet been mutated while lock is held.
                        if target == "unbound":
                            self.assertNotIn("extended-statistics: yes", unbound_conf.read_text(encoding="utf-8"))
                        else:
                            self.assertNotIn("table <doh>", pf_conf.read_text(encoding="utf-8"))
                    finally:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    out, err = proc.communicate(timeout=20)
                    self.assertEqual(proc.returncode, 0, out + err)
            finally:
                os.close(fd)

            if target == "unbound":
                self.assertIn("extended-statistics: yes", unbound_conf.read_text(encoding="utf-8"))
            else:
                self.assertIn("table <doh>", pf_conf.read_text(encoding="utf-8"))

    def test_h5_unbound_statistics_and_anchor_acquire_unbound_lock(self) -> None:
        self._run_with_lock_probe("unbound")

    def test_h5_pf_interception_and_doh_acquire_pf_lock(self) -> None:
        self._run_with_lock_probe("pf")


class UpgradeSpaceAndRetentionTests(unittest.TestCase):
    def test_require_upgrade_space_enforces_reserve_and_prunes_oldest_bundles(self) -> None:
        source = UPGRADE.read_text(encoding="utf-8")
        require_fn = extract_function(source, "require_upgrade_space")
        prune_fn = extract_function(source, "prune_upgrade_backups")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "df").write_text(
                "#!/bin/sh\n"
                "printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n"
                "printf 'zroot/ROOT/default 10000000 5000000 %s 50%% /\\n' \"${FAKE_AVAIL_KIB:?}\"\n",
                encoding="ascii",
            )
            (bin_dir / "df").chmod(0o755)

            backups = root / "backups"
            backups.mkdir()
            names = [
                "upgrade-20261110-100000-101",
                "upgrade-20261111-100000-102",
                "upgrade-20261112-100000-103",
                "upgrade-20261113-100000-104",
                "upgrade-20261114-100000-105",
            ]
            for name in names:
                (backups / name).mkdir()
            custom = backups / "manual-keep"
            custom.mkdir()
            active = backups / names[-1]

            script = (
                "#!/bin/sh\nset -eu\n"
                "fail() { echo \"gatebsd-upgrade: $*\" >&2; exit 1; }\n"
                + require_fn
                + "\n"
                + prune_fn
                + "\n"
                'require_upgrade_space "$TARGET_DIR" "$NEED_KIB"\n'
                'prune_upgrade_backups\n'
            )

            env_low = {
                "PATH": f"{bin_dir}:/usr/bin:/bin",
                "TARGET_DIR": str(backups),
                "BACKUP_ROOT": str(backups),
                "backup": str(active),
                "NEED_KIB": "1000",
                "MIN_FREE_KIB": "1048576",
                "KEEP_BACKUPS": "3",
                "FAKE_AVAIL_KIB": "1049000",
            }
            low = subprocess.run(["sh", "-c", script], env=env_low, capture_output=True, text=True, check=False)
            self.assertNotEqual(low.returncode, 0)
            self.assertIn("insufficient free space", low.stderr)

            env_ok = {**env_low, "FAKE_AVAIL_KIB": "2097152"}
            ok = subprocess.run(["sh", "-c", script], env=env_ok, capture_output=True, text=True, check=False)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

            self.assertFalse((backups / names[0]).exists())
            self.assertFalse((backups / names[1]).exists())
            for kept in names[2:]:
                self.assertTrue((backups / kept).is_dir(), kept)
            self.assertTrue(custom.is_dir())


if __name__ == "__main__":
    unittest.main()
