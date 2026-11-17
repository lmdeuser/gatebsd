"""The build must outlive the ssh session that started it.

The defect these exist for: pipeline run #44 built gatebsd-2.9.31 to completion
-- package produced, verified, installed into the jail -- and then the ssh
session carrying the job from ci-master to the stand was reset. The process
group got SIGHUP, ``gatebsd-ci-build``'s cleanup trap ran, and a finished build
was recorded ``FAILED`` and never published. The transport is not ours to make
reliable; discarding a completed build because of it is.

``supervise()`` therefore computes the build id, starts the real build detached
through ``daemon(8)``, and only watches its output; ``watch_build()`` streams
that output and ends when the worker does.

These tests execute both functions from ``ci/host/gatebsd-ci-build`` -- the real
file, not a copy -- with the worker replaced at the ``lockf`` seam, so the
watcher/worker split is what runs. Killing the watcher must leave the worker
alive and let it finish; that is the property #44 lacked, and the reintroduction
below restores the old foreground form to prove the test can see the difference.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "ci" / "host" / "gatebsd-ci-build"

SHA = "a" * 40
BUILD_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")


class DetachHarness:
    """Runs the real entry point with the worker replaced at the lockf seam.

    Everything the watcher touches is real: it computes the build id, creates
    the log directory, spawns through ``daemon``, then follows ``job.log`` and
    decides on ``result``. Only two host tools are stubbed, and neither is part
    of what is under test.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log_root = root / "logs"
        self.worker_marker = root / "worker-finished"
        self.worker_started = root / "worker-started"

        for name in (
            "sh", "grep", "printf", "date", "sleep", "cat", "tail", "wc",
            "head", "sed", "kill", "rm", "mkdir", "touch", "setsid",
        ):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

        # The watcher refuses to run as anything but root and the sandbox is
        # not; stubbing id(1) leaves that check in the script rather than
        # editing it out.
        self._stub("id", 'case "${1:-}" in -u) echo 0 ;; *) echo 0 ;; esac\n')

        # `install -d -o root -g wheel` cannot work off FreeBSD and not as root.
        # The directory and mode semantics the watcher relies on are kept; only
        # the ownership flags are dropped.
        real_install = shutil.which("install") or "/usr/bin/install"
        self._stub(
            "install",
            'set -- "$@" "--end--"\n'
            "while :; do\n"
            '  case "$1" in\n'
            '    --end--) shift; break ;;\n'
            "    -o|-g) shift 2 ;;\n"
            '    *) set -- "$@" "$1"; shift ;;\n'
            "  esac\n"
            "done\n"
            f'exec {real_install} "$@"\n',
        )

        # daemon(8) is FreeBSD's. This reproduces exactly the three flags the
        # watcher passes -- detach, write a pid file, redirect output -- and
        # nothing else.
        self._stub(
            "daemon",
            "pidfile=; outfile=/dev/null\n"
            "while :; do\n"
            '  case "${1:-}" in\n'
            "    -f) shift ;;\n"
            '    -p) pidfile=$2; shift 2 ;;\n'
            '    -o) outfile=$2; shift 2 ;;\n'
            "    *) break ;;\n"
            "  esac\n"
            "done\n"
            'setsid "$@" >>"$outfile" 2>&1 &\n'
            '[ -z "$pidfile" ] || printf "%s\\n" "$!" > "$pidfile"\n'
            "exit 0\n",
        )

    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}", encoding="ascii")
        path.chmod(0o755)

    def install_worker(self, body: str) -> None:
        """Replace the worker at the seam the watcher spawns it through.

        The watcher runs `daemon ... lockf -t 0 "$LOCK" "$0" _locked "$sha"`.
        Stubbing lockf puts a fake build in place of the real one while leaving
        every line of the watcher genuinely executing.
        """
        self._stub("lockf", body)

    def install_daemon_without_pidfile(self) -> None:
        """Run the child but reproduce FreeBSD daemon's early-exit pid gap."""
        self._stub(
            "daemon",
            "pidfile=; outfile=/dev/null\n"
            "while :; do\n"
            '  case "${1:-}" in\n'
            "    -f) shift ;;\n"
            '    -p) pidfile=$2; shift 2 ;;\n'
            '    -o) outfile=$2; shift 2 ;;\n'
            "    *) break ;;\n"
            "  esac\n"
            "done\n"
            '"$@" >>"$outfile" 2>&1\n'
            "exit 0\n",
        )

    def finishing_worker(self, *, result: str = "SUCCESS", seconds: int = 6) -> str:
        """A worker that keeps logging for a while, then records `result`.

        It writes to the log directory the *watcher* named, which is the whole
        point: the watcher has to know the path before this process exists.
        """
        return (
            'while [ "${1:-}" != _locked ]; do shift || break; done\n'
            # Recorded before anything can go wrong, so "the worker never
            # started" always means exactly that.
            f'touch {self.worker_started}\n'
            # The real worker is handed its build id in the environment and
            # derives every path from it; so does this one, which is why the
            # watcher can name the log before the worker exists.
            f'dir={self.log_root}/${{GATEBSD_CI_BUILD_ID:?no build id in the environment}}\n'
            "i=0\n"
            f"while [ $i -lt {seconds} ]; do\n"
            '  echo "building step $i"\n'
            "  i=$((i+1)); sleep 1\n"
            "done\n"
            f'touch {self.worker_marker}\n'
            f'printf "{result}\\n" > "$dir/result"\n'
        )

    def racing_worker(self, *, result: str = "FAILED") -> str:
        """A worker that dies a moment BEFORE its result appears.

        The real worker writes `result` from its trap and exits in the next
        breath. The watcher checks the file first and the pid second, so a
        pass that read the file before the write and the pid after the exit
        saw no result and a dead process -- and called a finished build a
        build that never answered.

        That window is sub-millisecond in normal running, which is no use to a
        test. Here the write is pushed into a detached child that waits, so
        the ordering the race produces by luck is produced on purpose, every
        time: the watcher WILL find the pid dead and the file missing, and has
        to wait and look again.

        The delay has to exceed the watcher's own poll interval, which is two
        seconds. At one second this test passed with the defect put back --
        the watcher simply slept through the whole window and met the result
        on its next pass, proving nothing. Three seconds lands the check
        inside the gap and stays well under the five-second grace.
        """
        return (
            'while [ "${1:-}" != _locked ]; do shift || break; done\n'
            f'touch {self.worker_started}\n'
            f'dir={self.log_root}/${{GATEBSD_CI_BUILD_ID:?no build id in the environment}}\n'
            'echo "building step 0"\n'
            f'touch {self.worker_marker}\n'
            f'( sleep 3; printf "{result}\\n" > "$dir/result" ) &\n'
        )

    def env(self) -> dict:
        env = dict(os.environ)
        # The script keeps a fixed PATH on purpose and honours a prefix only
        # behind this flag -- the same gate sbin/gatebsd-route-op uses so its
        # harness can substitute route(8). Without both, the stubs are ignored
        # and the real install(1) runs, which is how this harness first failed.
        env["GATEBSD_ALLOW_TEST_PATH"] = "1"
        env["GATEBSD_TEST_PATH_PREFIX"] = str(self.bin)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        return env

    def run(self, *, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sh", str(self.script_path()), SHA],
            capture_output=True, text=True, timeout=timeout, env=self.env(),
        )

    def popen(self) -> subprocess.Popen:
        """Start the watcher in its own session so it can be signalled as a group.

        Output goes to a file rather than a pipe: nothing reads it while the
        test sleeps, and a watcher blocked on a full pipe would look exactly
        like the survival this test is trying to observe.
        """
        self.watcher_log = open(self.root / "watcher.out", "w", encoding="utf-8")
        return subprocess.Popen(
            ["sh", str(self.script_path()), SHA],
            stdout=self.watcher_log, stderr=subprocess.STDOUT,
            text=True, env=self.env(), start_new_session=True,
        )

    def script_path(self) -> Path:
        """The real script with only its host paths pointed at the sandbox.

        Rewriting the three root paths is not a rewrite of the logic: the
        watcher, the seam and the decision on `result` are the file's own lines.
        """
        source = BUILD_SCRIPT.read_text(encoding="utf-8")
        source = source.replace("LOG_ROOT=/tank/ci/logs", f"LOG_ROOT={self.log_root}")
        source = source.replace(
            "LOCK=/var/run/gatebsd-ci-build.lock", f"LOCK={self.root}/build.lock"
        )
        path = self.root / "gatebsd-ci-build"
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)
        return path

    def log_dirs(self) -> list[Path]:
        return sorted(p for p in self.log_root.glob("*Z-*") if p.is_dir())


class WatcherOutlivesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = DetachHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_build_survives_the_watcher_being_killed(self) -> None:
        """The property run #44 lacked: the caller dying must not end the build."""
        self.harness.install_worker(self.harness.finishing_worker(seconds=8))
        proc = self.harness.popen()
        # Wait until the worker is genuinely running, then kill the watcher the
        # way a reset ssh session kills it -- the whole process group.
        deadline = time.time() + 20
        while time.time() < deadline and not self.harness.worker_started.exists():
            time.sleep(0.2)
        self.assertTrue(
            self.harness.worker_started.exists(), "the worker never started"
        )
        os.killpg(os.getpgid(proc.pid), signal.SIGHUP)
        proc.wait(timeout=20)
        self.harness.watcher_log.close()

        deadline = time.time() + 30
        while time.time() < deadline and not self.harness.worker_marker.exists():
            time.sleep(0.3)
        self.assertTrue(
            self.harness.worker_marker.exists(),
            "the build died with the watcher -- this is defect 5.11",
        )
        dirs = self.harness.log_dirs()
        self.assertEqual(len(dirs), 1)
        self.assertEqual((dirs[0] / "result").read_text().strip(), "SUCCESS")

    def test_the_watcher_reports_the_builds_success(self) -> None:
        self.harness.install_worker(self.harness.finishing_worker(seconds=2))
        done = self.harness.run()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("building step 0", done.stdout)

    def test_the_watcher_fails_when_the_build_fails(self) -> None:
        self.harness.install_worker(
            self.harness.finishing_worker(result="FAILED", seconds=2)
        )
        done = self.harness.run()
        self.assertEqual(done.returncode, 1)
        self.assertIn("Build failed", done.stdout + done.stderr)

    def test_a_result_arriving_as_the_worker_dies_is_not_called_missing(self) -> None:
        """A dead worker proves nothing more will arrive, not that nothing did.

        This is what took down the gate on 3 August: the run had finished and
        recorded FAILED, and the watcher reported "The build exited without
        recording a result. A build for another commit may already hold the
        lock." -- a true statement about the process and a false statement
        about the build, pointing whoever read it at a lock that was never
        involved. Both endings exit 1, so the wrong one is easy to live with
        for a long time.

        Asserting on the message and not only on the exit code is the point.
        """
        self.harness.install_worker(self.harness.racing_worker(result="FAILED"))
        done = self.harness.run()
        self.assertEqual(done.returncode, 1)
        self.assertIn("Build failed", done.stdout + done.stderr)
        self.assertNotIn("without recording a result", done.stdout + done.stderr)

    def test_a_worker_that_dies_without_a_result_is_not_waited_for_forever(self) -> None:
        """What `lockf -t 0` refusing a concurrent build looks like."""
        self.harness.install_worker("exit 73\n")
        done = self.harness.run(timeout=40)
        self.assertEqual(done.returncode, 1)
        self.assertIn("without recording a result", done.stdout + done.stderr)

    def test_an_early_worker_exit_without_a_pidfile_is_not_waited_for_forever(self) -> None:
        """FreeBSD daemon -p may leave no pid file if its child dies at once."""
        self.harness.install_daemon_without_pidfile()
        self.harness.install_worker(
            'echo "Forgejo GateBSD repository is missing."\nexit 69\n'
        )
        done = self.harness.run(timeout=30)
        self.assertEqual(done.returncode, 1)
        self.assertIn("Forgejo GateBSD repository is missing.", done.stdout)
        self.assertIn("before creating its worker pid file", done.stderr)

    def test_the_build_id_the_watcher_chose_names_the_log_directory(self) -> None:
        self.harness.install_worker(self.harness.finishing_worker(seconds=1))
        self.harness.run()
        dirs = self.harness.log_dirs()
        self.assertEqual(len(dirs), 1)
        self.assertRegex(dirs[0].name, BUILD_ID_RE)
        self.assertTrue(dirs[0].name.endswith(SHA[:12]))


class ReintroductionTests(unittest.TestCase):
    """Restore the foreground form and show the survival test can see it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = DetachHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_foreground_form_loses_the_build_when_the_caller_dies(self) -> None:
        harness = self.harness
        harness.install_worker(harness.finishing_worker(seconds=8))

        original = harness.script_path
        def foreground_script() -> Path:
            path = original()
            source = path.read_text(encoding="utf-8")
            # The shape the script had when #44 threw away a finished build:
            # the worker runs in the caller's own process group.
            # Everything the fixed form does *except* detaching: same build id,
            # same log directory, same worker. The worker simply runs in the
            # caller's process group, which is the whole of defect 5.11.
            source = source.replace(
                "    supervise \"$1\"\n    exit $?\n",
                "    _bid=$(date -u '+%Y%m%dT%H%M%SZ')-$(printf '%.12s' \"$1\")\n"
                '    install -d -m 0750 "$LOG_ROOT" "$LOG_ROOT/$_bid"\n'
                "    GATEBSD_CI_BUILD_ID=$_bid; export GATEBSD_CI_BUILD_ID\n"
                '    exec lockf -t 0 "$LOCK" "$0" _locked "$1"\n',
            )
            self.assertIn("exec lockf -t 0", source, "reintroduction did not apply")
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)
            return path
        harness.script_path = foreground_script  # type: ignore[method-assign]

        proc = harness.popen()
        deadline = time.time() + 20
        while time.time() < deadline and not harness.worker_started.exists():
            time.sleep(0.2)
        self.assertTrue(harness.worker_started.exists(), "the worker never started")
        os.killpg(os.getpgid(proc.pid), signal.SIGHUP)
        proc.wait(timeout=20)
        harness.watcher_log.close()

        time.sleep(6)
        self.assertFalse(
            harness.worker_marker.exists(),
            "the foreground form was expected to lose the build, but it finished",
        )

    def test_removing_the_missing_pid_guard_restores_the_infinite_wait(self) -> None:
        """Reintroduce the exact two-day orphan-watcher failure from the stand."""
        harness = self.harness
        harness.install_daemon_without_pidfile()
        harness.install_worker(
            'echo "Forgejo GateBSD repository is missing."\nexit 69\n'
        )

        original = harness.script_path

        def unguarded_script() -> Path:
            path = original()
            source = path.read_text(encoding="utf-8")
            source, replacements = re.subn(
                r'        if \[ ! -s "\$_pidf" \]; then\n'
                r'.*?'
                r'        fi\n'
                r'        sleep 2\n',
                "        sleep 2\n",
                source,
                count=1,
                flags=re.DOTALL,
            )
            self.assertEqual(replacements, 1, "reintroduction did not apply")
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)
            return path

        harness.script_path = unguarded_script  # type: ignore[method-assign]
        with self.assertRaises(subprocess.TimeoutExpired):
            harness.run(timeout=12)


if __name__ == "__main__":
    unittest.main()
