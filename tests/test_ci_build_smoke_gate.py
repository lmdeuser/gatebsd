#!/usr/bin/env python3
"""Functional regression tests for jail build and smoke-check gating in gatebsd-ci-build.

All jail build and post-install verification commands used to be piped directly
into ``tee -a "$BUILD_LOG"`` under POSIX ``/bin/sh`` (``set -euf``, no
``pipefail``).  Because the exit status of a pipeline is the exit status of its
last command (``tee``), a failing ``ci/build.sh``, ``pkg add``, cron check,
``gatebsd_ui.integrity`` check, or DB schema migration returned 0 and let
``gatebsd-ci-build`` sign and publish a broken release.

These tests extract ``run_logged`` and ``build_and_verify_in_jail`` directly
from ``ci/host/gatebsd-ci-build`` and execute them in an isolated harness.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "ci" / "host" / "gatebsd-ci-build"

EXTRACTED = ("run_logged", "build_and_verify_in_jail")


def extract_function(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\n\{{$", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{name}() not found in ci/host/gatebsd-ci-build")
    end = source.index("\n}", match.start())
    return source[match.start() : end + 2]


class SmokeGateHarness:
    """Runs the extracted jail build & verification block under controlled failures."""

    BUILD_ID = "20261115T000000Z-abcdef123456"
    COMMIT_SHA = "a" * 40

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log_dir = root / "logs" / self.BUILD_ID
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.build_log = self.log_dir / "build.log"
        self.artifact_dir = root / "artifacts" / self.BUILD_ID
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.jail_root = root / "jailroot"
        (self.jail_root / "build" / "dist").mkdir(parents=True, exist_ok=True)
        (self.jail_root / "usr" / "local" / "etc").mkdir(parents=True, exist_ok=True)
        (self.jail_root / "etc").mkdir(parents=True, exist_ok=True)
        self.record_file = root / "calls.log"
        self.source = BUILD_SCRIPT.read_text(encoding="utf-8")

        for name in (
            "sh", "env", "printf", "echo", "cat", "tee", "rm",
            "find", "head", "basename", "date", "grep",
        ):
            real = shutil.which(name)
            if real and not (self.bin / name).exists():
                (self.bin / name).symlink_to(real)

        real_install = shutil.which("install") or "/usr/bin/install"
        self._write_executable(
            "install",
            f"#!/bin/sh\n{self._filter_install_args(real_install)}",
        )
        self._write_executable("pkg", "#!/bin/sh\nexit 0\n")
        self._write_executable("jexec", self._jexec_shim())

    @staticmethod
    def _filter_install_args(real: str) -> str:
        return (
            'set -- "$@" "--end--"\n'
            "while :; do\n"
            '  case "$1" in\n'
            '    --end--) shift; break ;;\n'
            "    -o|-g) shift 2 ;;\n"
            '    *) set -- "$@" "$1"; shift ;;\n'
            "  esac\n"
            "done\n"
            f'exec {real} "$@"\n'
        )

    @staticmethod
    def _jexec_shim() -> str:
        return textwrap.dedent("""\
            #!/bin/sh
            set -eu
            shift  # jail name
            if [ "${1:-}" = env ]; then
                shift
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        -i|*=*) shift ;;
                        *) break ;;
                    esac
                done
            fi
            cmd="${1:-}"
            scenario="${SMOKE_SCENARIO:-ok}"
            rec="${SMOKE_RECORD}"
            jail_dist="${SMOKE_JAIL_ROOT}/build/dist"

            case "$cmd" in
                /bin/sh)
                    arg="${2:-}"
                    if [ "$arg" = "/build/src/ci/build.sh" ]; then
                        echo "build_sh" >> "$rec"
                        : > "${jail_dist}/gatebsd-2.9.132.pkg"
                        echo "ci/build.sh running"
                        if [ "$scenario" = "fail_build" ]; then
                            echo "ci/build.sh failed deliberately" >&2
                            exit 17
                        fi
                        exit 0
                    fi
                    if [ "$arg" = "-c" ]; then
                        script="${3:-}"
                        case "$script" in
                            *"pkg which -q"*)
                                echo "cron_verify" >> "$rec"
                                echo "cron ownership check running"
                                if [ "$scenario" = "fail_cron" ]; then
                                    echo "cron duplication check failed" >&2
                                    exit 19
                                fi
                                exit 0
                                ;;
                            *)
                                echo "cron_seed" >> "$rec"
                                exit 0
                                ;;
                        esac
                    fi
                    ;;
                pkg)
                    echo "pkg_add" >> "$rec"
                    echo "pkg add running"
                    if [ "$scenario" = "fail_pkg_add" ]; then
                        echo "pkg add failed deliberately" >&2
                        exit 23
                    fi
                    exit 0
                    ;;
                /usr/local/libexec/gatebsd-python)
                    if [ "${2:-}" = "-m" ] && [ "${3:-}" = "gatebsd_ui.integrity" ]; then
                        echo "integrity" >> "$rec"
                        echo "integrity check running"
                        if [ "$scenario" = "fail_integrity" ]; then
                            echo "integrity verification failed" >&2
                            exit 29
                        fi
                        exit 0
                    fi
                    if [ "${2:-}" = "-c" ]; then
                        echo "migrate" >> "$rec"
                        echo "storage migration running"
                        if [ "$scenario" = "fail_migrate" ]; then
                            echo "storage migration failed" >&2
                            exit 31
                        fi
                        exit 0
                    fi
                    ;;
            esac
            echo "unexpected jexec command: $*" >&2
            exit 99
        """)

    def _write_executable(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def extracted_functions(self, *, source_override: str | None = None) -> str:
        src = source_override if source_override is not None else self.source
        return "\n".join(extract_function(src, name) for name in EXTRACTED)

    def run_gate(
        self, *, scenario: str = "ok", functions_script: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        funcs = functions_script if functions_script is not None else self.extracted_functions()
        script = (
            f"set -euf\n"
            f"BUILD_ID={self.BUILD_ID}\n"
            f"COMMIT_SHA={self.COMMIT_SHA}\n"
            f"JAIL_NAME=gatebsd_test_jail\n"
            f"JAIL_ROOT={self.jail_root}\n"
            f"ARTIFACT_DIR={self.artifact_dir}\n"
            f"LOG_DIR={self.log_dir}\n"
            f"BUILD_LOG={self.build_log}\n"
            f"{funcs}\n"
            f"build_and_verify_in_jail\n"
            f'printf "FINAL_PACKAGE=%s\\n" "${{PACKAGE:-}}"\n'
        )
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "SMOKE_SCENARIO": scenario,
            "SMOKE_JAIL_ROOT": str(self.jail_root),
            "SMOKE_RECORD": str(self.record_file),
        }
        return subprocess.run(
            ["/bin/sh", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def recorded_steps(self) -> list[str]:
        if not self.record_file.exists():
            return []
        return self.record_file.read_text(encoding="utf-8").splitlines()


class CiBuildSmokeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = SmokeGateHarness(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_happy_path_streams_output_and_stages_package(self) -> None:
        result = self.harness.run_gate(scenario="ok")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(
            self.harness.recorded_steps(),
            ["build_sh", "cron_seed", "pkg_add", "cron_verify", "integrity", "migrate"],
        )
        staged_pkg = self.harness.artifact_dir / "gatebsd-2.9.132.pkg"
        self.assertTrue(staged_pkg.is_file())
        self.assertIn(f"FINAL_PACKAGE={self.harness.jail_root}/build/dist/gatebsd-2.9.132.pkg", result.stdout)

        log_text = self.harness.build_log.read_text(encoding="utf-8")
        for marker in (
            "ci/build.sh running",
            "pkg add running",
            "cron ownership check running",
            "integrity check running",
            "storage migration running",
        ):
            self.assertIn(marker, result.stdout)
            self.assertIn(marker, log_text)

    def test_failing_build_script_after_partial_pkg_aborts_immediately(self) -> None:
        result = self.harness.run_gate(scenario="fail_build")
        self.assertEqual(result.returncode, 17, result.stderr + result.stdout)
        self.assertEqual(self.harness.recorded_steps(), ["build_sh"])
        self.assertFalse((self.harness.artifact_dir / "gatebsd-2.9.132.pkg").exists())
        self.assertIn(
            "ci/build.sh failed deliberately",
            self.harness.build_log.read_text(encoding="utf-8"),
        )

    def test_each_post_build_smoke_failure_propagates_nonzero(self) -> None:
        cases = (
            ("fail_pkg_add", 23, "pkg add failed deliberately"),
            ("fail_cron", 19, "cron duplication check failed"),
            ("fail_integrity", 29, "integrity verification failed"),
            ("fail_migrate", 31, "storage migration failed"),
        )
        for scenario, expected_rc, expected_log in cases:
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as tmp:
                    harness = SmokeGateHarness(Path(tmp))
                    result = harness.run_gate(scenario=scenario)
                    self.assertEqual(result.returncode, expected_rc, result.stderr + result.stdout)
                    self.assertIn(expected_log, harness.build_log.read_text(encoding="utf-8"))

    def test_missing_or_corrupt_rc_file_fails_closed(self) -> None:
        run_logged_fn = extract_function(self.harness.source, "run_logged")

        scenarios = (
            (
                "missing_rc",
                'mkdir -p "{log_dir}/.run_logged.rc/lock"; echo blocked',
                1,
            ),
            (
                "symlink_rc",
                'printf "0\\n" > "{log_dir}/zero"; ln -s "{log_dir}/zero" "{log_dir}/.run_logged.rc"',
                1,
            ),
            (
                "nonzero_rc",
                'echo step_failed >&2; exit 42',
                42,
            ),
        )
        for name, cmd_template, expected_rc in scenarios:
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    log_dir = root / "logs"
                    log_dir.mkdir()
                    build_log = log_dir / "build.log"
                    cmd = cmd_template.format(log_dir=log_dir)
                    script = (
                        f"set -euf\n"
                        f"LOG_DIR={log_dir}\n"
                        f"BUILD_LOG={build_log}\n"
                        f"{run_logged_fn}\n"
                        f"run_logged /bin/sh -c '{cmd}'\n"
                    )
                    res = subprocess.run(
                        ["/bin/sh", "-c", script],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(res.returncode, expected_rc, res.stderr + res.stdout)
                    shutil.rmtree(log_dir / ".run_logged.rc", ignore_errors=True)

    @staticmethod
    def _reintroduce_tee_pipe(funcs_script: str) -> str:
        """Replace ``run_logged <cmd>`` calls (including multiline ones) with ``| tee -a``."""
        lines = funcs_script.splitlines()
        out: list[str] = []
        active = False
        in_single_quote = False
        for line in lines:
            match = re.match(r"^(\s*)run_logged\s+(.*)$", line) if not active else None
            if match is not None:
                active = True
                line = f"{match.group(1)}{match.group(2)}"
            if active:
                if line.count("'") % 2 == 1:
                    in_single_quote = not in_single_quote
                if not in_single_quote and not line.rstrip().endswith("\\"):
                    line = f'{line} 2>&1 | tee -a "$BUILD_LOG"'
                    active = False
            out.append(line)
        return "\n".join(out)

    def test_reintroducing_pipe_to_tee_masks_smoke_failures(self) -> None:
        real_funcs = self.harness.extracted_functions()
        masked_funcs = self._reintroduce_tee_pipe(real_funcs)
        self.assertNotEqual(real_funcs, masked_funcs)
        for scenario in ("fail_build", "fail_pkg_add", "fail_cron", "fail_integrity", "fail_migrate"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as tmp:
                    broken = SmokeGateHarness(Path(tmp))
                    result = broken.run_gate(scenario=scenario, functions_script=masked_funcs)
                    self.assertEqual(
                        result.returncode,
                        0,
                        f"reintroduced tee pipe unexpectedly failed for {scenario}",
                    )


if __name__ == "__main__":
    unittest.main()
