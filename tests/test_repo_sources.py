"""Test package source selection, bootstrap rendering, and parser parity.

The web panel manages where packages are fetched from without controlling
whose signature this appliance accepts. Two invariants must hold across all
configurations:

1. The rendered pkg configuration must never name a trust anchor other than
   the project stand's hardcoded public key, even when custom mirrors or root
   prefixes are configured.
2. The format has two separate parsers (POSIX sh in gatebsd-repo-bootstrap
   and Python in the web panel) which must agree exactly on every input.
   Divergence between dual implementations is a recurrent defect class where
   the UI accepts a configuration that subsequently breaks during deployment
   or vice versa.

Additionally, tests enforce the single-writer architectural invariant: the
web panel updates repo-sources.conf and invokes gatebsd-repo-bootstrap, never
modifying pkg's gatebsd.conf directly.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "webui" / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "webui" / "backend"))

from gatebsd_ui.writers import repo

BOOTSTRAP_SCRIPT = ROOT / "sbin" / "gatebsd-repo-bootstrap"
SHIPPED_SOURCES = ROOT / "etc" / "gatebsd" / "repo-sources.conf.sample"
SHIPPED_REPO_CONF = ROOT / "etc" / "pkg" / "repos" / "gatebsd.conf"
SOURCE_DIR = ROOT / "etc" / "pkg"
STAND_PUBKEY_PATH = "/usr/local/etc/pkg/keys/gatebsd-stand.pub"


def _run_bootstrap(
    prefix_dir: Path,
    source_dir: Path,
    sources_file: Path | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute gatebsd-repo-bootstrap under a redirected root prefix."""
    cmd = [
        "sh",
        str(BOOTSTRAP_SCRIPT),
        "--prefix",
        str(prefix_dir),
        "--source-dir",
        str(source_dir),
    ]
    if check:
        cmd.append("--check")

    env = os.environ.copy()
    env["GATEBSD_REPO_BACKUP_ROOT"] = str(prefix_dir / "backups")
    if sources_file is not None:
        env["GATEBSD_REPO_SOURCES"] = str(sources_file)

    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _find_rendered_conf(prefix_dir: Path) -> Path:
    """Locate gatebsd.conf within a redirected prefix directory."""
    candidates = list(prefix_dir.glob("**/gatebsd.conf"))
    if not candidates:
        raise FileNotFoundError(f"gatebsd.conf not found under {prefix_dir}")
    return candidates[0]


class RenderedConfig(unittest.TestCase):
    """Verify repository configuration rendering and trust anchor isolation."""

    def test_default_source_reproduces_shipped_config(self) -> None:
        """Catch drift between bootstrap output and shipped reference configuration.

        If the bootstrap renderer or default source format changes without
        updating the reference configuration, clean installations will immediately
        report configuration drift.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "target"
            prefix.mkdir()

            res = _run_bootstrap(
                prefix_dir=prefix,
                source_dir=SOURCE_DIR,
                sources_file=SHIPPED_SOURCES,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Bootstrap failed on shipped sources: {res.stderr}",
            )

            rendered_path = _find_rendered_conf(prefix)
            rendered_bytes = rendered_path.read_bytes()
            shipped_bytes = SHIPPED_REPO_CONF.read_bytes()

            self.assertEqual(
                rendered_bytes,
                shipped_bytes,
                "Rendered bootstrap configuration drifted from etc/pkg/repos/gatebsd.conf",
            )

    def test_mutation_changes_both_urls_and_differs_from_shipped(self) -> None:
        """Catch hardcoded template outputs or half-updated repository blocks.

        Proves that test_default_source_reproduces_shipped_config can fail
        when the input changes, and ensures that both release and port repository
        URLs are parameterized from the active source rather than leaving one stale.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "target"
            prefix.mkdir()
            custom_sources = Path(tmpdir) / "repo-sources.conf"
            custom_sources.write_text(
                "active|http://pkg-stand-02.lan\n",
                encoding="utf-8",
            )

            res = _run_bootstrap(
                prefix_dir=prefix,
                source_dir=SOURCE_DIR,
                sources_file=custom_sources,
            )
            self.assertEqual(res.returncode, 0, f"Bootstrap failed: {res.stderr}")

            rendered_path = _find_rendered_conf(prefix)
            rendered_text = rendered_path.read_text(encoding="utf-8")
            shipped_text = SHIPPED_REPO_CONF.read_text(encoding="utf-8")

            self.assertNotEqual(
                rendered_text,
                shipped_text,
                "Mutation test failed: rendered config matched shipped default despite changed source",
            )

            urls = re.findall(r'url:\s*"([^"]+)"', rendered_text)
            self.assertEqual(
                len(urls),
                2,
                f"Expected 2 repository URLs in rendered config, found {len(urls)}: {urls}",
            )
            for url in urls:
                self.assertTrue(
                    url.startswith("http://pkg-stand-02.lan/gatebsd/"),
                    f"Repository URL did not reflect mutated source: {url}",
                )

    def test_check_reports_drift_accurately(self) -> None:
        """Catch failure of --check to detect divergence between sources and disk.

        A defective check mode that returns 0 on mismatched configuration allows
        unbootstrapped or tampered states to escape monitoring.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = Path(tmpdir) / "target"
            prefix.mkdir()

            res_install = _run_bootstrap(
                prefix_dir=prefix,
                source_dir=SOURCE_DIR,
                sources_file=SHIPPED_SOURCES,
            )
            self.assertEqual(res_install.returncode, 0)

            res_check_clean = _run_bootstrap(
                prefix_dir=prefix,
                source_dir=SOURCE_DIR,
                sources_file=SHIPPED_SOURCES,
                check=True,
            )
            self.assertEqual(
                res_check_clean.returncode,
                0,
                f"Clean check returned non-zero: {res_check_clean.stderr or res_check_clean.stdout}",
            )
            self.assertIn("matches the release", res_check_clean.stdout)

            divergent_sources = Path(tmpdir) / "divergent.conf"
            divergent_sources.write_text(
                "active|http://drifted-mirror.example.lan\n",
                encoding="utf-8",
            )

            res_check_drift = _run_bootstrap(
                prefix_dir=prefix,
                source_dir=SOURCE_DIR,
                sources_file=divergent_sources,
                check=True,
            )
            self.assertNotEqual(
                res_check_drift.returncode,
                0,
                "Check mode reported success despite divergent sources configuration",
            )
            self.assertIn("DRIFT", res_check_drift.stdout)

    def test_trust_anchor_pubkey_path_is_invariant(self) -> None:
        """Catch security regressions that allow sources or prefixes to change the pubkey path.

        Package mirror selection decides WHERE packages originate, never WHOSE
        cryptographic signature is trusted. The public key path must remain
        fixed to the appliance trust anchor regardless of host or prefix redirects.
        """
        test_urls = [
            "http://mirror.example.lan",
            "https://custom-mirror.internal:8443",
            "http://192.168.10.254",
        ]

        for url in test_urls:
            with tempfile.TemporaryDirectory() as tmpdir:
                prefix = Path(tmpdir) / "target"
                prefix.mkdir()
                sources_file = Path(tmpdir) / "sources.conf"
                sources_file.write_text(f"active|{url}\n", encoding="utf-8")

                res = _run_bootstrap(
                    prefix_dir=prefix,
                    source_dir=SOURCE_DIR,
                    sources_file=sources_file,
                )
                self.assertEqual(res.returncode, 0, f"Failed for {url}: {res.stderr}")

                rendered_path = _find_rendered_conf(prefix)
                rendered_text = rendered_path.read_text(encoding="utf-8")

                pubkey_matches = re.findall(
                    r'^\s*pubkey:\s*"([^"]+)"',
                    rendered_text,
                    re.MULTILINE,
                )
                self.assertEqual(
                    len(pubkey_matches),
                    2,
                    f"Expected exactly 2 pubkey directives, found {len(pubkey_matches)}",
                )
                for path in pubkey_matches:
                    self.assertEqual(
                        path,
                        STAND_PUBKEY_PATH,
                        f"Trust anchor pubkey path was rewritten to {path} for URL {url}",
                    )


class BothParsersAgree(unittest.TestCase):
    """Assert POSIX sh bootstrap parser and Python web panel parser reach identical verdicts."""

    def test_parsers_reach_identical_verdicts(self) -> None:
        """Catch dual-parser semantic drift on configuration syntax and edge cases.

        If the shell reader and Python parser diverge, valid panel configurations
        will fail during bootstrap or invalid configurations will pass the panel
        and break backend operations.
        """
        table: list[tuple[str, str, str | None]] = [
            (
                "shipped default",
                "active|http://mirror.example.lan\n",
                "http://mirror.example.lan",
            ),
            (
                "leading and trailing whitespace",
                "  active  |  http://mirror.example.lan  \n",
                "http://mirror.example.lan",
            ),
            (
                "comments and blank lines",
                "\n# header\n\nactive|http://mirror.example.lan\n# footer\n",
                "http://mirror.example.lan",
            ),
            (
                "two active lines",
                "active|http://mirror1.lan\nactive|http://mirror2.lan\n",
                None,
            ),
            (
                "zero active lines",
                "known|http://mirror.example.lan\n",
                None,
            ),
            (
                "unknown state word",
                "standby|http://mirror.example.lan\n",
                None,
            ),
            (
                "missing delimiter",
                "active http://mirror.example.lan\n",
                None,
            ),
            (
                "extra delimiter",
                "active|http://mirror.example.lan|extra\n",
                None,
            ),
            (
                "url with a path",
                "active|http://mirror.example.lan/gatebsd/packages\n",
                None,
            ),
            (
                "url with valid port",
                "active|http://mirror.example.lan:8080\n",
                "http://mirror.example.lan:8080",
            ),
            (
                "injection attempt with quotes and braces",
                'active|http://mirror.example.lan" }\nattacker: {\n',
                None,
            ),
            (
                "injection attempt with shell metacharacters",
                "active|http://mirror.example.lan;rm -rf /\n",
                None,
            ),
            (
                "non-http scheme",
                "active|ftp://mirror.example.lan\n",
                None,
            ),
            (
                "active and known entries combined",
                "known|http://backup.lan:9000\nactive|https://primary.lan\n",
                "https://primary.lan",
            ),
        ]

        accepted_count = 0
        rejected_count = 0

        for label, content, expected_url in table:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as tmpdir:
                    prefix = Path(tmpdir) / "target"
                    prefix.mkdir()
                    sources_file = Path(tmpdir) / "sources.conf"
                    sources_file.write_text(content, encoding="utf-8")

                    sh_res = _run_bootstrap(
                        prefix_dir=prefix,
                        source_dir=SOURCE_DIR,
                        sources_file=sources_file,
                    )
                    sh_ok = sh_res.returncode == 0
                    sh_url: str | None = None
                    if sh_ok:
                        match = re.search(r"^source\s+(\S+)", sh_res.stdout, re.MULTILINE)
                        sh_url = match.group(1) if match else None

                    py_entries, py_err = repo._parse(content)
                    py_ok = py_entries is not None
                    py_url: str | None = None
                    if py_ok and py_entries is not None:
                        active_items = [e["url"] for e in py_entries if e["state"] == "active"]
                        py_url = active_items[0] if active_items else None

                    self.assertEqual(
                        sh_ok,
                        py_ok,
                        f"Parser verdict divergence on {label!r}: sh_ok={sh_ok}, py_ok={py_ok} (py_err={py_err!r}, sh_stderr={sh_res.stderr!r})",
                    )

                    if expected_url is not None:
                        self.assertTrue(sh_ok, f"Expected acceptance for {label!r}")
                        self.assertEqual(sh_url, expected_url, f"Shell URL mismatch for {label!r}")
                        self.assertEqual(py_url, expected_url, f"Python URL mismatch for {label!r}")
                        accepted_count += 1
                    else:
                        self.assertFalse(sh_ok, f"Expected rejection for {label!r}")
                        rejected_count += 1

        self.assertGreater(accepted_count, 0, "Test suite did not exercise accepted parser cases")
        self.assertGreater(rejected_count, 0, "Test suite did not exercise rejected parser cases")
        self.assertEqual(
            accepted_count + rejected_count,
            len(table),
            "Not all table entries were accounted for",
        )


class PanelNeverWritesPkgConfig(unittest.TestCase):
    """Enforce the single-writer invariant between the web panel and pkg configuration."""

    def setUp(self) -> None:
        self._orig_sources = repo.SOURCES_FILE
        self._orig_conf = repo.LIVE_REPO_CONF
        self._orig_bootstrap = repo.BOOTSTRAP
        self._orig_pkg = repo.PKG

    def tearDown(self) -> None:
        repo.SOURCES_FILE = self._orig_sources
        repo.LIVE_REPO_CONF = self._orig_conf
        repo.BOOTSTRAP = self._orig_bootstrap
        repo.PKG = self._orig_pkg

    def test_set_sources_delegates_to_bootstrap_without_touching_live_conf(self) -> None:
        """Catch two-writer defects where the panel directly writes gatebsd.conf.

        The web panel must update repo-sources.conf and delegate rendering to
        gatebsd-repo-bootstrap under an exclusive lock. Direct modification of
        gatebsd.conf creates race conditions with bootstrap operations.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sources_file = tmp_path / "etc" / "gatebsd" / "repo-sources.conf"
            sources_file.parent.mkdir(parents=True, exist_ok=True)

            live_conf = tmp_path / "etc" / "pkg" / "repos" / "gatebsd.conf"
            live_conf.parent.mkdir(parents=True, exist_ok=True)
            initial_conf_bytes = b"# Original unmanaged gatebsd.conf\n"
            live_conf.write_bytes(initial_conf_bytes)

            old_mtime = time.time() - 3600
            os.utime(live_conf, (old_mtime, old_mtime))
            initial_stat = live_conf.stat()

            marker_file = tmp_path / "bootstrap_ran.marker"
            stub_bootstrap = tmp_path / "stub-bootstrap.sh"
            stub_bootstrap.write_text(
                f"#!/bin/sh\necho ran > {marker_file}\nexit 0\n",
                encoding="utf-8",
            )
            stub_bootstrap.chmod(0o755)

            # The command runner pins PATH to a safe list, so a stub cannot be
            # smuggled in through the environment -- which is the point of that
            # pin. The binary is named explicitly instead.
            stub_bin = tmp_path / "bin"
            stub_bin.mkdir()
            stub_pkg = stub_bin / "pkg"
            stub_pkg.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub_pkg.chmod(0o755)

            repo.SOURCES_FILE = sources_file
            repo.LIVE_REPO_CONF = live_conf
            repo.BOOTSTRAP = str(stub_bootstrap)
            repo.PKG = str(stub_pkg)

            status, resp = repo.set_sources({
                "active": "http://mirror-update.lan",
                "known": ["http://mirror-standby.lan:8080"],
            })

            self.assertEqual(status, 200, f"set_sources returned error: {resp}")
            self.assertTrue(resp.get("ok"), f"Response marked not ok: {resp}")
            self.assertTrue(marker_file.exists(), "Stub bootstrap was never executed")

            self.assertTrue(sources_file.exists(), "repo-sources.conf was not written")
            sources_text = sources_file.read_text(encoding="utf-8")
            self.assertIn("active|http://mirror-update.lan", sources_text)
            self.assertIn("known|http://mirror-standby.lan:8080", sources_text)

            current_stat = live_conf.stat()
            self.assertEqual(
                live_conf.read_bytes(),
                initial_conf_bytes,
                "Panel modified gatebsd.conf directly, violating single-writer invariant",
            )
            self.assertEqual(
                current_stat.st_mtime_ns,
                initial_stat.st_mtime_ns,
                "Panel touched gatebsd.conf metadata directly",
            )

    def test_rejected_source_preserves_state_and_runs_nothing(self) -> None:
        """Catch validation bypass where invalid input mutates disk state or triggers child execution.

        Malformed payloads (such as URLs containing paths or illegal characters)
        must fail fast at the boundary before writing files or invoking subprocesses.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sources_file = tmp_path / "etc" / "gatebsd" / "repo-sources.conf"
            sources_file.parent.mkdir(parents=True, exist_ok=True)
            initial_sources_bytes = b"active|http://original.lan\n"
            sources_file.write_bytes(initial_sources_bytes)

            marker_file = tmp_path / "bootstrap_ran.marker"
            stub_bootstrap = tmp_path / "stub-bootstrap.sh"
            stub_bootstrap.write_text(
                f"#!/bin/sh\necho ran > {marker_file}\nexit 0\n",
                encoding="utf-8",
            )
            stub_bootstrap.chmod(0o755)

            repo.SOURCES_FILE = sources_file
            repo.BOOTSTRAP = str(stub_bootstrap)
            repo.PKG = "/nonexistent/pkg"

            status, resp = repo.set_sources({
                "active": "http://mirror.example.lan/disallowed/path",
                "known": [],
            })

            self.assertEqual(status, 400, f"Expected 400 status for invalid URL, got {status}")
            self.assertIn("error", resp)
            self.assertFalse(marker_file.exists(), "Bootstrap script ran on invalid input")
            self.assertEqual(
                sources_file.read_bytes(),
                initial_sources_bytes,
                "sources file was modified despite validation failure",
            )


class ProbeTrustsTheCatalogue(unittest.TestCase):
    """The discovery probe must not accept an address just because pkg exited 0.

    Measured against the real mirror on the stand: with a public key that signs
    nothing there, `pkg update -f` complains about the key and still exits 0.
    The first version of this probe read that exit code as "signature verified"
    and would have offered a mirror serving somebody else's packages as good.
    What separates the cases is asking the catalogue for the appliance: it
    answers with the stand's key and answers nothing without it.

    The stub below reproduces exactly that shape, so the guard is exercised
    without a working pkg or a network.
    """

    def _stub_pkg(self, directory: Path, *, rquery_exit: int, rquery_out: str) -> Path:
        stub = directory / "pkg-stub"
        stub.write_text(
            "#!/bin/sh\n"
            "for a in \"$@\"; do\n"
            "  case $a in\n"
            "    update) exit 0 ;;\n"
            f"    rquery) printf '%s' \"{rquery_out}\"; exit {rquery_exit} ;;\n"
            "  esac\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return stub

    def test_update_alone_is_not_enough(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            stub = self._stub_pkg(Path(tmpdir), rquery_exit=1, rquery_out="")
            original = repo.PKG
            repo.PKG = str(stub)
            try:
                result = repo.probe("http://mirror.example.lan")
            finally:
                repo.PKG = original
            self.assertFalse(
                result["ok"],
                "an address whose catalogue holds nothing was accepted on the update alone",
            )
            self.assertIsNone(result["version"])

    def test_a_readable_catalogue_is_accepted(self) -> None:
        """The negative case above must not pass by rejecting everything."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stub = self._stub_pkg(Path(tmpdir), rquery_exit=0, rquery_out="gatebsd-2.9.92")
            original = repo.PKG
            repo.PKG = str(stub)
            try:
                result = repo.probe("http://mirror.example.lan")
            finally:
                repo.PKG = original
            self.assertTrue(result["ok"], f"a working mirror was rejected: {result}")
            self.assertEqual(result["version"], "gatebsd-2.9.92")


if __name__ == "__main__":
    unittest.main()
