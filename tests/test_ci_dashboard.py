"""Functional regression tests for the CI/CD dashboard generator.

Why these exist
---------------
Everything the GateBSD pipeline does already worked before the dashboard: runs
execute, packages are signed, releases land at a stable URL. None of it was
visible to an operator. Forgejo's own Actions UI redirects anonymous visitors to
a login page (anonymous repository access is disabled on purpose -- the runner
executes on the host with no container isolation), and this Forgejo version does
not serve the job-level REST endpoint at all: ``/actions/runs/<n>/jobs`` returns
404. So the only way to see whether a build succeeded was to log in, and the
only way to find its package was to read a job log for a build ID nobody could
derive.

``infra/freebsd-ci/ci-dashboard-update.sh`` closes that gap by reading Forgejo's
database read-only and rendering static HTML and JSON. That places it on the
trust boundary, so these tests pin the properties that make it safe and correct:

- it opens the database read-only and must never write to it, because Forgejo is
  a live service using the same file;
- it must not use ``immutable=1``, which would make SQLite ignore the WAL and
  silently omit every run recorded since the last checkpoint;
- a failed run must not advertise a package, because ``gatebsd-ci-build`` writes
  the .pkg *before* it verifies the catalogue signature, so a run that failed
  after that write leaves an unverified package on disk;
- a dangling ``versions/<VERSION>`` symlink must be reported, not hidden: it
  means an advertised URL resolves to nothing, which is how a package repository
  breaks for an operator mid-upgrade;
- author-controlled commit titles must be escaped in both HTML and JSON;
- the published tree must be swapped in atomically, so a fetch never observes a
  half-written dashboard.

The generator is exercised end to end against a synthetic Forgejo database and a
synthetic release tree. It was additionally run against the real Forgejo database
on the FreeBSD 15.1 host where the pipeline lives.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh"
TEMPLATE = ROOT / "infra" / "freebsd-ci" / "ci-dashboard.html"
INSTALLER = ROOT / "infra" / "freebsd-ci" / "install-ci-dashboard.sh"
LANDING = ROOT / "infra" / "freebsd-ci" / "mirror-index.html"

# The generator pins its own PATH, as anything run from cron should. That means
# it finds sqlite3 only in the standard system locations, which is correct in
# production but not necessarily true of a developer machine, so the tests pass
# an explicit interpreter path through the same override the script exposes.
SQLITE3 = shutil.which("sqlite3")

# Forgejo's action status enum. Confirmed against this instance by comparing the
# integers stored in action_run_job with what the REST API reports for the same
# rows: 1 -> success, 2 -> failure, 4 -> skipped.
SUCCESS, FAILURE, CANCELLED, SKIPPED = 1, 2, 3, 4


def zstd_available() -> bool:
    return shutil.which("zstd") is not None or shutil.which("zstdcat") is not None


class DashboardHarness:
    """Builds a synthetic Forgejo database and release tree, then runs the generator."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.db = root / "forgejo.db"
        self.actions_log = root / "actions_log"
        self.release_root = root / "releases"
        self.artifact_root = root / "artifacts"
        self.status_dir = root / "status"
        self.out_dir = root / "www" / "ci"
        self.template_dir = root / "template"

        for path in (
            self.actions_log,
            self.release_root / "builds",
            self.release_root / "versions",
            self.artifact_root,
            self.status_dir,
            self.out_dir.parent,
            self.template_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

        shutil.copy(TEMPLATE, self.template_dir / "ci-dashboard.html")
        self._init_db()

    # --- database ----------------------------------------------------------

    def _init_db(self) -> None:
        """Create the subset of Forgejo's schema the generator reads."""
        con = sqlite3.connect(self.db)
        con.executescript(
            """
            CREATE TABLE "user" (id INTEGER PRIMARY KEY, lower_name TEXT);
            CREATE TABLE repository (id INTEGER PRIMARY KEY, owner_id INTEGER,
                                     lower_name TEXT);
            CREATE TABLE action_run (id INTEGER PRIMARY KEY, "index" INTEGER,
                                     repo_id INTEGER, status INTEGER, event TEXT,
                                     ref TEXT, commit_sha TEXT, started INTEGER,
                                     stopped INTEGER, title TEXT);
            CREATE TABLE action_run_job (id INTEGER PRIMARY KEY, run_id INTEGER,
                                         name TEXT, status INTEGER,
                                         started INTEGER, stopped INTEGER,
                                         task_id INTEGER);
            CREATE TABLE action_task (id INTEGER PRIMARY KEY, log_filename TEXT);
            CREATE TABLE action_runner (id INTEGER PRIMARY KEY, name TEXT,
                                        version TEXT, last_online INTEGER);
            INSERT INTO "user" (id, lower_name) VALUES (2, 'gatebsd');
            INSERT INTO repository (id, owner_id, lower_name)
                VALUES (1, 2, 'gatebsd');
            """
        )
        con.commit()
        con.close()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        con = sqlite3.connect(self.db)
        con.execute(sql, params)
        con.commit()
        con.close()

    def add_runner(self, name: str = "ci-master", version: str = "v12.7.3",
                   *, age_seconds: int = 10) -> None:
        import time

        self._exec(
            "INSERT INTO action_runner (id, name, version, last_online)"
            " VALUES (1, ?, ?, ?)",
            (name, version, int(time.time()) - age_seconds),
        )

    def add_run(self, index: int, *, status: int = SUCCESS, sha: str,
                title: str = "a commit", event: str = "push",
                ref: str = "refs/heads/master",
                started: int = 1_785_384_869, duration: int = 30) -> int:
        self._exec(
            'INSERT INTO action_run (id, "index", repo_id, status, event, ref,'
            " commit_sha, started, stopped, title)"
            " VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
            (index, index, status, event, ref, sha, started,
             started + duration, title),
        )
        return index

    def add_job(self, job_id: int, run_id: int, name: str, *,
                status: int = SUCCESS, task_id: int = 0,
                log: str | None = None, log_body: str = "job output\n") -> None:
        self._exec(
            "INSERT INTO action_run_job (id, run_id, name, status, started,"
            " stopped, task_id) VALUES (?, ?, ?, ?, 0, 0, ?)",
            (job_id, run_id, name, status, task_id),
        )
        if task_id:
            self._exec(
                "INSERT INTO action_task (id, log_filename) VALUES (?, ?)",
                (task_id, log or ""),
            )
        if log:
            self._write_log(log, log_body)

    def _write_log(self, rel: str, body: str) -> None:
        target = self.actions_log / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".zst"):
            plain = target.with_suffix("")
            plain.write_text(body, encoding="utf-8")
            subprocess.run(
                ["zstd", "-q", "-f", str(plain), "-o", str(target)],
                check=True, capture_output=True,
            )
            plain.unlink()
        else:
            target.write_text(body, encoding="utf-8")

    # --- release tree ------------------------------------------------------

    def publish_release(self, version: str, build_id: str, *,
                        signed: bool = True, link_version: bool = True,
                        current: bool = False) -> Path:
        build = self.release_root / "builds" / build_id
        build.mkdir(parents=True, exist_ok=True)
        (build / f"gatebsd-{version}.pkg").write_bytes(b"payload\n")
        members = ["packagesite.yaml"]
        if signed:
            members.insert(0, "signature")
        self._write_tar(build / "packagesite.pkg", members)
        if link_version:
            link = self.release_root / "versions" / version
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(f"../builds/{build_id}")
        if current:
            cur = self.release_root / "current"
            if cur.is_symlink() or cur.exists():
                cur.unlink()
            cur.symlink_to(f"builds/{build_id}")
        return build

    def stage_artifact(self, build_id: str, version: str) -> Path:
        build = self.artifact_root / build_id
        build.mkdir(parents=True, exist_ok=True)
        (build / f"gatebsd-{version}.pkg").write_bytes(b"payload\n")
        return build

    def _write_tar(self, path: Path, members: list[str]) -> None:
        staging = self.root / "tarstage"
        staging.mkdir(exist_ok=True)
        with tarfile.open(path, "w") as tar:
            for member in members:
                entry = staging / member
                entry.write_text("x", encoding="ascii")
                tar.add(entry, arcname=member)

    # --- run the generator -------------------------------------------------

    def run(self, **overrides: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env.update(
            FORGEJO_DB=str(self.db),
            ACTIONS_LOG_ROOT=str(self.actions_log),
            RELEASE_ROOT=str(self.release_root),
            ARTIFACT_ROOT=str(self.artifact_root),
            STATUS_DIR=str(self.status_dir),
            OUT_DIR=str(self.out_dir),
            TEMPLATE_DIR=str(self.template_dir),
            BASE_URL="http://mirror.example.lan",
            FORGE_URL="https://git.example.lan/forgejo",
            REPO_SLUG="gatebsd/gatebsd",
        )
        if SQLITE3:
            env["SQLITE3"] = SQLITE3
        env.update(overrides)
        return subprocess.run(
            ["sh", str(GENERATOR)],
            env=env, capture_output=True, text=True,
        )

    # --- output accessors --------------------------------------------------

    @property
    def html(self) -> str:
        return (self.out_dir / "index.html").read_text(encoding="utf-8")

    @property
    def status(self) -> dict:
        return json.loads((self.out_dir / "status.json").read_text(encoding="utf-8"))


@unittest.skipUnless(SQLITE3, "the sqlite3 command line tool is required")
class DashboardTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.h = DashboardHarness(Path(self._tmp.name))

    def assertGenerated(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(
            result.returncode, 0,
            f"generator failed\nstdout: {result.stdout}\nstderr: {result.stderr}",
        )


class TestRendering(DashboardTestCase):
    """The dashboard must show runs, jobs and released packages."""

    def test_a_successful_run_shows_its_jobs_and_released_package(self) -> None:
        sha = "035d1dca97b0" + "a" * 28
        self.h.add_runner()
        self.h.add_run(12, sha=sha, title="fix(ci): publish releases")
        self.h.add_job(23, 12, "validate", task_id=23)
        self.h.add_job(24, 12, "freebsd-package", task_id=24)
        self.h.publish_release("2.9.4", "20260730T041451Z-035d1dca97b0",
                               current=True)

        self.assertGenerated(self.h.run())
        html = self.h.html

        self.assertIn("#12", html)
        self.assertIn("fix(ci): publish releases", html)
        self.assertIn("validate", html)
        self.assertIn("freebsd-package", html)
        self.assertIn("gatebsd-2.9.4.pkg", html)

        status = self.h.status
        self.assertEqual(status["pipeline"]["state"], "success")
        self.assertEqual(status["current_release"], "2.9.4")
        self.assertEqual(len(status["runs"]), 1)
        self.assertEqual(
            [job["name"] for job in status["runs"][0]["jobs"]],
            ["validate", "freebsd-package"],
        )

    def test_the_release_table_reports_the_signature_and_current_marker(self) -> None:
        self.h.add_runner()
        self.h.publish_release("2.9.4", "20260730T041451Z-aaaaaaaaaaaa",
                               signed=True, current=True)
        self.h.publish_release("2.9.3", "20260729T010101Z-bbbbbbbbbbbb",
                               signed=True)

        self.assertGenerated(self.h.run())

        releases = {r["version"]: r for r in self.h.status["releases"]}
        self.assertTrue(releases["2.9.4"]["signed"])
        self.assertTrue(releases["2.9.4"]["current"])
        self.assertFalse(releases["2.9.3"]["current"])
        self.assertIn("current", self.h.html)

    def test_an_unsigned_release_is_reported_as_unsigned(self) -> None:
        """An unsigned catalogue is accepted by a client configured without
        signature_type, so the dashboard must not imply it is signed."""
        self.h.add_runner()
        self.h.publish_release("2.9.4", "20260730T041451Z-aaaaaaaaaaaa",
                               signed=False, current=True)

        self.assertGenerated(self.h.run())

        self.assertFalse(self.h.status["releases"][0]["signed"])
        self.assertIn("signature: no", self.h.html)

    def test_releases_are_ordered_by_version_not_by_spelling(self) -> None:
        """Sorted as text, 2.9.9 outranks 2.9.15 and the newest release sinks.

        The table exists to answer "what is the current version", so the tenth
        release of a minor series must not push the whole of 2.9.4..2.9.9 above
        it.
        """
        self.h.add_runner()
        for index, version in enumerate(("2.9.4", "2.9.9", "2.9.10", "2.9.15")):
            self.h.publish_release(
                version,
                f"2026073{index}T041451Z-{'abcdef' * 2}",
                signed=True,
                current=(version == "2.9.15"),
            )

        self.assertGenerated(self.h.run())

        self.assertEqual(
            [release["version"] for release in self.h.status["releases"]],
            ["2.9.15", "2.9.10", "2.9.9", "2.9.4"],
        )

    def test_runs_are_ordered_newest_first(self) -> None:
        self.h.add_runner()
        for index in (1, 2, 3):
            self.h.add_run(index, sha=f"{index:012d}" + "0" * 28,
                           title=f"commit {index}")

        self.assertGenerated(self.h.run())

        self.assertEqual(
            [run["index"] for run in self.h.status["runs"]], [3, 2, 1]
        )

    def test_the_run_limit_is_honoured(self) -> None:
        self.h.add_runner()
        for index in range(1, 8):
            self.h.add_run(index, sha=f"{index:012d}" + "0" * 28)

        self.assertGenerated(self.h.run(RUN_LIMIT="3"))

        self.assertEqual(len(self.h.status["runs"]), 3)


class TestArtifactAttribution(DashboardTestCase):
    """A package must only be advertised for a run that actually released it."""

    def test_a_failed_run_does_not_advertise_a_package(self) -> None:
        """gatebsd-ci-build writes the .pkg before verifying the catalogue
        signature, so a run that failed after that write leaves an unverified
        package on disk. Offering it as though it were released invites an
        operator to install an artifact the pipeline rejected."""
        sha = "14ebcdedca98" + "b" * 28
        self.h.add_runner()
        self.h.add_run(8, status=FAILURE, sha=sha, title="fix(ci): broken build")
        self.h.add_job(16, 8, "freebsd-package", status=FAILURE)
        # The package exists on disk, exactly as it does for real failed builds.
        self.h.stage_artifact("20260729T221207Z-14ebcdedca98", "2.9.3_2")

        self.assertGenerated(self.h.run())

        self.assertIsNone(self.h.status["runs"][0]["artifact"])
        self.assertNotIn("gatebsd-2.9.3_2.pkg", self.h.html)
        self.assertIn("build failed", self.h.html)

    def test_a_successful_run_is_matched_to_its_build_by_commit(self) -> None:
        """The build ID embeds the short commit, which is what lets a release be
        attributed to a run without parsing a job log."""
        sha = "035d1dca97b0" + "a" * 28
        self.h.add_runner()
        self.h.add_run(12, sha=sha)
        self.h.publish_release("2.9.4", "20260730T041451Z-035d1dca97b0",
                               current=True)

        self.assertGenerated(self.h.run())

        artifact = self.h.status["runs"][0]["artifact"]
        self.assertEqual(artifact["build_id"], "20260730T041451Z-035d1dca97b0")
        self.assertEqual(artifact["package"], "gatebsd-2.9.4.pkg")
        self.assertIn("/gatebsd/releases/builds/", artifact["url"])

    def test_a_release_is_preferred_over_a_scratch_artifact(self) -> None:
        """/tank/ci/artifacts is pruned by build count; the release tree is
        retained by version. When both hold the same build, the durable URL is
        the one worth publishing."""
        sha = "035d1dca97b0" + "a" * 28
        build_id = "20260730T041451Z-035d1dca97b0"
        self.h.add_runner()
        self.h.add_run(12, sha=sha)
        self.h.stage_artifact(build_id, "2.9.4")
        self.h.publish_release("2.9.4", build_id, current=True)

        self.assertGenerated(self.h.run())

        self.assertIn(
            "/gatebsd/releases/builds/",
            self.h.status["runs"][0]["artifact"]["url"],
        )

    def test_a_run_that_published_nothing_says_so(self) -> None:
        self.h.add_runner()
        self.h.add_run(5, status=SKIPPED, sha="deadbeefcafe" + "0" * 28)

        self.assertGenerated(self.h.run())

        self.assertIsNone(self.h.status["runs"][0]["artifact"])
        self.assertIn("package not published", self.h.html)


class TestDanglingRelease(DashboardTestCase):
    """A version link that resolves to nothing must be surfaced."""

    def test_a_dangling_version_symlink_is_reported_as_broken(self) -> None:
        """prune_releases() is written never to remove a referenced build, but a
        dangling link is how a pkg repository fails for an operator mid-upgrade:
        pkg reports a fetch error rather than an absent repository. Hiding it
        would make the dashboard agree with a broken repository."""
        self.h.add_runner()
        build = self.h.publish_release("2.9.4", "20260730T041451Z-aaaaaaaaaaaa")
        shutil.rmtree(build)

        self.assertGenerated(self.h.run())

        self.assertIn("dangling link", self.h.html)
        # A broken release must not be offered as installable.
        self.assertEqual(self.h.status["releases"], [])


class TestProjectSlug(DashboardTestCase):
    """The dashboard links into the mirror tree, which is rooted per project.

    One stand serves the closed development loop of more than one product, so
    `/gatebsd/` is the first product's root and not the platform's. The links
    are derived from PROJECT_SLUG now; its default is `gatebsd`, which is what
    keeps every URL on the published page exactly what it is today.
    """

    def publish(self) -> None:
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)
        self.h.publish_release("2.9.4", "20260730T041451Z-035d1dca97b0", current=True)

    def test_the_default_links_where_the_dashboard_links_today(self) -> None:
        self.publish()
        self.assertGenerated(self.h.run())
        self.assertIn("/gatebsd/releases/versions/2.9.4/", self.h.html)
        self.assertIn('href="/gatebsd/releases/current/"', self.h.html)
        self.assertIn(
            "/gatebsd/releases/builds/", self.h.status["runs"][0]["artifact"]["url"]
        )

    def test_a_second_product_is_linked_under_its_own_root(self) -> None:
        """Every link the page carries has to move together. A page that sent
        an operator of the second product to the first product's release tree
        would be worse than one with no links: the tree it points at exists,
        answers, and holds somebody else's packages."""
        self.publish()
        self.assertGenerated(self.h.run(PROJECT_SLUG="harborward"))
        html = self.h.html
        self.assertIn("/harborward/releases/versions/2.9.4/", html)
        self.assertIn('href="/harborward/releases/current/"', html)
        self.assertIn(
            "/harborward/releases/builds/",
            self.h.status["runs"][0]["artifact"]["url"],
        )
        self.assertNotIn("/gatebsd/releases/", html)

    def test_an_unusable_slug_is_refused_before_anything_is_published(self) -> None:
        """The slug reaches a filesystem path and an HTML attribute. Failing
        loudly beats publishing a page whose links climb out of the web root."""
        self.publish()
        for slug in ("", "../escape", "gate bsd"):
            with self.subTest(slug=slug):
                result = self.h.run(PROJECT_SLUG=slug)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("PROJECT_SLUG", result.stderr)


class TestRunnerHealth(DashboardTestCase):
    """A silent runner is the failure mode where a push produces no run at all."""

    def test_a_recently_seen_runner_is_online(self) -> None:
        self.h.add_runner(age_seconds=10)

        self.assertGenerated(self.h.run())

        self.assertEqual(self.h.status["runner"]["state"], "online")

    def test_a_stale_runner_is_offline(self) -> None:
        self.h.add_runner(age_seconds=3600)

        self.assertGenerated(self.h.run())

        self.assertEqual(self.h.status["runner"]["state"], "offline")

    def test_a_missing_runner_is_reported(self) -> None:
        self.assertGenerated(self.h.run())

        self.assertEqual(self.h.status["runner"]["state"], "missing")


class TestLogPublication(DashboardTestCase):
    """Job logs are the reason an operator visits at all when a build fails."""

    @unittest.skipUnless(zstd_available(), "zstd is required to write test logs")
    def test_a_compressed_job_log_is_decompressed_and_published(self) -> None:
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)
        self.h.add_job(
            24, 12, "freebsd-package", task_id=24,
            log="gatebsd/gatebsd/18/24.log.zst",
            log_body="Built /build/dist/gatebsd-2.9.4.pkg\n",
        )

        self.assertGenerated(self.h.run())

        published = self.h.out_dir / "logs" / "24.txt"
        self.assertTrue(published.is_file())
        self.assertIn("gatebsd-2.9.4.pkg", published.read_text(encoding="utf-8"))
        self.assertEqual(self.h.status["runs"][0]["jobs"][0]["log"], "logs/24.txt")

    @unittest.skipUnless(zstd_available(), "zstd is required to write test logs")
    def test_an_oversized_log_is_truncated(self) -> None:
        """A runaway job would otherwise let one build fill the web root."""
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)
        self.h.add_job(
            24, 12, "freebsd-package", task_id=24,
            log="gatebsd/gatebsd/18/24.log.zst",
            log_body="x" * 100_000,
        )

        self.assertGenerated(self.h.run(LOG_MAX_BYTES="4096"))

        published = self.h.out_dir / "logs" / "24.txt"
        self.assertLessEqual(published.stat().st_size, 4096)

    def test_a_job_without_a_log_is_marked_as_such(self) -> None:
        self.h.add_runner()
        self.h.add_run(2, status=FAILURE, sha="b10001073bc9" + "0" * 28)
        self.h.add_job(3, 2, "validate", status=FAILURE)

        self.assertGenerated(self.h.run())

        self.assertIsNone(self.h.status["runs"][0]["jobs"][0]["log"])
        self.assertIn("no log", self.h.html)

    @unittest.skipUnless(zstd_available(), "zstd is required to write test logs")
    def test_logs_are_published_only_for_the_newest_runs(self) -> None:
        self.h.add_runner()
        for index in (1, 2, 3):
            self.h.add_run(index, sha=f"{index:012d}" + "0" * 28)
            self.h.add_job(
                index, index, "validate", task_id=index,
                log=f"gatebsd/gatebsd/{index}/{index}.log.zst",
            )

        self.assertGenerated(self.h.run(LOG_RUNS="1"))

        logs = sorted(p.name for p in (self.h.out_dir / "logs").iterdir())
        self.assertEqual(logs, ["3.txt"])

    def test_a_traversing_log_path_is_refused(self) -> None:
        """log_filename is Forgejo-generated, but it still crosses into a
        filesystem path here, so a traversal attempt must not be followed."""
        secret = self.h.root / "secret.txt"
        secret.write_text("private key material\n", encoding="utf-8")
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)
        self.h.add_job(24, 12, "validate", task_id=24, log="../secret.txt")

        self.assertGenerated(self.h.run())

        self.assertIsNone(self.h.status["runs"][0]["jobs"][0]["log"])
        published = list((self.h.out_dir / "logs").iterdir())
        self.assertEqual(published, [])


class TestEscaping(DashboardTestCase):
    """Commit titles are author-controlled and land in HTML and JSON alike."""

    def test_a_commit_title_with_markup_is_escaped_in_html(self) -> None:
        self.h.add_runner()
        self.h.add_run(
            12, sha="035d1dca97b0" + "a" * 28,
            title='<img src=x onerror="alert(1)">',
        )

        self.assertGenerated(self.h.run())

        html = self.h.html
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img src=x", html)
        self.assertIn("&quot;", html)

    def test_a_commit_title_with_quotes_produces_valid_json(self) -> None:
        self.h.add_runner()
        self.h.add_run(
            12, sha="035d1dca97b0" + "a" * 28,
            title='fix: handle a "quoted" path and a \\ backslash',
        )

        self.assertGenerated(self.h.run())

        # Parsing is the assertion: an unescaped quote or backslash would raise.
        title = self.h.status["runs"][0]["title"]
        self.assertIn("quoted", title)

    def test_the_rendered_page_leaves_no_unsubstituted_placeholder(self) -> None:
        import re

        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)

        self.assertGenerated(self.h.run())

        leftover = re.findall(r"@@[A-Z_]+@@", self.h.html)
        self.assertEqual(leftover, [], f"unsubstituted placeholders: {leftover}")


class TestDatabaseSafety(DashboardTestCase):
    """Forgejo is live and uses the same database file."""

    def test_the_database_is_opened_read_only(self) -> None:
        source = GENERATOR.read_text(encoding="utf-8")
        self.assertIn("mode=ro", source)
        self.assertIn("-readonly", source)

    def test_the_database_is_not_opened_immutable(self) -> None:
        """immutable=1 makes SQLite ignore the WAL. Against a running Forgejo
        that silently drops every run recorded since the last checkpoint, so the
        newest build -- the one an operator is looking for -- would be missing.

        The assertion inspects the connection URI actually passed to sqlite3
        rather than searching the whole file, because the comment explaining why
        immutable is unsafe here necessarily mentions it by name.
        """
        source = GENERATOR.read_text(encoding="utf-8")
        uris = re.findall(r'"file:\$\{FORGEJO_DB\}\?([^"]*)"', source)
        self.assertTrue(uris, "no sqlite3 connection URI found in the generator")
        for query in uris:
            self.assertNotIn("immutable", query)
            self.assertIn("mode=ro", query)

    def test_generating_the_dashboard_does_not_modify_the_database(self) -> None:
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)
        self.h.add_job(24, 12, "validate", task_id=24)

        before = self.h.db.read_bytes()
        self.assertGenerated(self.h.run())
        self.assertEqual(self.h.db.read_bytes(), before)

    def test_a_missing_database_fails_loudly(self) -> None:
        result = self.h.run(FORGEJO_DB=str(self.h.root / "absent.db"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not readable", result.stderr)

    def test_an_unknown_repository_fails_loudly(self) -> None:
        result = self.h.run(REPO_SLUG="nobody/nothing")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr)


class TestAtomicPublication(DashboardTestCase):
    """A fetch must never observe a half-written dashboard."""

    def test_a_previous_dashboard_is_replaced_completely(self) -> None:
        self.h.add_runner()
        self.h.add_run(11, sha="e2d3eec47c4c" + "0" * 28, title="first")
        self.assertGenerated(self.h.run())
        stale = self.h.out_dir / "logs" / "stale.txt"
        stale.write_text("from an older generation\n", encoding="utf-8")

        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28, title="second")
        self.assertGenerated(self.h.run())

        self.assertFalse(stale.exists(), "stale output survived the swap")
        self.assertIn("second", self.h.html)

    def test_no_staging_directory_is_left_behind(self) -> None:
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)

        self.assertGenerated(self.h.run())

        leftovers = [
            p.name for p in self.h.out_dir.parent.iterdir()
            if p.name.startswith("ci.new") or p.name.startswith("ci.old")
            or p.name.startswith(".ci-dashboard")
        ]
        self.assertEqual(leftovers, [])

    def test_the_output_is_world_readable(self) -> None:
        """nginx runs as www and must be able to read what was just published."""
        self.h.add_runner()
        self.h.add_run(12, sha="035d1dca97b0" + "a" * 28)

        self.assertGenerated(self.h.run())

        for path in (self.h.out_dir / "index.html", self.h.out_dir / "status.json"):
            self.assertTrue(path.stat().st_mode & 0o044, f"{path} is not readable")


class TestInstaller(unittest.TestCase):
    """The installer must be safe to re-run and must not shadow an existing route."""

    def setUp(self) -> None:
        self.source = INSTALLER.read_text(encoding="utf-8")

    def test_the_idempotency_guard_matches_the_exact_route(self) -> None:
        """A plain `grep 'location /ci/'` also matches the pre-existing
        `location /ci/artifacts/`, so the installer reports the route as present
        and never inserts it -- leaving /ci/ a 404. This was observed on the
        stand before the guard was anchored."""
        self.assertIn(r"location /ci/ \{", self.source)
        self.assertNotIn("grep -q 'location /ci/'", self.source)

    def test_the_slashless_url_is_redirected(self) -> None:
        """`location /ci/` does not match a request for /ci, and nginx only
        synthesises the trailing-slash redirect automatically for `root`, not for
        `alias`. Without an explicit redirect the obvious URL an operator types
        falls through to `location /` and returns 404 -- which is exactly what
        happened on the stand after the first install."""
        self.assertIn("location = /ci {", self.source)
        self.assertIn("return 301 /ci/;", self.source)

    def test_the_generated_route_is_structurally_valid(self) -> None:
        """Run the installer's own awk transform and check the config it produces.

        Asserting on the script text was tried first and proved worthless: the
        explanatory comment above the block contains the literal `location /ci/`,
        and every string-matching variant either passed on a genuinely broken
        arrangement or pinned an ordering rule nginx does not actually enforce
        (both orders load fine in an isolated server block -- verified on the
        host). What nginx does reject is the exact-match block ending up *inside*
        the prefix block, which is the failure hit on the stand.

        So this drives the real transform over a representative config and parses
        the result, which is the only form of this test that distinguishes a
        working route from a broken one.
        """
        transform = self._extract_awk_program()
        base = (
            "server {\n"
            "    location /ci/artifacts/ {\n"
            "        alias /tank/ci/artifacts/;\n"
            "    }\n"
            "}\n"
        )
        result = subprocess.run(
            ["awk", transform], input=base, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = result.stdout

        self.assertIn("location = /ci {", generated)
        self.assertIn("return 301 /ci/;", generated)
        self.assertIn("location /ci/ {", generated)

        # Depth-track the braces of the emitted config. The redirect must sit at
        # the same depth as the prefix location (both direct children of server),
        # never deeper.
        depth = 0
        depth_of = {}
        for line in generated.splitlines():
            stripped = line.strip()
            if stripped.startswith("location = /ci ") or stripped.startswith("location /ci/ "):
                depth_of[stripped.split("{")[0].strip()] = depth
            depth += line.count("{") - line.count("}")

        self.assertIn("location = /ci", depth_of, "redirect block not emitted")
        self.assertIn("location /ci/", depth_of, "prefix block not emitted")
        self.assertEqual(
            depth_of["location = /ci"], depth_of["location /ci/"],
            "the /ci redirect must be a sibling of location /ci/, not nested"
            ' inside it; nginx rejects the latter with \'location "/ci" is'
            ' outside location "/ci/"\'',
        )

    def _extract_awk_program(self) -> str:
        """Pull the awk program the installer runs to insert the route."""
        start = self.source.index("awk '")
        end = self.source.index("' \"${conf}\"", start)
        return self.source[start + len("awk '") : end]

    def test_the_artifacts_route_is_preserved(self) -> None:
        """nginx matches the longest prefix, so /ci/artifacts/ must keep working
        after /ci/ is added. The installer anchors to it rather than replacing
        it."""
        self.assertIn("location /ci/artifacts/", self.source)

    def test_nginx_is_validated_before_reload(self) -> None:
        """A bad config would take the mirror, the package repository and the
        Forgejo web UI down together."""
        self.assertIn("nginx -t", self.source)
        validate = self.source.index("nginx -t")
        reload_at = self.source.index("service nginx reload")
        self.assertLess(validate, reload_at)

    def test_a_rejected_config_is_rolled_back(self) -> None:
        self.assertIn("before-ci-dashboard-", self.source)
        self.assertIn("restoring the previous one", self.source)

    def test_the_generator_runs_once_at_install_time(self) -> None:
        """Without this the route resolves to a 404 until the first cron tick."""
        self.assertIn("/usr/local/sbin/ci-dashboard-update", self.source)


class TestLandingPage(unittest.TestCase):
    """The dashboard is worthless if nothing links to it."""

    def setUp(self) -> None:
        self.source = LANDING.read_text(encoding="utf-8")

    def test_the_landing_page_links_to_the_dashboard(self) -> None:
        self.assertIn('href="/ci/"', self.source)
        self.assertIn("CI/CD", self.source)

    def test_the_landing_page_links_to_the_current_release(self) -> None:
        self.assertIn('href="/gatebsd/releases/current/"', self.source)

    def test_the_dashboard_is_listed_before_the_mirror_internals(self) -> None:
        """An operator looking for a build should not have to scan past six
        mirror-browsing links to find it."""
        self.assertLess(
            self.source.index('href="/ci/"'),
            self.source.index('href="/freebsd/git/src/"'),
        )


if __name__ == "__main__":
    unittest.main()
