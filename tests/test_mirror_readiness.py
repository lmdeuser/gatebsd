"""A mirror being refreshed is not a mirror that is down.

The release pipeline gates on /health/ready, which is a flag file the mirror
health check writes. Readiness used to require STATUS=OK in the sync report --
true only *between* nightly runs. The sync takes hours, so a push inside that
window failed the pipeline on "mirror: FAIL" while the mirror was serving
perfectly well, and the message named no cause. Measured 2026-08-01: sync
started 00:15 and was still running at 03:00, `current` intact throughout,
base.txz answering 206 over HTTP, release blocked.

Publication is atomic by construction -- the sync builds versions/.staging and
moves the `current` symlink in one step -- so what is being served cannot be
half-written, and a sync in flight says nothing about it.

These tests RUN the script against a fabricated mirror and a real HTTP server.
"""
from __future__ import annotations

import functools
import http.server
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infra" / "freebsd-ci" / "mirror-health-check.sh"

RELEASE = "releases/amd64/amd64"
ISO = f"{RELEASE}/ISO-IMAGES/15.1/FreeBSD-15.1-RELEASE-amd64-disc1.iso"
BASE_TXZ = f"{RELEASE}/15.1-RELEASE/base.txz"


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401 - silence the server
        pass


@unittest.skipUnless(shutil.which("curl"), "the check shells out to curl")
class MirrorReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)

        # A published tree, complete and served: pub/current -> versions/<ts>.
        version = self.root / "pub" / "versions" / "20260730T191500Z" / "FreeBSD"
        (version / f"{RELEASE}/15.1-RELEASE").mkdir(parents=True)
        (version / f"{RELEASE}/ISO-IMAGES/15.1").mkdir(parents=True)
        (version / BASE_TXZ).write_bytes(b"base")
        (version / ISO).write_bytes(b"iso")
        (self.root / "pub" / "current").symlink_to(version.parent)
        # nginx serves /pub/FreeBSD/ out of whatever `current` points at; the
        # check dials that URL, so the fake mirror has to offer the same shape.
        (self.root / "pub" / "FreeBSD").symlink_to(version)
        (self.root / "status").mkdir(parents=True)

        handler = functools.partial(_QuietHandler, directory=str(self.root))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def _write_sync_status(self, state: str) -> None:
        (self.root / "status" / "freebsd-15-amd64-sync.txt").write_text(
            "UPDATED_UTC=2026-07-31T19:15:00Z\n"
            f"STATUS={state}\n"
            "UPSTREAM=rsync://ftp.de.FreeBSD.org/FreeBSD\n",
            encoding="utf-8",
        )

    def _fake_zpool(self, capacity: int, free: str = "120G") -> str:
        """A stub zpool(8). The machine these tests run on has none, and a
        space guard that cannot be driven to its thresholds has not been shown
        to work at all."""
        stub = self.root / "zpool"
        stub.write_text(
            "#!/bin/sh\n"
            # zpool list -H -o <field> <pool>: the field is $4, not $3.
            'case "$4" in\n'
            f'  capacity) echo "{capacity}%" ;;\n'
            f'  free) echo "{free}" ;;\n'
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return str(stub)

    def _run(self, zpool: str | None = None, pkg: str | None = None,
             poudriere_jail: str | None = None) -> dict[str, str]:
        environment = dict(os.environ)
        environment.update({
            "MIRROR_ROOT": str(self.root),
            "MIRROR_BASE_URL": self.base_url,
        })
        if zpool is not None:
            environment["MIRROR_ZPOOL"] = zpool
        if pkg is not None:
            environment["MIRROR_PKG"] = pkg
        if poudriere_jail is not None:
            environment["MIRROR_POUDRIERE_JAIL"] = poudriere_jail
        # The overall exit status is not asserted: this fabricated mirror has no
        # git repositories or poudriere tree, so other checks legitimately fail.
        # What matters is the verdict recorded for the published 15.1 tree.
        subprocess.run(
            ["sh", str(SCRIPT)], env=environment, capture_output=True, text=True, timeout=120,
        )
        detail = (self.root / "status" / "health-detail.txt").read_text(encoding="utf-8")
        return dict(
            line.split("=", 1) for line in detail.splitlines() if "=" in line
        )

    def test_a_sync_in_progress_does_not_condemn_the_published_tree(self) -> None:
        self._write_sync_status("IN_PROGRESS")
        fields = self._run()
        self.assertEqual(
            fields.get("freebsd_15_amd64_full"), "OK",
            "a mirror serving a complete tree was reported as unusable because a "
            "refresh happened to be running",
        )

    def test_the_sync_state_is_still_reported(self) -> None:
        """Dropping it from the gate must not drop it from view."""
        self._write_sync_status("IN_PROGRESS")
        self.assertEqual(self._run().get("freebsd_15_amd64_sync"), "IN_PROGRESS")

    def test_a_failed_sync_is_visible_but_not_fatal(self) -> None:
        self._write_sync_status("FAILED")
        fields = self._run()
        self.assertEqual(fields.get("freebsd_15_amd64_sync"), "FAILED")
        self.assertEqual(fields.get("freebsd_15_amd64_full"), "OK")

    def test_a_genuinely_broken_tree_still_fails(self) -> None:
        """The substantive checks must keep their teeth."""
        self._write_sync_status("OK")
        (self.root / "pub" / "current" / "FreeBSD" / BASE_TXZ).unlink()
        self.assertEqual(self._run().get("freebsd_15_amd64_full"), "FAIL")

    def test_a_missing_sync_report_reads_as_unknown(self) -> None:
        fields = self._run()
        self.assertEqual(fields.get("freebsd_15_amd64_sync"), "UNKNOWN")



class PoolSpaceTests(MirrorReadinessTests):
    """A full pool is the failure that reports itself as somebody else's error.

    On 23 August 2026 tank reached 100%, the release sync started exiting rc=1,
    and the published mirror stopped moving for four days while every other
    check here stayed green -- the tree was still there and still served, it
    just never changed. Nothing on this list was wrong, and that was the
    problem. Measured cause: 104 rollback copies of the git mirror, 180 GB,
    going back to 19 July, which nothing pruned.
    """

    def test_a_roomy_pool_is_ok(self) -> None:
        self._write_sync_status("OK")
        fields = self._run(zpool=self._fake_zpool(32, "403G"))
        self.assertEqual("OK", fields["pool_space"])
        self.assertEqual("32%", fields["pool_capacity"])
        self.assertEqual("403G", fields["pool_free"])

    def test_the_warning_arrives_before_the_failure(self) -> None:
        """80% is reported but is not the same verdict as full: there is still
        room to act, and blocking releases at that point costs more than it
        saves.

        Not covered here: that LOW leaves overall readiness alone. This
        fabricated mirror has no git repositories and no poudriere tree, so it
        is NOT_READY whatever the pool says, and an assertion on the flag would
        pass for the wrong reason.
        """
        self._write_sync_status("OK")
        fields = self._run(zpool=self._fake_zpool(85))
        self.assertEqual("LOW", fields["pool_space"])

    def test_a_pool_about_to_fill_is_condemned(self) -> None:
        self._write_sync_status("OK")
        fields = self._run(zpool=self._fake_zpool(95))
        self.assertEqual("FULL", fields["pool_space"])

    def test_the_boundaries_belong_to_the_worse_verdict(self) -> None:
        self._write_sync_status("OK")
        for capacity, verdict in ((79, "OK"), (80, "LOW"), (89, "LOW"), (90, "FULL")):
            with self.subTest(capacity=capacity):
                fields = self._run(zpool=self._fake_zpool(capacity))
                self.assertEqual(verdict, fields["pool_space"])

    def test_no_zpool_is_unknown_rather_than_healthy(self) -> None:
        """Absent evidence must not read as a healthy pool."""
        self._write_sync_status("OK")
        fields = self._run(zpool=str(self.root / "no-such-zpool"))
        self.assertEqual("UNKNOWN", fields["pool_capacity"])
        self.assertNotIn("pool_space", fields)


class PoudriereJailIsPristine(MirrorReadinessTests):
    """The build image must carry nothing, and until 27 August it carried 73.

    `prepare-gatebsd-build-jail.sh` installed the appliance's package set into
    the jail poudriere clones every builder from, perl5 among them. It cost
    nothing while the ports tree wanted that same perl. When the tree moved
    5.42.2 -> 5.42.3 on 26 August, `perl5>=5.42.r<5.43` was satisfied by the
    stale in-jail copy, poudriere never queued a rebuild, and five p5- ports
    died on `env: /usr/local/bin/perl5.42.3: No such file or directory`, taking
    40 more down as skipped -- including the two the router's VPN runs on.

    The separation landed the same day with nothing to verify it. These tests
    are that verification, and they run the script rather than read it.
    """

    def _fake_pkg(self, *names: str, rootdir_exists: bool = True) -> str:
        """A pkg that answers `query %n` the way the real one was measured to.

        Empty output with exit 0 for a pristine jail, one name per line for a
        populated one, exit 1 when the root does not exist.
        """
        stub = self.root / f"pkg-stub-{len(names)}-{int(rootdir_exists)}"
        listing = "".join(f"echo {name}\n" for name in names)
        stub.write_text(
            "#!/bin/sh\n"
            + ("" if rootdir_exists else "exit 1\n")
            + listing
            + "exit 0\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return str(stub)

    def test_an_empty_build_jail_is_healthy(self) -> None:
        self._write_sync_status("OK")
        fields = self._run(pkg=self._fake_pkg(), poudriere_jail=str(self.root))
        self.assertEqual("OK", fields["poudriere_jail_pristine"])
        self.assertEqual("0", fields["poudriere_jail_packages"])

    def test_a_contaminated_build_jail_is_named_as_such(self) -> None:
        """The case that actually happened: perl5 sitting in the build image.

        Not covered here: that the verdict actually stops a release. This
        fabricated mirror has no git repositories, no poudriere tree and no
        nginx, so it is NOT_READY whatever this check decides, and asserting on
        the flag would pass with the `ready=0` deleted -- which is exactly what
        a mutation showed it doing. The gate was proven instead where a mirror
        is genuinely ready, on the stand on 2026-08-27: with a stub reporting
        two packages the run exited 1, wrote NOT_READY and removed
        health-ready-ok; with the real pkg the next run exited 0 and put both
        back.
        """
        self._write_sync_status("OK")
        fields = self._run(
            pkg=self._fake_pkg("perl5", "amnezia-kmod", "nginx"),
            poudriere_jail=str(self.root),
        )
        self.assertEqual("CONTAMINATED", fields["poudriere_jail_pristine"])
        self.assertEqual("3", fields["poudriere_jail_packages"])

    def test_a_jail_that_cannot_be_asked_is_unknown_rather_than_healthy(self) -> None:
        """Absent evidence must not read as a clean image.

        Not covered: that UNKNOWN leaves overall readiness alone. This
        fabricated mirror is NOT_READY whatever this check says, so asserting
        on the flag here would pass for the wrong reason.
        """
        self._write_sync_status("OK")
        fields = self._run(
            pkg=self._fake_pkg(rootdir_exists=False), poudriere_jail=str(self.root),
        )
        self.assertEqual("UNKNOWN", fields["poudriere_jail_pristine"])
        self.assertNotIn("poudriere_jail_packages", fields)


if __name__ == "__main__":
    unittest.main()
