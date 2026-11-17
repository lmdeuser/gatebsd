"""Four files on the stand had more than one writer, and the extra was invisible.

`ci/host/configure_freebsd_mirror.sh` wrote, from heredocs:

  * `/usr/local/etc/cron.d/freebsd-local-repo`, which
    `infra/freebsd-ci/deployment.manifest` also owns. The manifest's copy won,
    because nobody re-ran the script -- but the script's version is a single
    04:15 line, so a re-run would have replaced the FreeBSD mirror sync, the
    health check, the status update and the TLS renewal with it. cron(8) would
    have taken that up without a word.

  * `/usr/local/etc/poudriere.d/gatebsd-pkglist`, which lost the race the other
    way: the live copy had been hand-edited to `lang/python312`,
    `databases/py-sqlite3@py312` and the two amnezia ports the router's VPN
    runs on, and the heredoc still said `lang/python3`. The pkglist was in no
    manifest and no verifier looked at it, so a re-run would have dropped the
    VPN's ports from the built package set and nothing would have said so.

  * `/usr/local/sbin/update-freebsd-local-repo`, which reads that list.

The fourth file is `/usr/local/etc/poudriere.conf`, and it had three writers.
`infra/freebsd-ci/bootstrap.sh` installed the repository's copy over it
wholesale; `configure_freebsd_mirror.sh` rewrote eleven keys of it in place
with awk, keeping a dated `cp -p` beside the live file each time; and a hand
edit had added nine keys neither script knew about. Editing in place is what
let it run for a year -- each writer preserved what it did not recognise -- but
the file was in no manifest, so nothing ever compared the repository's copy to
the machine's, and the repository's copy drifted into a version that had never
been deployed anywhere. It has no PKG_REPO_SIGNING_KEY. Installing it, which
is exactly what step 2 of the recovery order did, would have left the stand
publishing an unsigned package repository that the router's pkg refuses.

All four are repository files now, deployed from the manifest. Every test here
RUNS something -- the installer, the verifier, the bring-up script or
bootstrap.sh. A test that reads `configure_freebsd_mirror.sh` looking for the
absence of a heredoc passes just as happily with the heredoc present and
sitting behind `if false`, which is how a wiring test in this tree missed a
defect before.
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "freebsd-ci"
INSTALL = INFRA / "install-ci-host.sh"
VERIFY = INFRA / "verify-deployment.sh"
BOOTSTRAP = INFRA / "bootstrap.sh"
CONFIGURE = ROOT / "ci" / "host" / "configure_freebsd_mirror.sh"

PKGLIST_SOURCE = INFRA / "gatebsd-pkglist"
CRON_SOURCE = INFRA / "freebsd-mirror.cron"
UPDATE_SOURCE = INFRA / "update-freebsd-local-repo.sh"
POUDRIERE_CONF_SOURCE = INFRA / "poudriere.conf"

# Read off the stand on 2026-08-06. These are the keys the repository's own
# copy of poudriere.conf had lost, and each is load-bearing: without the
# signing key the local repository is published unsigned and the appliance's
# pkg, which asks for `signature_type: "pubkey"`, installs nothing at all; the
# rest are what nginx serves the build logs from.
SETTINGS_THE_REPOSITORY_HAD_LOST = {
    "PKG_REPO_SIGNING_KEY": "/usr/local/etc/ssl/keys/pkg.key",
    "URL_BASE": "http://mirror.example.lan/poudriere",
    "POUDRIERE_HTML_DATA": "/usr/local/share/poudriere/html",
    "POUDRIERE_LOG_PATH": "/tank/packages/poudriere/data/logs",
    "POUDRIERE_LOG_PATH_STATIC": "/tank/packages/poudriere/data/logs/bulk",
    "POUDRIERE_LOG_URL": "/data",
    "POUDRIERE_DATA_URL": "/data",
    "POUDRIERE_LOG_HTML_URL": "/poudriere",
    "POUDRIERE_HTML_URL": "/poudriere",
}

# The dated copies `configure_freebsd_mirror.sh` left in /usr/local/etc, still
# there in August. Two of the three are byte-identical to the live file, which
# is what a backup taken before an edit that changes nothing looks like.
DATED_COPIES_ON_THE_STAND = (
    "poudriere.conf.before-local-repo-20260714-162337",
    "poudriere.conf.before-local-repo-20260714-165910",
    "poudriere.conf.before-local-repo-20260714-175856",
)


def copies_beside(conf: Path) -> list[str]:
    """Every `poudriere.conf*` in the directory except the managed file itself.

    Both writers kept a dated `cp -p` of the previous file next to the live
    one, which is the habit this repository forbids: a copy beside a live file
    is not a backup, it is a second live file. Asserting on the whole
    directory instead would fail on the ssl/ tree the bring-up creates for the
    signing key, which it is supposed to create.
    """
    return sorted(
        p.name
        for p in conf.parent.iterdir()
        if p.name.startswith(conf.name) and p.name != conf.name
    )


def poudriere_settings(text: str) -> dict[str, str]:
    """The key=value pairs poudriere would see, comments and blanks dropped.

    poudriere sources the file as sh(1), so the comments this repository adds
    are free -- but only the assignments are the configuration, and those are
    what a test may assert on.
    """
    settings = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        settings[key] = value
    return settings

# What the appliance requires. This started as a copy of the stand's live
# pkglist, which is why net/amneziawg-go was missing from it: the live list was
# hand-edited before the userspace implementation existed as a port here. The
# live file is evidence of what someone typed, not a statement of what the
# appliance needs -- taking it as the expectation is how the omission got
# reproduced into a test that then defended it.
EXPECTED_ORIGINS = [
    "databases/py-sqlite3@py312",
    "dns/unbound",
    "lang/python312",
    "net/amnezia-kmod",
    "net/amnezia-tools",
    "net/amneziawg-go",
    "net/isc-dhcp44-server",
    "net/mpd5",
    "net/rsync",
    "security/acme.sh",
    "security/ca_root_nss",
    "security/p5-Authen-SASL",
    "security/sudo",
    "sysutils/nut",
    "sysutils/smartmontools",
    "www/nginx",
]


def poudriere_origins(text: str) -> list[str]:
    """Read a pkglist the way poudriere does.

    common.sh takes the first whitespace-separated word of each line as the
    origin and ignores the rest, and skips a line whose first word begins with
    '#' -- "Skip blank lines and comments". Annotations are therefore free; the
    origins are what the build actually gets.
    """
    origins = []
    for line in text.splitlines():
        first = line.split()[:1]
        if not first or first[0].startswith("#"):
            continue
        origins.append(first[0])
    return origins


def root_check_stub(directory: Path) -> Path:
    """An `id` that answers 0 to `id -u`, and nothing else.

    install-ci-host.sh and the bring-up script both refuse to run as anyone but
    root, and rightly so. Only that check is faked here; every write these
    tests observe is a real write by the real script, and the manifests they
    are given name the invoking user so install(1) needs no privilege.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "id"
    stub.write_text(
        '#!/bin/sh\nif [ "$1" = -u ]; then echo 0; exit 0; fi\nexec /usr/bin/id "$@"\n',
        encoding="ascii",
    )
    stub.chmod(0o755)
    return stub


def me() -> tuple[str, str]:
    """The invoking user and group, for a manifest a non-root run can install.

    install(1) applies the manifest's owner and group, so a synthetic manifest
    naming root:wheel would restrict every test below to a root harness. Naming
    the caller keeps the real installer under test everywhere.
    """
    user = pwd.getpwuid(os.getuid()).pw_name
    try:
        group = grp.getgrgid(os.getgid()).gr_name
    except KeyError:
        group = str(os.getgid())
    return user, group


def write_stub(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="ascii")
    path.chmod(0o755)
    return path


def install_passthrough_stub(directory: Path) -> None:
    """An `install` that keeps the write and drops only the ownership flags.

    install(1) applies the owner and group it is asked for, which needs root.
    The wrapper drops -o and -g and hands everything else to the real install,
    so the file still gets written -- a stub that swallowed the write would
    make a reintroduced defect invisible, which is the one thing these tests
    must not do.
    """
    real_install = shutil.which("install") or "/usr/bin/install"
    write_stub(
        directory,
        "install",
        "args=''\n"
        "while [ $# -gt 0 ]; do\n"
        '  case "$1" in\n'
        "    -o|-g) shift ;;\n"
        '    *) args="$args \'$1\'" ;;\n'
        "  esac\n"
        "  shift\n"
        "done\n"
        f'eval exec {real_install} $args\n',
    )


def poudriere_stub(directory: Path, calls: Path) -> None:
    """Records what it was asked to do, and answers the two `-l -n` greps.

    Named jail and ports tree, so the scripts take the "already exists" branch
    rather than trying to build a FreeBSD jail inside the test suite.
    """
    write_stub(
        directory,
        "poudriere",
        f'printf "%s\\n" "$*" >> {calls}\n'
        'case "$1 $2" in\n'
        '  "ports -l") echo default ;;\n'
        '  "jail -l") echo freebsd_151_amd64 ;;\n'
        "esac\n"
        "exit 0\n",
    )


def pkg_stub(directory: Path, owned: tuple[str, ...] = ()) -> None:
    """A `pkg` that answers `which -q` for the paths a package owns.

    leftovers.sh asks pkg who owns a candidate before judging its name, which
    is the only thing that separates poudriere's own `poudriere.conf.sample`
    from a dated backup of ours -- both are the managed name plus a dot. Linux
    has no pkg at all, so without this stub the rule is unreachable and the
    exemption would go untested.

    `pkg info -e` answers no, so install-ci-host.sh's package loop is a no-op
    here rather than reaching a real package manager.
    """
    cases = "".join(f'    {path}) exit 0 ;;\n' for path in owned)
    write_stub(
        directory,
        "pkg",
        'if [ "$1" = which ]; then\n'
        "  shift\n"
        '  while [ $# -gt 0 ]; do\n'
        '    case "$1" in -*|--) shift ;; *) break ;; esac\n'
        "  done\n"
        '  case "$1" in\n'
        f"{cases}"
        "    *) exit 1 ;;\n"
        "  esac\n"
        "fi\n"
        "exit 1\n",
    )


class ManagedPackageListTests(unittest.TestCase):
    """The pkglist is a repository file now. Drive the installer and verifier."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.localbase = self.root / "usr/local"
        self.pkglist = self.localbase / "etc/poudriere.d/gatebsd-pkglist"
        self.cron = self.localbase / "etc/cron.d/freebsd-local-repo"
        self.update = self.localbase / "sbin/update-freebsd-local-repo"
        self.conf = self.localbase / "etc/poudriere.conf"
        self.backups = self.root / "backups"
        self.stubs = self.root / "stubbin"
        root_check_stub(self.stubs)
        # poudriere's own sample file is the only thing in /usr/local/etc that
        # this stub is asked to claim, and it is claimed only where a test
        # puts one there.
        pkg_stub(self.stubs, owned=(str(self.conf.with_name("poudriere.conf.sample")),))

        user, group = me()
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            "\n".join(
                f"{source} {target} {mode} {user} {group}"
                for source, target, mode in (
                    ("infra/freebsd-ci/gatebsd-pkglist", self.pkglist, "0644"),
                    ("infra/freebsd-ci/freebsd-mirror.cron", self.cron, "0644"),
                    (
                        "infra/freebsd-ci/update-freebsd-local-repo.sh",
                        self.update,
                        "0750",
                    ),
                    ("infra/freebsd-ci/poudriere.conf", self.conf, "0644"),
                )
            )
            + "\n",
            encoding="utf-8",
        )

    def env(self) -> dict[str, str]:
        # Both, and not just PATH: these scripts set their own PATH from
        # GATEBSD_PATH, so a stub that only lands in PATH is never seen.
        searchpath = f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin"
        return {
            "PATH": searchpath,
            "GATEBSD_PATH": searchpath,
            "GATEBSD_REPO_DIR": str(ROOT),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            # This suite is about files; it declares no package dependencies
            # rather than inheriting the stand's real list.
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "GATEBSD_CRON_DIRS": str(self.localbase / "etc/cron.d"),
            "GATEBSD_MANAGED_PREFIX": str(self.localbase),
            "HOME": str(self.root),
            "LANG": "C",
        }

    def run_install(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(INSTALL), *args],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(VERIFY)],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def test_the_origins_survive_the_annotations(self) -> None:
        """The comments are documentation; the origins are the build.

        Getting this wrong drops a port from the appliance, which is the whole
        failure this file exists to prevent.
        """
        self.assertEqual(
            poudriere_origins(PKGLIST_SOURCE.read_text(encoding="utf-8")),
            EXPECTED_ORIGINS,
        )

    def test_the_installer_deploys_the_package_list(self) -> None:
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.pkglist.is_file(), "the pkglist was not deployed")
        self.assertEqual(
            self.pkglist.read_text(encoding="utf-8"),
            PKGLIST_SOURCE.read_text(encoding="utf-8"),
        )
        self.assertTrue(self.update.is_file(), "the rebuild script was not deployed")
        self.assertEqual(self.run_verify().returncode, 0)

    def test_a_hand_edited_package_list_is_reported_as_drift(self) -> None:
        """The defect, reintroduced exactly as it happened on the stand.

        Someone edited the live pkglist to add amnezia and move to python312
        and left `gatebsd-pkglist.before-amnezia-20260730` beside it. Nothing
        noticed, because nothing was comparing. Here the edit runs the other
        way -- amnezia removed, python312 reverted, which is what a re-run of
        the bring-up script used to do -- and the verifier has to catch it.
        """
        self.assertEqual(self.run_install().returncode, 0)

        edited = "\n".join(
            line
            for line in self.pkglist.read_text(encoding="utf-8").splitlines()
            if "amnezia" not in line
        ).replace("python312", "python3").replace("py-sqlite3@py312", "py-sqlite3")
        self.pkglist.write_text(edited + "\n", encoding="utf-8")
        self.assertNotIn(
            "net/amnezia-kmod", poudriere_origins(edited), "the edit must remove the VPN's ports"
        )

        result = self.run_verify()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("DRIFTED", result.stdout)
        self.assertIn("gatebsd-pkglist", result.stdout)

    def test_the_dated_copy_beside_the_package_list_is_retired(self) -> None:
        """`gatebsd-pkglist.before-amnezia-20260730` is sitting on the stand.

        It is the pre-amnezia, python311 generation. Nothing retired it because
        the pkglist was in no manifest, so `leftovers_beside` was never asked
        about that directory.
        """
        self.assertEqual(self.run_install().returncode, 0)
        stale = self.pkglist.with_name("gatebsd-pkglist.before-amnezia-20260730")
        stale.write_text("lang/python311\ndns/unbound\n", encoding="utf-8")

        before = self.run_verify()
        self.assertEqual(before.returncode, 1)
        self.assertIn("LEFTOVER", before.stdout)
        self.assertIn("before-amnezia", before.stdout)

        second = self.run_install()

        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertFalse(stale.exists(), "the older generation is still in poudriere.d")
        self.assertTrue(self.pkglist.is_file(), "the managed list must not be touched")
        self.assertEqual(self.run_verify().returncode, 0)

    def test_the_installer_deploys_the_poudriere_configuration(self) -> None:
        result = self.run_install()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.conf.is_file(), "poudriere.conf was not deployed")
        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            POUDRIERE_CONF_SOURCE.read_text(encoding="utf-8"),
        )
        self.assertEqual(self.run_verify().returncode, 0)

    def test_the_deployed_configuration_still_signs_the_repository(self) -> None:
        """The keys the repository's copy had lost, asserted by value.

        Comparing the deployed file to the repository proves they agree; it
        cannot notice that they agree on a configuration which publishes an
        unsigned package repository. This is the assertion that would fail if
        someone "tidied" the file back towards its old sixteen lines.
        """
        self.assertEqual(self.run_install().returncode, 0)

        settings = poudriere_settings(self.conf.read_text(encoding="utf-8"))

        for key, value in SETTINGS_THE_REPOSITORY_HAD_LOST.items():
            self.assertEqual(settings.get(key), value, f"{key} is not deployed")

    def test_a_key_rewritten_in_place_is_reported_as_drift(self) -> None:
        """The second writer's edit, reproduced exactly.

        `set_conf PARALLEL_JOBS 2` was an awk pass that replaced the line and
        left every other one alone. That is why it went unnoticed for a year:
        the file still looks entirely reasonable afterwards. Nothing but a
        comparison against the repository can catch it, and until poudriere.conf
        was in the manifest there was no comparison to make.
        """
        self.assertEqual(self.run_install().returncode, 0)

        rewritten = "\n".join(
            "PARALLEL_JOBS=8" if line.startswith("PARALLEL_JOBS=") else line
            for line in self.conf.read_text(encoding="utf-8").splitlines()
        )
        self.conf.write_text(rewritten + "\n", encoding="utf-8")
        self.assertEqual(
            poudriere_settings(rewritten)["PARALLEL_JOBS"],
            "8",
            "the edit must actually change the build",
        )

        result = self.run_verify()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("DRIFTED", result.stdout)
        self.assertIn("poudriere.conf", result.stdout)

    def test_the_dated_copies_beside_the_configuration_are_retired(self) -> None:
        """Three of them have been in /usr/local/etc since 14 July.

        Nothing retired them because poudriere.conf was in no manifest, so
        `leftovers_beside` was never asked about that directory at all.
        """
        self.assertEqual(self.run_install().returncode, 0)
        stale = [self.conf.with_name(name) for name in DATED_COPIES_ON_THE_STAND]
        for copy in stale:
            copy.write_text("ZPOOL=tank\nPARALLEL_JOBS=4\n", encoding="utf-8")

        before = self.run_verify()
        self.assertEqual(before.returncode, 1)
        self.assertIn("LEFTOVER", before.stdout)
        for copy in stale:
            self.assertIn(copy.name, before.stdout)

        second = self.run_install()

        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        for copy in stale:
            self.assertFalse(copy.exists(), f"{copy.name} is still in /usr/local/etc")
        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            POUDRIERE_CONF_SOURCE.read_text(encoding="utf-8"),
            "the managed configuration must not be touched",
        )
        self.assertEqual(self.run_verify().returncode, 0)

    def test_poudrieres_own_sample_file_is_not_retired(self) -> None:
        """`poudriere.conf.sample` is the managed name plus a dot, and is not ours.

        pkg(8) registers it to poudriere-3.4.8. Retiring it would leave
        `pkg check -s` reporting the port as damaged, and the next upgrade
        would put it back for the retirer to move again on the following run.
        The name cannot tell it apart from a dated backup; only its owner can.
        """
        self.assertEqual(self.run_install().returncode, 0)
        sample = self.conf.with_name("poudriere.conf.sample")
        sample.write_text("# poudriere.conf.sample from the port\n", encoding="utf-8")
        ours = self.conf.with_name(DATED_COPIES_ON_THE_STAND[0])
        ours.write_text("ZPOOL=tank\n", encoding="utf-8")

        before = self.run_verify()

        self.assertEqual(before.returncode, 1, "our own dated copy is still a leftover")
        self.assertIn(ours.name, before.stdout)
        self.assertNotIn("poudriere.conf.sample", before.stdout)

        self.assertEqual(self.run_install().returncode, 0)

        self.assertTrue(sample.is_file(), "poudriere's own sample file was carried off")
        self.assertFalse(ours.exists(), "our dated copy should have been retired")
        self.assertEqual(self.run_verify().returncode, 0)


class TheRealManifestClaimsTheseFilesTests(unittest.TestCase):
    """Every test above builds its own synthetic manifest, and has to.

    That leaves one hole they cannot see: infra/freebsd-ci/deployment.manifest
    is the file the stand is actually deployed from, and deleting a line from
    it puts a file back outside the mechanism without failing anything. That
    is precisely the state all four of these were found in.

    Driven by running install-ci-host.sh --dry-run against the real manifest,
    not by reading it. The dry run installs nothing and retires nothing; the
    leftover scan is pointed at a temporary directory so it never consults the
    developer's own /usr/local.
    """

    MANAGED = (
        ("infra/freebsd-ci/freebsd-mirror.cron", "/usr/local/etc/cron.d/freebsd-local-repo"),
        ("infra/freebsd-ci/gatebsd-pkglist", "/usr/local/etc/poudriere.d/gatebsd-pkglist"),
        (
            "infra/freebsd-ci/update-freebsd-local-repo.sh",
            "/usr/local/sbin/update-freebsd-local-repo",
        ),
        ("infra/freebsd-ci/poudriere.conf", "/usr/local/etc/poudriere.conf"),
    )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.stubs = self.root / "stubbin"
        root_check_stub(self.stubs)

    def dry_run(self) -> subprocess.CompletedProcess[str]:
        searchpath = f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin"
        return subprocess.run(
            ["sh", str(INSTALL), "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": searchpath,
                "GATEBSD_PATH": searchpath,
                "GATEBSD_REPO_DIR": str(ROOT),
                # The real manifest, deliberately. That is the whole point.
                "GATEBSD_DEPLOY_MANIFEST": str(INFRA / "deployment.manifest"),
                "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
                "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
                "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.root / "backups"),
                "GATEBSD_CRON_DIRS": str(self.root / "cron.d"),
                "GATEBSD_MANAGED_PREFIX": str(self.root),
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def test_the_installer_handles_every_file_this_mechanism_owns(self) -> None:
        result = self.dry_run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for source, target in self.MANAGED:
            # "would install <source> -> <target>" where the target is absent,
            # "unchanged <target>" where it is already deployed and identical.
            # Both mean the manifest paired them; which one appears depends on
            # the machine the suite runs on.
            handled = (
                f"would install  {source} -> {target}" in result.stdout
                or f"unchanged  {target}" in result.stdout
            )
            self.assertTrue(
                handled,
                f"deployment.manifest does not deploy {source} to {target}\n"
                f"{result.stdout}",
            )


class BringUpDoesNotWriteManagedFilesTests(unittest.TestCase):
    """Runs ci/host/configure_freebsd_mirror.sh for real.

    Against a synthetic tree with poudriere, openssl, nginx and service stubbed
    out -- the point is not what poudriere does, it is which files exist
    afterwards and what is in them. Putting any of the three heredocs back
    fails a test here, and so does putting `set_conf` back.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.localbase = self.root / "usr/local"
        self.tank = self.root / "tank"
        self.stubs = self.root / "stubbin"
        self.calls = self.root / "poudriere.calls"
        self.backups = self.root / "backups"

        self.pkglist = self.localbase / "etc/poudriere.d/gatebsd-pkglist"
        self.cron = self.localbase / "etc/cron.d/freebsd-local-repo"
        self.update = self.localbase / "sbin/update-freebsd-local-repo"
        self.conf = self.localbase / "etc/poudriere.conf"

        user, group = me()
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/gatebsd-pkglist {self.pkglist} 0644 {user} {group}\n"
            f"infra/freebsd-ci/freebsd-mirror.cron {self.cron} 0644 {user} {group}\n"
            f"infra/freebsd-ci/update-freebsd-local-repo.sh {self.update} 0750 {user} {group}\n"
            f"infra/freebsd-ci/poudriere.conf {self.conf} 0644 {user} {group}\n",
            encoding="utf-8",
        )

        # What the bring-up script expects to find already there, because
        # poudriere put it there. poudriere.d included, and deliberately: the
        # refusal tests below have to fail because the script declined to
        # invent a package list or a configuration, not because it could not
        # have written one anyway. Neither file is seeded here -- both are
        # deployed from the manifest by deploy().
        (self.localbase / "etc/poudriere.d").mkdir(parents=True)
        (self.tank / "packages/poudriere/data/packages/freebsd_151_amd64-default").mkdir(
            parents=True
        )
        self._write_stubs()

    def _write_stubs(self) -> None:
        root_check_stub(self.stubs)
        install_passthrough_stub(self.stubs)
        poudriere_stub(self.stubs, self.calls)
        pkg_stub(self.stubs)
        write_stub(
            self.stubs,
            "openssl",
            # -out is the only argument that matters here: whatever it names has
            # to exist afterwards, because the script installs it.
            'out=""\n'
            'while [ $# -gt 0 ]; do [ "$1" = -out ] && out=$2; shift; done\n'
            '[ -z "$out" ] || : > "$out"\n'
            "exit 0\n",
        )
        write_stub(self.stubs, "nginx", "exit 0\n")
        write_stub(self.stubs, "service", "exit 0\n")

    def env(self, **extra: str) -> dict[str, str]:
        searchpath = f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin"
        env = {
            "PATH": searchpath,
            # install-ci-host.sh and the retirer set their own PATH from this,
            # so a stub that only lands in PATH is never seen by them.
            "GATEBSD_PATH": searchpath,
            "GATEBSD_LOCALBASE": str(self.localbase),
            "GATEBSD_TANK": str(self.tank),
            "GATEBSD_REPO_DIR": str(ROOT),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "GATEBSD_CRON_DIRS": str(self.localbase / "etc/cron.d"),
            "GATEBSD_MANAGED_PREFIX": str(self.localbase),
            "HOME": str(self.root),
            "LANG": "C",
        }
        env.update(extra)
        return env

    def deploy(self) -> None:
        result = subprocess.run(
            ["sh", str(INSTALL)],
            capture_output=True, text=True, check=False, env=self.env(),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_configure(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(CONFIGURE)],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(VERIFY)],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def test_it_runs_at_all(self) -> None:
        """A guard on the harness itself.

        Every assertion below is of the form "the file is unchanged". If the
        script had simply failed before reaching the place a heredoc used to
        be, they would all pass and prove nothing.
        """
        self.deploy()

        result = self.run_configure()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text(encoding="utf-8")
        self.assertIn("bulk", calls, "the script never got as far as building")
        self.assertIn(str(self.pkglist), calls, "the build did not use the managed list")

    def test_the_mirror_schedule_survives_the_bring_up(self) -> None:
        """The whole schedule, not just the file.

        The heredoc's crontab was one 04:15 line. Comparing the file to the
        repository would catch its return, but naming the four jobs that were
        being dropped says what the loss actually is.
        """
        self.deploy()

        self.assertEqual(self.run_configure().returncode, 0)

        deployed = self.cron.read_text(encoding="utf-8")
        self.assertEqual(deployed, CRON_SOURCE.read_text(encoding="utf-8"))
        for job in (
            "mirror-sync-freebsd-15-amd64",
            "mirror-health-check",
            "mirror-status-update",
            "renew-stand-tls",
        ):
            self.assertIn(job, deployed, f"{job} is no longer scheduled")

    def test_the_package_list_survives_the_bring_up(self) -> None:
        """The ports the router's VPN runs on must still be in the built set."""
        self.deploy()

        self.assertEqual(self.run_configure().returncode, 0)

        deployed = self.pkglist.read_text(encoding="utf-8")
        self.assertEqual(deployed, PKGLIST_SOURCE.read_text(encoding="utf-8"))
        origins = poudriere_origins(deployed)
        self.assertIn("net/amnezia-kmod", origins)
        self.assertIn("net/amnezia-tools", origins)
        self.assertIn("lang/python312", origins)

    def test_the_rebuild_script_survives_the_bring_up(self) -> None:
        self.deploy()

        self.assertEqual(self.run_configure().returncode, 0)

        self.assertEqual(
            self.update.read_text(encoding="utf-8"),
            UPDATE_SOURCE.read_text(encoding="utf-8"),
        )

    def test_the_poudriere_configuration_survives_the_bring_up(self) -> None:
        """Not one key rewritten, and no dated copy left beside it.

        `set_conf` wrote eleven keys and `cp -p` kept a copy of the previous
        file each run. Both halves are asserted: the content is the
        repository's byte for byte, and /usr/local/etc gained nothing.
        """
        self.deploy()

        self.assertEqual(self.run_configure().returncode, 0)

        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            POUDRIERE_CONF_SOURCE.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            copies_beside(self.conf),
            [],
            "the bring-up left a dated copy beside the live configuration",
        )

    def test_it_refuses_to_run_without_the_deployed_configuration(self) -> None:
        """Same refusal as the package list, and for the same reason.

        A bring-up that repairs the poudriere configuration it finds -- or
        writes one when there is none -- is the second writer again, just
        later. It stops, and says which script deploys the file.
        """
        self.deploy()
        self.conf.unlink()

        result = self.run_configure()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("poudriere.conf", result.stderr)
        self.assertIn("install-ci-host.sh", result.stderr)
        self.assertFalse(self.conf.exists(), "the script wrote a configuration of its own")
        self.assertFalse(self.calls.exists(), "it built something without a configuration")

    def test_the_verifier_is_still_clean_after_the_bring_up(self) -> None:
        """The check the stand itself would run, in the same order."""
        self.deploy()
        self.assertEqual(self.run_configure().returncode, 0)

        result = self.run_verify()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No drift", result.stdout)

    def test_it_refuses_to_run_without_the_deployed_package_list(self) -> None:
        """Not "falls back to a built-in list" -- that is how the set diverged.

        A bring-up that invents its own package set when the managed one is
        absent is the second writer again, just later.
        """
        result = self.run_configure()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("gatebsd-pkglist", result.stderr)
        self.assertIn("install-ci-host.sh", result.stderr)
        self.assertFalse(
            self.pkglist.exists(), "the script wrote a package list of its own"
        )
        self.assertFalse(self.calls.exists(), "it built something without a list")


class BootstrapDoesNotInstallItsOwnConfigurationTests(unittest.TestCase):
    """Runs infra/freebsd-ci/bootstrap.sh for real.

    This is the writer that would have done the damage. It installed the
    repository's poudriere.conf over the live one wholesale, and it is step 2
    of the recovery order in infra/README.md -- so it runs at the one moment
    nobody is watching the build host closely. The repository's copy had no
    PKG_REPO_SIGNING_KEY, and a stand that publishes an unsigned repository
    stops the appliance installing anything, weeks later, with no trail back.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.localbase = self.root / "usr/local"
        self.tank = self.root / "tank"
        self.stubs = self.root / "stubbin"
        self.calls = self.root / "poudriere.calls"
        self.backups = self.root / "backups"
        self.conf = self.localbase / "etc/poudriere.conf"

        user, group = me()
        self.manifest = self.root / "deployment.manifest"
        self.manifest.write_text(
            f"infra/freebsd-ci/poudriere.conf {self.conf} 0644 {user} {group}\n",
            encoding="utf-8",
        )

        root_check_stub(self.stubs)
        install_passthrough_stub(self.stubs)
        poudriere_stub(self.stubs, self.calls)
        pkg_stub(self.stubs)

    def env(self) -> dict[str, str]:
        searchpath = f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin"
        return {
            "PATH": searchpath,
            "GATEBSD_PATH": searchpath,
            "GATEBSD_LOCALBASE": str(self.localbase),
            "GATEBSD_TANK": str(self.tank),
            "GATEBSD_REPO_DIR": str(ROOT),
            "GATEBSD_DEPLOY_MANIFEST": str(self.manifest),
            "GATEBSD_DEPLOY_PACKAGES": str(self.root / "no-such-packages.list"),
            "GATEBSD_DEPLOY_SCAN": str(self.root / "no-such-deployment.scan"),
            "GATEBSD_LEFTOVER_BACKUP_ROOT": str(self.backups),
            "GATEBSD_CRON_DIRS": str(self.localbase / "etc/cron.d"),
            "GATEBSD_MANAGED_PREFIX": str(self.localbase),
            "HOME": str(self.root),
            "LANG": "C",
        }

    def deploy(self) -> None:
        result = subprocess.run(
            ["sh", str(INSTALL)],
            capture_output=True, text=True, check=False, env=self.env(),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_bootstrap(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(BOOTSTRAP)],
            capture_output=True, text=True, check=False, env=self.env(),
        )

    def test_it_runs_at_all(self) -> None:
        """The same guard as the bring-up class, for the same reason.

        The assertion below is "the configuration is unchanged". A script that
        died before reaching the line that used to overwrite it would satisfy
        that and prove nothing.
        """
        self.deploy()

        result = self.run_bootstrap()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            (self.tank / "packages/poudriere/data/logs/bulk").is_dir(),
            "bootstrap.sh never got as far as creating the datasets",
        )
        self.assertIn("jail -l", self.calls.read_text(encoding="utf-8"))

    def test_the_deployed_configuration_survives_the_bootstrap(self) -> None:
        self.deploy()

        self.assertEqual(self.run_bootstrap().returncode, 0)

        self.assertEqual(
            self.conf.read_text(encoding="utf-8"),
            POUDRIERE_CONF_SOURCE.read_text(encoding="utf-8"),
        )
        settings = poudriere_settings(self.conf.read_text(encoding="utf-8"))
        self.assertEqual(
            settings.get("PKG_REPO_SIGNING_KEY"),
            "/usr/local/etc/ssl/keys/pkg.key",
            "the repository is no longer signed after a recovery",
        )
        self.assertEqual(
            copies_beside(self.conf),
            [],
            "bootstrap.sh left a dated copy beside the live configuration",
        )

    def test_it_refuses_to_run_without_the_deployed_configuration(self) -> None:
        """Not "installs the one it ships with" -- that is the defect itself."""
        (self.localbase / "etc").mkdir(parents=True)

        result = self.run_bootstrap()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("poudriere.conf", result.stderr)
        self.assertIn("install-ci-host.sh", result.stderr)
        self.assertFalse(self.conf.exists(), "it installed a configuration of its own")
        self.assertFalse(self.calls.exists(), "it configured poudriere without one")


class TheNightlyRebuildUsesTheOverlay(unittest.TestCase):
    """`-O gatebsd` on the bulk invocation, proved by running the script.

    The Python security-patch ports are carried in this repository's overlay.
    Without the flag poudriere silently builds the upstream ones and publishes
    them over the patched packages. Amnezia formerly justified the same flag;
    its official 3.1 ports now carry the complete kernel and userspace paths.

    This RUNS the script against a poudriere that records its arguments.
    Asserting on the source text would pass just as happily with the whole
    invocation sitting behind a condition that is never true.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.stubs = self.root / "stubbin"
        self.calls = self.root / "poudriere.calls"

        # The other harnesses get this directory for free from root_check_stub,
        # which mkdirs it. This script has no root check to fake, so it has to
        # be made here or write_stub lands on a path that does not exist.
        self.stubs.mkdir(parents=True)
        poudriere_stub(self.stubs, self.calls)
        # lockf(1) is the script's own front door -- it re-execs itself through
        # it. Stubbing the lock rather than skipping past it with the internal
        # argument keeps the real entry path under test; the lock file lives in
        # /var/run, which a test has no business writing.
        write_stub(self.stubs, "lockf", 'shift 3\nexec "$@"\n')
        # The script mirrors the FreeBSD src repository when it is done. Left
        # real, this test would clone it over the network.
        write_stub(self.stubs, "git", "exit 0\n")

    def run_update(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(UPDATE_SOURCE)],
            capture_output=True, text=True, check=False,
            env={
                "PATH": f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(self.root),
                "LANG": "C",
            },
        )

    def bulk_call(self) -> str:
        self.assertTrue(self.calls.exists(), "poudriere was never invoked")
        for line in self.calls.read_text(encoding="utf-8").splitlines():
            if line.startswith("bulk "):
                return line
        self.fail("the script never got as far as building")

    def test_it_runs_at_all(self) -> None:
        """A guard on the harness. Every assertion below reads a recorded call,
        and a script that died early would record nothing and fail them all for
        the wrong reason."""
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("bulk", self.bulk_call())

    def test_the_build_selects_the_overlay(self) -> None:
        self.run_update()
        self.assertIn(
            "-O gatebsd",
            self.bulk_call(),
            "the nightly rebuild would replace the Python security-patch overlays "
            "with unpatched upstream packages",
        )

    def test_the_build_reads_the_managed_list(self) -> None:
        self.run_update()
        self.assertIn("/usr/local/etc/poudriere.d/gatebsd-pkglist", self.bulk_call())


class TheOverlayPortsAreInTheBuiltSet(unittest.TestCase):
    """Every overlaid port is named in the list the build is given.

    Carrying a port in the overlay and leaving it out of the package list gets
    the worst of both: the repository claims to own the version, and nothing
    ever builds it. The scan covers every category so removing one overlay
    cannot make the test vacuous or hide another missing origin.
    """

    def test_every_overlay_port_is_listed(self) -> None:
        origins = poudriere_origins(PKGLIST_SOURCE.read_text(encoding="utf-8"))
        overlay_root = INFRA / "ports-overlay"
        overlaid = sorted(
            f"{category.name}/{port.name}"
            for category in overlay_root.iterdir()
            if category.is_dir()
            for port in category.iterdir()
            if port.is_dir() and (port / "Makefile").is_file()
        )
        self.assertTrue(overlaid, "the overlay has no ports; this test is vacuous")
        for origin in overlaid:
            self.assertIn(
                origin,
                origins,
                f"{origin} is carried in the overlay but never built",
            )


if __name__ == "__main__":
    unittest.main()
