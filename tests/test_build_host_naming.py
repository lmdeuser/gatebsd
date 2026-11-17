"""The build host is named by its role, and named once.

`n100-ci` and `n100_ci_config` are the ssh alias and config the pipeline opens
to reach the FreeBSD build host. Until now that pair was spelled out
independently in three places -- the workflow, the controller script, and the
provisioner that writes the files on the runner -- plus a fourth, orphaned copy
of the ssh config under ci/controller/ that nothing read and that had already
drifted: it said `HostName buildhost.example.lan` while the runner in service says
`HostName 198.51.100.11`, the internal segment the deploy is supposed to use.

Two separate problems, and this file is about the first:

1. The name is a machine model, not a role. A second FreeBSD project built the
   same way would inherit a mini-PC's name for a host that is now a VM.
2. Three independent copies of one string. Renaming in one place leaves a
   pipeline that cannot reach the build host at all, and the failure surfaces
   only when a release is already in flight.

The names are now derived from BUILD_HOST_ALIAS and KEY_STEM, whose defaults
are exactly the names every provisioned runner already carries -- so nothing on
disk was renamed. These tests pin that equality, and fail if the three
declarations ever stop agreeing.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".forgejo" / "workflows" / "ci.yml"
CONTROLLER = ROOT / "ci" / "controller" / "run-freebsd-build.sh"
PROVISIONER = ROOT / "infra" / "runner" / "provision-keys.sh"

# What the runner carries today. Changing these means renaming files on a live
# runner, which provision-keys.sh must do in the same change -- so they are
# spelled out here rather than read from the code they are meant to constrain.
DEPLOYED_ALIAS = "n100-ci"
DEPLOYED_CONFIG = "n100_ci_config"
DEPLOYED_KEY_STEM = "n100_ci"

SHA = "0123456789abcdef" * 2 + "01234567"


def shell_default(text: str, name: str) -> str | None:
    """The default in `NAME=${NAME:-default}`."""
    m = re.search(r"^%s=\$\{%s:-([^}]*)\}" % (name, name), text, re.MULTILINE)
    return m.group(1) if m else None


def yaml_env(text: str, name: str) -> str | None:
    """The value of a top-level `env:` key. The block is flat and two-space
    indented; a full YAML parser is not a dependency this tree carries."""
    m = re.search(r"^  %s:\s*(\S+)\s*$" % name, text, re.MULTILINE)
    return m.group(1) if m else None


class DeclarationsAgree(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.controller = CONTROLLER.read_text(encoding="utf-8")
        self.provisioner = PROVISIONER.read_text(encoding="utf-8")

    def test_the_workflow_declares_the_pair(self) -> None:
        self.assertEqual(yaml_env(self.workflow, "BUILD_HOST_ALIAS"), DEPLOYED_ALIAS)
        self.assertEqual(yaml_env(self.workflow, "BUILD_SSH_CONFIG"), DEPLOYED_CONFIG)

    def test_the_controller_defaults_to_the_same_pair(self) -> None:
        self.assertEqual(
            shell_default(self.controller, "BUILD_HOST_ALIAS"), DEPLOYED_ALIAS
        )
        self.assertEqual(
            shell_default(self.controller, "BUILD_SSH_CONFIG"), DEPLOYED_CONFIG
        )

    def test_the_provisioner_writes_the_same_pair(self) -> None:
        self.assertEqual(
            shell_default(self.provisioner, "BUILD_HOST_ALIAS"), DEPLOYED_ALIAS
        )
        stem = shell_default(self.provisioner, "KEY_STEM")
        self.assertEqual(stem, DEPLOYED_KEY_STEM)
        # The config filename the workflow opens is the stem plus `_config`.
        # If that ever stops being true, the workflow opens a file the
        # provisioner never wrote and every job dies at the first ssh.
        self.assertEqual(f"{stem}_config", DEPLOYED_CONFIG)

    def test_the_provisioner_interpolates_rather_than_repeats(self) -> None:
        """A declaration nothing reads is worse than no declaration: it reads as
        parameterised and behaves as hardcoded."""
        body = "\n".join(
            line for line in self.provisioner.splitlines()
            if not line.lstrip().startswith("#")
            and "KEY_STEM=" not in line
            and "BUILD_HOST_ALIAS=" not in line
        )
        self.assertNotIn(DEPLOYED_KEY_STEM, body)
        self.assertNotIn(DEPLOYED_ALIAS, body)

    def test_the_workflow_opens_the_variable_not_the_literal(self) -> None:
        for line in self.workflow.splitlines():
            if "ssh -F" in line:
                self.assertIn("$BUILD_SSH_CONFIG", line)
                self.assertIn("$BUILD_HOST_ALIAS", line)
                self.assertNotIn(DEPLOYED_CONFIG, line)

    def test_the_orphaned_copy_of_the_ssh_config_is_gone(self) -> None:
        """It was read by nothing and had drifted to the wrong HostName, so a
        runner provisioned from it would have deployed over the LAN instead of
        the internal segment -- working, and wrong."""
        self.assertFalse((ROOT / "ci" / "controller" / "n100_ci_config").exists())
        self.assertFalse((ROOT / "ci" / "controller" / "n100_ci_known_hosts").exists())


class ControllerReachesTheDeclaredHost(unittest.TestCase):
    """Runs the controller with ssh stubbed, and reads the argv it produced.

    Asserting on the source would pass against a script that declares the
    variables and then execs the literal anyway.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.argv = self.root / "argv.txt"
        stub = self.bin / "ssh"
        stub.write_text(
            f'#!/bin/sh\nprintf "%s\\n" "$@" > "{self.argv}"\nexit 0\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def run_controller(self, **env: str) -> subprocess.CompletedProcess:
        full = dict(os.environ)
        full.update(
            PATH=f"{self.bin}:/usr/bin:/bin",
            HOME=str(self.root),
        )
        full.update(env)
        return subprocess.run(
            ["sh", str(CONTROLLER), SHA],
            capture_output=True, text=True, check=False, env=full,
        )

    def args(self) -> list[str]:
        return self.argv.read_text(encoding="utf-8").split("\n")

    def test_by_default_it_reaches_the_host_the_runner_is_provisioned_for(self) -> None:
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = self.args()
        self.assertEqual(args[1], f"{self.root}/.ssh/{DEPLOYED_CONFIG}")
        self.assertEqual(args[2], DEPLOYED_ALIAS)
        self.assertEqual(args[3], "ci-build")
        self.assertEqual(args[4], SHA)

    def test_a_second_project_can_point_it_at_its_own_host(self) -> None:
        result = self.run_controller(
            BUILD_HOST_ALIAS="harbor-build", BUILD_SSH_CONFIG="harbor_build_config"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = self.args()
        self.assertEqual(args[1], f"{self.root}/.ssh/harbor_build_config")
        self.assertEqual(args[2], "harbor-build")

    def test_a_bad_commit_is_still_refused(self) -> None:
        """The naming change must not have loosened the guard in front of it."""
        result = subprocess.run(
            ["sh", str(CONTROLLER), "not-a-sha"],
            capture_output=True, text=True, check=False,
            env={**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root)},
        )
        self.assertEqual(result.returncode, 64)
        self.assertFalse(self.argv.exists(), "ssh was reached with a bad SHA")



class RepositorySlugAgrees(unittest.TestCase):
    """The repository's owner, spelled once.

    Same disease as the alias above, and it cost a release. Forgejo stores a
    repository under its OWNER's directory, and the owner is `operator`. That
    name was written out independently three times: the workflow's
    `git remote add origin`, REPO_SLUG in ci-dashboard-update.sh, and
    REPOSITORY in ci/host/gatebsd-ci-build. Commit 06091e0 corrected the first
    two on 18 August 2026 and missed the third.

    It stayed missed for nine days, because the job that reaches that line was
    being skipped silently by the version gate the same commit left broken. Two
    defects covering for each other: the gate never ran the job, so the job's
    wrong path never had a chance to fail. Release 2.9.87 was the first push
    that got past the gate, and it died on `Forgejo GateBSD repository is
    missing.`
    """

    OWNER = "owner"
    NAME = "gatebsd"

    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.dashboard = (ROOT / "infra" / "freebsd-ci" / "ci-dashboard-update.sh").read_text(
            encoding="utf-8"
        )
        self.builder = (ROOT / "ci" / "host" / "gatebsd-ci-build").read_text(encoding="utf-8")

    def test_the_builder_and_the_dashboard_name_the_same_repository(self) -> None:
        expected = f"{self.OWNER}/{self.NAME}"
        self.assertEqual(shell_default(self.dashboard, "REPO_SLUG"), expected)
        self.assertEqual(shell_default(self.builder, "REPO_SLUG"), expected)

    def test_the_builder_derives_its_path_instead_of_repeating_the_owner(self) -> None:
        """A fourth literal copy is what this is meant to prevent."""
        self.assertNotIn(
            f"forgejo-repositories/{self.OWNER}/", self.builder,
            "the repository path spells the owner out again instead of using REPO_SLUG",
        )
        self.assertIn("REPO_SLUG%%/*", self.builder)
        self.assertIn("REPO_SLUG##*/", self.builder)

    def test_no_file_still_names_the_owner_that_does_not_exist(self) -> None:
        """`gatebsd/gatebsd` was the wrong owner every one of these once had."""
        for label, text in (
            ("workflow", self.workflow),
            ("dashboard", self.dashboard),
            ("builder", self.builder),
        ):
            with self.subTest(file=label):
                self.assertNotIn(f"{self.NAME}/{self.NAME}", text)

    def test_the_workflow_pushes_to_the_same_owner(self) -> None:
        self.assertIn(f"{self.OWNER}/{self.NAME}.git", self.workflow)


if __name__ == "__main__":
    unittest.main()
