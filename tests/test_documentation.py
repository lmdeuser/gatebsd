from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def tracked_markdown() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "--", "*.md"], cwd=ROOT, text=True
    )
    return [ROOT / name for name in output.splitlines()]


def portable_documentation() -> list[Path]:
    return [
        path
        for path in tracked_markdown()
        if path.name not in {"AGENTS.md", "CLAUDE.md"}
    ]


class DocumentationContractTests(unittest.TestCase):
    def test_relative_markdown_links_resolve(self) -> None:
        broken: list[str] = []
        for document in tracked_markdown():
            text = document.read_text(encoding="utf-8")
            for raw_target in MARKDOWN_LINK.findall(text):
                target = raw_target.strip().removeprefix("<").removesuffix(">")
                target = target.split("#", 1)[0]
                if not target or target.startswith("/"):
                    continue
                if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target):
                    continue
                if not (document.parent / target).resolve().exists():
                    broken.append(f"{document.relative_to(ROOT)} -> {raw_target}")
        self.assertEqual([], broken)

    def test_portable_docs_do_not_depend_on_local_working_note(self) -> None:
        dependents = [
            str(path.relative_to(ROOT))
            for path in portable_documentation()
            if "NEXT_TASK.md" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual([], dependents)


    def test_infra_readme_restores_forgejo_secrets_before_deploy(self) -> None:
        readme = (ROOT / "infra" / "README.md").read_text(encoding="utf-8")
        self.assertIn("/root/.secrets/backup-passphrase", readme)
        # Check disaster recovery ordering: snapshot + app.ini/step/keys restore before deploy.sh
        dr_section = readme[readme.find("## Recovery order"):]
        snapshot_pos = dr_section.find("snapshot")
        deploy_pos = dr_section.find("forgejo/deploy.sh")
        self.assertNotEqual(snapshot_pos, -1)
        self.assertNotEqual(deploy_pos, -1)
        self.assertLess(
            snapshot_pos,
            deploy_pos,
            "Disaster recovery must restore Forgejo data and secrets BEFORE running forgejo/deploy.sh",
        )

    def test_backup_and_upgrade_docs_match_retention_contracts(self) -> None:
        for rel in ("README.md", "backup/README.md", "backup/INSTRUCTIONS.md"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("three latest images", text.lower(), rel)
        for rel in ("backup/README.md", "backup/INSTRUCTIONS.md"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("GATEBSD_IMAGE_BACKUP_KEEP", text, rel)
        upgrade_doc = (ROOT / "docs" / "ROUTER_UPGRADE.md").read_text(encoding="utf-8")
        self.assertNotIn("/var/tmp/All/gatebsd-<version>.pkg", upgrade_doc)
        for token in (
            "/var/tmp/gatebsd-<version>.pkg",
            "GATEBSD_UPGRADE_BACKUP_KEEP",
            "GATEBSD_UPGRADE_MIN_FREE_KIB",
        ):
            self.assertIn(token, upgrade_doc)


if __name__ == "__main__":
    unittest.main()
