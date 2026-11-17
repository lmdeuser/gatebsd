from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from gatebsd_ui import backup, paths

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SCRIPT = ROOT / "sbin" / "gatebsd-backup.sh"
FORGEJO_SCRIPT = ROOT / "infra" / "forgejo" / "backup.sh"


class ShellBackupHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.backup_dir = self.root / "backups"
        self.version = self.root / "VERSION"
        self.version.write_text("test\n", encoding="ascii")
        self.service_log = self.root / "service.log"
        self._write("id", "#!/bin/sh\nif [ \"${1:-}\" = -u ]; then echo 0; else exec /usr/bin/id \"$@\"; fi\n")
        self._write("install", "#!/bin/sh\nfor last do :; done\n[ \"$last\" != /tank/backups/forgejo ] || last=$TEST_BACKUP_ROOT\nmkdir -p \"$last\"\nchmod 700 \"$last\"\n")
        self._write("df", "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\nprintf 'stub 1000000 0 %s 0%% /backup\\n' \"${DF_AVAIL:?}\"\n")
        self._write("stat", """#!/bin/sh
if [ "$1" = -f ]; then
  format=$2
  shift 2
  case "$format" in
    '%u') printf '0\n'; exit 0 ;;
    '%Lp') exec /usr/bin/stat -c '%a' "$@" ;;
    '%z') exec /usr/bin/stat -c '%s' "$@" ;;
    '%m %N') exec /usr/bin/stat -c '%Y %n' "$@" ;;
    *) exit 2 ;;
  esac
fi
exec /usr/bin/stat "$@"
""")
        self._write("zfs", """#!/bin/sh
case "${1:-}" in
  list)
    case " $* " in *' -o refer '*) printf '%s\\n' "${ZFS_REFER_BYTES:-1048576}" ;; esac
    ;;
  snapshot) [ "${ZFS_SNAPSHOT_OK:-1}" = 1 ] ;;
  send)
    if [ "${2:-}" = -nvP ]; then printf 'size\\t%s\\n' "${ZFS_ESTIMATE_BYTES:-1048576}" >&2
    else printf 'test zfs stream'; fi
    ;;
  destroy) ;;
  *) exit 2 ;;
esac
""")
        self._write("zstreamdump", """#!/bin/sh
if [ "${1:-}" = "-q" ]; then
  echo "zstreamdump: invalid option -- q" >&2
  exit 1
fi
cat >/dev/null
""")
        self._write("sha256", "#!/bin/sh\nexec /usr/bin/sha256sum \"$@\"\n")
        self._write("service", "#!/bin/sh\nprintf '%s %s\\n' \"$1\" \"$2\" >>\"$SERVICE_LOG\"\n")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="ascii")
        path.chmod(0o755)

    def _env(self, available: int) -> dict[str, str]:
        path = f"{self.bin}:/usr/local/bin:/usr/bin:/bin"
        return {
            "PATH": path,
            "GATEBSD_PATH": path,
            "HOME": str(self.root),
            "LANG": "C",
            "DF_AVAIL": str(available),
            "SERVICE_LOG": str(self.service_log),
            "TEST_BACKUP_ROOT": str(self.backup_dir),
            "TMPDIR": str(self.root),
        }

    def run_image(
        self,
        available: int = 1000000,
        *,
        text: str | None = None,
        keep: str | None = "2",
    ) -> subprocess.CompletedProcess[str]:
        script = IMAGE_SCRIPT if text is None else self._variant(text)
        env = {
            **self._env(available),
            "GATEBSD_IMAGE_BACKUP_LOCK_HELD": "1",
            "GATEBSD_IMAGE_BACKUP_LOCK": str(self.root / "run" / "image.lock"),
            "GATEBSD_IMAGE_BACKUP_DIR": str(self.backup_dir),
            "GATEBSD_VERSION_FILE": str(self.version),
            "GATEBSD_IMAGE_BACKUP_MIN_FREE_KIB": "100",
        }
        if keep is not None:
            env["GATEBSD_IMAGE_BACKUP_KEEP"] = keep
        return subprocess.run(["sh", str(script)], env=env, text=True, capture_output=True, timeout=20)

    def run_forgejo(self, available: int = 1000000, *, text: str | None = None) -> subprocess.CompletedProcess[str]:
        script = FORGEJO_SCRIPT if text is None else self._variant(text)
        env = {
            **self._env(available),
            "FORGEJO_BACKUP_DATASET": "tank/forgejo",
            "FORGEJO_BACKUP_ROOT": str(self.backup_dir),
            "FORGEJO_BACKUP_MIN_FREE_KIB": "100",
            "ZFS_SNAPSHOT_OK": "0",
        }
        return subprocess.run(["sh", str(script), "_locked"], env=env, text=True, capture_output=True, timeout=20)

    def _variant(self, text: str) -> Path:
        path = self.root / "variant.sh"
        path.write_text(text, encoding="utf-8")
        return path


class ImageBackupSpaceTests(ShellBackupHarness):
    def test_insufficient_space_stops_before_streaming(self) -> None:
        result = self.run_image(available=1000)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("insufficient free space", result.stderr)
        self.assertFalse(list(self.backup_dir.glob("*.img.gz")))

    def test_reintroducing_image_preflight_allows_the_write(self) -> None:
        original = IMAGE_SCRIPT.read_text(encoding="utf-8")
        marker = 'require_space "$BACKUP_DIR" "$REQUIRED_KIB"'
        if marker not in original:
            self.skipTest("preflight is not implemented yet")
        result = self.run_image(available=1000, text=original.replace(marker, ":"))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(1, len(list(self.backup_dir.glob("*.img.gz"))))

    def test_image_retention_keeps_only_the_newest_two(self) -> None:
        result1 = self.run_image()
        self.assertEqual(0, result1.returncode, result1.stdout + result1.stderr)
        first = sorted(self.backup_dir.glob("*.img.gz"))[0]
        os.utime(first, (1000, 1000))

        result2 = self.run_image()
        self.assertEqual(0, result2.returncode, result2.stdout + result2.stderr)
        second = [p for p in self.backup_dir.glob("*.img.gz") if p != first][0]
        os.utime(second, (2000, 2000))

        result3 = self.run_image()
        self.assertEqual(0, result3.returncode, result3.stdout + result3.stderr)
        remaining = set(self.backup_dir.glob("*.img.gz"))
        self.assertEqual(2, len(remaining), remaining)
        self.assertNotIn(first, remaining)
        self.assertIn(second, remaining)

    def test_default_image_retention_keeps_single_newest(self) -> None:
        result1 = self.run_image(keep=None)
        self.assertEqual(0, result1.returncode, result1.stdout + result1.stderr)
        first = sorted(self.backup_dir.glob("*.img.gz"))[0]
        os.utime(first, (1000, 1000))

        result2 = self.run_image(keep=None)
        self.assertEqual(0, result2.returncode, result2.stdout + result2.stderr)
        remaining = list(self.backup_dir.glob("*.img.gz"))
        self.assertEqual(1, len(remaining), remaining)
        self.assertNotEqual(first, remaining[0])


class RestoreStreamValidationTests(unittest.TestCase):
    def test_restore_validator_accepts_the_real_freebsd_zstreamdump_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation = root / "validation"
            validation.mkdir()
            image = root / "image.gz"
            image.write_bytes(b"fixture-stream")
            zstreamdump = root / "zstreamdump"
            zstreamdump.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = \"-q\" ]; then\n"
                "  echo 'zstreamdump: invalid option -- q' >&2\n"
                "  exit 1\n"
                "fi\n"
                "cat >/dev/null\n",
                encoding="utf-8",
            )
            zstreamdump.chmod(0o755)
            gzip = root / "gzip"
            gzip.write_text("#!/bin/sh\n[ \"$1\" = -dc ] || exit 2\ncat \"$2\"\n", encoding="utf-8")
            gzip.chmod(0o755)
            source = (ROOT / "backup" / "gatebsd-restore.sh").read_text(encoding="utf-8")
            function = "validate_zfs_stream() {" + source.split("validate_zfs_stream() {", 1)[1].split("\n}", 1)[0] + "\n}"
            env = dict(os.environ)
            env.update({
                "PATH": f"{root}:/usr/bin:/bin",
                "VALIDATION_DIR": str(validation),
                "BACKUP_FILE": str(image),
            })
            result = subprocess.run(
                ["/bin/sh", "-eu", "-c", function + '\nvalidate_zfs_stream "$BACKUP_FILE"'],
                env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class ForgejoBackupSpaceTests(ShellBackupHarness):
    def test_insufficient_space_stops_before_stopping_forgejo(self) -> None:
        result = self.run_forgejo(available=1000)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("insufficient free space", result.stderr)
        self.assertFalse(self.service_log.exists())

    def test_reintroducing_forgejo_preflight_stops_the_service_first(self) -> None:
        original = FORGEJO_SCRIPT.read_text(encoding="utf-8")
        marker = 'require_space "$BACKUP_ROOT" "$REQUIRED_KIB"'
        if marker not in original:
            self.skipTest("preflight is not implemented yet")
        result = self.run_forgejo(available=1000, text=original.replace(marker, ":"))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("forgejo stop", self.service_log.read_text(encoding="utf-8"))


class ConfigBackupSpaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.backup_dir = self.root / "backups"
        self.source = self.root / "config"
        self.source.write_bytes(b"x" * 128)
        self._patches = [
            mock.patch.object(paths, "BACKUP_DIR", self.backup_dir),
            mock.patch.object(backup, "_MAX_BACKUP_COUNT", 2, create=True),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def test_insufficient_space_refuses_before_creating_a_snapshot(self) -> None:
        with mock.patch.object(backup.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(OSError, "insufficient free space"):
                backup.backup_files([self.source])
        self.assertFalse(self.backup_dir.exists() and any(self.backup_dir.iterdir()))

    def test_successful_snapshots_are_pruned_to_the_count_limit(self) -> None:
        for _ in range(3):
            backup.backup_files([self.source])
        self.assertEqual(2, len(backup.list_backups()["backups"]))

    def test_successful_snapshots_obey_the_total_byte_limit(self) -> None:
        with (
            mock.patch.object(backup, "_MAX_BACKUP_COUNT", 10),
            mock.patch.object(backup, "_MAX_BACKUP_STORE_SIZE", 256, create=True),
        ):
            for _ in range(3):
                backup.backup_files([self.source])
            items = backup.list_backups()["backups"]
        self.assertLessEqual(sum(item["size"] for item in items), 256)
        self.assertEqual(2, len(items))


if __name__ == "__main__":
    unittest.main()
