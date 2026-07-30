import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lfs_antivirus_aaha.engine import ProcessResult
from lfs_antivirus_aaha.scanner import ClamAvScanner, parse_clamscan_output, validate_scan_target


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app_data = tempfile.TemporaryDirectory()
        self.local_app_data = patch.dict(os.environ, {"LOCALAPPDATA": self.app_data.name})
        self.local_app_data.start()

    def tearDown(self) -> None:
        self.local_app_data.stop()
        self.app_data.cleanup()

    def test_parse_infected_windows_path_and_summary(self) -> None:
        output = """C:\\Users\\Adam\\sample.txt: Win.Test.Signature FOUND
----------- SCAN SUMMARY -----------
Known viruses: 9000000
Scanned files: 12
Infected files: 1
"""
        summary = parse_clamscan_output(
            output,
            root=Path("C:/Users/Adam"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=1,
            engine_version="ClamAV 1.5.3",
        )

        self.assertEqual(summary.files_scanned, 12)
        self.assertEqual(summary.threats_found, 1)
        self.assertEqual(summary.findings[0].path, "C:\\Users\\Adam\\sample.txt")
        self.assertEqual(summary.findings[0].threat_name, "Win.Test.Signature")
        self.assertEqual(summary.findings[0].severity, "not provided")
        self.assertEqual(summary.findings[0].status, "Detected")
        self.assertEqual(summary.errors, [])

    def test_parse_scan_error_and_inconsistent_infected_exit(self) -> None:
        summary = parse_clamscan_output(
            "C:\\locked.txt: Access denied ERROR\nScanned files: 0\n",
            root=Path("C:/"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=2,
        )
        self.assertTrue(any("Access denied" in item for item in summary.errors))
        self.assertTrue(any("exit code 2" in item for item in summary.errors))

        inconsistent = parse_clamscan_output(
            "Scanned files: 1\n",
            root=Path("C:/"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=1,
        )
        self.assertTrue(any("no parseable finding" in item for item in inconsistent.errors))

    def test_global_clamav_warning_is_not_silently_ignored(self) -> None:
        summary = parse_clamscan_output(
            "LibClamAV Warning: database is older than recommended\nScanned files: 1\n",
            root=Path("C:/fixture"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=0,
        )
        self.assertTrue(any("older than recommended" in item for item in summary.errors))

    def test_empty_output_and_count_mismatch_are_incomplete(self) -> None:
        empty = parse_clamscan_output(
            "",
            root=Path("C:/fixture"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=0,
        )
        self.assertTrue(any("complete parseable" in item for item in empty.errors))

        mismatch = parse_clamscan_output(
            "C:\\sample.txt: Unit.Test FOUND\nScanned files: 1\nInfected files: 0\n",
            root=Path("C:/fixture"),
            started_at="2026-07-29T00:00:00+00:00",
            exit_code=1,
        )
        self.assertTrue(any("does not match" in item for item in mismatch.errors))

    def test_scanner_builds_non_destructive_fixed_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "folder;not-a-command"
            target.mkdir()
            database = root / "database"
            database.mkdir()
            (database / "main.cvd").write_bytes(b"fixture")
            (database / "daily.cvd").write_bytes(b"fixture")
            engine_path = Path("C:/ClamAV/clamscan.exe")
            scanner = ClamAvScanner(engine_path, database, "ClamAV 1.5.3")
            fixture = ProcessResult(0, "Scanned files: 0\nInfected files: 0\n")

            with patch("lfs_antivirus_aaha.scanner.run_command", return_value=fixture) as mocked:
                summary = scanner.scan_path(target)

            argv = mocked.call_args.args[0]
            self.assertEqual(argv[0], str(engine_path))
            self.assertEqual(argv[-1], str(target.resolve()))
            self.assertIn("--recursive=yes", argv)
            self.assertIn("--follow-dir-symlinks=0", argv)
            self.assertIn("--follow-file-symlinks=0", argv)
            self.assertNotIn("--remove", argv)
            self.assertFalse(any(item.startswith("--move") or item.startswith("--copy") for item in argv))
            self.assertEqual(summary.files_scanned, 0)
            self.assertEqual(summary.errors, [])

    def test_network_and_application_data_targets_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Choose a local"):
            validate_scan_target("   ")
        with self.assertRaisesRegex(ValueError, "network"):
            validate_scan_target(r"\\server\share\folder")

        protected = Path(self.app_data.name) / "AAHA" / "lfs-antivirus-aaha" / "quarantine"
        protected.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "application-data"):
            validate_scan_target(protected)

    def test_selected_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            (target / "nested-file.txt").write_bytes(b"fixture")
            link = root / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(ValueError, "Symbolic-link"):
                validate_scan_target(link)

            with self.assertRaisesRegex(ValueError, "Symbolic-link"):
                validate_scan_target(link / "nested-file.txt")

    def test_mapped_remote_drive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target"
            target.mkdir()
            with (
                patch("lfs_antivirus_aaha.engine.path_is_remote", return_value=True),
                patch.object(Path, "lstat") as lstat,
            ):
                with self.assertRaisesRegex(ValueError, "network"):
                    validate_scan_target(target)
            lstat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
