import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from lfs_antivirus_aaha.engine import ProcessResult
from lfs_antivirus_aaha.storage import clamav_database_backup_dir, clamav_database_dir
from lfs_antivirus_aaha.updater import (
    FreshClamUpdater,
    UpdateControl,
    database_status,
    database_operation_lock,
    recover_database_activation,
    write_freshclam_config,
)


class UpdaterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app_data = tempfile.TemporaryDirectory()
        self.local_app_data = patch.dict(os.environ, {"LOCALAPPDATA": self.app_data.name})
        self.local_app_data.start()

    def tearDown(self) -> None:
        self.local_app_data.stop()
        self.app_data.cleanup()

    def _seed_active_database(self, value: bytes = b"old") -> Path:
        database = clamav_database_dir()
        database.mkdir(parents=True, exist_ok=True)
        (database / "main.cvd").write_bytes(value)
        (database / "daily.cvd").write_bytes(value)
        return database

    def test_successful_update_activates_staging_and_keeps_backup(self) -> None:
        database = self._seed_active_database()
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))

        def fake_run(argv, **_kwargs):
            if str(argv[0]).endswith("freshclam.exe"):
                (updater.staging_dir / "main.cvd").write_bytes(b"new")
                (updater.staging_dir / "daily.cvd").write_bytes(b"new")
                return ProcessResult(0, "daily.cvd updated\n")
            return ProcessResult(0, f"{database}: OK\n")

        with patch("lfs_antivirus_aaha.updater.run_command", side_effect=fake_run) as mocked:
            result = updater.update()

        self.assertTrue(result.database_status.ready)
        self.assertEqual((database / "main.cvd").read_bytes(), b"new")
        self.assertEqual((clamav_database_backup_dir() / "main.cvd").read_bytes(), b"old")
        self.assertFalse(updater.staging_dir.exists())
        update_argv = mocked.call_args_list[0].args[0]
        self.assertIn(f"--datadir={updater.staging_dir}", update_argv)
        self.assertEqual(len(mocked.call_args_list), 2)

    def test_freshclam_failure_preserves_active_database(self) -> None:
        database = self._seed_active_database()
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))
        with patch(
            "lfs_antivirus_aaha.updater.run_command",
            return_value=ProcessResult(1, "ERROR: network unavailable\n"),
        ):
            with self.assertRaisesRegex(RuntimeError, "exit code 1"):
                updater.update()

        self.assertEqual((database / "main.cvd").read_bytes(), b"old")
        self.assertFalse(updater.staging_dir.exists())

    def test_database_validation_failure_preserves_active_database(self) -> None:
        database = self._seed_active_database()
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))

        def fake_run(argv, **_kwargs):
            if str(argv[0]).endswith("freshclam.exe"):
                (updater.staging_dir / "main.cvd").write_bytes(b"candidate")
                (updater.staging_dir / "daily.cvd").write_bytes(b"candidate")
                return ProcessResult(0, "updated\n")
            return ProcessResult(2, "database load failed\n")

        with patch("lfs_antivirus_aaha.updater.run_command", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "validation failed"):
                updater.update()

        self.assertEqual((database / "daily.cvd").read_bytes(), b"old")
        self.assertFalse(updater.staging_dir.exists())

    def test_activation_failure_restores_active_database_and_preserves_backup(self) -> None:
        database = self._seed_active_database()
        backup = clamav_database_backup_dir()
        backup.mkdir(parents=True)
        (backup / "main.cvd").write_bytes(b"older")
        (backup / "daily.cvd").write_bytes(b"older")
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))

        def fake_run(argv, **_kwargs):
            if str(argv[0]).endswith("freshclam.exe"):
                (updater.staging_dir / "main.cvd").write_bytes(b"candidate")
                (updater.staging_dir / "daily.cvd").write_bytes(b"candidate")
                return ProcessResult(0, "updated\n")
            return ProcessResult(0, "probe: OK\n")

        original_replace = Path.replace

        def fail_candidate_activation(source: Path, target: Path):
            if source == updater.staging_dir and target == database:
                raise OSError("injected activation failure")
            return original_replace(source, target)

        with (
            patch("lfs_antivirus_aaha.updater.run_command", side_effect=fake_run),
            patch.object(Path, "replace", autospec=True, side_effect=fail_candidate_activation),
        ):
            with self.assertRaisesRegex(RuntimeError, "previous active database was restored"):
                updater.update()

        self.assertEqual((database / "main.cvd").read_bytes(), b"old")
        self.assertEqual((backup / "main.cvd").read_bytes(), b"older")
        self.assertFalse(updater.previous_dir.exists())
        self.assertFalse(updater.staging_dir.exists())
        self.assertFalse(updater.activation_marker.exists())

    def test_first_activation_failure_clears_marker_without_claiming_rollback(self) -> None:
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))

        def fake_run(argv, **_kwargs):
            if str(argv[0]).endswith("freshclam.exe"):
                (updater.staging_dir / "main.cvd").write_bytes(b"candidate")
                (updater.staging_dir / "daily.cvd").write_bytes(b"candidate")
                return ProcessResult(0, "updated\n")
            return ProcessResult(0, "probe: OK\n")

        original_replace = Path.replace

        def fail_candidate_activation(source: Path, target: Path):
            if source == updater.staging_dir and target == updater.database_dir:
                raise OSError("injected activation failure")
            return original_replace(source, target)

        with (
            patch("lfs_antivirus_aaha.updater.run_command", side_effect=fake_run),
            patch.object(Path, "replace", autospec=True, side_effect=fail_candidate_activation),
        ):
            with self.assertRaisesRegex(RuntimeError, "no active database was replaced"):
                updater.update()

        self.assertFalse(updater.database_dir.exists())
        self.assertFalse(updater.staging_dir.exists())
        self.assertFalse(updater.activation_marker.exists())

    def test_startup_recovery_restores_previous_database_and_clears_transaction(self) -> None:
        database = clamav_database_dir()
        previous = database.with_name(database.name + ".previous")
        staging = database.with_name(database.name + ".staging")
        marker = database.parent / "clamav-database-activation.json"
        previous.mkdir(parents=True)
        staging.mkdir()
        (previous / "main.cvd").write_bytes(b"old")
        (previous / "daily.cvd").write_bytes(b"old")
        (staging / "main.cvd").write_bytes(b"candidate")
        marker.write_text('{"phase":"active_moved","had_current":true}', encoding="utf-8")

        note = recover_database_activation()

        self.assertIn("Recovered the previous active", note or "")
        self.assertEqual((database / "main.cvd").read_bytes(), b"old")
        self.assertFalse(previous.exists())
        self.assertFalse(staging.exists())
        self.assertFalse(marker.exists())

    def test_startup_recovery_completes_interrupted_first_activation(self) -> None:
        database = clamav_database_dir()
        staging = database.with_name(database.name + ".staging")
        marker = database.parent / "clamav-database-activation.json"
        staging.mkdir(parents=True)
        (staging / "main.cvd").write_bytes(b"candidate")
        (staging / "daily.cvd").write_bytes(b"candidate")
        marker.write_text('{"phase":"prepared","had_current":false}', encoding="utf-8")

        note = recover_database_activation()

        self.assertIn("Completed an interrupted first", note or "")
        self.assertEqual((database / "main.cvd").read_bytes(), b"candidate")
        self.assertFalse(staging.exists())
        self.assertFalse(marker.exists())

    def test_startup_recovery_finishes_backup_rotation_after_new_database_is_active(self) -> None:
        database = self._seed_active_database(b"new")
        previous = database.with_name(database.name + ".previous")
        previous.mkdir()
        (previous / "main.cvd").write_bytes(b"old")
        (previous / "daily.cvd").write_bytes(b"old")
        marker = database.parent / "clamav-database-activation.json"
        marker.write_text('{"phase":"active_moved","had_current":true}', encoding="utf-8")

        note = recover_database_activation()

        self.assertIn("Completed pending", note or "")
        self.assertEqual((database / "main.cvd").read_bytes(), b"new")
        self.assertEqual((clamav_database_backup_dir() / "main.cvd").read_bytes(), b"old")
        self.assertFalse(previous.exists())
        self.assertFalse(marker.exists())

    def test_cancelled_freshclam_preserves_active_database_and_removes_config(self) -> None:
        database = self._seed_active_database()
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))
        with patch(
            "lfs_antivirus_aaha.updater.run_command",
            return_value=ProcessResult(-15, "cancelled\n", cancelled=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                updater.update()

        self.assertEqual((database / "main.cvd").read_bytes(), b"old")
        self.assertFalse(updater.staging_dir.exists())
        self.assertFalse((database.parent / "freshclam.conf").exists())

    def test_cancellation_after_validation_does_not_activate_staging(self) -> None:
        database = self._seed_active_database()
        updater = FreshClamUpdater(Path("C:/ClamAV/freshclam.exe"), Path("C:/ClamAV/clamscan.exe"))
        control = UpdateControl()

        def fake_run(argv, **_kwargs):
            if str(argv[0]).endswith("freshclam.exe"):
                (updater.staging_dir / "main.cvd").write_bytes(b"candidate")
                (updater.staging_dir / "daily.cvd").write_bytes(b"candidate")
                return ProcessResult(0, "updated\n")
            self.assertTrue(control.request_cancel())
            return ProcessResult(0, "probe: OK\n")

        with patch("lfs_antivirus_aaha.updater.run_command", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                updater.update(control=control)

        self.assertEqual((database / "main.cvd").read_bytes(), b"old")
        self.assertFalse(updater.staging_dir.exists())
        self.assertFalse(updater.activation_marker.exists())

    def test_commit_barrier_is_atomic_with_cancel_requests(self) -> None:
        cancelled = UpdateControl()
        self.assertTrue(cancelled.request_cancel())
        self.assertFalse(cancelled.begin_commit())

        committing = UpdateControl()
        self.assertTrue(committing.begin_commit())
        self.assertFalse(committing.request_cancel())
        self.assertTrue(committing.commit_started.is_set())

    def test_database_operation_lock_rejects_a_second_process_scope(self) -> None:
        with database_operation_lock():
            with self.assertRaisesRegex(RuntimeError, "Another Local-First Antivirus process"):
                recover_database_activation()

    def test_config_is_minimal_and_database_status_requires_main_and_daily(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "freshclam.conf"
            database = Path(temp) / "database"
            write_freshclam_config(config, database)
            text = config.read_text(encoding="utf-8")
            self.assertIn(f'DatabaseDirectory "{database}"', text)
            self.assertIn("DatabaseMirror database.clamav.net", text)
            self.assertNotIn("Example", text)

        database = clamav_database_dir()
        database.mkdir(parents=True)
        (database / "main.cvd").write_bytes(b"fixture")
        self.assertFalse(database_status().ready)
        (database / "daily.cld").write_bytes(b"fixture")
        self.assertTrue(database_status().ready)


if __name__ == "__main__":
    unittest.main()
