import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from lfs_antivirus_aaha.engine import (
    ProcessResult,
    run_command,
    suggested_installation,
    validate_installation,
)


class EngineTests(unittest.TestCase):
    def test_validation_uses_exact_absolute_paths_without_path_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "ClamAV"
            parent.mkdir()
            clamscan = parent / "clamscan.exe"
            freshclam = parent / "freshclam.exe"
            clamscan.write_bytes(b"unit fixture")
            freshclam.write_bytes(b"unit fixture")

            with patch(
                "lfs_antivirus_aaha.engine.run_command",
                side_effect=(
                    ProcessResult(0, "ClamAV 1.5.3/27800\n"),
                    ProcessResult(0, "ClamAV 1.5.3/27800\n"),
                ),
            ) as mocked:
                installation = validate_installation(clamscan, freshclam)

            self.assertEqual(installation.clamscan_path, clamscan.resolve())
            self.assertEqual(installation.freshclam_path, freshclam.resolve())
            self.assertEqual(
                mocked.call_args_list,
                [
                    call(
                        [str(clamscan.resolve()), "--version"],
                        cancel_event=None,
                        timeout=15,
                    ),
                    call(
                        [str(freshclam.resolve()), "--version"],
                        cancel_event=None,
                        timeout=15,
                    ),
                ],
            )

    def test_cancelled_validation_does_not_start_second_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            clamscan = Path(temp) / "clamscan.exe"
            freshclam = Path(temp) / "freshclam.exe"
            clamscan.write_bytes(b"one")
            freshclam.write_bytes(b"two")
            with patch(
                "lfs_antivirus_aaha.engine.run_command",
                return_value=ProcessResult(-15, "", cancelled=True),
            ) as mocked:
                with self.assertRaisesRegex(RuntimeError, "cancelled"):
                    validate_installation(clamscan, freshclam)
            self.assertEqual(mocked.call_count, 1)

    def test_cancellation_between_version_checks_does_not_start_second_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            clamscan = Path(temp) / "clamscan.exe"
            freshclam = Path(temp) / "freshclam.exe"
            clamscan.write_bytes(b"one")
            freshclam.write_bytes(b"two")
            cancelled = threading.Event()

            def finish_then_cancel(*_args, **_kwargs):
                cancelled.set()
                return ProcessResult(0, "ClamAV 1.5.3\n")

            with patch(
                "lfs_antivirus_aaha.engine.run_command",
                side_effect=finish_then_cancel,
            ) as mocked:
                with self.assertRaisesRegex(RuntimeError, "cancelled"):
                    validate_installation(clamscan, freshclam, cancel_event=cancelled)
            self.assertEqual(mocked.call_count, 1)

    def test_validation_rejects_executables_from_different_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            clamscan = Path(temp) / "one" / "clamscan.exe"
            freshclam = Path(temp) / "two" / "freshclam.exe"
            clamscan.parent.mkdir()
            freshclam.parent.mkdir()
            clamscan.write_bytes(b"one")
            freshclam.write_bytes(b"two")

            with self.assertRaisesRegex(ValueError, "same directory"):
                validate_installation(clamscan, freshclam)

    def test_validation_rejects_relative_path_and_unexpected_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute path"):
            validate_installation(Path("clamscan.exe"), Path("freshclam.exe"))

        with tempfile.TemporaryDirectory() as temp:
            clamscan = Path(temp) / "clamscan.exe"
            freshclam = Path(temp) / "freshclam.exe"
            clamscan.write_bytes(b"one")
            freshclam.write_bytes(b"two")
            with patch(
                "lfs_antivirus_aaha.engine.run_command",
                side_effect=(ProcessResult(0, "not the expected tool\n"), ProcessResult(0, "ClamAV 1.5.3\n")),
            ):
                with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                    validate_installation(clamscan, freshclam)

    def test_run_command_passes_a_list_and_disables_the_shell(self) -> None:
        process = MagicMock()
        process.communicate.return_value = ("done\n", None)
        process.returncode = 0
        with patch("lfs_antivirus_aaha.engine.subprocess.Popen", return_value=process) as popen:
            result = run_command(["C:/ClamAV/clamscan.exe", "--version"])

        self.assertEqual(result.returncode, 0)
        arguments, keywords = popen.call_args
        self.assertEqual(arguments[0], ["C:/ClamAV/clamscan.exe", "--version"])
        self.assertIs(keywords["shell"], False)
        self.assertEqual(keywords["stdin"], subprocess.DEVNULL)

    def test_run_command_terminates_when_cancelled(self) -> None:
        process = MagicMock()
        cancelled = threading.Event()
        calls = 0

        def communicate(*, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                cancelled.set()
                raise subprocess.TimeoutExpired(cmd="fixture", timeout=timeout)
            return "partial\n", None

        process.communicate.side_effect = communicate
        process.returncode = -15
        process.poll.return_value = -15
        with (
            patch("lfs_antivirus_aaha.engine.subprocess.Popen", return_value=process),
            patch("lfs_antivirus_aaha.engine._terminate_process_tree") as terminate_tree,
        ):
            result = run_command(
                ["C:/ClamAV/clamscan.exe", "C:/sample"], cancel_event=cancelled
            )

        terminate_tree.assert_called_once_with(process)
        self.assertTrue(result.cancelled)
        self.assertFalse(result.timed_out)

    def test_normal_process_exit_still_observes_a_cancellation_request(self) -> None:
        process = MagicMock()
        cancelled = threading.Event()

        def communicate(*, timeout):
            cancelled.set()
            return "Scanned files: 1\nInfected files: 0\n", None

        process.communicate.side_effect = communicate
        process.returncode = 0
        with patch("lfs_antivirus_aaha.engine.subprocess.Popen", return_value=process):
            result = run_command(["C:/ClamAV/clamscan.exe", "C:/sample"], cancel_event=cancelled)

        self.assertTrue(result.cancelled)
        process.terminate.assert_not_called()

    def test_pre_cancelled_command_never_starts_a_process(self) -> None:
        cancelled = threading.Event()
        cancelled.set()
        with patch("lfs_antivirus_aaha.engine.subprocess.Popen") as popen:
            result = run_command(["C:/ClamAV/clamscan.exe", "C:/sample"], cancel_event=cancelled)
        self.assertTrue(result.cancelled)
        popen.assert_not_called()

    def test_force_kill_path_has_bounded_final_wait(self) -> None:
        process = MagicMock()
        cancelled = threading.Event()
        calls = 0

        def communicate(*, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                cancelled.set()
            raise subprocess.TimeoutExpired(cmd="fixture", timeout=timeout, output="partial\n")

        process.communicate.side_effect = communicate
        process.wait.side_effect = subprocess.TimeoutExpired(cmd="fixture", timeout=1)
        process.poll.return_value = None
        with (
            patch("lfs_antivirus_aaha.engine.subprocess.Popen", return_value=process),
            patch("lfs_antivirus_aaha.engine._force_kill_process_tree") as force_kill,
        ):
            result = run_command(["C:/ClamAV/clamscan.exe", "C:/sample"], cancel_event=cancelled)

        force_kill.assert_called_once_with(process)
        process.stdout.close.assert_called_once_with()
        self.assertEqual(result.returncode, -9)
        self.assertTrue(result.cancelled)

    def test_validation_rejects_link_ancestors_and_remote_drives(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            (real / "clamscan.exe").write_bytes(b"one")
            (real / "freshclam.exe").write_bytes(b"two")
            link = root / "linked-clamav"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(ValueError, "Symbolic-link"):
                validate_installation(link / "clamscan.exe", link / "freshclam.exe")

            with patch("lfs_antivirus_aaha.engine.path_is_remote", return_value=True):
                with self.assertRaisesRegex(ValueError, "network"):
                    validate_installation(real / "clamscan.exe", real / "freshclam.exe")

            with (
                patch.dict(
                    os.environ,
                    {"ProgramFiles": str(real), "ProgramFiles(x86)": ""},
                ),
                patch("lfs_antivirus_aaha.engine.path_is_remote", return_value=True),
                patch.object(Path, "lstat") as lstat,
            ):
                self.assertIsNone(suggested_installation())
            lstat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
