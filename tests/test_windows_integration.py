from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from lfs_antivirus_aaha.engine import run_command
from lfs_antivirus_aaha.scanner import validate_scan_target
from lfs_antivirus_aaha.updater import database_operation_lock


@unittest.skipUnless(os.name == "nt", "Windows release integration gate")
class WindowsIntegrationTests(unittest.TestCase):
    def test_database_lock_blocks_a_second_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            environment = dict(os.environ)
            environment["LOCALAPPDATA"] = temp_dir
            child_code = (
                "from lfs_antivirus_aaha.updater import database_operation_lock; "
                "import sys; "
                "\ntry:\n"
                "    with database_operation_lock():\n"
                "        sys.exit(7)\n"
                "except RuntimeError as exc:\n"
                "    print(str(exc))\n"
                "    sys.exit(0)\n"
            )
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": temp_dir}):
                with database_operation_lock():
                    completed = subprocess.run(
                        [sys.executable, "-c", child_code],
                        cwd=Path(__file__).resolve().parents[1],
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Another Local-First Antivirus process", completed.stdout)

    def test_cancellation_terminates_a_spawned_process_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_file = Path(temp_dir) / "child.pid"
            parent_code = (
                "import pathlib, subprocess, sys, time; "
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid), encoding='ascii'); "
                "time.sleep(60)"
            )
            cancellation = threading.Event()
            result_holder: list[object] = []

            worker = threading.Thread(
                target=lambda: result_holder.append(
                    run_command([sys.executable, "-c", parent_code], cancel_event=cancellation)
                ),
                daemon=True,
            )
            worker.start()
            deadline = time.monotonic() + 15
            child_pid: int | None = None
            while child_pid is None and time.monotonic() < deadline:
                try:
                    content = pid_file.read_text(encoding="ascii").strip()
                    if content.isdecimal():
                        child_pid = int(content)
                except OSError:
                    pass
                time.sleep(0.05)
            if child_pid is None:
                cancellation.set()
                worker.join(timeout=15)
                self.fail("The child process did not report a complete PID.")

            try:
                cancellation.set()
                worker.join(timeout=15)
                self.assertFalse(worker.is_alive(), "Cancellation did not return in bounded time.")
                self.assertEqual(len(result_holder), 1)
                self.assertTrue(result_holder[0].cancelled)

                deadline = time.monotonic() + 10
                while _windows_process_is_running(child_pid) and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertFalse(
                    _windows_process_is_running(child_pid),
                    "A descendant remained running after process-tree cancellation.",
                )
            finally:
                if _windows_process_is_running(child_pid):
                    subprocess.run(
                        [
                            str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"),
                            "/PID",
                            str(child_pid),
                            "/T",
                            "/F",
                        ],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )

    def test_mapped_remote_drive_is_rejected_before_access(self) -> None:
        kernel32 = ctypes.windll.kernel32
        kernel32.DefineDosDeviceW.argtypes = [ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_wchar_p]
        kernel32.DefineDosDeviceW.restype = ctypes.c_int
        kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetDriveTypeW.restype = ctypes.c_uint

        drive_letter = next(
            (
                letter
                for letter in reversed("DEFGHIJKLMNOPQRSTUVWXYZ")
                if kernel32.GetDriveTypeW(f"{letter}:\\") == 1
            ),
            None,
        )
        self.assertIsNotNone(drive_letter, "No unused drive letter was available for the test.")
        device_name = f"{drive_letter}:"
        raw_target = r"\??\UNC\127.0.0.1\AAHA-NONEXISTENT-SHARE"
        define_flags = 0x00000001 | 0x00000008
        remove_flags = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008

        created = kernel32.DefineDosDeviceW(define_flags, device_name, raw_target)
        self.assertNotEqual(created, 0, "DefineDosDeviceW could not create the test mapping.")
        try:
            self.assertEqual(kernel32.GetDriveTypeW(f"{drive_letter}:\\"), 4)
            with self.assertRaisesRegex(ValueError, "Mapped and UNC network paths"):
                validate_scan_target(Path(f"{drive_letter}:\\probe.txt"))
        finally:
            kernel32.DefineDosDeviceW(remove_flags, device_name, raw_target)


def _windows_process_is_running(pid: int) -> bool:
    synchronize = 0x00100000
    wait_timeout = 0x00000102
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(handle, 0) == wait_timeout
    finally:
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
