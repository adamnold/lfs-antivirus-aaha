import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lfs_antivirus_aaha.storage import (
    app_data_dir,
    canonical_app_data_dir,
    ensure_app_dirs,
    legacy_app_data_dir,
)


class StorageTests(unittest.TestCase):
    def test_fresh_install_uses_canonical_aaha_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"LOCALAPPDATA": temp}):
            expected = Path(temp) / "AAHA" / "lfs-antivirus-aaha"

            self.assertEqual(app_data_dir(), expected)
            self.assertEqual(canonical_app_data_dir(), expected)

    def test_legacy_only_installation_keeps_using_legacy_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"LOCALAPPDATA": temp}):
            legacy = Path(temp) / "LocalShieldAV"
            payload = legacy / "quarantine" / "existing.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"preserve legacy quarantine payload")

            self.assertEqual(app_data_dir(), legacy)
            self.assertEqual(legacy_app_data_dir(), legacy)
            ensure_app_dirs()
            self.assertEqual(payload.read_bytes(), b"preserve legacy quarantine payload")

    def test_canonical_directory_wins_when_both_locations_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"LOCALAPPDATA": temp}):
            canonical = Path(temp) / "AAHA" / "lfs-antivirus-aaha"
            canonical.mkdir(parents=True)
            (Path(temp) / "LocalShieldAV").mkdir()

            self.assertEqual(app_data_dir(), canonical)


if __name__ == "__main__":
    unittest.main()
