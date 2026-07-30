import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lfs_antivirus_aaha.quarantine import list_records_with_errors
from lfs_antivirus_aaha.storage import quarantine_dir, write_json


class LegacyQuarantineTests(unittest.TestCase):
    def test_duplicate_ids_and_malformed_records_are_read_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"LOCALAPPDATA": temp}):
            directory = quarantine_dir()
            directory.mkdir(parents=True)
            payload = directory / "preserved.bin"
            payload.write_bytes(b"preserve me")
            valid = {
                "id": "duplicate-id",
                "original_path": "C:/one.txt",
                "stored_path": str(payload),
                "quarantined_at": "2026-05-12T00:00:00+00:00",
                "finding": {
                    "path": "C:/one.txt",
                    "threat_name": "Legacy.Unit",
                    "severity": "high",
                    "reason": "fixture",
                    "sha256": "",
                    "size": 1,
                },
            }
            write_json(directory / "one.json", valid)
            second = dict(valid)
            second["original_path"] = "C:/two.txt"
            write_json(directory / "two.json", second)
            write_json(directory / "malformed.json", {**valid, "finding": "not-an-object"})
            (directory / "invalid-utf8.json").write_bytes(b"\xff\xfe\x00")

            records, errors = list_records_with_errors()

            self.assertEqual(len(records), 2)
            self.assertEqual([item.id for item in records], ["duplicate-id", "duplicate-id"])
            self.assertEqual(errors, 2)
            self.assertEqual(payload.read_bytes(), b"preserve me")


if __name__ == "__main__":
    unittest.main()
