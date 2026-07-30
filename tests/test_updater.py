import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from lfs_antivirus_aaha.updater import convert_clamav_cvd_file, parse_clamav_hash_line


class UpdaterTests(unittest.TestCase):
    def test_parse_clamav_hash_line(self) -> None:
        parsed = parse_clamav_hash_line("0121216ba3756be9d997b8086f7629cc:26:Unit.Test")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["md5"], "0121216ba3756be9d997b8086f7629cc")
        self.assertEqual(parsed["name"], "Unit.Test")

    def test_convert_clamav_cvd_file_imports_hash_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.cvd"
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w:gz") as archive:
                data = b"0121216ba3756be9d997b8086f7629cc:26:Unit.Test\n"
                info = tarfile.TarInfo("unit.hdb")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            header = b"ClamAV-VDB:12 May 2026 00-0000:1:1:90:md5:sig:builder:0"
            path.write_bytes(header.ljust(512, b" ") + payload.getvalue())

            converted = convert_clamav_cvd_file(path, "Unit CVD")

            self.assertEqual(converted["hashes"][0]["md5"], "0121216ba3756be9d997b8086f7629cc")
            self.assertIn("Unit CVD", converted["version"])


if __name__ == "__main__":
    unittest.main()
