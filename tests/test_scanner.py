import tempfile
import unittest
from pathlib import Path

from localshield_av.definitions import Definitions
from localshield_av.definitions import load_definitions
from localshield_av.models import ScanFinding, Signature
from localshield_av.quarantine import quarantine_file, restore_record
from localshield_av.scanner import LocalScanner


class ScannerTests(unittest.TestCase):
    def test_demo_content_signature_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.txt"
            path.write_text("hello LOCALSHIELD_TEST_THREAT world", encoding="utf-8")
            scanner = LocalScanner(load_definitions())

            findings = scanner.scan_file(path)

            self.assertTrue(any(item.threat_name == "LocalShield Demo Test Signature" for item in findings))

    def test_double_extension_heuristic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invoice.pdf.exe"
            path.write_bytes(b"not executable, just a test fixture")
            scanner = LocalScanner(load_definitions())

            findings = scanner.scan_file(path)

            self.assertTrue(any(item.threat_name == "Suspicious Double Extension" for item in findings))

    def test_md5_hash_signature_is_detected_without_modifying_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "known-sample.bin"
            path.write_bytes(b"hash-only unit test sample")
            definitions = Definitions(
                version="unit",
                updated_at="2026-05-12T00:00:00+00:00",
                hash_signatures=[
                    Signature(
                        id="UNIT-MD5",
                        name="Unit MD5 Hash",
                        severity="high",
                        kind="md5",
                        value="761bbdded0c9f8c174b3595c1563f78e",
                    )
                ],
                content_signatures=[],
                risky_extensions=set(),
                scan_archives=False,
            )
            scanner = LocalScanner(definitions)

            findings = scanner.scan_file(path)

            self.assertTrue(path.exists())
            self.assertTrue(any(item.threat_name == "Unit MD5 Hash" for item in findings))

    def test_quarantine_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample-threat.txt"
            path.write_text("LOCALSHIELD_TEST_THREAT", encoding="utf-8")
            finding = ScanFinding(
                path=str(path),
                threat_name="Unit Test Threat",
                severity="high",
                reason="Unit test",
                sha256="",
                size=path.stat().st_size,
            )

            record = quarantine_file(finding)
            self.assertFalse(path.exists())

            restored = restore_record(record.id)
            self.assertEqual(restored, path)
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
