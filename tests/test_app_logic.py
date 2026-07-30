import unittest

from lfs_antivirus_aaha.app import scan_summary_is_accepted
from lfs_antivirus_aaha.models import ScanSummary


class AppLogicTests(unittest.TestCase):
    def test_only_complete_non_cancelled_summary_replaces_accepted_state(self) -> None:
        base = {
            "started_at": "2026-07-29T00:00:00+00:00",
            "completed_at": "2026-07-29T00:00:01+00:00",
            "root": "C:/fixture",
            "exit_code": 0,
        }
        self.assertTrue(scan_summary_is_accepted(ScanSummary(**base)))
        self.assertFalse(scan_summary_is_accepted(ScanSummary(**base, cancelled=True)))
        self.assertFalse(scan_summary_is_accepted(ScanSummary(**base, errors=["incomplete"])))


if __name__ == "__main__":
    unittest.main()
