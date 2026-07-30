"""Read-only access to quarantine records created by earlier prototypes."""

from __future__ import annotations

from .models import QuarantineRecord
from .storage import quarantine_dir, read_json


def list_records() -> list[QuarantineRecord]:
    """List legacy records without moving, restoring, or deleting user files."""

    records, _ = list_records_with_errors()
    return records


def list_records_with_errors() -> tuple[list[QuarantineRecord], int]:
    """Return valid legacy records and the number that could not be decoded."""

    records: list[QuarantineRecord] = []
    errors = 0
    quarantine_dir().mkdir(parents=True, exist_ok=True)
    for path in sorted(quarantine_dir().glob("*.json")):
        try:
            records.append(QuarantineRecord.from_dict(read_json(path, {})))
        except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
            errors += 1
    return records, errors
