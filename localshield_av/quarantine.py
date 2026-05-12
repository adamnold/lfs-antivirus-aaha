from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from .models import QuarantineRecord, ScanFinding, utc_now_iso
from .storage import quarantine_dir, read_json, write_json


def _record_path(record_id: str) -> Path:
    return quarantine_dir() / f"{record_id}.json"


def list_records() -> list[QuarantineRecord]:
    records: list[QuarantineRecord] = []
    quarantine_dir().mkdir(parents=True, exist_ok=True)
    for path in sorted(quarantine_dir().glob("*.json")):
        try:
            records.append(QuarantineRecord.from_dict(read_json(path, {})))
        except (KeyError, TypeError, ValueError):
            continue
    return records


def quarantine_file(finding: ScanFinding) -> QuarantineRecord:
    source = Path(finding.path)
    if not source.exists():
        raise FileNotFoundError(f"Source no longer exists: {source}")
    record_id = uuid.uuid4().hex
    quarantine_dir().mkdir(parents=True, exist_ok=True)
    stored_path = quarantine_dir() / f"{record_id}.bin"
    shutil.move(str(source), stored_path)
    finding.status = "Quarantined"
    record = QuarantineRecord(
        id=record_id,
        original_path=str(source),
        stored_path=str(stored_path),
        quarantined_at=utc_now_iso(),
        finding=finding,
    )
    write_json(_record_path(record_id), record.to_dict())
    return record


def restore_record(record_id: str, destination: Path | None = None) -> Path:
    record = _load_record(record_id)
    stored = Path(record.stored_path)
    if not stored.exists():
        raise FileNotFoundError(f"Quarantined payload is missing: {stored}")
    target = destination or Path(record.original_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"Restore target already exists: {target}")
    shutil.move(str(stored), target)
    _record_path(record_id).unlink(missing_ok=True)
    return target


def delete_record(record_id: str) -> None:
    record = _load_record(record_id)
    Path(record.stored_path).unlink(missing_ok=True)
    _record_path(record_id).unlink(missing_ok=True)


def _load_record(record_id: str) -> QuarantineRecord:
    path = _record_path(record_id)
    if not path.exists():
        raise FileNotFoundError(f"Quarantine record not found: {record_id}")
    return QuarantineRecord.from_dict(read_json(path, {}))
