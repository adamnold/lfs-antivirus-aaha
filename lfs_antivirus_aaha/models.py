"""Core data models for Local-First Antivirus."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ScanFinding:
    path: str
    threat_name: str
    severity: str
    reason: str
    sha256: str
    size: int
    detected_at: str = field(default_factory=utc_now_iso)
    status: str = "Detected"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScanFinding":
        return cls(
            path=str(value.get("path", "")),
            threat_name=str(value.get("threat_name", "Unknown")),
            severity=str(value.get("severity", "medium")),
            reason=str(value.get("reason", "")),
            sha256=str(value.get("sha256", "")),
            size=int(value.get("size", 0)),
            detected_at=str(value.get("detected_at", utc_now_iso())),
            status=str(value.get("status", "Detected")),
        )


@dataclass
class ScanSummary:
    started_at: str
    completed_at: str
    root: str
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    findings: list[ScanFinding] = field(default_factory=list)
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)
    engine_version: str = ""
    database_version: str = ""
    exit_code: int | None = None

    @property
    def threats_found(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["threats_found"] = self.threats_found
        return data


@dataclass
class QuarantineRecord:
    id: str
    original_path: str
    stored_path: str
    quarantined_at: str
    finding: ScanFinding

    @property
    def original_name(self) -> str:
        return Path(self.original_path).name

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["finding"] = self.finding.to_dict()
        return data

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "QuarantineRecord":
        finding = value.get("finding")
        if not isinstance(finding, dict):
            raise ValueError("Quarantine record finding must be an object.")
        return cls(
            id=str(value["id"]),
            original_path=str(value["original_path"]),
            stored_path=str(value["stored_path"]),
            quarantined_at=str(value["quarantined_at"]),
            finding=ScanFinding.from_dict(finding),
        )
