from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

from .definitions import install_definitions, validate_definitions
from .storage import write_json


def download_definitions(url: str, timeout: int = 20) -> Path:
    request = Request(url, headers={"User-Agent": "LocalShieldAV/0.1"})
    with urlopen(request, timeout=timeout) as response:
        if response.status >= 400:
            raise RuntimeError(f"Definitions server returned HTTP {response.status}.")
    body = response.read(5 * 1024 * 1024)
    raw = json.loads(body.decode("utf-8"))
    validate_definitions(raw)
    temp = Path(tempfile.gettempdir()) / f"localshield-definitions-{uuid.uuid4().hex}.json"
    write_json(temp, raw)
    return temp


def update_definitions_from_url(url: str):
    temp = download_definitions(url)
    try:
        return install_definitions(temp)
    finally:
        temp.unlink(missing_ok=True)
