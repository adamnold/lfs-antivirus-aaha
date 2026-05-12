# LocalShield AV

LocalShield AV is a native local desktop antivirus-style tool for Windows. It uses Python and Tkinter, so the UI is a normal desktop window and does not use a browser, webview, Electron, Tauri, or a web UI.

## What this first version does

- Scans a selected file or folder locally.
- Checks SHA-256 hash signatures from `definitions/signatures.json`.
- Checks harmless content signatures.
- Flags basic heuristic review items such as risky script extensions and disguised double extensions.
- Quarantines, restores, and permanently deletes detected files.
- Keeps logs and settings under `%LOCALAPPDATA%\LocalShieldAV`.
- Imports definitions from a local JSON file or downloads them from a URL you explicitly configure.

This is a legitimate defensive scanner prototype. It is not a replacement for Microsoft Defender or a commercial antivirus engine.

## Run locally

From this folder:

```powershell
.\run-localshield.ps1
```

Or:

```powershell
python -m localshield_av.app
```

## Install for the current Windows user

```powershell
.\install-localshield.ps1
```

That copies the app to `%LOCALAPPDATA%\Programs\LocalShieldAV` and creates a Start Menu shortcut.

## Test detection safely

Create a text file containing this harmless marker:

```text
LOCALSHIELD_TEST_THREAT
```

Scan the folder containing that file. The scanner should report `LocalShield Demo Test Signature`.

## Definition format

Definitions are JSON:

```json
{
  "version": "2026.05.11.1",
  "updated_at": "2026-05-11T00:00:00+00:00",
  "hashes": [
    {
      "id": "SAMPLE",
      "name": "Sample Hash",
      "severity": "high",
      "sha256": "..."
    }
  ],
  "content": [
    {
      "id": "SAMPLE-CONTENT",
      "name": "Sample Content",
      "severity": "medium",
      "pattern": "SOME_MARKER"
    }
  ],
  "heuristics": {
    "risky_extensions": [".ps1", ".js", ".vbs"],
    "scan_archives": false
  }
}
```
