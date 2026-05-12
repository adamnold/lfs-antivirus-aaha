# LocalShield AV

LocalShield AV is a native local desktop antivirus-style tool for Windows. It uses Python and Tkinter, so the UI is a normal desktop window and does not use a browser, webview, Electron, Tauri, or a web UI.

## What this first version does

- Scans a selected file or folder locally.
- Checks SHA-256 hash signatures from `definitions/signatures.json`.
- Checks imported MD5, SHA-1, and SHA-256 file-hash signatures.
- Checks harmless content signatures.
- Flags basic heuristic review items such as risky script extensions and disguised double extensions.
- Quarantines, restores, and permanently deletes files only after explicit user approval.
- Keeps logs and settings under `%LOCALAPPDATA%\LocalShieldAV`.
- Imports definitions from a local JSON file or from supported source presets.

This is a legitimate defensive scanner prototype. It is not a replacement for Microsoft Defender or a commercial antivirus engine.

## Safety model

Scans are read-only. Detection does not automatically quarantine, delete, restore, upload, or modify files. Quarantine and delete actions are available only from user-selected buttons, and destructive actions require confirmation.

## Definition sources

The bundled starting definitions are a small local test set: the EICAR test-file hash plus the harmless `LOCALSHIELD_TEST_THREAT` marker. They are for validating the scanner, not broad malware coverage.

The Updates tab includes a definitions source dropdown. Supported online presets currently include official ClamAV `daily.cvd` and `main.cvd` imports. LocalShield converts compatible ClamAV file-hash signatures into its local JSON format. ClamAV bytecode signatures and abuse.ch sources are listed as known sources but require additional engine or API-key support before they can be used directly.

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
