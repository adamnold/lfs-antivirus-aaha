# AAHA Local-First Series

Last Updated: 2026-07-29

The Local-First Series is Adam And His Agents' family of AAHA-developed,
local-first applications. Each application should remain useful without an
account or continuously available remote service and should make network
behavior visible and bounded.

## Series principles

1. **Local work is primary.** Core user workflows execute on the user's device.
2. **User state stays understandable.** Storage locations and migration behavior
   are documented.
3. **Network activity is bounded.** A feature identifies when and why it connects
   to an external service.
4. **Destructive actions are explicit and safe.** Unsafe destructive workflows
   remain disabled until they have a recoverable design.
5. **No hidden telemetry.** Analytics or remote diagnostics are absent unless a
   future release introduces them with prominent documentation and consent.
6. **Limits are public.** Incomplete protection, unavailable integrations, and
   verification boundaries are documented rather than implied away.

## Naming convention

| Surface | Value |
| --- | --- |
| Product | Local-First Antivirus |
| Series | AAHA Local-First Series |
| Organization | Adam And His Agents (AAHA) |
| Repository/directory | `lfs-antivirus-aaha` |
| Python package | `lfs_antivirus_aaha` |
| New local data identifier | `AAHA/lfs-antivirus-aaha` |

## Antivirus interpretation for 0.3.0-beta.1

“Local-first” means the user selects local content and a separately installed
`clamscan.exe` inspects it on the same computer. The AAHA application does not
upload content or require an account.

The optional external ClamAV engine is user-provided. A network request occurs
only when the user explicitly runs `freshclam.exe` through **Update
Definitions**; it contacts ClamAV's configured official mirror, not an AAHA
service. Definition updates are not required continuously for the UI to open,
but current definitions are required before scanning is enabled.

Local-first does not mean full endpoint protection. This unsigned public beta
provides on-demand scanning only and disables unsafe legacy file actions. Its
Windows release workflow verifies packaging and the ClamAV 1.5.3 clean-scan
boundary, while physical Windows 10/11 and broader engine acceptance remain
future work.
