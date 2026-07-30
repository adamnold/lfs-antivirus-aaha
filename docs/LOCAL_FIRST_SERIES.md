# AAHA Local-First Series

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
4. **Destructive actions are explicit.** Deletion or movement of user files
   requires an intentional user action.
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

## Antivirus interpretation

“Local-first” means file inspection and finding generation happen locally. A
user-triggered definition update is an optional network operation; it does not
send files for remote scanning. The current update integration is unavailable,
so bundled or manually imported local definitions are the usable paths in
version 0.2.0.

Local-first does not by itself mean complete or production-grade antivirus
protection. The product continues to identify itself as a prototype until its
scanner, definition trust, quarantine, packaging, and Windows acceptance gaps
are resolved.
