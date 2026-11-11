# Privacy Policy — AI-NTIVIR (AI Antivirus)

Last updated: 2026-11-11

AI-NTIVIR is an open-source antivirus prototype for Windows 10/11.
This policy describes what data the application handles. **Short version: the
application does not collect, transmit or sell any personal data.**

## What the application stores (locally, on your computer only)

| Data | Location | Purpose |
|---|---|---|
| Application & scan logs | `%LOCALAPPDATA%\AI-Antivirus\logs` and `%PROGRAMDATA%\AI_Antivirus\logs` | Diagnostics; log files are auto-cleaned after 24 hours |
| Quarantined files + quarantine database | `<install dir>\_internal\quarantine` | Files detected as threats, kept locally so they can be restored or analyzed |
| Learning / detection databases | install directory | Local detection state |

Nothing in these folders is uploaded anywhere by the application.

## Network access

The application performs **no telemetry** and makes **no analytics requests**.
Its only network activity is:

- **Signature database download**: the installer (and, as a fallback, the app)
  downloads the signature database (`signatures.db`) over HTTPS from the
  project's official mirror. No personal data is sent — this is a plain file
  download.

Remote upload features that exist as placeholders in the source code are
**disabled**: no log upload, no cloud sync, no threat-sharing occurs.

## Windows Defender / other antivirus interaction

AI-NTIVIR is itself an antivirus prototype. It does not read, modify or
disable any Windows security settings.

## Third parties

None. The project has no ads, no trackers and no third-party services.

## Contact

Questions about this policy: **info@krapulixai.com** or open an issue at
https://github.com/krapulax915/ai-ntivir

---

*Magyar összefoglaló: az alkalmazás nem gyűjt és nem küld személyes adatot.
Minden napló és karantén-adat kizárólag a saját gépeden marad; az egyetlen
hálózati művelet a szignatúradatbázis letöltése.*
