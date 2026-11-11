# Vírusirtó-gyártói engedélyezési (allowlist) kérelmek

> Cél: **megelőzni** a késleltetett hamis pozitívokat (a korábbi tanúsítvány nélküli
> verzióra hetekkel a VT-feltöltés után riasztottak 5 nagy motor). A kérelmeket
> érdemes **most, a riasztások előtt** beadni, és minden jelentősebb verziónál megismételni
> az új hash-sel.

## Kitöltendő adatok (aktuális release)

| Mező | Érték |
|---|---|
| Fájl | `AI-NTIVIR-Setup-1.0.5.exe` |
| SHA256 | `a66fc57fc4e6ebb899f8ca90f3678396ffa8630b26903c095d519de5f6397ed2` |
| Méret | 137 729 603 bájt |
| Aláíró | CN=Daniel Bozsik, O=Krapulix Soft (önaláírt tesztcert; SignPath Foundation kérelem folyamatban) |
| Típus | Windows installer (Inno Setup) — PyInstaller csomagolt Python-alkalmazás |
| Forráskód | https://github.com/krapulix915/ai-ntivir (MIT) |
| VirusTotal | 47/47 motor tiszta *(ide illeszd be a saját VT-linket)* |

**Megjegyzés**: miután megjött a SignPath Foundation tanúsítvány, az **aláírt** fájl
új SHA256-ával **ismételd meg** a kérelmeket — az aláírt build whitelistelése a
későbbi verziókra is kiterjed (aláíró-szintű engedélyezés).

---

## Egyetemes kérelem-szöveg (angol — másold be a gyártói űrlapba)

```
Subject: Allowlist request — AI-NTIVIR open-source antivirus installer (false positive prevention)

Hello,

We are the developers of AI-NTIVIR, an open-source antivirus prototype for
Windows 10/11 (MIT license). We kindly request that the following installer
be allowlisted before distribution, to prevent heuristic false positives:

File name:        AI-NTIVIR-Setup-1.0.5.exe
SHA256:           a66fc57fc4e6ebb899f8ca90f3678396ffa8630b26903c095d519de5f6397ed2
Size:             137,729,603 bytes
Type:             Inno Setup installer (PyInstaller-bundled Python 3.10 application)
Code signature:   CN=Daniel Bozsik, O=Krapulix Soft (self-signed test certificate;
                  application for a SignPath Foundation open-source certificate in progress)
Source code:      https://github.com/krapulix915/ai-ntivir (public, MIT license)
VirusTotal:       47/47 engines clean — no vendor flagged the file as malicious
                  (<paste your VT analysis link here>)

Intended behavior of the application (why it looks "antivirus-like"):
- Monitors user folders (Downloads, Desktop, Documents, Temp) with a watchdog
- Reads files and computes SHA256/MD5/SHA1 hashes against a LOCAL signature
  database (559,456 entries, bundled SQLite file)
- Moves detected test files (e.g. EICAR) into a local quarantine folder
  (ProgramData / install-dir\quarantine)
- Writes logs to %LOCALAPPDATA%\AI-Antivirus\logs and %PROGRAMDATA%\AI_Antivirus\logs
- Does NOT modify Windows Defender settings, does NOT inject into processes,
  does NOT contain any network telemetry (the only network access is an optional
  signature-database download from a fixed HTTPS mirror)

The file is intentionally a defensive security tool, not malware. Any detection
of this installer is a false positive.

Requested action: allowlist this file (and future builds signed with the same
certificate) in your detection systems.

Contact: Daniel Bozsik — info@ai-ntivir.eu — https://github.com/krapulax915/ai-ntivir

Thank you!
```

---

## Hová nyújtsd be (a legfontosabb gyártók)

| Gyártó | Beküldési pont |
|---|---|
| **Microsoft** (Defender + SmartScreen) | https://www.microsoft.com/en-us/wdsi/filesubmission → *Software developer* → „Request a change / allowlist" — ez a legfontosabb (SmartScreen-reputáció) |
| **Kaspersky** | https://opentip.kaspersky.com/ → *False positive* fül |
| **ESET** | ESET Support → Virus/False positive sample submission (support.eset.com) |
| **Bitdefender** | Bitdefender Support → False positive bejelentés (bitdefender.com → Support) |
| **Avast / AVG** | Avast FP file submission űrlap (avast.com → Support → False positive) |
| **Malwarebytes** | support.malwarebytes.com → False positive bejelentés |

*Tipp*: az űrlapoknál mindig válaszd a **„Software developer / false positive /
allowlist request"** kategóriát (nem a felhasználói bejelentést) — gyorsabb és
tartósabb engedélyezést ad.

---

## Frissítési ritmus

1. Most: az 1.0.5-ös (aláírt) telepítőre beadni mindenkinek.
2. Az elkövetkező **4–6 hétben hetente** VirusTotal → *Re-scan* — ha bármelyik motor váltana, azonnal FP-kérelem annak a motornak.
3. Minden új verzió: új kérelem az új SHA256-hossal **ugyanazzal az aláíróval** (a Foundation certtel az aláíró-szintű whitelist felhalmozódik).
