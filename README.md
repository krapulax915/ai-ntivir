# AI-NTIVIR (AI Antivirus) — BETA

[![Build AI-NTIVIR installer](https://github.com/krapulax915/ai-ntivir/actions/workflows/build.yml/badge.svg)](https://github.com/krapulax915/ai-ntivir/actions/workflows/build.yml)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-0%2F64%20engines%20clean-brightgreen)](https://www.virustotal.com/gui/file/bf38769c6d012f46c82540d3a1ac6d79352f9773d36ffefcbe47b01371ebb839)

Windows-alapú, Python 3.10 + PyQt5 fejlesztésű antivírus prototípus beépített AI-modellel.
Python-based antivirus prototype with an onboard AI model (ONNX), for Windows 10/11.

> ⚠️ **BETA / oktatási célú prototípus.** Nem helyettesíti a kereskedelmi vírusirtókat.
> Valós idejű védelem tesztelése csak saját felelősségre, tesztgépen.

## Funkciók / Features

- **Többrétegű detektálás**: SHA-256/MD5/SHA-1 szignatúradb (~559 ezer bejegyzés, `signatures/signatures.db`), heurisztikus-entópia és PE-elemzés, ONNX AI-osztályozó (`models/virus_detection_balanced.onnx`), anomália-detektálás
- **Enhanced Quick Scan** (Dashboard és Scan tab): startup registry, rendszerkönyvtárak (mélységkorlátozva), autorun helyek, memóriafolyamatok, böngésző- és temp-könyvtárak — 5 perces kereten belül
- **Real-time protection**: watchdog-alapú fájlfigyelés (Downloads/Desktop/Documents/Temp), Score-alapú automatikus karantén (EICAR-teszt is), tálca-ikon és állapotjelzés
- **Karantén**: teljes tartalommal helyezi át a fájlokat (méret-ellenőrzött copy+delete), SQLite nyilvántartás, visszaállítás/törlés
- **GUI**: PyQt5, Dashboard/Scan/Quarantine/Protection tabok, tálca menü, felugró figyelmeztetés ha a védelem kikapcsol

## Telepítés forrásból / Run from source

```bat
py -3.10 -m pip install -r requirements.txt
py -3.10 main.py --gui --show-gui
```

Szükséges csomagok: PyQt5, numpy, scikit-learn, psutil, watchdog, requests, onnxruntime (opcionális).

## Telepítő / Installer

Lásd `installer/` — PyInstaller + Inno Setup alapú .exe telepítő Windows 10/11-re
(`installer/build_installer.bat`). Az AI-NTIVIR.exe és a telepítő kódaláírt (SignPath).

### Letöltés / Downloads

**[Releases oldal](https://github.com/krapulax915/ai-ntivir/releases)** — itt érhetők el az
aláírt telepítők.

> 🔏 **Code signing: this project uses the [SignPath Foundation](https://signpath.org) for code signing.**
> (A projekt a SignPath Foundation programjának ingyenes, nyílt forráskódú kódaláíró tanúsítványát használja.)
> Privacy policy: [PRIVACY.md](PRIVACY.md)
> VirusTotal (latest signed release, 64 engines): **0 detections** —
> https://www.virustotal.com/gui/file/bf38769c6d012f46c82540d3a1ac6d79352f9773d36ffefcbe47b01371ebb839

A telepítő a **signatures.db-t (180 MB) telepítés közben tölti le** a hivatalos
tükörről, így a telepítőfájl kicsi marad. Internetkapcsolat szükséges a telepítéshez.

**Hivatalos szignatúra-adatbázis tükör (kézi letöltés):**
<https://files.catbox.moe/lkjqct.db>
sha256: `9e890c7177d5ccf307c3d3e4f410bc20b51cd10ad8651f33c951b3ca6b54de4b`
Helye a telepítés után: `C:\Program Files\AI-NTIVIR\signatures\signatures.db`
(app indításkor magától letölti, ha hiányzik)

## Projektstruktúra

```
main.py                     belépési pont (GUI/tray mód)
enhanced_quick_scan_system.py  Enhanced Quick Scan motor
log_management_system.py    naplózás (PROGRAMDATA\AI_Antivirus\logs)
src/core/                   AI engine, file monitor, karantén
src/detection/              szignatúra-, heurisztika-, anomália-motorok
src/protection/             valós idejű védelem, böngészővédelem
src/gui/                    PyQt5 felület
models/                     ONNX modellek + scalerek
signatures/                 signatures.db (Git LFS + telepítéskori letöltés)
docs/                       fejlesztési dokumentáció (HU)
tests/, tools/              tesztek és smoke-check
```

## Licenc

MIT — lásd `LICENSE`.
