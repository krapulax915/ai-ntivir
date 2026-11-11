# SignPath Foundation — ingyenes kódaláíró tanúsítvány jelentkezés

> Cél: a teszt-tanúsítvány (2026-11-17-én lejár) helyett **valódi, CA által kiadott,
> megbízható láncú** kódaláíró tanúsítvány — nyílt forráskódú projekteknek INGYENES.
> Elbírálás: jellemzően 1–2 hét. Évente megújítható, amíg a projekt nyílt forráskódú és aktív.

## Lépések

1. Nyisd meg: **https://signpath.org** → *Open Source* / Foundation oldal → **"Apply for a certificate"** (vagy a megadott jelentkezési e-mail címre küldd el az alábbi adatokat).
2. Az űrlapon/levélben add meg az alábbi **"Application data"** blokk tartalmát (angolul, készre írt).
3. A jóváhagyás után a SignPath fiókodban megjelenik a Foundation tanúsítvány + hozzá tartozó **Signing Policy**.
4. Itt a repóban: hozz létre (vagy válaszd ki) a **Project**-et (`AI-NTIVIR`), kösd hozzá a Foundation policy-t, és töltsd ki az `installer/signpath_config.json`-t (ApiToken, OrganizationId, ProjectId, SigningPolicyId).
5. Ezután `installer\build_installer.bat` → a build végén automatikus aláírás, vagy kézzel: `powershell -ExecutionPolicy Bypass -File installer\sign_with_signpath.ps1 -File "installer\output\AI-NTIVIR-Setup-<verzió>.exe"` (nyers .exe, ne ZIP!).

---

## Application data (kész szöveg — másold be az űrlapba)

```
Project name: AI-NTIVIR (AI Antivirus)

Source repository: https://github.com/krapulix915/ai-ntivir

License: MIT (https://github.com/krapulax915/ai-ntivir/blob/main/LICENSE)

Public description:
AI-NTIVIR is an open-source antivirus prototype for Windows 10/11, written in
Python 3.10 with a PyQt5 GUI. It combines a 559k-entry hash signature database,
heuristic analysis, an ONNX-based AI classifier, real-time protection
(watchdog-based monitoring of user folders with automatic quarantine), a
 Enhanced Quick Scan of critical system areas, and a self-updating signature
database. The project ships as a signed Windows installer built with PyInstaller
and Inno Setup; all source code, build scripts and development history are
public in the repository.

Why code signing is needed:
The project distributes Windows installers to beta testers. Unsigned binaries
trigger SmartScreen warnings and are prone to delayed false-positive flags by
antivirus vendors (this already happened to an earlier unsigned build).
A trusted code-signing certificate would let testers verify the publisher,
and would establish signer reputation with antivirus vendors for future
releases. The project already integrates the SignPath REST API for artifact
signing and has been validated end-to-end with a test certificate.

Signing use: signing of Windows installers (PE executables) released from the
public GitHub repository above. Files are signed manually per release through
the SignPath web UI or the SignPath REST API.

Maintainer: Daniel Bozsik (Krapulix Soft)
Country: Hungary
E-mail: info@krapulixai.com / info@krapulixai.com
GitHub account: krapulax915

VirusTotal for the current release: 47/47 engines clean
(no vendor flagged the file as malicious)
```

---

## Jóváhagyás után (ellenőrzőlista)

- [ ] SignPath org: Project létrehozása (pl. `AI-NTIVIR`), artifact-configuration: `<pe-file><authenticode-sign /></pe-file>`
- [ ] Signing Policy: a Foundation policy hozzárendelése a projekthez
- [ ] `installer/signpath_config.json` kitöltése (ApiToken, OrganizationId, ProjectId, SigningPolicyId)
- [ ] Teszt: `sign_with_signpath.ps1` egy buildre → `Get-AuthenticodeSignature` = **Valid** (nem UnknownError)
- [ ] Régi tesztcert (2026-11-17-ig érvényes) nyugdíjba vonása
