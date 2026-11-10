# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for AI-NTIVIR (AI Antivirus) - Windows 10/11
# Build:  pyinstaller installer\AI-NTIVIR.spec --noconfirm
# Result: installer\dist\AI-NTIVIR\  (folder with AI-NTIVIR.exe)

import os

block_cipher = None

app_root = os.path.abspath(os.path.join(SPECPATH, '..'))

a = Analysis(
    ['..\\main.py'],
    pathex=[app_root],
    binaries=[],
    datas=[
        # Application source tree (imported at runtime via sys.path)
        ('..\\src', 'src'),
        # Config + AI models + signature database
        ('..\\config', 'config'),
        ('..\\models', 'models'),
        ('..\\signatures\\signatures.db', 'signatures'),
        ('..\\config.json', '.'),
        ('..\\requirements.txt', '.'),
        ('..\\LICENSE', '.'),
        ('..\\README.md', '.'),
    ],
    hiddenimports=[
        # Modules imported dynamically (not visible to static analysis)
        'enhanced_quick_scan_system',
        'log_management_system',
        'src.gui.analytics_dashboard',
        'src.gui.auto_tuning_panel',
        'src.gui.behavioral_analysis_panel',
        'src.gui.browser_protection_tab',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # NOT used at runtime - keeps the bundle small (torch alone is >1 GB)
        'torch',
        'torchvision',
        'torchaudio',
        'matplotlib',
        'pytest',
        'IPython',
        'jedi',
        'tkinter',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AI-NTIVIR',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # GUI app - no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='AI-NTIVIR',
)
