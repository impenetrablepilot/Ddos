# shieldchain.spec
# PyInstaller build spec for ShieldChain.
# Bundles the Flask templates, trained models, and dataset as data files
# so the resulting .exe is fully self-contained.
#
# Build with:  pyinstaller shieldchain.spec

import sys
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hidden_imports = (
    collect_submodules("sklearn")
    + collect_submodules("joblib")
    + ["pandas", "numpy"]
)

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("templates", "templates"),
        ("models", "models"),
        ("data", "data"),
        ("ml", "ml"),
        ("blockchain", "blockchain"),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ShieldChain",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,   # keep a console window so the user can see server logs
    icon=None,      # put a path to a .ico file here if you have one
)
