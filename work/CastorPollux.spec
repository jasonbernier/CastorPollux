# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from pathlib import Path

root = Path.cwd().resolve()
data = [
    (str(root / 'work/archives'), 'archives'),
    (str(root / 'work/runtime/node_modules'), 'runtime/node_modules'),
    (str(root / 'work/runtime/pnpm'), 'runtime/pnpm'),
    (str(root / 'work/scripts'), 'scripts'),
    (str(root / 'work/content'), 'content'),
    (str(root / 'work/assets'), 'assets'),
    (str(root / 'outputs/CastorPollux-Licenses'), 'credits/CastorPollux-Licenses'),
    (str(root / 'outputs/CastorPollux-CREDITS.md'), 'credits'),
] + collect_data_files('customtkinter') + collect_data_files('reportlab')

a = Analysis(
    [str(root / 'work/castorpollux.py')],
    pathex=[str(root / 'work')],
    binaries=[(str(root / 'work/runtime/node.exe'), 'runtime')],
    datas=data,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# pnpm's install metadata records the build machine's absolute workspace path.
# Node's runtime module resolution does not use this file.
a.datas = [item for item in a.datas
           if item[0].replace('\\', '/') != 'runtime/node_modules/.modules.yaml']
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='CastorPollux', debug=False, bootloader_ignore_signals=False,
    strip=False, upx=True, upx_exclude=[], runtime_tmpdir=None,
    console=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None, icon=str(root / 'work/assets/CastorPollux.ico'),
)
