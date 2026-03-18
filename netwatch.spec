# netwatch.spec
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        # Bundle the entire ui/ folder
        ('ui/index.html', 'ui'),
        # If you ever add assets (icons, sounds), add them here too
        # ('assets/', 'assets'),
    ],
    hiddenimports=[
        # pywebview backends — include all so it works on any machine
        'webview.platforms.cocoa',      # macOS
        'webview.platforms.gtk',        # Linux GTK
        'webview.platforms.qt',         # Linux Qt fallback
        # ping3 uses raw sockets internally
        'ping3',
        # Your own packages
        'core.database',
        'core.alerts',
        'core.api_server',
        'core.arp',
        'core.context',
        'core.dns_tools',
        'core.monitor',
        'core.network',
        'core.portscan',
        'core.resolver',
        'core.storage',
        'core.traceroute',
        'core.wol',
        'api.bridge',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim fat you don't need
        'tkinter', 'unittest', 'xmlrpc',
        'pydoc', 'doctest', 'difflib',
    ],
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
    name='NETWATCH',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,            # compress — requires UPX installed (optional)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,       # no terminal window
    # icon='assets/netwatch.ico',  # uncomment if you have an icon
    onefile=True,        # single .exe
)
