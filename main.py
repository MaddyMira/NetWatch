#!/usr/bin/env python3
"""
main.py — NETWATCH entry point
Run: python main.py
Requires: pip install pywebview ping3
"""
import os, sys

missing = []
try:    import webview
except ImportError: missing.append("pywebview  (pip install pywebview)")
try:    from ping3 import ping
except ImportError: missing.append("ping3      (pip install ping3)")
if missing:
    print("Missing dependencies:\n  " + "\n  ".join(missing)); sys.exit(1)

import core.database as db
import core.storage  as storage
from core.context  import AppContext, DEFAULT_DEVICES
from core.monitor  import MonitorEngine
from core.alerts   import AlertEngine
from api.bridge    import Api

def resource_path(relative: str) -> str:
    """Works both in dev (normal __file__) and in a PyInstaller bundle."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)

# ── Init SQLite ───────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "netwatch.db")
db.init(DB_PATH)
db.init_alert_schema()

# ── One-time migration ────────────────────────────────────────────────────────
_old_json = os.path.join(os.path.dirname(__file__), "devices.json")
if os.path.exists(_old_json) and not db.get_devices():
    import json
    try:
        with open(_old_json) as f:
            db.migrate_from_json(json.load(f))
        print("[main] Migrated devices.json → SQLite")
    except Exception as e:
        print(f"[main] Migration warning: {e}")

if not db.get_devices():
    for d in DEFAULT_DEVICES:
        db.add_device(d["ip"], d["name"])

# ── App context ───────────────────────────────────────────────────────────────
ctx    = AppContext()
ctx.db = db
storage.load_settings(ctx)

_rows = db.get_devices_ordered()          # Phase 5: use ordered query
ctx.devices = [{"id": r["id"], "ip": r["ip"], "name": r["name"],
                "group_id": r["group_id"], "group_name": r["group_name"],
                "group_color": r["group_color"], "notes": r["notes"],
                "poll_interval": r.get("poll_interval"),
                "mac": "", "vendor": ""} for r in _rows]
ctx.groups = db.get_groups()

# ── Wire components ───────────────────────────────────────────────────────────
api          = Api(ctx)
engine       = MonitorEngine(ctx=ctx, on_update=api.push_status_update,
                             on_status_change=api.push_notification)
alert_engine = AlertEngine(ctx=ctx, push_fn=api._push)
engine.alert_engine = alert_engine
api.set_engine(engine)
api.set_alert_engine(alert_engine)

# ── Auto-start REST API if previously enabled ─────────────────────────────────
_api_cfg = db.get_notif_config()    # reuse notification_config table for API settings
if _api_cfg.get("api_server_enabled") == "1":
    from core.api_server import RestApiServer
    _host  = _api_cfg.get("api_server_host", "127.0.0.1")
    _port  = int(_api_cfg.get("api_server_port", "8765"))
    _prom  = _api_cfg.get("api_server_prometheus", "1") == "1"
    _srv   = RestApiServer(ctx, host=_host, port=_port, enable_prometheus=_prom)
    _srv.start()
    api._rest_server = _srv

# ── Window ────────────────────────────────────────────────────────────────────
UI_PATH = resource_path(os.path.join("ui", "index.html"))
window  = webview.create_window(
    title="NETWATCH", url=f"file://{UI_PATH}", js_api=api,
    width=1380, height=880, min_size=(980, 660), background_color="#06080e",
)
api.set_window(window)
window.events.loaded += lambda: api.on_ready()

if __name__ == "__main__":
    webview.start(debug="--debug" in sys.argv)