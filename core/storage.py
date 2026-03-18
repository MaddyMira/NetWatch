"""
core/storage.py
───────────────
Settings only — persisted as JSON.
Devices, groups, ping log, and MAC cache now live in SQLite (core/database.py).
"""
import json
import os
from typing import Optional

from core.context import AppContext

SETTINGS_FILE = "gui_settings.json"


def load_settings(ctx: AppContext) -> None:
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                ctx.settings.update(json.load(f))
    except Exception as e:
        print(f"[storage] Could not load settings: {e}")


def save_settings(ctx: AppContext) -> None:
    if not ctx.settings.get('auto_save', True):
        return
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(ctx.settings, f, indent=2)
    except Exception as e:
        print(f"[storage] Could not save settings: {e}")


def export_config(ctx: AppContext, path: str) -> None:
    import core.database as db
    payload = {
        'settings': ctx.settings,
        'groups':   db.get_groups(),
        'devices':  db.get_devices(),
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)


def import_config(ctx: AppContext, path: str) -> None:
    import core.database as db
    with open(path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    ctx.settings.update(cfg.get('settings', {}))
    # Re-import groups then devices
    for g in cfg.get('groups', []):
        try:
            db.add_group(g['name'], g.get('color', '#00d4aa'))
        except Exception:
            pass
    for d in cfg.get('devices', []):
        try:
            db.add_device(d['ip'], d['name'],
                          group_id=d.get('group_id'),
                          notes=d.get('notes', ''))
        except Exception:
            pass
    ctx.devices = [{'ip': d['ip'], 'name': d['name'],
                    'id': d['id'], 'group_id': d.get('group_id'),
                    'group_name': d.get('group_name'), 'group_color': d.get('group_color'),
                    'notes': d.get('notes', '')}
                   for d in db.get_devices()]
    ctx.groups = db.get_groups()