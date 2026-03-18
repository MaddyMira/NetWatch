"""
core/context.py
───────────────
Central shared-state object passed to every component.
No I/O — pure data + a reference to the Database instance.
"""
from typing import Any, Dict, List, Optional

DEFAULT_SETTINGS: Dict[str, Any] = {
    'monitor_interval': 10,
    'ping_timeout': 3,
    'max_retries': 2,
    'theme': 'dark',
    'auto_save': True,
}

DEFAULT_DEVICES: List[Dict] = [
    {"ip": "8.8.8.8",     "name": "Google DNS"},
    {"ip": "1.1.1.1",     "name": "Cloudflare DNS"},
    {"ip": "192.168.1.1", "name": "Router"},
]


class AppContext:
    """Single source of truth for the entire application."""

    def __init__(self) -> None:
        self.devices: List[Dict] = []
        self.groups:  List[Dict] = []      # {id, name, color}
        self.settings: Dict[str, Any] = dict(DEFAULT_SETTINGS)
        # ip -> {name, status, latency, last_check, group_name, group_color}
        self.device_status: Dict[str, Dict] = {}
        self.device_history: Dict[str, Dict] = {}
        self.notification_enabled: bool = True
        self.monitoring: bool = False
        self.db = None   # set to Database instance in main.py