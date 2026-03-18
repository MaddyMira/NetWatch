"""
core/database.py
────────────────
Single SQLite database for all persistent data.

Tables
──────
  groups    — device groups / tags (id, name, color)
  devices   — monitored hosts (id, ip, name, group_id, notes, created_at)
  ping_log  — time-series ping results (id, device_ip, device_name,
                                        status, latency_ms, checked_at)
  mac_cache — ARP-resolved MAC addresses (ip, mac, vendor, updated_at)

Thread safety
─────────────
Each call opens its own connection with check_same_thread=False and a
module-level lock, so background threads (monitor, ARP scan) are safe.
"""
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

_DB_PATH = "netwatch.db"
_lock    = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS groups (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT    NOT NULL UNIQUE,
    color   TEXT    NOT NULL DEFAULT '#00d4aa'
);

CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    group_id   INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    notes      TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
);

CREATE TABLE IF NOT EXISTS ping_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip   TEXT    NOT NULL,
    device_name TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    latency_ms  REAL,
    checked_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ping_ip   ON ping_log(device_ip);
CREATE INDEX IF NOT EXISTS idx_ping_time ON ping_log(checked_at);

CREATE TABLE IF NOT EXISTS mac_cache (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    vendor     TEXT,
    updated_at TEXT NOT NULL
);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Init
# ─────────────────────────────────────────────────────────────────────────────

def init(path: str = _DB_PATH) -> None:
    """Create the schema if it does not exist and set the active DB path."""
    global _DB_PATH
    _DB_PATH = path
    with _lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()


def migrate_from_json(devices_json: List[Dict]) -> None:
    """
    One-time import of a devices.json list into the SQLite devices table.
    Only inserts rows whose IP is not already present.
    """
    with _lock:
        conn = _connect()
        for d in devices_json:
            conn.execute(
                "INSERT OR IGNORE INTO devices(ip, name) VALUES(?,?)",
                (d.get("ip", ""), d.get("name", "")),
            )
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Groups
# ─────────────────────────────────────────────────────────────────────────────

def get_groups() -> List[Dict]:
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT id, name, color FROM groups ORDER BY name"
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def add_group(name: str, color: str = "#00d4aa") -> Dict:
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO groups(name, color) VALUES(?,?)", (name, color)
        )
        conn.commit()
        gid = cur.lastrowid
        conn.close()
    return {"id": gid, "name": name, "color": color}


def update_group(gid: int, name: str, color: str) -> bool:
    with _lock:
        conn = _connect()
        conn.execute(
            "UPDATE groups SET name=?, color=? WHERE id=?", (name, color, gid)
        )
        conn.commit()
        conn.close()
    return True


def delete_group(gid: int) -> bool:
    """Deletes the group; devices in it get group_id = NULL."""
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM groups WHERE id=?", (gid,))
        conn.commit()
        conn.close()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Devices
# ─────────────────────────────────────────────────────────────────────────────

def get_devices() -> List[Dict]:
    with _lock:
        conn = _connect()
        rows = conn.execute("""
            SELECT d.id, d.ip, d.name, d.group_id, d.notes, d.created_at,
                   d.poll_interval,
                   g.name  AS group_name,
                   g.color AS group_color
            FROM   devices d
            LEFT JOIN groups g ON d.group_id = g.id
            ORDER  BY d.id
        """).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def add_device(ip: str, name: str,
               group_id: Optional[int] = None,
               notes: str = "",
               poll_interval: Optional[int] = None) -> Dict:
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO devices(ip, name, group_id, notes, poll_interval) VALUES(?,?,?,?,?)",
            (ip, name, group_id, notes, poll_interval),
        )
        conn.commit()
        did = cur.lastrowid
        conn.close()
    return {"id": did, "ip": ip, "name": name,
            "group_id": group_id, "notes": notes, "poll_interval": poll_interval}


def update_device(did: int, ip: str, name: str,
                  group_id: Optional[int] = None,
                  notes: str = "",
                  poll_interval: Optional[int] = None) -> bool:
    with _lock:
        conn = _connect()
        conn.execute(
            "UPDATE devices SET ip=?, name=?, group_id=?, notes=?, poll_interval=? WHERE id=?",
            (ip, name, group_id, notes, poll_interval, did),
        )
        conn.commit()
        conn.close()
    return True


def delete_device(did: int) -> bool:
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM devices WHERE id=?", (did,))
        conn.commit()
        conn.close()
    return True


def get_device_by_ip(ip: str) -> Optional[Dict]:
    with _lock:
        conn = _connect()
        row = conn.execute(
            "SELECT id, ip, name, group_id, notes FROM devices WHERE ip=?", (ip,)
        ).fetchone()
        conn.close()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Ping log
# ─────────────────────────────────────────────────────────────────────────────

def log_ping(device_ip: str, device_name: str,
             status: str, latency_ms: Optional[float]) -> None:
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO ping_log(device_ip, device_name, status, latency_ms, checked_at)"
            " VALUES(?,?,?,?,?)",
            (device_ip, device_name, status, latency_ms, _now()),
        )
        conn.commit()
        conn.close()


def get_history(limit: int = 100,
                device_ip: Optional[str] = None) -> List[Dict]:
    """Return rows newest-first. limit=0 → all rows."""
    clause = "WHERE device_ip=?" if device_ip else ""
    params: tuple = (device_ip,) if device_ip else ()
    lim    = f"LIMIT {limit}" if limit > 0 else ""
    with _lock:
        conn = _connect()
        rows = conn.execute(
            f"SELECT checked_at, device_ip, device_name, status, latency_ms"
            f" FROM ping_log {clause}"
            f" ORDER BY id DESC {lim}",
            params,
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def clear_history() -> None:
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM ping_log")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='ping_log'")
        conn.commit()
        conn.close()


def get_statistics() -> Dict:
    """
    Returns per-device uptime % and latency metrics,
    plus overall summary counts.
    """
    with _lock:
        conn = _connect()

        # ── per-device uptime ──────────────────────────────────────────
        uptime_rows = conn.execute("""
            SELECT
                device_name                                              AS name,
                device_ip                                                AS ip,
                COUNT(*)                                                 AS total,
                SUM(CASE WHEN status='ONLINE' THEN 1 ELSE 0 END)        AS online_count,
                MAX(CASE WHEN status='ONLINE' THEN checked_at END)       AS last_seen,
                (SELECT status FROM ping_log p2
                 WHERE p2.device_ip=p.device_ip
                 ORDER BY p2.id DESC LIMIT 1)                            AS current_status
            FROM ping_log p
            GROUP BY device_ip
        """).fetchall()

        # ── per-device latency metrics ────────────────────────────────
        perf_rows = conn.execute("""
            SELECT
                device_name                 AS name,
                COUNT(*)                    AS total,
                SUM(CASE WHEN status='OFFLINE' THEN 1 ELSE 0 END) AS failed,
                AVG(latency_ms)             AS avg_lat,
                MIN(latency_ms)             AS min_lat,
                MAX(latency_ms)             AS max_lat
            FROM ping_log
            WHERE latency_ms IS NOT NULL
            GROUP BY device_ip
        """).fetchall()

        # ── totals ────────────────────────────────────────────────────
        total_entries = conn.execute(
            "SELECT COUNT(*) FROM ping_log"
        ).fetchone()[0]
        db_size_kb = conn.execute(
            "SELECT page_count*page_size/1024.0 FROM pragma_page_count(), pragma_page_size()"
        ).fetchone()[0]

        conn.close()

    uptime = []
    for r in uptime_rows:
        pct = round((r["online_count"] / max(r["total"], 1)) * 100, 1)
        uptime.append({
            "name":           r["name"],
            "ip":             r["ip"],
            "uptime_pct":     pct,
            "last_seen":      r["last_seen"] or "",
            "current_status": r["current_status"] or "UNKNOWN",
        })

    perf = []
    for r in perf_rows:
        loss = round((r["failed"] / max(r["total"] + r["failed"], 1)) * 100, 1)
        perf.append({
            "name":     r["name"],
            "avg":      round(r["avg_lat"], 1) if r["avg_lat"] is not None else None,
            "min":      round(r["min_lat"], 1) if r["min_lat"] is not None else None,
            "max":      round(r["max_lat"], 1) if r["max_lat"] is not None else None,
            "loss_pct": loss,
        })

    return {
        "uptime":        uptime,
        "perf":          perf,
        "total_entries": total_entries,
        "db_size_kb":    round(db_size_kb, 1),
    }


def get_rolling_packet_loss(device_ip: str, window: int = 20) -> float:
    """
    Compute real packet-loss % over the last *window* ping entries for *device_ip*.
    Returns a float 0.0–100.0.
    """
    with _lock:
        conn = _connect()
        row = conn.execute("""
            SELECT
                COUNT(*)                                            AS total,
                SUM(CASE WHEN status='OFFLINE' THEN 1 ELSE 0 END)  AS failed
            FROM (
                SELECT status FROM ping_log
                WHERE  device_ip = ?
                ORDER  BY id DESC
                LIMIT  ?
            )
        """, (device_ip, window)).fetchone()
        conn.close()
    if not row or not row["total"]:
        return 0.0
    return round((row["failed"] / row["total"]) * 100.0, 1)


def get_latency_series(device_ip: str, limit: int = 60) -> List[Dict]:
    """Last *limit* latency readings for a single device (oldest first)."""
    with _lock:
        conn = _connect()
        # Use a CTE so we can re-sort the newest-N rows by id ascending.
        # Avoids referencing rowid on a derived table (which SQLite disallows).
        rows = conn.execute("""
            WITH recent AS (
                SELECT id, checked_at, latency_ms, status
                FROM   ping_log
                WHERE  device_ip = ?
                ORDER  BY id DESC
                LIMIT  ?
            )
            SELECT checked_at, latency_ms, status
            FROM   recent
            ORDER  BY id ASC
        """, (device_ip, limit)).fetchall()
        conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# MAC cache
# ─────────────────────────────────────────────────────────────────────────────

def get_mac(ip: str) -> Optional[Dict]:
    with _lock:
        conn = _connect()
        row = conn.execute(
            "SELECT ip, mac, vendor, updated_at FROM mac_cache WHERE ip=?", (ip,)
        ).fetchone()
        conn.close()
    return dict(row) if row else None


def set_mac(ip: str, mac: str, vendor: str) -> None:
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO mac_cache(ip, mac, vendor, updated_at)"
            " VALUES(?,?,?,?)",
            (ip, mac.upper(), vendor, _now()),
        )
        conn.commit()
        conn.close()


def get_all_macs() -> List[Dict]:
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT ip, mac, vendor, updated_at FROM mac_cache ORDER BY ip"
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Visualisation queries
# ─────────────────────────────────────────────────────────────────────────────

def get_uptime_calendar(device_ip: str, days: int = 84) -> List[Dict]:
    """
    Daily uptime % for the last *days* days for *device_ip*.

    Returns a list of dicts ordered by date ascending:
        {date, total, online, pct}

    Gaps (days with no data) are filled with {date, total:0, online:0, pct:None}
    so the heatmap always renders a full grid.
    """
    from datetime import date, timedelta

    with _lock:
        conn = _connect()
        rows = conn.execute("""
            SELECT
                date(checked_at)                                        AS day,
                COUNT(*)                                                AS total,
                SUM(CASE WHEN status='ONLINE' THEN 1 ELSE 0 END)       AS online
            FROM ping_log
            WHERE device_ip = ?
              AND checked_at >= date('now', ? || ' days')
            GROUP BY day
            ORDER BY day
        """, (device_ip, f"-{days}")).fetchall()
        conn.close()

    # Build a map so we can fill gaps
    data_map = {}
    for r in rows:
        pct = round((r["online"] / max(r["total"], 1)) * 100, 1)
        data_map[r["day"]] = {"date": r["day"], "total": r["total"],
                               "online": r["online"], "pct": pct}

    today   = date.today()
    result  = []
    for i in range(days - 1, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        result.append(data_map.get(d, {"date": d, "total": 0, "online": 0, "pct": None}))

    return result


def get_hourly_packet_loss(device_ip: str, hours: int = 48) -> List[Dict]:
    """
    Hourly packet-loss % for the last *hours* hours for *device_ip*.

    Returns rows ordered by hour ascending:
        {hour, total, failed, loss_pct}
    """
    from datetime import datetime, timedelta

    with _lock:
        conn = _connect()
        rows = conn.execute("""
            SELECT
                strftime('%Y-%m-%d %H:00', checked_at)                 AS hour,
                COUNT(*)                                                AS total,
                SUM(CASE WHEN status='OFFLINE' THEN 1 ELSE 0 END)      AS failed
            FROM ping_log
            WHERE device_ip = ?
              AND checked_at >= datetime('now', ? || ' hours')
            GROUP BY hour
            ORDER BY hour
        """, (device_ip, f"-{hours}")).fetchall()
        conn.close()

    data_map = {}
    for r in rows:
        loss = round((r["failed"] / max(r["total"], 1)) * 100, 1)
        data_map[r["hour"]] = {"hour": r["hour"], "total": r["total"],
                                "failed": r["failed"], "loss_pct": loss}

    now    = datetime.now()
    result = []
    for i in range(hours - 1, -1, -1):
        h = (now - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        result.append(data_map.get(h, {"hour": h, "total": 0, "failed": 0, "loss_pct": 0.0}))

    return result


def get_all_devices_latency_latest(limit_per_device: int = 60) -> List[Dict]:
    """Per-device last N readings — CTE approach, no window functions."""
    with _lock:
        conn = _connect()
        ips = [r[0] for r in conn.execute(
            "SELECT DISTINCT device_ip FROM ping_log"
        ).fetchall()]
        all_rows = []
        for ip in ips:
            rows = conn.execute("""
                WITH recent AS (
                    SELECT id, device_ip, device_name, checked_at, latency_ms, status
                    FROM   ping_log
                    WHERE  device_ip = ?
                    ORDER  BY id DESC
                    LIMIT  ?
                )
                SELECT device_ip, device_name, checked_at, latency_ms, status
                FROM   recent
                ORDER  BY id ASC
            """, (ip, limit_per_device)).fetchall()
            all_rows.extend([dict(r) for r in rows])
        conn.close()
    return all_rows


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Alerts & Automation
# ─────────────────────────────────────────────────────────────────────────────

_ALERT_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    device_ip   TEXT,           -- NULL = applies to all devices
    rule_type   TEXT    NOT NULL,  -- 'offline', 'latency_gt', 'packet_loss_gt', 'online'
    threshold   REAL,           -- ms or %, depends on rule_type
    duration_s  INTEGER NOT NULL DEFAULT 0,  -- must persist for N seconds to fire
    enabled     INTEGER NOT NULL DEFAULT 1,
    channels    TEXT    NOT NULL DEFAULT '[]',  -- JSON list: ['toast','sound','email','webhook','discord']
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
);

CREATE TABLE IF NOT EXISTS alert_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
    rule_name   TEXT    NOT NULL,
    device_ip   TEXT    NOT NULL,
    device_name TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    fired_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_events_time ON alert_events(fired_at);

CREATE TABLE IF NOT EXISTS notification_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

def init_alert_schema() -> None:
    """Create alert tables — called from main.py after db.init()."""
    with _lock:
        conn = _connect()
        conn.executescript(_ALERT_SCHEMA)
        conn.commit()
        # Safe migration: add poll_interval column if the schema predates it
        try:
            conn.execute(
                "ALTER TABLE devices ADD COLUMN poll_interval INTEGER DEFAULT NULL"
            )
            conn.commit()
        except Exception:
            pass   # column already exists
        conn.close()

# ── Alert rules ───────────────────────────────────────────────────────────────

def get_alert_rules() -> List[Dict]:
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM alert_rules ORDER BY id"
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]

def add_alert_rule(name: str, device_ip: Optional[str], rule_type: str,
                   threshold: Optional[float], duration_s: int,
                   channels: List[str]) -> Dict:
    import json as _json
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO alert_rules(name,device_ip,rule_type,threshold,duration_s,channels)"
            " VALUES(?,?,?,?,?,?)",
            (name, device_ip, rule_type, threshold, duration_s,
             _json.dumps(channels)),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
    return {"id": rid, "name": name, "device_ip": device_ip,
            "rule_type": rule_type, "threshold": threshold,
            "duration_s": duration_s, "channels": channels, "enabled": 1}

def update_alert_rule(rid: int, name: str, device_ip: Optional[str],
                      rule_type: str, threshold: Optional[float],
                      duration_s: int, channels: List[str],
                      enabled: bool = True) -> bool:
    import json as _json
    with _lock:
        conn = _connect()
        conn.execute(
            "UPDATE alert_rules SET name=?,device_ip=?,rule_type=?,threshold=?,"
            "duration_s=?,channels=?,enabled=? WHERE id=?",
            (name, device_ip, rule_type, threshold, duration_s,
             _json.dumps(channels), 1 if enabled else 0, rid),
        )
        conn.commit()
        conn.close()
    return True

def delete_alert_rule(rid: int) -> bool:
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
        conn.commit()
        conn.close()
    return True

def toggle_alert_rule(rid: int, enabled: bool) -> bool:
    with _lock:
        conn = _connect()
        conn.execute("UPDATE alert_rules SET enabled=? WHERE id=?",
                     (1 if enabled else 0, rid))
        conn.commit()
        conn.close()
    return True

# ── Alert events (fire log) ───────────────────────────────────────────────────

def log_alert_event(rule_id: int, rule_name: str, device_ip: str,
                    device_name: str, message: str) -> None:
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO alert_events(rule_id,rule_name,device_ip,device_name,message,fired_at)"
            " VALUES(?,?,?,?,?,?)",
            (rule_id, rule_name, device_ip, device_name, message, _now()),
        )
        # Keep only last 500 events
        conn.execute(
            "DELETE FROM alert_events WHERE id NOT IN "
            "(SELECT id FROM alert_events ORDER BY id DESC LIMIT 500)"
        )
        conn.commit()
        conn.close()

def get_alert_events(limit: int = 100) -> List[Dict]:
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM alert_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]

def clear_alert_events() -> None:
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM alert_events")
        conn.commit()
        conn.close()

# ── Notification config ───────────────────────────────────────────────────────

def get_notif_config() -> Dict[str, str]:
    with _lock:
        conn = _connect()
        rows = conn.execute("SELECT key, value FROM notification_config").fetchall()
        conn.close()
    return {r["key"]: r["value"] for r in rows}

def set_notif_config(key: str, value: str) -> None:
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO notification_config(key,value) VALUES(?,?)",
            (key, value),
        )
        conn.commit()
        conn.close()

def set_notif_config_bulk(data: Dict[str, str]) -> None:
    with _lock:
        conn = _connect()
        for k, v in data.items():
            conn.execute(
                "INSERT OR REPLACE INTO notification_config(key,value) VALUES(?,?)",
                (k, str(v)),
            )
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Device ordering
# ─────────────────────────────────────────────────────────────────────────────

def set_device_order(device_id: int, order_index: int) -> None:
    """
    Persist the display order for a device.
    Silently adds the order_index column if the schema predates Phase 5.
    """
    with _lock:
        conn = _connect()
        # Add column if missing (safe migration)
        try:
            conn.execute("ALTER TABLE devices ADD COLUMN order_index INTEGER DEFAULT 0")
            conn.commit()
        except Exception:
            pass   # column already exists
        conn.execute(
            "UPDATE devices SET order_index=? WHERE id=?",
            (order_index, device_id),
        )
        conn.commit()
        conn.close()


def get_devices_ordered() -> List[Dict]:
    """Return devices sorted by order_index, falling back to id."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("""
                SELECT d.id, d.ip, d.name, d.group_id, d.notes,
                       d.created_at, d.poll_interval,
                       COALESCE(d.order_index, d.id) AS sort_key,
                       g.name  AS group_name,
                       g.color AS group_color
                FROM   devices d
                LEFT JOIN groups g ON d.group_id = g.id
                ORDER  BY sort_key
            """).fetchall()
        except Exception:
            # Fallback if order_index column doesn't exist yet
            rows = conn.execute("""
                SELECT d.id, d.ip, d.name, d.group_id, d.notes,
                       d.created_at, d.poll_interval,
                       g.name  AS group_name,
                       g.color AS group_color
                FROM   devices d
                LEFT JOIN groups g ON d.group_id = g.id
                ORDER  BY d.id
            """).fetchall()
        conn.close()
    return [dict(r) for r in rows]