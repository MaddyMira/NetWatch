"""
core/api_server.py
──────────────────
Lightweight local REST API server using only stdlib http.server.
No Flask, no extra dependencies.

Endpoints
─────────
  GET  /api/status          — all device status snapshots
  GET  /api/devices         — configured device list
  GET  /api/groups          — group list
  GET  /api/history?limit=N — last N ping log entries
  GET  /api/statistics      — uptime + perf aggregates
  GET  /api/alerts          — fired alert events
  GET  /health              — {"ok": true}
  GET  /metrics             — Prometheus text format (if enabled)
  POST /api/devices         — add device  {ip, name, group_id?, notes?}
  DELETE /api/devices/<ip>  — remove device by IP

All responses are JSON (UTF-8) unless the endpoint is /metrics.
CORS header `Access-Control-Allow-Origin: *` is set on every response
so browser dashboards can consume the API.

Usage
─────
    server = RestApiServer(ctx, host="127.0.0.1", port=8765)
    server.start()   # starts daemon thread
    server.stop()
    server.is_running()
"""
import json
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse, parse_qs

import core.database as db
from core.context import AppContext


# ── Prometheus text helpers ───────────────────────────────────────────────────

def _prometheus_metrics(ctx: AppContext) -> str:
    lines = []

    def metric(name, help_text, mtype, samples):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            lstr = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f'{name}{{{lstr}}} {value}')

    online  = [d for d in ctx.devices if ctx.device_status.get(d["ip"], {}).get("status") == "ONLINE"]
    offline = [d for d in ctx.devices if ctx.device_status.get(d["ip"], {}).get("status") == "OFFLINE"]

    metric("netwatch_device_online",
           "1 if device is currently online, 0 otherwise", "gauge",
           [
               ({"ip": d["ip"], "name": d["name"],
                 "group": d.get("group_name") or ""},
                1 if ctx.device_status.get(d["ip"], {}).get("status") == "ONLINE" else 0)
               for d in ctx.devices
           ])

    metric("netwatch_device_latency_ms",
           "Last measured round-trip latency in milliseconds", "gauge",
           [
               ({"ip": d["ip"], "name": d["name"]},
                float(ctx.device_status[d["ip"]]["latency"].replace("ms","").strip())
                if ctx.device_status.get(d["ip"], {}).get("latency","—") not in ("-","—","") else -1)
               for d in ctx.devices
               if d["ip"] in ctx.device_status
           ])

    metric("netwatch_devices_total",    "Total configured devices",        "gauge", [({}, len(ctx.devices))])
    metric("netwatch_devices_online",   "Devices currently online",        "gauge", [({}, len(online))])
    metric("netwatch_devices_offline",  "Devices currently offline",       "gauge", [({}, len(offline))])
    metric("netwatch_monitoring_active","1 if monitoring loop is running", "gauge",
           [({}, 1 if ctx.monitoring else 0)])

    lines.append("")
    return "\n".join(lines)


# ── Request handler ───────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):

    # Server sets this before starting
    ctx: AppContext = None
    enable_prometheus: bool = True

    def log_message(self, fmt, *args):
        pass   # suppress access log noise

    def _send(self, code: int, body: str, content_type: str = "application/json") -> None:
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(encoded)

    def _json(self, code: int, data) -> None:
        self._send(code, json.dumps(data, default=str), "application/json")

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            raw = self.rfile.read(length)
            try:
                return json.loads(raw)
            except Exception:
                pass
        return {}

    def do_OPTIONS(self):
        self._send(204, "")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)
        ctx    = self.ctx

        # Health
        if path == "/health":
            return self._json(200, {"ok": True, "ts": datetime.now().isoformat()})

        # Prometheus metrics
        if path == "/metrics":
            if not self.enable_prometheus:
                return self._json(404, {"error": "Prometheus endpoint disabled"})
            return self._send(200, _prometheus_metrics(ctx),
                              "text/plain; version=0.0.4")

        # REST API
        if path == "/api/status":
            return self._json(200, ctx.device_status)

        if path == "/api/devices":
            return self._json(200, ctx.devices)

        if path == "/api/groups":
            return self._json(200, ctx.groups)

        if path == "/api/history":
            limit = int(qs.get("limit", ["100"])[0])
            rows  = db.get_history(limit=limit)
            return self._json(200, rows)

        if path == "/api/statistics":
            stats = db.get_statistics()
            online  = sum(1 for s in ctx.device_status.values() if s["status"] == "ONLINE")
            offline = sum(1 for s in ctx.device_status.values() if s["status"] == "OFFLINE")
            stats["live"] = {"online": online, "offline": offline,
                             "total": len(ctx.devices),
                             "monitoring": ctx.monitoring}
            return self._json(200, stats)

        if path == "/api/alerts":
            limit = int(qs.get("limit", ["50"])[0])
            return self._json(200, db.get_alert_events(limit))

        if path == "/api/rules":
            import json as _j
            rules = db.get_alert_rules()
            for r in rules:
                if isinstance(r.get("channels"), str):
                    try:    r["channels"] = _j.loads(r["channels"])
                    except: r["channels"] = []
            return self._json(200, rules)

        self._json(404, {"error": f"Unknown endpoint: {path}"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        body   = self._read_body()
        ctx    = self.ctx

        if path == "/api/devices":
            ip   = (body.get("ip")   or "").strip()
            name = (body.get("name") or "").strip()
            if not ip or not name:
                return self._json(400, {"error": "ip and name required"})
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._json(400, {"error": f"Invalid IP: {ip}"})
            if any(d["ip"] == ip for d in ctx.devices):
                return self._json(409, {"error": f"Device {ip} already exists"})
            gid   = body.get("group_id")
            notes = body.get("notes", "")
            db.add_device(ip, name, group_id=int(gid) if gid else None, notes=notes)
            # Reload ctx.devices
            rows = db.get_devices()
            ctx.devices = [{"id": r["id"], "ip": r["ip"], "name": r["name"],
                            "group_id": r["group_id"], "group_name": r["group_name"],
                            "group_color": r["group_color"], "notes": r["notes"],
                            "mac": "", "vendor": ""} for r in rows]
            return self._json(201, {"ok": True, "ip": ip, "name": name})

        self._json(404, {"error": f"Unknown endpoint: {path}"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        ctx    = self.ctx

        m = re.match(r"^/api/devices/(.+)$", path)
        if m:
            ip  = m.group(1)
            dev = db.get_device_by_ip(ip)
            if not dev:
                return self._json(404, {"error": f"Device {ip} not found"})
            db.delete_device(dev["id"])
            ctx.devices = [d for d in ctx.devices if d["ip"] != ip]
            return self._json(200, {"ok": True, "removed": ip})

        self._json(404, {"error": f"Unknown endpoint: {path}"})


# ── Server wrapper ────────────────────────────────────────────────────────────

class RestApiServer:

    def __init__(self, ctx: AppContext,
                 host: str = "127.0.0.1",
                 port: int = 8765,
                 enable_prometheus: bool = True) -> None:
        self.ctx                = ctx
        self.host               = host
        self.port               = port
        self.enable_prometheus  = enable_prometheus
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if self._server:
            return False    # already running
        try:
            # Bind a fresh handler class with context injected
            class BoundHandler(_Handler):
                pass
            BoundHandler.ctx                = self.ctx
            BoundHandler.enable_prometheus  = self.enable_prometheus

            self._server = HTTPServer((self.host, self.port), BoundHandler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True, name="RestApiServer",
            )
            self._thread.start()
            print(f"[api_server] Listening on http://{self.host}:{self.port}")
            return True
        except OSError as e:
            print(f"[api_server] Could not bind {self.host}:{self.port} — {e}")
            self._server = None
            return False

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
            print("[api_server] Stopped")

    def is_running(self) -> bool:
        return self._server is not None

    def reconfigure(self, host: str, port: int,
                    enable_prometheus: bool) -> bool:
        was_running = self.is_running()
        if was_running:
            self.stop()
        self.host              = host
        self.port              = int(port)
        self.enable_prometheus = enable_prometheus
        if was_running:
            return self.start()
        return True
