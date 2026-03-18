"""
api/bridge.py
─────────────
Python ↔ JS bridge for pywebview.
All public methods are callable from JS as:
    const result = await window.pywebview.api.method_name(args)
"""
import concurrent.futures
import ipaddress
import json
import os
import threading
from datetime import datetime
from typing import List, Optional

import core.database as db
import core.storage  as storage
from core.context  import AppContext
from core.network  import detect_networks, classify_device, ping_host_fast, ping_host
from core          import resolver
from core.arp      import refresh_mac_cache


class Api:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self._win = None
        self._engine = None
        self._scan_active = False

    def set_window(self, win) -> None:    self._win = win
    def set_engine(self, engine) -> None: self._engine = engine

    # ── Push helpers ──────────────────────────────────────────────────────────

    def _js(self, code: str) -> None:
        if self._win:
            try:
                self._win.evaluate_js(code)
            except Exception as e:
                print(f"[bridge] js error: {e}")

    def _push(self, fn: str, payload) -> None:
        self._js(f"window.__nm_{fn}({json.dumps(payload)})")

    # ── Startup ───────────────────────────────────────────────────────────────

    def on_ready(self) -> None:
        self._push("init", {
            "devices":    self.ctx.devices,
            "groups":     self.ctx.groups,
            "settings":   self.ctx.settings,
            "status":     self.ctx.device_status,
            "monitoring": self.ctx.monitoring,
        })

    # ── Monitor push callbacks ────────────────────────────────────────────────

    def push_status_update(self) -> None:
        self._push("statusUpdate", dict(self.ctx.device_status))

    def push_notification(self, name: str, current: str, previous: str) -> None:
        if self.ctx.notification_enabled:
            self._push("notification", {
                "name": name, "current": current, "previous": previous,
            })

    # ═════════════════════════════════════════════════════════════════════════
    # GROUPS
    # ═════════════════════════════════════════════════════════════════════════

    def get_groups(self) -> list:
        return db.get_groups()

    def add_group(self, name: str, color: str = "#00d4aa") -> dict:
        name = (name or "").strip()
        if not name:
            return {"ok": False, "error": "Group name required"}
        try:
            g = db.add_group(name, color)
            self.ctx.groups = db.get_groups()
            return {"ok": True, "group": g}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def update_group(self, gid: int, name: str, color: str) -> dict:
        try:
            db.update_group(int(gid), (name or "").strip(), color)
            self.ctx.groups = db.get_groups()
            self._reload_devices()
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def delete_group(self, gid: int) -> dict:
        try:
            db.delete_group(int(gid))
            self.ctx.groups = db.get_groups()
            self._reload_devices()
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ═════════════════════════════════════════════════════════════════════════
    # DEVICES
    # ═════════════════════════════════════════════════════════════════════════

    def get_devices(self) -> list:
        return self.ctx.devices

    def add_device(self, ip: str, name: str,
                   group_id=None, notes: str = "",
                   poll_interval=None) -> dict:
        ip = (ip or "").strip()
        name = (name or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"ok": False, "error": f"'{ip}' is not a valid IP address (IPv4 or IPv6)"}
        if any(d["ip"] == ip for d in self.ctx.devices):
            return {"ok": False, "error": f"Device {ip} already exists"}
        gid = int(group_id) if group_id else None
        pi  = int(poll_interval) if poll_interval and int(poll_interval) > 0 else None
        db.add_device(ip, name, group_id=gid, notes=notes or "", poll_interval=pi)
        self._reload_devices()
        return {"ok": True}

    def update_device(self, did: int, ip: str, name: str,
                      group_id=None, notes: str = "",
                      poll_interval=None) -> dict:
        ip = (ip or "").strip()
        name = (name or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"ok": False, "error": f"'{ip}' is not a valid IP address (IPv4 or IPv6)"}
        gid = int(group_id) if group_id else None
        pi  = int(poll_interval) if poll_interval and int(poll_interval) > 0 else None
        db.update_device(int(did), ip, name, group_id=gid, notes=notes or "", poll_interval=pi)
        self._reload_devices()
        return {"ok": True}

    def remove_device(self, did: int) -> dict:
        db.delete_device(int(did))
        self._reload_devices()
        return {"ok": True}

    def test_device(self, ip: str) -> None:
        def _run():
            lat = ping_host(
                ip,
                timeout=float(self.ctx.settings.get("ping_timeout", 3)),
                retries=int(self.ctx.settings.get("max_retries", 2)),
            )
            self._push("pingResult", {
                "ip": ip,
                "online": lat is not None,
                "latency": round(lat, 1) if lat is not None else None,
            })
        threading.Thread(target=_run, daemon=True).start()

    def _reload_devices(self) -> None:
        """Sync ctx.devices from SQLite and enrich with MAC vendor."""
        rows = db.get_devices()
        mac_map = {m["ip"]: m for m in db.get_all_macs()}
        self.ctx.devices = []
        for r in rows:
            mac_entry = mac_map.get(r["ip"], {})
            self.ctx.devices.append({
                "id":            r["id"],
                "ip":            r["ip"],
                "name":          r["name"],
                "group_id":      r["group_id"],
                "group_name":    r["group_name"],
                "group_color":   r["group_color"],
                "notes":         r["notes"],
                "poll_interval": r.get("poll_interval"),
                "mac":           mac_entry.get("mac", ""),
                "vendor":        mac_entry.get("vendor", ""),
            })

    # ═════════════════════════════════════════════════════════════════════════
    # MONITORING
    # ═════════════════════════════════════════════════════════════════════════

    def start_monitoring(self) -> dict:
        if not self.ctx.devices:
            return {"ok": False, "error": "No devices configured"}
        if self._engine:
            self._engine.start()
        return {"ok": True}

    def stop_monitoring(self) -> dict:
        if self._engine:
            self._engine.stop()
        return {"ok": True}

    def manual_refresh(self) -> dict:
        if not self.ctx.devices:
            return {"ok": False, "error": "No devices configured"}
        if self._engine:
            self._engine.manual_refresh(done_callback=lambda: None)
        return {"ok": True}

    def get_latency_series(self, ip: str, limit: int = 60) -> list:
        """Return the last N latency readings for a device (for sparklines)."""
        return db.get_latency_series(ip, limit)

    # ═════════════════════════════════════════════════════════════════════════
    # SETTINGS
    # ═════════════════════════════════════════════════════════════════════════

    def get_settings(self) -> dict:
        return self.ctx.settings

    def save_settings(self, data: dict) -> dict:
        try:
            self.ctx.settings["monitor_interval"] = int(data.get("monitor_interval", 10))
            self.ctx.settings["ping_timeout"]     = int(data.get("ping_timeout", 3))
            self.ctx.settings["max_retries"]      = int(data.get("max_retries", 2))
            self.ctx.settings["auto_save"]        = bool(data.get("auto_save", True))
            self.ctx.notification_enabled         = bool(data.get("notifications", True))
            storage.save_settings(self.ctx)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ═════════════════════════════════════════════════════════════════════════
    # DISCOVERY
    # ═════════════════════════════════════════════════════════════════════════

    def get_networks(self) -> list:
        nets = detect_networks()
        return [{"network": n["network"], "interface": n["interface"],
                 "ip": n.get("ip",""), "gateway": n.get("gateway",""),
                 "priority": n["priority"]} for n in nets]

    def start_scan(self, network: str, resolve_hostnames: bool = True) -> dict:
        if self._scan_active:
            return {"ok": False, "error": "Scan already in progress"}
        try:
            ipaddress.IPv4Network(network)
        except ValueError:
            return {"ok": False, "error": f"Invalid network: {network}"}
        self._scan_active = True
        threading.Thread(
            target=self._scan_thread, args=(network, resolve_hostnames), daemon=True
        ).start()
        return {"ok": True}

    def _scan_thread(self, network: str, resolve: bool) -> None:
        try:
            net_obj = ipaddress.IPv4Network(network)
            alive   = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
                futures = {pool.submit(ping_host_fast, str(ip)): ip
                           for ip in net_obj.hosts()}
                for f in concurrent.futures.as_completed(futures):
                    result = f.result()
                    if result:
                        ip, rt = result
                        alive.append((ip, rt))
                        self._push("scanResult", {
                            "ip": ip, "rt": round(rt, 1),
                            "hostname": None, "dtype": classify_device(ip),
                        })
            if alive and resolve:
                ips       = [ip for ip, _ in alive]
                hostnames = resolver.resolve_batch(ips)
                for ip in ips:
                    hn    = hostnames.get(ip)
                    dtype = classify_device(ip, hn)
                    self._push("scanHostname", {"ip": ip, "hostname": hn, "dtype": dtype})
            self._push("scanComplete", {"count": len(alive)})
        except Exception as e:
            self._push("scanComplete", {"count": 0, "error": str(e)})
        finally:
            self._scan_active = False

    def add_discovered(self, devices: list) -> dict:
        added = 0
        for d in devices:
            ip   = (d.get("ip") or "").strip()
            name = (d.get("name") or "").strip()
            if ip and name and not any(x["ip"] == ip for x in self.ctx.devices):
                db.add_device(ip, name)
                added += 1
        if added:
            self._reload_devices()
        return {"ok": True, "added": added}

    # ═════════════════════════════════════════════════════════════════════════
    # ARP
    # ═════════════════════════════════════════════════════════════════════════

    def refresh_arp(self) -> dict:
        """
        Read OS ARP table, resolve vendors, persist to mac_cache,
        and return enriched rows.  Fast (< 1 s).
        """
        try:
            rows = refresh_mac_cache()
            # Also update MAC info on ctx.devices
            self._reload_devices()
            return {"ok": True, "rows": rows}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_mac_cache(self) -> list:
        return db.get_all_macs()

    # ═════════════════════════════════════════════════════════════════════════
    # HISTORY
    # ═════════════════════════════════════════════════════════════════════════

    def get_history(self, limit: int = 100) -> list:
        rows = db.get_history(limit=int(limit))
        return [
            {
                "ts":      r["checked_at"],
                "ip":      r["device_ip"],
                "name":    r["device_name"],
                "status":  r["status"],
                "latency": f"{r['latency_ms']:.1f}" if r["latency_ms"] is not None else "—",
            }
            for r in rows
        ]

    def get_device_history(self, ip: str, limit: int = 60) -> list:
        rows = db.get_history(limit=int(limit), device_ip=ip)
        return [
            {"ts": r["checked_at"], "status": r["status"], "latency": r["latency_ms"]}
            for r in rows
        ]

    def clear_history(self) -> dict:
        try:
            db.clear_history()
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def export_log(self) -> dict:
        if not self._win:
            return {"ok": False, "error": "Window not ready"}
        import csv as csv_mod
        rows = db.get_history(limit=0)
        if not rows:
            return {"ok": False, "error": "No log entries to export"}
        paths = self._win.create_file_dialog(
            dialog_type=1, save_filename="netwatch_log.csv",
            file_types=("CSV Files (*.csv)", "All Files (*.*)"),
        )
        if not paths:
            return {"ok": False, "error": "Cancelled"}
        dest = paths[0] if isinstance(paths, (list, tuple)) else paths
        with open(dest, "w", newline="", encoding="utf-8") as f:
            writer = csv_mod.DictWriter(
                f, fieldnames=["checked_at","device_ip","device_name","status","latency_ms"]
            )
            writer.writeheader()
            writer.writerows(rows)
        return {"ok": True, "path": dest}

    # ═════════════════════════════════════════════════════════════════════════
    # STATISTICS
    # ═════════════════════════════════════════════════════════════════════════

    def get_statistics(self) -> dict:
        stats = db.get_statistics()
        online  = sum(1 for s in self.ctx.device_status.values() if s["status"] == "ONLINE")
        offline = sum(1 for s in self.ctx.device_status.values() if s["status"] == "OFFLINE")
        lats    = [float(s["latency"].replace("ms",""))
                   for s in self.ctx.device_status.values()
                   if s.get("latency") and s["latency"] not in ("-","")]
        stats["summary"] = {
            "total":         len(self.ctx.devices),
            "online":        online,
            "offline":       offline,
            "avg_lat":       round(sum(lats)/len(lats), 1) if lats else None,
            "monitoring":    self.ctx.monitoring,
            "notifications": self.ctx.notification_enabled,
            "total_entries": stats.pop("total_entries", 0),
            "db_size_kb":    stats.pop("db_size_kb", 0),
        }
        return stats

    def generate_report(self) -> dict:
        if not self._win:
            return {"ok": False, "error": "Window not ready"}
        paths = self._win.create_file_dialog(
            dialog_type=1, save_filename="netwatch_report.txt",
            file_types=("Text Files (*.txt)", "All Files (*.*)"),
        )
        if not paths:
            return {"ok": False, "error": "Cancelled"}
        dest = paths[0] if isinstance(paths, (list, tuple)) else paths
        stats = db.get_statistics()
        with open(dest, "w", encoding="utf-8") as f:
            f.write("NETWATCH — REPORT\n" + "=" * 44 + "\n")
            f.write(f"Generated : {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
            f.write("DEVICES\n" + "-"*20 + "\n")
            for d in self.ctx.devices:
                grp = d.get("group_name") or "—"
                f.write(f"  {d['name']} ({d['ip']})  [group: {grp}]")
                if d.get("mac"):
                    f.write(f"  [MAC: {d['mac']} — {d.get('vendor','')}]")
                f.write("\n")
                if d.get("notes"):
                    f.write(f"    Notes: {d['notes']}\n")
            f.write("\nCURRENT STATUS\n" + "-"*14 + "\n")
            for ip, s in self.ctx.device_status.items():
                f.write(f"  {s['name']} ({ip}): {s['status']} — {s['latency']}\n")
            f.write(f"\nDB entries : {stats.get('total_entries',0):,}\n")
            f.write(f"DB size    : {stats.get('db_size_kb',0):.1f} KB\n")
        return {"ok": True, "path": dest}

    # ═════════════════════════════════════════════════════════════════════════
    # CONFIG
    # ═════════════════════════════════════════════════════════════════════════

    def export_config(self) -> dict:
        if not self._win:
            return {"ok": False, "error": "Window not ready"}
        paths = self._win.create_file_dialog(
            dialog_type=1, save_filename="netwatch_config.json",
            file_types=("JSON Files (*.json)", "All Files (*.*)"),
        )
        if not paths:
            return {"ok": False, "error": "Cancelled"}
        dest = paths[0] if isinstance(paths, (list, tuple)) else paths
        try:
            storage.export_config(self.ctx, dest)
            return {"ok": True, "path": dest}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def import_config(self) -> dict:
        if not self._win:
            return {"ok": False, "error": "Window not ready"}
        paths = self._win.create_file_dialog(
            dialog_type=0,
            file_types=("JSON Files (*.json)", "All Files (*.*)"),
        )
        if not paths:
            return {"ok": False, "error": "Cancelled"}
        src = paths[0] if isinstance(paths, (list, tuple)) else paths
        try:
            storage.import_config(self.ctx, src)
            storage.save_settings(self.ctx)
            self._push("init", {
                "devices":    self.ctx.devices,
                "groups":     self.ctx.groups,
                "settings":   self.ctx.settings,
                "status":     self.ctx.device_status,
                "monitoring": self.ctx.monitoring,
            })
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 2 — PORT SCANNER
    # ═════════════════════════════════════════════════════════════════════════

    def start_port_scan(self, ip: str, profile: str = 'quick') -> dict:
        """
        Launch a port scan in a daemon thread.
        Progress pushed via __nm_portScanProgress(done, total).
        Final result pushed via __nm_portScanResult({ip, ports:[...]}).
        """
        from core.portscan import scan_ports_profile, PROFILES
        if profile not in PROFILES:
            return {"ok": False, "error": f"Unknown profile '{profile}'"}
        total = len(PROFILES[profile])

        def _progress(done, total):
            try:
                self._push("portScanProgress", {"done": done, "total": total})
            except Exception:
                pass

        def _run():
            results = scan_ports_profile(ip, profile=profile, on_progress=_progress)
            self._push("portScanResult", {"ip": ip, "profile": profile, "ports": results})

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "total": total}

    def get_port_profiles(self) -> dict:
        from core.portscan import PROFILES
        return {k: len(v) for k, v in PROFILES.items()}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 2 — TRACEROUTE
    # ═════════════════════════════════════════════════════════════════════════

    def run_traceroute(self, target: str, max_hops: int = 30) -> dict:
        """
        Run traceroute asynchronously.
        Result pushed via __nm_tracerouteResult({target, hops:[...]}).
        """
        from core.traceroute import run_traceroute

        def _run():
            hops = run_traceroute(target, max_hops=int(max_hops))
            self._push("tracerouteResult", {"target": target, "hops": hops})

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 2 — WAKE-ON-LAN
    # ═════════════════════════════════════════════════════════════════════════

    def send_wol(self, mac: str, broadcast: str = '255.255.255.255',
                 port: int = 9) -> dict:
        from core.wol import send_wol
        return send_wol(mac, broadcast=broadcast, port=int(port))

    def validate_mac(self, mac: str) -> dict:
        from core.wol import validate_mac, format_mac
        valid = validate_mac(mac)
        return {"valid": valid, "formatted": format_mac(mac) if valid else None}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 2 — DNS & GEOLOCATION
    # ═════════════════════════════════════════════════════════════════════════

    def lookup_dns(self, host: str) -> dict:
        """Run DNS lookups synchronously (fast, < 3 s)."""
        from core.dns_tools import lookup_dns
        return lookup_dns(host.strip())

    def geolocate_ip(self, ip: str) -> dict:
        """Return geolocation data for an IP (cached, uses ip-api.com)."""
        from core.dns_tools import geolocate_ip
        return geolocate_ip(ip.strip())

    def lookup_dns_and_geo(self, host: str) -> dict:
        """
        Combined DNS + geolocation lookup run concurrently.
        Pushed via __nm_dnsGeoResult({host, dns:{...}, geo:{...}}).
        """
        from core.dns_tools import lookup_dns, geolocate_ip
        import concurrent.futures as cf

        def _run():
            with cf.ThreadPoolExecutor(max_workers=2) as pool:
                dns_fut = pool.submit(lookup_dns, host.strip())
                # Geolocate the first resolved A record (or the host itself)
                dns_res = dns_fut.result()
                target_ip = dns_res['A'][0] if dns_res.get('A') else host.strip()
                geo_res = geolocate_ip(target_ip)
            self._push("dnsGeoResult", {
                "host": host.strip(),
                "dns":  dns_res,
                "geo":  geo_res,
            })

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 3 — VISUALISATION
    # ═════════════════════════════════════════════════════════════════════════

    def get_chart_data(self, ip: str, latency_limit: int = 80,
                       loss_hours: int = 48) -> dict:
        """
        Return all chart data for a single device in one call:
          latency  — [{checked_at, latency_ms, status}]   last N readings
          loss     — [{hour, total, failed, loss_pct}]     last N hours
        """
        return {
            "ip":      ip,
            "latency": db.get_latency_series(ip, latency_limit),
            "loss":    db.get_hourly_packet_loss(ip, loss_hours),
        }

    def get_heatmap_data(self, ip: str, days: int = 84) -> dict:
        """
        Uptime calendar data for one device.
        Returns {ip, name, days:[{date, total, online, pct}]}
        """
        name = next((d["name"] for d in self.ctx.devices if d["ip"] == ip), ip)
        return {
            "ip":   ip,
            "name": name,
            "days": db.get_uptime_calendar(ip, int(days)),
        }

    def get_all_heatmap_data(self, days: int = 84) -> list:
        """Uptime calendar for every configured device."""
        result = []
        for dev in self.ctx.devices:
            result.append({
                "ip":   dev["ip"],
                "name": dev["name"],
                "days": db.get_uptime_calendar(dev["ip"], int(days)),
            })
        return result

    def get_topology_data(self) -> dict:
        """
        Snapshot of device nodes + group clusters + live status for
        the topology map.

        Returns:
          nodes  — [{id, ip, name, status, latency, group_id,
                     group_name, group_color, mac, vendor}]
          groups — [{id, name, color, count}]
          edges  — [] reserved for Phase 4 (traceroute-derived links)
        """
        group_counts: dict[int, int] = {}
        nodes = []
        for dev in self.ctx.devices:
            s      = self.ctx.device_status.get(dev["ip"], {})
            gid    = dev.get("group_id")
            if gid:
                group_counts[gid] = group_counts.get(gid, 0) + 1
            nodes.append({
                "id":          dev["ip"],
                "ip":          dev["ip"],
                "name":        dev["name"],
                "status":      s.get("status", "UNKNOWN"),
                "latency":     s.get("latency", "—"),
                "group_id":    gid,
                "group_name":  dev.get("group_name"),
                "group_color": dev.get("group_color", "#00d4aa"),
                "mac":         dev.get("mac", ""),
                "vendor":      dev.get("vendor", ""),
            })

        groups = [
            {**g, "count": group_counts.get(g["id"], 0)}
            for g in self.ctx.groups
        ]

        return {"nodes": nodes, "groups": groups, "edges": []}

    def get_packet_loss_trend(self, ip: str, hours: int = 48) -> list:
        """Hourly packet-loss % for the last N hours for a single device."""
        return db.get_hourly_packet_loss(ip, int(hours))

    def get_all_charts_seed(self) -> list:
        """
        Seed payload for the Charts section on first load.
        Returns per-device: last 60 latency readings + last 24h hourly loss.
        """
        result = []
        for dev in self.ctx.devices:
            result.append({
                "ip":      dev["ip"],
                "name":    dev["name"],
                "latency": db.get_latency_series(dev["ip"], 60),
                "loss":    db.get_hourly_packet_loss(dev["ip"], 24),
            })
        return result

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 4 — ALERTS & NOTIFICATIONS
    # ═════════════════════════════════════════════════════════════════════════

    def set_alert_engine(self, engine) -> None:
        self._alert_engine = engine

    # ── Alert rules ───────────────────────────────────────────────────────────

    def get_alert_rules(self) -> list:
        import json
        rules = db.get_alert_rules()
        # Parse channels JSON for JS
        for r in rules:
            if isinstance(r.get("channels"), str):
                try:    r["channels"] = json.loads(r["channels"])
                except: r["channels"] = []
        return rules

    def add_alert_rule(self, name: str, device_ip, rule_type: str,
                       threshold, duration_s: int, channels: list) -> dict:
        name = (name or "").strip()
        if not name:
            return {"ok": False, "error": "Rule name required"}
        if rule_type not in ("offline", "online", "latency_gt", "packet_loss_gt"):
            return {"ok": False, "error": f"Unknown rule type: {rule_type}"}
        try:
            r = db.add_alert_rule(
                name,
                device_ip or None,
                rule_type,
                float(threshold) if threshold is not None and threshold != "" else None,
                int(duration_s),
                channels or [],
            )
            return {"ok": True, "rule": r}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def update_alert_rule(self, rid: int, name: str, device_ip,
                          rule_type: str, threshold, duration_s: int,
                          channels: list, enabled: bool = True) -> dict:
        try:
            db.update_alert_rule(
                int(rid), name.strip(), device_ip or None, rule_type,
                float(threshold) if threshold not in (None, "") else None,
                int(duration_s), channels or [], enabled,
            )
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def delete_alert_rule(self, rid: int) -> dict:
        try:
            db.delete_alert_rule(int(rid))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def toggle_alert_rule(self, rid: int, enabled: bool) -> dict:
        try:
            db.toggle_alert_rule(int(rid), bool(enabled))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Alert events ──────────────────────────────────────────────────────────

    def get_alert_events(self, limit: int = 100) -> list:
        return db.get_alert_events(int(limit))

    def clear_alert_events(self) -> dict:
        try:
            db.clear_alert_events()
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Notification config ───────────────────────────────────────────────────

    def get_notif_config(self) -> dict:
        return db.get_notif_config()

    def save_notif_config(self, data: dict) -> dict:
        try:
            db.set_notif_config_bulk({k: str(v) for k, v in data.items()})
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def test_channel(self, channel: str) -> dict:
        """Send a test notification on the specified channel."""
        import json as _json
        cfg = db.get_notif_config()
        from core.alerts import (_send_sound, _send_email,
                                  _send_webhook, _send_discord, _send_telegram)
        try:
            if channel == "toast":
                self._push("alertFired", {
                    "title":   "🧪 Test Notification",
                    "message": "NETWATCH alert system is working correctly",
                    "rtype":   "test", "ip": "—", "name": "Test",
                })
            elif channel == "sound":
                _send_sound(cfg)
            elif channel == "email":
                _send_email(cfg, "NETWATCH Test Alert",
                            "This is a test notification from NETWATCH.")
            elif channel == "webhook":
                _send_webhook(cfg, "NETWATCH Test Alert",
                              "Test notification from NETWATCH",
                              "Test", "0.0.0.0", "test")
            elif channel == "discord":
                _send_discord(cfg, "NETWATCH Test Alert",
                              "Test notification from NETWATCH",
                              "test", "Test")
            elif channel == "telegram":
                _send_telegram(cfg, "NETWATCH Test Alert",
                               "Test notification from NETWATCH")
            else:
                return {"ok": False, "error": f"Unknown channel: {channel}"}
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_packet_loss(self, ip: str, window: int = 20) -> dict:
        """Return real rolling packet-loss % for a device."""
        try:
            loss = db.get_rolling_packet_loss(ip, window=int(window))
            return {"ok": True, "ip": ip, "loss_pct": loss, "window": window}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 5 — POWER FEATURES
    # ═════════════════════════════════════════════════════════════════════════

    # ── REST API / Prometheus server ──────────────────────────────────────────

    def get_api_server_status(self) -> dict:
        srv = getattr(self, '_rest_server', None)
        if srv:
            return {"running": srv.is_running(),
                    "host": srv.host,
                    "port": srv.port,
                    "prometheus": srv.enable_prometheus}
        return {"running": False, "host": "127.0.0.1",
                "port": 8765, "prometheus": True}

    def start_api_server(self, host: str = "127.0.0.1",
                         port: int = 8765,
                         enable_prometheus: bool = True) -> dict:
        from core.api_server import RestApiServer
        srv = getattr(self, '_rest_server', None)
        if srv is None:
            srv = RestApiServer(self.ctx, host=host,
                                port=int(port),
                                enable_prometheus=enable_prometheus)
            self._rest_server = srv
        else:
            srv.reconfigure(host, int(port), enable_prometheus)
        ok = srv.start() if not srv.is_running() else True
        return {"ok": ok, "url": f"http://{srv.host}:{srv.port}"}

    def stop_api_server(self) -> dict:
        srv = getattr(self, '_rest_server', None)
        if srv:
            srv.stop()
        return {"ok": True}

    def reconfigure_api_server(self, host: str, port: int,
                                enable_prometheus: bool) -> dict:
        from core.api_server import RestApiServer
        srv = getattr(self, '_rest_server', None)
        if srv is None:
            srv = RestApiServer(self.ctx, host=host, port=int(port),
                                enable_prometheus=enable_prometheus)
            self._rest_server = srv
        ok = srv.reconfigure(host, int(port), bool(enable_prometheus))
        return {"ok": ok, "host": host, "port": port}

    # ── Theme ─────────────────────────────────────────────────────────────────

    def get_theme(self) -> str:
        return self.ctx.settings.get('ui_theme', 'dark')

    def set_theme(self, theme: str) -> dict:
        if theme not in ('dark', 'light'):
            return {"ok": False, "error": "Theme must be 'dark' or 'light'"}
        self.ctx.settings['ui_theme'] = theme
        import core.storage as _st
        _st.save_settings(self.ctx)
        return {"ok": True, "theme": theme}

    # ── Device ordering ───────────────────────────────────────────────────────

    def reorder_devices(self, ordered_ids: list) -> dict:
        """
        Persist a new device order.  ordered_ids is a list of device DB ids
        in the desired display order.  We re-create ctx.devices in that order
        and write order_index to the DB.
        """
        import core.database as _db
        try:
            id_to_dev = {d["id"]: d for d in self.ctx.devices}
            new_order = []
            for oid in ordered_ids:
                dev = id_to_dev.get(int(oid))
                if dev:
                    new_order.append(dev)
            # Append any devices not in the list (safety)
            seen = {d["id"] for d in new_order}
            for d in self.ctx.devices:
                if d["id"] not in seen:
                    new_order.append(d)
            self.ctx.devices = new_order
            # Persist order via update (keep all fields, just re-write rows in order)
            for idx, dev in enumerate(self.ctx.devices):
                _db.set_device_order(dev["id"], idx)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Quick search (Ctrl+K) ─────────────────────────────────────────────────

    def search(self, query: str) -> list:
        """
        Full-text search across devices, groups, recent alert events.
        Returns a list of result dicts with {type, label, sublabel, action}.
        """
        q   = query.strip().lower()
        out = []
        if not q:
            return out

        # Devices
        for dev in self.ctx.devices:
            if q in dev["name"].lower() or q in dev["ip"]:
                s     = self.ctx.device_status.get(dev["ip"], {})
                out.append({
                    "type":     "device",
                    "label":    dev["name"],
                    "sublabel": dev["ip"],
                    "status":   s.get("status", "UNKNOWN"),
                    "latency":  s.get("latency", "—"),
                    "action":   f"navigate:devices",
                    "ip":       dev["ip"],
                })

        # Groups
        for grp in self.ctx.groups:
            if q in grp["name"].lower():
                out.append({
                    "type":     "group",
                    "label":    grp["name"],
                    "sublabel": f"{sum(1 for d in self.ctx.devices if d.get('group_id')==grp['id'])} devices",
                    "color":    grp["color"],
                    "action":   "navigate:groups",
                })

        # Sections (always search)
        SECTIONS = [
            ("dashboard",    "Dashboard",         "Overview"),
            ("devices",      "Devices",           "Manage hosts"),
            ("discovery",    "Network Discovery", "Scan subnet"),
            ("arp",          "ARP Table",         "MAC addresses"),
            ("portscan",     "Port Scanner",      "TCP scan"),
            ("traceroute",   "Traceroute",        "Hop diagram"),
            ("wol",          "Wake-on-LAN",       "Magic packets"),
            ("dns",          "DNS / Geo",         "Record lookup"),
            ("charts",       "Live Charts",       "Latency & loss"),
            ("heatmap",      "Uptime Heatmap",    "Calendar view"),
            ("topology",     "Topology Map",      "Network graph"),
            ("alerts",       "Alert Rules",       "Notifications"),
            ("alert-log",    "Alert Log",         "Fired alerts"),
            ("notif-config", "Notifications",     "Channel config"),
            ("history",      "History",           "Ping log"),
            ("statistics",   "Statistics",        "Analytics"),
            ("groups",       "Groups",            "Device tags"),
            ("settings",     "Settings",          "App config"),
            ("api-settings", "REST API",          "HTTP endpoints"),
            ("guide",        "Guide",              "How-to & best practices"),
        ]
        for sid, name, sub in SECTIONS:
            if q in name.lower() or q in sub.lower():
                out.append({
                    "type":     "section",
                    "label":    name,
                    "sublabel": sub,
                    "action":   f"navigate:{sid}",
                })

        return out[:20]   # cap at 20 results