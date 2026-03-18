"""
core/alerts.py
──────────────
Alert rule engine and notification dispatcher.

AlertEngine runs in the monitor's cycle (called after each ping batch).
It evaluates every enabled rule against the current device_status snapshot
and fires configured channels when a rule triggers.

Channels
────────
  toast    — push via bridge._push("alertFired", …)  [always available]
  sound    — play a system beep / WAV file
  email    — SMTP (TLS) using stdlib smtplib
  webhook  — HTTP POST JSON to any URL (Slack, custom)
  discord  — Discord webhook (separate format from generic webhook)

Rule types
──────────
  offline          — device has been OFFLINE for ≥ duration_s
  online           — device just came back ONLINE (flip detection)
  latency_gt N     — latency_ms > N for ≥ duration_s
  packet_loss_gt N — hourly packet loss % > N (last full hour)

Duration logic
──────────────
Each rule keeps an internal "pending since" timer per device.
A rule only fires when the condition has been TRUE continuously for
at least duration_s seconds.  Repeated cycles refresh the fired flag
so the rule does not spam on every cycle once triggered — it resets
only when the condition clears.
"""
import json
import smtplib
import socket
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.text import MIMEText
from typing import Callable, Dict, List, Optional

import core.database as db
from core.context import AppContext


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_ts() -> float:
    return time.monotonic()


def _fmt(msg: str, device_name: str, device_ip: str, value=None) -> str:
    return (msg
            .replace("{name}", device_name)
            .replace("{ip}", device_ip)
            .replace("{value}", str(value) if value is not None else ""))


# ─────────────────────────────────────────────────────────────────────────────
# Notification senders
# ─────────────────────────────────────────────────────────────────────────────

def _send_sound(cfg: Dict) -> None:
    """Play a sound alert (cross-platform best-effort)."""
    import os
    wav = cfg.get("sound_file", "")
    try:
        if wav and os.path.exists(wav):
            if os.name == "nt":
                import winsound
                winsound.PlaySound(wav, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                os.system(f"aplay -q {wav} &")
        else:
            # System beep fallback
            if os.name == "nt":
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                print("\a", end="", flush=True)
    except Exception as e:
        print(f"[alerts] sound error: {e}")


def _send_email(cfg: Dict, subject: str, body: str) -> None:
    host    = cfg.get("email_smtp_host", "")
    port    = int(cfg.get("email_smtp_port", 587))
    user    = cfg.get("email_smtp_user", "")
    pw      = cfg.get("email_smtp_pass", "")
    to_addr = cfg.get("email_to", "")
    if not (host and user and to_addr):
        print("[alerts] email not configured — skipping")
        return
    try:
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"]    = user
        msg["To"]      = to_addr
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, pw)
            smtp.send_message(msg)
        print(f"[alerts] email sent to {to_addr}")
    except Exception as e:
        print(f"[alerts] email error: {e}")


def _send_webhook(cfg: Dict, title: str, message: str,
                  device_name: str, device_ip: str,
                  rule_type: str) -> None:
    url = cfg.get("webhook_url", "")
    if not url:
        return
    payload = {
        "text":      f"*{title}*\n{message}",
        "device":    device_name,
        "ip":        device_ip,
        "rule_type": rule_type,
        "timestamp": datetime.now().isoformat(),
    }
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "NETWATCH/4.0"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        print(f"[alerts] webhook error: {e}")


def _send_discord(cfg: Dict, title: str, message: str,
                  rule_type: str, device_name: str) -> None:
    url = cfg.get("discord_webhook_url", "")
    if not url:
        return
    color = 0xFF4D4D if "offline" in rule_type else \
            0x22D35B if "online"  in rule_type else \
            0xF59E0B
    payload = {
        "embeds": [{
            "title":       title,
            "description": message,
            "color":       color,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
            "footer":      {"text": f"NETWATCH • {device_name}"},
        }]
    }
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "NETWATCH/4.0"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        print(f"[alerts] discord error: {e}")


def _send_telegram(cfg: Dict, title: str, message: str) -> None:
    """Send an alert via Telegram Bot API."""
    token   = cfg.get("telegram_bot_token", "")
    chat_id = cfg.get("telegram_chat_id", "")
    if not (token and chat_id):
        print("[alerts] telegram not configured — skipping")
        return
    text    = f"*{title}*\n{message}"
    payload = json.dumps({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "Markdown",
    }).encode()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "NETWATCH/4.0"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8)
    except Exception as e:
        print(f"[alerts] telegram error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Alert Engine
# ─────────────────────────────────────────────────────────────────────────────

class AlertEngine:
    """
    Evaluate alert rules after every monitor cycle.

    Usage (in MonitorEngine._cycle):
        if self.alert_engine:
            self.alert_engine.evaluate(self.ctx.device_status)
    """

    def __init__(
        self,
        ctx: AppContext,
        push_fn: Callable[[str, dict], None],   # bridge._push
    ) -> None:
        self.ctx     = ctx
        self._push   = push_fn
        self._lock   = threading.Lock()
        # ip → rule_id → timestamp when condition first became true
        self._pending: Dict[str, Dict[int, float]] = {}
        # ip → rule_id → True if rule already fired (prevents repeat spam)
        self._fired:   Dict[str, Dict[int, bool]]  = {}

    # ── Public ────────────────────────────────────────────────────────────────

    def evaluate(self, status: Dict[str, Dict]) -> None:
        """Called from the monitor thread after each cycle."""
        rules = db.get_alert_rules()
        cfg   = db.get_notif_config()
        now   = _now_ts()

        for rule in rules:
            if not rule["enabled"]:
                continue
            try:
                channels = json.loads(rule["channels"]) if rule["channels"] else []
                self._eval_rule(rule, channels, cfg, status, now)
            except Exception as e:
                print(f"[alerts] rule {rule['id']} error: {e}")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _eval_rule(self, rule: Dict, channels: List[str],
                   cfg: Dict, status: Dict, now: float) -> None:
        rtype  = rule["rule_type"]
        thresh = rule["threshold"]
        dur    = rule["duration_s"]
        target = rule["device_ip"]          # None = all devices
        rid    = rule["id"]

        # Build list of device IPs to check
        ips = [target] if target else list(status.keys())

        for ip in ips:
            s = status.get(ip)
            if not s:
                continue
            name = s.get("name", ip)
            lat  = self._parse_latency(s.get("latency", "—"))

            condition_met = self._check_condition(rtype, thresh, s, lat, ip=ip)

            # Duration gating
            ip_pending = self._pending.setdefault(ip, {})
            ip_fired   = self._fired.setdefault(ip, {})

            if condition_met:
                if rid not in ip_pending:
                    ip_pending[rid] = now       # start timer
                elapsed = now - ip_pending[rid]
                if elapsed >= dur and not ip_fired.get(rid):
                    ip_fired[rid] = True
                    self._fire(rule, channels, cfg, ip, name, rtype, thresh, lat)
            else:
                # Condition cleared → reset
                ip_pending.pop(rid, None)
                ip_fired[rid] = False

    def _check_condition(self, rtype: str, thresh, s: Dict,
                         lat: Optional[float], ip: Optional[str] = None) -> bool:
        st = s.get("status", "UNKNOWN")
        if rtype == "offline":
            return st == "OFFLINE"
        if rtype == "online":
            return st == "ONLINE"
        if rtype == "latency_gt":
            return lat is not None and thresh is not None and lat > thresh
        if rtype == "packet_loss_gt":
            if ip and thresh is not None:
                loss = db.get_rolling_packet_loss(ip, window=20)
                return loss > thresh
            # Fallback if no DB data yet
            return st == "OFFLINE"
        return False

    @staticmethod
    def _parse_latency(lat_str: str) -> Optional[float]:
        try:
            return float(lat_str.replace("ms", "").strip())
        except (ValueError, AttributeError):
            return None

    def _fire(self, rule: Dict, channels: List[str], cfg: Dict,
              ip: str, name: str, rtype: str, thresh, lat) -> None:
        # Build human-readable message
        if rtype == "offline":
            title   = "🔴 Device Offline"
            message = f"{name} ({ip}) has gone offline"
        elif rtype == "online":
            title   = "🟢 Device Online"
            message = f"{name} ({ip}) is back online"
        elif rtype == "latency_gt":
            title   = "⚠ High Latency"
            message = f"{name} ({ip}) latency {lat:.0f} ms > {thresh:.0f} ms"
        elif rtype == "packet_loss_gt":
            real_loss = db.get_rolling_packet_loss(ip, window=20)
            title   = "⚠ Packet Loss"
            message = f"{name} ({ip}) packet loss {real_loss:.1f}% > {thresh:.0f}% (last 20 pings)"
        else:
            title   = f"Alert: {rule['name']}"
            message = f"{name} ({ip}) triggered rule '{rule['name']}'"

        # Log to DB
        db.log_alert_event(rule["id"], rule["name"], ip, name, message)

        # Dispatch channels (in background threads to not block monitor)
        threading.Thread(target=self._dispatch,
                         args=(channels, cfg, title, message,
                               name, ip, rtype, rule["id"]),
                         daemon=True).start()

    def _dispatch(self, channels: List[str], cfg: Dict,
                  title: str, message: str,
                  name: str, ip: str, rtype: str, rule_id: int) -> None:
        # Toast (always send — UI will ignore if window not open)
        self._push("alertFired", {
            "title":   title,
            "message": message,
            "rtype":   rtype,
            "ip":      ip,
            "name":    name,
        })

        for ch in channels:
            try:
                if ch == "sound":
                    _send_sound(cfg)
                elif ch == "email":
                    _send_email(cfg, title, message)
                elif ch == "webhook":
                    _send_webhook(cfg, title, message, name, ip, rtype)
                elif ch == "discord":
                    _send_discord(cfg, title, message, rtype, name)
                elif ch == "telegram":
                    _send_telegram(cfg, title, message)
            except Exception as e:
                print(f"[alerts] channel '{ch}' error: {e}")