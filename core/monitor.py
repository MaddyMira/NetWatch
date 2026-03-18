"""
core/monitor.py
───────────────
Background monitoring engine — logs to SQLite + evaluates alert rules.

Per-device poll intervals: if a device has poll_interval set (seconds),
it is polled on its own cadence instead of the global monitor_interval.
"""
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Optional

import core.database as db
from core.context import AppContext
from core.network import ping_host


class MonitorEngine:

    def __init__(
        self,
        ctx: AppContext,
        on_update: Callable[[], None],
        on_status_change: Callable[[str, str, str], None],
    ) -> None:
        self.ctx = ctx
        self.on_update = on_update
        self.on_status_change = on_status_change
        self.alert_engine = None        # set by main.py after AlertEngine init
        self._thread: Optional[threading.Thread] = None
        # ip → monotonic timestamp of last poll
        self._last_polled: Dict[str, float] = {}

    def start(self) -> None:
        if self.ctx.monitoring:
            return
        self.ctx.monitoring = True
        self._last_polled.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="MonitorEngine"
        )
        self._thread.start()

    def stop(self) -> None:
        self.ctx.monitoring = False

    def manual_refresh(self, done_callback: Callable[[], None]) -> None:
        def _run():
            self._cycle(force_all=True)
            done_callback()
        threading.Thread(target=_run, daemon=True, name="ManualRefresh").start()

    def _loop(self) -> None:
        """
        Tick every 0.5 s; each tick we poll devices whose individual interval
        has elapsed.  Devices without a custom interval use the global setting.
        This means the engine never blocks for a full interval period, and
        devices with short custom intervals are still serviced promptly.
        """
        while self.ctx.monitoring:
            try:
                self._cycle(force_all=False)
            except Exception as e:
                print(f"[monitor] Loop error: {e}")
            # Sleep in small increments so stop() is responsive
            for _ in range(5):   # 5 × 0.1 s = 0.5 s tick
                if not self.ctx.monitoring:
                    return
                time.sleep(0.1)

    def _cycle(self, force_all: bool = False) -> None:
        now       = time.monotonic()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timeout   = float(self.ctx.settings.get('ping_timeout', 3))
        retries   = int(self.ctx.settings.get('max_retries', 2))
        global_interval = int(self.ctx.settings.get('monitor_interval', 10))

        any_polled = False
        for device in list(self.ctx.devices):
            ip       = device['ip']
            interval = device.get('poll_interval') or global_interval

            last = self._last_polled.get(ip, 0.0)
            if not force_all and (now - last) < interval:
                continue   # not yet due

            self._last_polled[ip] = now
            any_polled = True

            latency = ping_host(ip, timeout=timeout, retries=retries)
            status      = "ONLINE" if latency is not None else "OFFLINE"
            latency_str = f"{latency:.0f}ms" if latency is not None else "-"

            prev = self.ctx.device_history.get(ip, {}).get('status')
            if prev and prev != status:
                self.on_status_change(device['name'], status, prev)

            self.ctx.device_status[ip] = {
                'name':         device['name'],
                'status':       status,
                'latency':      latency_str,
                'last_check':   timestamp,
                'group_name':   device.get('group_name'),
                'group_color':  device.get('group_color'),
                'poll_interval': interval,
            }
            self.ctx.device_history[ip] = {
                'name': device['name'], 'status': status, 'timestamp': timestamp,
            }
            db.log_ping(ip, device['name'], status, latency)

        if any_polled:
            self.on_update()
            if self.alert_engine:
                try:
                    self.alert_engine.evaluate(self.ctx.device_status)
                except Exception as e:
                    print(f"[monitor] alert engine error: {e}")