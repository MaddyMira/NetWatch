# NETWATCH

A local network monitoring tool for keeping an eye on devices in your LAN. You add devices by IP, it pings them on a configurable interval, and shows you who's up, who's down, and how latency is trending over time. Everything is stored locally in a SQLite database — no cloud, no accounts.

Built with Python and pywebview (so it runs as a desktop app with a web-based UI).

---

## What it does

- **Ping monitoring** — polls each device on a configurable interval using ICMP. Supports both IPv4 and IPv6.
- **Per-device poll intervals** — critical servers can be polled every 5 s while printers sit at 60 s.
- **Dashboard** — live status cards for all devices with latency bars and last-check timestamps.
- **Alerts** — rule-based notifications when a device goes offline, comes back online, latency exceeds a threshold, or packet loss crosses a limit. Real packet loss is computed from the last 20 pings, not just the current status.
- **Notification channels** — toast (in-app), sound, email (SMTP), Discord webhook, Telegram bot, and generic webhook.
- **Network discovery** — ping-scans a subnet and lets you bulk-add found hosts.
- **ARP table** — reads the OS ARP cache, resolves MAC OUI to vendor name.
- **Port scanner** — TCP connect scan with banner grabbing. Three profiles: quick (16 ports), common (all well-known), full (1–1024 + common high ports).
- **Traceroute** — hop-by-hop path to any target.
- **Wake-on-LAN** — sends a magic packet to wake a machine, then polls until it comes up.
- **DNS / Geo** — A, PTR, MX, NS, TXT lookups and IP geolocation via ip-api.com.
- **Charts** — latency sparklines and hourly packet-loss bar charts per device.
- **Uptime heatmap** — GitHub-style calendar showing daily availability.
- **Topology map** — force-directed graph of all devices, grouped by colour.
- **History & statistics** — full ping log with CSV export, uptime %, and latency min/avg/max per device.
- **Groups** — tag devices by function (Servers, Cameras, etc.) for filtering and topology clustering.
- **REST API** — optional local HTTP server exposing device status, history, and alert data as JSON. Includes a `/metrics` endpoint for Prometheus/Grafana if you want it.
- **Dark and light theme.**
- **Ctrl+K** command palette for quick navigation.

---

## Requirements

- Python 3.9+
- Windows

```bash
pip install pywebview ping3
```

---

## Running from source

```
netwatch/
├── main.py
├── api/
│   └── bridge.py
├── core/
│   ├── alerts.py
│   ├── api_server.py
│   ├── arp.py
│   ├── context.py
│   ├── database.py
│   ├── dns_tools.py
│   ├── monitor.py
│   ├── network.py
│   ├── portscan.py
│   ├── resolver.py
│   ├── storage.py
│   ├── traceroute.py
│   └── wol.py
└── ui/
    └── index.html
```

```bash
python main.py
```

Pass `--debug` to open the webview dev tools:

```bash
python main.py --debug
```

### Permissions

Ping requires raw socket access.

**Windows** — run as Administrator, or grant the Python interpreter the required privileges.

---

## Building a standalone executable

Requires PyInstaller 6+:

```bash
pip install pyinstaller
pyinstaller netwatch.spec
```

The exe lands in `dist/NETWATCH.exe`. See `netwatch.spec` for the full build config. You need to build on the target OS — cross-compilation isn't supported.


---

## Alert channels setup

### Telegram
1. Create a bot via [@BotFather](https://t.me/BotFather) and copy the token.
2. Send any message to the bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` to find your chat ID.
3. Enter both in **Notifications → Telegram Bot**.

### Discord
Paste a Discord webhook URL into **Notifications → Discord Webhook**.

### Email
Standard SMTP with STARTTLS (port 587). Works with Gmail app passwords, Outlook, or any SMTP relay.

### Webhook
HTTP POST with a JSON body — compatible with Slack, Teams, and anything else that accepts webhooks.

---

## REST API

Enable it in **REST API** settings. Binds to `127.0.0.1:8765` by default.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Current status of all devices |
| GET | `/api/devices` | Device list |
| POST | `/api/devices` | Add a device `{ip, name, group_id?, notes?}` |
| DELETE | `/api/devices/<ip>` | Remove a device |
| GET | `/api/groups` | Group list |
| GET | `/api/history?limit=N` | Ping log |
| GET | `/api/statistics` | Uptime and latency aggregates |
| GET | `/api/alerts` | Fired alert events |
| GET | `/api/rules` | Alert rules |
| GET | `/health` | `{"ok": true}` |
| GET | `/metrics` | Prometheus text format |

No authentication. If you expose it beyond localhost, put it behind a reverse proxy.

---

## Data

Everything is stored in `netwatch.db` (SQLite) next to the executable. The database is created automatically on first run. To reset, delete the file.

Settings are stored in `netwatch_settings.json` in the same directory.

---

## Known limitations

- Discovery scans are IPv4 only (CIDR-based). IPv6 devices must be added manually.
- Port scanner is TCP only — UDP services won't appear.
- Wake-on-LAN only works within the same broadcast domain; it won't cross routers.
- The REST API has no authentication.
- Geolocation uses ip-api.com's free tier (45 requests/minute). Private IPs return "Private Network" without making a network request.

---

## License

MPL 2.0
