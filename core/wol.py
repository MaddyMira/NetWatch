"""
core/wol.py
───────────
Wake-on-LAN (WOL) magic packet sender.

send_wol(mac, broadcast='255.255.255.255', port=9)
    → sends the 102-byte magic packet over UDP broadcast

Supports MAC formats:
    AA:BB:CC:DD:EE:FF
    AA-BB-CC-DD-EE-FF
    AABBCCDDEEFF
"""
import socket
import re
from typing import Optional

_MAC_RE = re.compile(
    r'^([0-9a-fA-F]{2})'
    r'(?:[:\-]?[0-9a-fA-F]{2}){5}$'
)


def _clean_mac(mac: str) -> Optional[bytes]:
    """
    Normalise a MAC string to 6 raw bytes.
    Returns None if the format is unrecognisable.
    """
    clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    if len(clean) != 12 or not re.fullmatch(r'[0-9A-F]{12}', clean):
        return None
    return bytes(int(clean[i:i+2], 16) for i in range(0, 12, 2))


def send_wol(
    mac: str,
    broadcast: str = '255.255.255.255',
    port: int = 9,
    repeat: int = 3,
) -> dict:
    """
    Build and broadcast a WOL magic packet.

    The magic packet is:
        6 × 0xFF  followed by  16 × MAC address bytes  = 102 bytes

    Parameters
    ──────────
    mac        — target MAC address (any common separator format)
    broadcast  — destination broadcast IP (default: global broadcast)
    port       — UDP port, traditionally 7 or 9
    repeat     — number of times to send (improves reliability on lossy networks)

    Returns
    ───────
    {"ok": True}  or  {"ok": False, "error": "..."}
    """
    mac_bytes = _clean_mac(mac)
    if mac_bytes is None:
        return {"ok": False, "error": f"Invalid MAC address: '{mac}'"}

    # Build the magic packet: 6 FF bytes + 16 repetitions of the MAC
    packet = b'\xff' * 6 + mac_bytes * 16

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(2)
            for _ in range(repeat):
                s.sendto(packet, (broadcast, port))
        return {"ok": True, "mac": mac.upper(), "broadcast": broadcast, "port": port}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def validate_mac(mac: str) -> bool:
    """Return True if *mac* is a parseable MAC address."""
    return _clean_mac(mac) is not None


def format_mac(mac: str) -> Optional[str]:
    """Return MAC in canonical AA:BB:CC:DD:EE:FF format, or None if invalid."""
    raw = _clean_mac(mac)
    if raw is None:
        return None
    return ':'.join(f'{b:02X}' for b in raw)
