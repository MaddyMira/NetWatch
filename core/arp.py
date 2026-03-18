"""
core/arp.py
───────────
ARP table reader and MAC-vendor resolver.

  get_arp_table()          → parse OS ARP cache → [{ip, mac, interface}]
  lookup_vendor(mac)       → vendor string from embedded OUI dict
  refresh_mac_cache(db)    → run ARP + write results into mac_cache table,
                             returns list of enriched entries

No external dependencies; uses only stdlib subprocess / socket.
"""
import re
import subprocess
import os
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Embedded OUI database (~300 entries, covers the vast majority of
# home/office/enterprise hardware by market share)
# Key format: first 6 uppercase hex chars, no separators.
# ─────────────────────────────────────────────────────────────────────────────

_OUI: Dict[str, str] = {
    # Apple
    "000A27":"Apple","000D93":"Apple","0010FA":"Apple","001124":"Apple",
    "001451":"Apple","0017F2":"Apple","001CB3":"Apple","0021E9":"Apple",
    "002312":"Apple","002500":"Apple","002608":"Apple","0050E4":"Apple",
    "00616C":"Apple","008065":"Apple","00C610":"Apple","040CCE":"Apple",
    "04F7E4":"Apple","0C4DE9":"Apple","0C74C2":"Apple","10494C":"Apple",
    "105083":"Apple","10DDB1":"Apple","1499E2":"Apple","18AF61":"Apple",
    "1C1AC0":"Apple","1C5CF2":"Apple","1C9E46":"Apple","20C9D0":"Apple",
    "28E02C":"Apple","2C1F23":"Apple","2CF0EE":"Apple","38C986":"Apple",
    "3C0754":"Apple","3C15C2":"Apple","407705":"Apple","4860BC":"Apple",
    "50EAD6":"Apple","54AE27":"Apple","58B035":"Apple","5C5948":"Apple",
    "60FB42":"Apple","6C4008":"Apple","6CAB31":"Apple","7006C6":"Apple",
    "7466E3":"Apple","78D75F":"Apple","78FD94":"Apple","7CC3A1":"Apple",
    "8C8590":"Apple","90B0ED":"Apple","94BF2D":"Apple","9801A7":"Apple",
    "A4B197":"Apple","A8BE27":"Apple","A8FAD8":"Apple","AC3C0B":"Apple",
    "ACC17E":"Apple","B065BD":"Apple","B4F0AB":"Apple","B8FF61":"Apple",
    "BC4CC4":"Apple","C82A14":"Apple","C86F1D":"Apple","CC08E0":"Apple",
    "D0E140":"Apple","D4F46F":"Apple","D82060":"Apple","DC2B2A":"Apple",
    "E0AC9B":"Apple","E4CE8F":"Apple","E8040B":"Apple","ECB5FA":"Apple",
    "F02475":"Apple","F45C89":"Apple","F4F15A":"Apple","F81EDF":"Apple",
    # Cisco
    "000142":"Cisco","000164":"Cisco","00017D":"Cisco","0001C9":"Cisco",
    "000216":"Cisco","00023B":"Cisco","00024B":"Cisco","00025B":"Cisco",
    "0002B9":"Cisco","0002FC":"Cisco","000301":"Cisco","00030F":"Cisco",
    "000340":"Cisco","000393":"Cisco","0003FD":"Cisco","000472":"Cisco",
    "0004DD":"Cisco","000502":"Cisco","000543":"Cisco","0005DC":"Cisco",
    "0006C1":"Cisco","000702":"Cisco","00072C":"Cisco","000785":"Cisco",
    "0007B3":"Cisco","0007EB":"Cisco","000813":"Cisco","00083E":"Cisco",
    "000906":"Cisco","000953":"Cisco","000B46":"Cisco","000BFC":"Cisco",
    "000C30":"Cisco","000D28":"Cisco","000D29":"Cisco","000D65":"Cisco",
    "000E08":"Cisco","000E38":"Cisco","000E83":"Cisco","000EF7":"Cisco",
    # Intel
    "001111":"Intel","001320":"Intel","00131E":"Intel","001517":"Intel",
    "0019D1":"Intel","001CC0":"Intel","002213":"Intel","00237A":"Intel",
    "0024D6":"Intel","00265A":"Intel","4C1487":"Intel","4CE17A":"Intel",
    "648D89":"Intel","7085C2":"Intel","8C8D28":"Intel","8C8590":"Intel",
    "9C4E36":"Intel","A0369F":"Intel","B0A4E4":"Intel","D4BE73":"Intel",
    # Samsung
    "000DBF":"Samsung","000DEE":"Samsung","0015B9":"Samsung","0018AF":"Samsung",
    "001D25":"Samsung","001EE1":"Samsung","0021D1":"Samsung","002339":"Samsung",
    "0024E9":"Samsung","002454":"Samsung","0026E2":"Samsung","00C0A5":"Samsung",
    "007232":"Samsung","047D7B":"Samsung","08FD0E":"Samsung","10D56A":"Samsung",
    "14495E":"Samsung","1C62B8":"Samsung","200DB0":"Samsung","24921A":"Samsung",
    "2C0E3D":"Samsung","34145F":"Samsung","3C62FE":"Samsung","4047D8":"Samsung",
    "445154":"Samsung","4C3C16":"Samsung","5001BB":"Samsung","5479DB":"Samsung",
    "546C0E":"Samsung","6C8336":"Samsung","6CB7F4":"Samsung","744427":"Samsung",
    "78BDBC":"Samsung","7C61B8":"Samsung","848506":"Samsung","88329B":"Samsung",
    "94D7B5":"Samsung","94E974":"Samsung","A8063B":"Samsung","AC5F3E":"Samsung",
    "B047BF":"Samsung","B47443":"Samsung","BC7727":"Samsung","C01173":"Samsung",
    "C819F7":"Samsung","CC07AB":"Samsung","D0176A":"Samsung","D487D8":"Samsung",
    "E4A7C5":"Samsung","E87724":"Samsung","ECACEB":"Samsung",
    # Raspberry Pi Foundation
    "2CCF67":"Raspberry Pi","B827EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
    "DCA632":"Raspberry Pi","E45F01":"Raspberry Pi",
    # TP-Link
    "14CC20":"TP-Link","1C61B4":"TP-Link","244BFE":"TP-Link","2831AA":"TP-Link",
    "2C54CF":"TP-Link","30DE4B":"TP-Link","50C7BF":"TP-Link","54AF97":"TP-Link",
    "60E3AC":"TP-Link","6466B3":"TP-Link","685B35":"TP-Link","6CB0CE":"TP-Link",
    "70AFA0":"TP-Link","74EA3A":"TP-Link","788CB5":"TP-Link","8C10D4":"TP-Link",
    "908D78":"TP-Link","940A1C":"TP-Link","9CEB8A":"TP-Link","A0F3C1":"TP-Link",
    "A42BB0":"TP-Link","B0487A":"TP-Link","B09575":"TP-Link","C46E1F":"TP-Link",
    "D8EB97":"TP-Link","E848B8":"TP-Link","EC1726":"TP-Link","F09FC2":"TP-Link",
    # Netgear
    "00095B":"Netgear","000FB5":"Netgear","001B2F":"Netgear","001E2A":"Netgear",
    "004069":"Netgear","00CAE6":"Netgear","04A151":"Netgear","08BD43":"Netgear",
    "0C9D92":"Netgear","208605":"Netgear","28C68E":"Netgear","30469A":"Netgear",
    "3C3786":"Netgear","40167E":"Netgear","44944B":"Netgear","4C60DE":"Netgear",
    "6CB0CE":"Netgear","8460EB":"Netgear","9C3DCF":"Netgear","A040A0":"Netgear",
    "C04A00":"Netgear","C43DC7":"Netgear","C83A35":"Netgear","CC40D0":"Netgear",
    # D-Link
    "000F3D":"D-Link","001195":"D-Link","001346":"D-Link","0015E9":"D-Link",
    "0018E7":"D-Link","001CF0":"D-Link","001E58":"D-Link","002191":"D-Link",
    "0026B9":"D-Link","1062EB":"D-Link","14D64D":"D-Link","1C7EE5":"D-Link",
    "28107B":"D-Link","34A84E":"D-Link","3C1E04":"D-Link","4CC418":"D-Link",
    "5CD998":"D-Link","6045CB":"D-Link","6490C1":"D-Link","9094E4":"D-Link",
    "B8A386":"D-Link","C4A81D":"D-Link","CC4699":"D-Link","F07D68":"D-Link",
    # Ubiquiti
    "00272D":"Ubiquiti","0418D6":"Ubiquiti","0C8112":"Ubiquiti","18E829":"Ubiquiti",
    "241302":"Ubiquiti","2AEE08":"Ubiquiti","44D9E7":"Ubiquiti","4CCA4B":"Ubiquiti",
    "60A4B7":"Ubiquiti","68D79A":"Ubiquiti","78453C":"Ubiquiti","788A20":"Ubiquiti",
    "7C5152":"Ubiquiti","802AA8":"Ubiquiti","986D35":"Ubiquiti","9C050C":"Ubiquiti",
    "B4FBE4":"Ubiquiti","DC9FDB":"Ubiquiti","E063DA":"Ubiquiti","F09FC2":"Ubiquiti",
    "F4E2C6":"Ubiquiti","FC:EC:DA":"Ubiquiti","FCECDA":"Ubiquiti",
    # Synology
    "001132":"Synology","0011324":"Synology","0C17A3":"Synology","1459C0":"Synology",
    "A8107B":"Synology","BC5FF4":"Synology","F4B8A7":"Synology",
    # QNAP
    "001402":"QNAP","247706":"QNAP","246895":"QNAP",
    # Mikrotik
    "000C42":"Mikrotik","18FD74":"Mikrotik","2CC8DC":"Mikrotik","4C5E0C":"Mikrotik",
    "6C3B6B":"Mikrotik","74AD0A":"Mikrotik","B8690A":"Mikrotik","C4AD34":"Mikrotik",
    # Broadcom
    "000AF7":"Broadcom","001018":"Broadcom","001E67":"Broadcom",
    # Realtek
    "00E04C":"Realtek","0060FF":"Realtek","52540C":"Realtek",
    # VMware / virtualisation
    "000C29":"VMware","000569":"VMware","001C14":"VMware","005056":"VMware",
    "080027":"VirtualBox","525400":"QEMU/KVM",
    # Google
    "001A11":"Google","003048":"Google","1C3ADE":"Google","3C5AB4":"Google",
    "48D705":"Google","54517E":"Google","58CB52":"Google","6C40CF":"Google",
    "9C2EBA":"Google","A4770A":"Google","F88FCA":"Google",
    # Amazon
    "F0272D":"Amazon","6C5697":"Amazon","40B4CD":"Amazon","74C246":"Amazon",
    "A002DC":"Amazon",
    # Microsoft / Xbox
    "00125A":"Microsoft","001DD8":"Microsoft","0017FA":"Microsoft","0025AE":"Microsoft",
    "7C1E52":"Microsoft","985FD3":"Microsoft",
    # HP
    "00096B":"HP","001321":"HP","0014C2":"HP","001708":"HP","0019BB":"HP",
    "001B78":"HP","001CC4":"HP","001E0B":"HP","002354":"HP","0024A8":"HP",
    "3C4A92":"HP","40B034":"HP","4CB199":"HP","5CB901":"HP","8C8D28":"HP",
    "A0B3CC":"HP","B499BA":"HP","D8D385":"HP","E82291":"HP",
    # Dell
    "000874":"Dell","0013E8":"Dell","00188B":"Dell","001A4B":"Dell",
    "001BFC":"Dell","001D09":"Dell","002170":"Dell","002248":"Dell",
    "002564":"Dell","14187E":"Dell","18DB F2":"Dell","1866DA":"Dell",
    "5C26OA":"Dell","843835":"Dell","9CEBE8":"Dell","B083FE":"Dell",
    "B08D54":"Dell","D4BE73":"Dell","F8DB88":"Dell",
    # Lenovo
    "000732":"Lenovo","001077":"Lenovo","286ED4":"Lenovo","4C7957":"Lenovo",
    "6045CB":"Lenovo","788CB5":"Lenovo","8C8D28":"Lenovo","AC7BA1":"Lenovo",
    "F81654":"Lenovo",
    # Asus
    "001A92":"Asus","047192":"Asus","08606E":"Asus","10BF48":"Asus",
    "1C872C":"Asus","24052B":"Asus","2C56DC":"Asus","3497F6":"Asus",
    "40167E":"Asus","48EE0C":"Asus","50465D":"Asus","5404A6":"Asus",
    "60A44C":"Asus","74D02B":"Asus","9C5C8E":"Asus","AC9E17":"Asus",
    "B06EBF":"Asus","E03F49":"Asus","F42853":"Asus",
    # Xiaomi
    "28E31F":"Xiaomi","34CE00":"Xiaomi","50EC50":"Xiaomi","64680C":"Xiaomi",
    "6C5AB5":"Xiaomi","74606B":"Xiaomi","8C4B14":"Xiaomi","98FAE3":"Xiaomi",
    "A87040":"Xiaomi","AC2260":"Xiaomi","B0E235":"Xiaomi","D4970B":"Xiaomi",
    "F48B32":"Xiaomi","F4F5DB":"Xiaomi","FC64BA":"Xiaomi",
    # Huawei
    "001E10":"Huawei","00259E":"Huawei","002EC7":"Huawei","003048":"Huawei",
    "0090FC":"Huawei","042B28":"Huawei","087A4C":"Huawei","0C37DC":"Huawei",
    "105172":"Huawei","1476FE":"Huawei","18C582":"Huawei","1CB044":"Huawei",
    "202BC1":"Huawei","280985":"Huawei","2C9EFB":"Huawei","3431C4":"Huawei",
    "3C47C9":"Huawei","40A0DC":"Huawei","444F8E":"Huawei","4C1FAB":"Huawei",
    "50BFA8":"Huawei","546742":"Huawei","5C8A38":"Huawei","60DE44":"Huawei",
    "6476BA":"Huawei","68A086":"Huawei","6CB311":"Huawei","704A0E":"Huawei",
    "78B554":"Huawei","7C60B7":"Huawei","8446FE":"Huawei","88E3AB":"Huawei",
    "90E7C4":"Huawei","983848":"Huawei","9C37F4":"Huawei","A03091":"Huawei",
    "A49C40":"Huawei","A4CAA0":"Huawei","B4430D":"Huawei","BC7574":"Huawei",
    "C8D15E":"Huawei","CC96A0":"Huawei","D0172B":"Huawei","D4612E":"Huawei",
    "D8490B":"Huawei","DC729C":"Huawei","E0244B":"Huawei","E4C2D1":"Huawei",
    "E8CD2D":"Huawei","F46AF7":"Huawei","F8018A":"Huawei","FC3F7C":"Huawei",
}


# ─────────────────────────────────────────────────────────────────────────────
# OUI lookup
# ─────────────────────────────────────────────────────────────────────────────

def lookup_vendor(mac: str) -> str:
    """
    Return vendor name for *mac*, or the raw OUI prefix if unknown.
    Input: any common MAC format (aa:bb:cc:dd:ee:ff / aa-bb-cc / AABBCC…)
    """
    if not mac:
        return "Unknown"
    # Normalise: strip separators, uppercase, take first 6 chars
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    oui   = clean[:6]
    vendor = _OUI.get(oui)
    if vendor:
        return vendor
    # Try partial match (sometimes 7-char OUI prefixes with sub-assignments)
    for key, val in _OUI.items():
        if key.startswith(oui[:4]):
            return val
    # Format as XX:XX:XX for display
    return f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"


# ─────────────────────────────────────────────────────────────────────────────
# ARP table reader
# ─────────────────────────────────────────────────────────────────────────────

_MAC_RE = re.compile(
    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
)
_IP_RE  = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def get_arp_table() -> List[Dict]:
    """
    Parse the OS ARP cache and return a list of
    {'ip': str, 'mac': str, 'interface': str}.
    Works on Windows and Linux/macOS.
    """
    entries: List[Dict] = []
    try:
        if os.name == "nt":
            entries = _parse_windows_arp()
        else:
            entries = _parse_linux_arp()
    except Exception as e:
        print(f"[arp] get_arp_table error: {e}")
    return entries


def _parse_windows_arp() -> List[Dict]:
    entries = []
    result  = subprocess.run(
        ["arp", "-a"], capture_output=True, text=True, shell=True, timeout=5
    )
    current_iface = ""
    for line in result.stdout.splitlines():
        # Interface header lines:  "Interface: 192.168.1.5 --- 0xf"
        if line.strip().lower().startswith("interface"):
            m = _IP_RE.search(line)
            current_iface = m.group(1) if m else line.strip()
            continue
        ip_m  = _IP_RE.search(line)
        mac_m = _MAC_RE.search(line)
        if ip_m and mac_m:
            ip  = ip_m.group(1)
            mac = mac_m.group(1).replace("-", ":").upper()
            # Skip broadcast / multicast
            if not ip.endswith(".255") and not ip.startswith("224.") \
               and not ip.startswith("239.") and mac != "FF:FF:FF:FF:FF:FF":
                entries.append({"ip": ip, "mac": mac, "interface": current_iface})
    return entries


def _parse_linux_arp() -> List[Dict]:
    entries = []
    # Try /proc/net/arp first (no subprocess needed)
    proc_arp = "/proc/net/arp"
    if os.path.exists(proc_arp):
        with open(proc_arp) as f:
            for line in f.readlines()[1:]:          # skip header
                parts = line.split()
                if len(parts) >= 6:
                    ip, _hw, flags, mac, _mask, iface = parts[:6]
                    if mac != "00:00:00:00:00:00" and flags != "0x0":
                        entries.append({
                            "ip": ip,
                            "mac": mac.upper(),
                            "interface": iface,
                        })
        return entries

    # Fallback: `arp -n`
    result = subprocess.run(
        ["arp", "-n"], capture_output=True, text=True, timeout=5
    )
    for line in result.stdout.splitlines()[1:]:
        ip_m  = _IP_RE.search(line)
        mac_m = _MAC_RE.search(line)
        if ip_m and mac_m:
            entries.append({
                "ip":        ip_m.group(1),
                "mac":       mac_m.group(1).upper(),
                "interface": line.split()[-1] if line.split() else "",
            })
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# High-level helper
# ─────────────────────────────────────────────────────────────────────────────

def refresh_mac_cache() -> List[Dict]:
    """
    Pull the OS ARP table, resolve vendor names, write into mac_cache,
    and return the enriched list.
    Import core.database lazily to avoid circular imports.
    """
    import core.database as db
    arp_rows = get_arp_table()
    enriched = []
    for row in arp_rows:
        vendor = lookup_vendor(row["mac"])
        db.set_mac(row["ip"], row["mac"], vendor)
        enriched.append({
            "ip":        row["ip"],
            "mac":       row["mac"],
            "vendor":    vendor,
            "interface": row["interface"],
        })
    return enriched
