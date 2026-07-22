#!/usr/bin/env python3
"""
macmask.py - A cross-platform MAC address masking utility.

Written as an information-security coursework project. Demonstrates:
  * IEEE 802 MAC address structure (OUI, U/L bit, I/G bit)
  * Generating standards-compliant locally-administered addresses
  * Vendor-plausible spoofing via real OUI prefixes
  * Platform-specific interface reconfiguration (Linux / macOS / Windows)
  * Safe restoration of the permanent (burned-in) hardware address

Requires administrator / root privileges to apply changes.
Use --dry-run to print the exact commands without executing them.
"""

import argparse
import ctypes
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# 1. MAC ADDRESS FUNDAMENTALS
# ---------------------------------------------------------------------------
#
# A MAC address is 48 bits, written as six hexadecimal octets.
#
#   ac : bc : 32 : 1f : 4e : 09
#   |________|    |__________|
#      OUI            NIC
#   (vendor ID)   (device ID)
#
# The two least-significant bits of the FIRST octet are flags:
#
#   bit 0 (0x01)  I/G  Individual/Group  0 = unicast, 1 = multicast
#   bit 1 (0x02)  U/L  Universal/Local   0 = vendor-assigned, 1 = locally
#                                            administered
#
# A randomly generated address MUST set the U/L bit and clear the I/G bit.
# Setting U/L declares "this address was not assigned by the IEEE," which
# guarantees it cannot collide with a real vendor allocation. This is exactly
# what iOS, Android, Windows and macOS do for their built-in Wi-Fi private
# address features.

IG_BIT = 0b00000001  # multicast flag
UL_BIT = 0b00000010  # locally-administered flag

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

# Real OUI prefixes, used for "blend in with the crowd" spoofing. An address
# that is locally administered is trivially identifiable as randomized, which
# on some networks is itself a signal. Borrowing a common vendor prefix makes
# the device look like ordinary hardware. Illustrative sample only - the full
# registry is published by the IEEE.
VENDOR_OUIS = {
    "apple":       ["00:1b:63", "ac:bc:32", "f0:18:98", "3c:07:54"],
    "samsung":     ["00:12:47", "5c:0a:5b", "78:1f:db", "e8:50:8b"],
    "intel":       ["00:1b:21", "3c:97:0e", "8c:16:45", "a4:c4:94"],
    "dell":        ["00:14:22", "18:03:73", "d4:be:d9", "f8:bc:12"],
    "cisco":       ["00:1a:a1", "00:26:0b", "f4:4e:05", "70:70:8b"],
    "hp":          ["00:1f:29", "3c:d9:2b", "94:57:a5", "d4:c9:ef"],
    "raspberrypi": ["b8:27:eb", "dc:a6:32", "e4:5f:01", "28:cd:c1"],
}


def normalize(mac: str) -> str:
    """Return a lowercase colon-separated MAC."""
    return mac.replace("-", ":").lower()


def is_valid(mac: str) -> bool:
    return bool(MAC_RE.match(mac))


def describe(mac: str) -> str:
    """Human-readable analysis of a MAC's flag bits."""
    first = int(normalize(mac).split(":")[0], 16)
    scope = "locally administered" if first & UL_BIT else "universal (vendor-assigned)"
    cast = "multicast" if first & IG_BIT else "unicast"
    return f"{scope}, {cast}"


def random_mac(oui: str | None = None) -> str:
    """
    Generate a random MAC.

    If `oui` is given, the first three octets are preserved verbatim so the
    address remains attributable to that vendor. Otherwise a fully random
    locally-administered address is produced.
    """
    if oui:
        prefix = [int(o, 16) for o in normalize(oui).split(":")]
    else:
        first = random.randint(0x00, 0xFF)
        first |= UL_BIT   # mark as locally administered
        first &= ~IG_BIT  # ensure unicast
        prefix = [first, random.randint(0x00, 0xFF), random.randint(0x00, 0xFF)]

    suffix = [random.randint(0x00, 0xFF) for _ in range(3)]
    return ":".join(f"{b:02x}" for b in prefix + suffix)


def vendor_mac(vendor: str) -> str:
    key = vendor.lower()
    if key not in VENDOR_OUIS:
        raise ValueError(
            f"Unknown vendor '{vendor}'. Choose from: {', '.join(sorted(VENDOR_OUIS))}"
        )
    return random_mac(random.choice(VENDOR_OUIS[key]))


# ---------------------------------------------------------------------------
# 2. PERSISTENT STATE
# ---------------------------------------------------------------------------
# The permanent address is recorded the first time an interface is modified so
# that `restore` always has a truthful target, even across reboots.

STATE_FILE = Path.home() / ".macmask.json"


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2))
        os.chmod(STATE_FILE, 0o600)
    except OSError as exc:
        print(f"[!] Could not persist state: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 3. PLATFORM BACKENDS
# ---------------------------------------------------------------------------

class Backend:
    """Interface every platform implementation must satisfy."""

    name = "generic"

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        if self.dry_run:
            print("    $ " + " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def list_interfaces(self) -> list[dict]:
        raise NotImplementedError

    def permanent_mac(self, iface: str) -> str | None:
        return None

    def set_mac(self, iface: str, mac: str) -> None:
        raise NotImplementedError


class LinuxBackend(Backend):
    name = "linux"

    def list_interfaces(self) -> list[dict]:
        out = []
        net = Path("/sys/class/net")
        for dev in sorted(net.iterdir()):
            addr_file = dev / "address"
            if not addr_file.exists():
                continue
            try:
                mac = addr_file.read_text().strip()
            except OSError:
                continue
            state = (dev / "operstate")
            out.append({
                "name": dev.name,
                "mac": mac,
                "state": state.read_text().strip() if state.exists() else "unknown",
                "wireless": (dev / "wireless").exists() or (dev / "phy80211").exists(),
            })
        return out

    def permanent_mac(self, iface: str) -> str | None:
        # ethtool reports the burned-in address, which survives spoofing.
        if not shutil.which("ethtool"):
            return None
        try:
            res = subprocess.run(["ethtool", "-P", iface],
                                 capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, OSError):
            return None
        tail = res.stdout.strip().split()[-1]
        if is_valid(tail) and tail != "00:00:00:00:00:00":
            return normalize(tail)
        return None

    def set_mac(self, iface: str, mac: str) -> None:
        # The link must be administratively down; the kernel refuses an
        # address change on a live interface for most drivers.
        self.run(["ip", "link", "set", "dev", iface, "down"])
        self.run(["ip", "link", "set", "dev", iface, "address", mac])
        self.run(["ip", "link", "set", "dev", iface, "up"])


class DarwinBackend(Backend):
    name = "darwin"

    AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")

    def list_interfaces(self) -> list[dict]:
        try:
            names = subprocess.run(["ifconfig", "-l"], capture_output=True,
                                   text=True, check=True).stdout.split()
        except (subprocess.CalledProcessError, OSError):
            return []
        out = []
        for n in names:
            try:
                detail = subprocess.run(["ifconfig", n], capture_output=True,
                                        text=True, check=True).stdout
            except (subprocess.CalledProcessError, OSError):
                continue
            m = re.search(r"ether\s+([0-9a-f:]{17})", detail)
            if not m:
                continue
            out.append({
                "name": n,
                "mac": m.group(1),
                "state": "up" if "status: active" in detail else "down",
                "wireless": n.startswith("en") and "802.11" in detail,
            })
        return out

    def set_mac(self, iface: str, mac: str) -> None:
        # Wi-Fi must be disassociated first or the change silently reverts
        # when the supplicant re-authenticates.
        if Path(self.AIRPORT).exists():
            self.run([self.AIRPORT, "-z"], check=False)
        self.run(["ifconfig", iface, "ether", mac])
        self.run(["ifconfig", iface, "up"], check=False)


class WindowsBackend(Backend):
    name = "windows"

    # Every network class driver lives under this registry key. Writing a
    # NetworkAddress value there makes the driver present a different address
    # to the NIC on next initialisation.
    CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

    def list_interfaces(self) -> list[dict]:
        ps = ("Get-NetAdapter | Select-Object Name,MacAddress,Status,"
              "InterfaceDescription,PhysicalMediaType | ConvertTo-Json -Compress")
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, check=True)
            data = json.loads(res.stdout or "[]")
        except (subprocess.CalledProcessError, OSError, json.JSONDecodeError):
            return []
        if isinstance(data, dict):
            data = [data]
        return [{
            "name": d.get("Name", "?"),
            "mac": normalize(d.get("MacAddress", "") or ""),
            "state": d.get("Status", "?"),
            "wireless": "802.11" in (d.get("PhysicalMediaType") or ""),
            "desc": d.get("InterfaceDescription", ""),
        } for d in data]

    def _find_registry_subkey(self, iface: str) -> str | None:
        import winreg
        target = None
        for entry in self.list_interfaces():
            if entry["name"].lower() == iface.lower():
                target = entry.get("desc", "")
                break
        if not target:
            return None
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.CLASS_KEY) as root:
            for i in range(2048):
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                if not sub.isdigit():
                    continue
                try:
                    with winreg.OpenKey(root, sub) as k:
                        desc, _ = winreg.QueryValueEx(k, "DriverDesc")
                        if desc == target:
                            return sub
                except OSError:
                    continue
        return None

    def set_mac(self, iface: str, mac: str) -> None:
        import winreg
        sub = self._find_registry_subkey(iface)
        if sub is None:
            raise RuntimeError(f"No registry entry found for adapter '{iface}'")

        # Windows expects twelve bare hex digits, no separators.
        value = mac.replace(":", "").lower()
        path = f"{self.CLASS_KEY}\\{sub}"

        if self.dry_run:
            print(f"    reg: HKLM\\{path}\\NetworkAddress = {value}")
        else:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "NetworkAddress", 0, winreg.REG_SZ, value)

        # The driver only re-reads NetworkAddress during initialisation.
        self.run(["powershell", "-NoProfile", "-Command",
                  f"Restart-NetAdapter -Name '{iface}' -Confirm:$false"])

    def clear_registry_override(self, iface: str) -> None:
        import winreg
        sub = self._find_registry_subkey(iface)
        if sub is None:
            return
        path = f"{self.CLASS_KEY}\\{sub}"
        if self.dry_run:
            print(f"    reg: DELETE HKLM\\{path}\\NetworkAddress")
            return
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, "NetworkAddress")
        except FileNotFoundError:
            pass
        self.run(["powershell", "-NoProfile", "-Command",
                  f"Restart-NetAdapter -Name '{iface}' -Confirm:$false"])


def get_backend(dry_run: bool = False) -> Backend:
    system = platform.system().lower()
    if system == "linux":
        return LinuxBackend(dry_run)
    if system == "darwin":
        return DarwinBackend(dry_run)
    if system == "windows":
        return WindowsBackend(dry_run)
    raise RuntimeError(f"Unsupported platform: {platform.system()}")


def is_privileged() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# 4. COMMANDS
# ---------------------------------------------------------------------------

def cmd_list(backend: Backend, args) -> int:
    interfaces = backend.list_interfaces()
    if not interfaces:
        print("No interfaces found.")
        return 1

    state = load_state()
    print(f"{'INTERFACE':<16}{'MAC ADDRESS':<20}{'STATE':<10}TYPE")
    print("-" * 62)
    for i in interfaces:
        kind = "wireless" if i["wireless"] else "wired"
        flag = " *" if i["name"] in state else ""
        print(f"{i['name']:<16}{i['mac']:<20}{i['state']:<10}{kind}{flag}")
        if args.verbose and i["mac"]:
            print(f"{'':<16}└─ {describe(i['mac'])}")
    if any(i["name"] in state for i in interfaces):
        print("\n* currently masked - run 'restore' to revert")
    return 0


def _apply(backend: Backend, iface: str, new_mac: str, dry_run: bool) -> int:
    interfaces = {i["name"]: i for i in backend.list_interfaces()}
    if iface not in interfaces:
        print(f"[!] Interface '{iface}' not found. Run 'list' to see options.",
              file=sys.stderr)
        return 1

    current = interfaces[iface]["mac"]
    state = load_state()

    # Record the true hardware address exactly once.
    if iface not in state:
        original = backend.permanent_mac(iface) or current
        state[iface] = {"original": original}
        save_state(state)

    print(f"Interface : {iface}")
    print(f"Current   : {current}  ({describe(current) if current else 'n/a'})")
    print(f"New       : {new_mac}  ({describe(new_mac)})")
    print()

    try:
        backend.set_mac(iface, new_mac)
    except (subprocess.CalledProcessError, RuntimeError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        print(f"[!] Failed to set address: {detail}".rstrip(), file=sys.stderr)
        return 1

    if dry_run:
        print("[dry-run] No changes were made.")
        return 0

    verify = {i["name"]: i["mac"] for i in backend.list_interfaces()}.get(iface)
    if verify == new_mac:
        print(f"[+] Success - {iface} is now {new_mac}")
        return 0
    print(f"[!] Verification failed. Interface reports {verify}.\n"
          f"    The driver may not support address override.", file=sys.stderr)
    return 1


def cmd_random(backend: Backend, args) -> int:
    return _apply(backend, args.interface, random_mac(), args.dry_run)


def cmd_vendor(backend: Backend, args) -> int:
    try:
        mac = vendor_mac(args.vendor)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return _apply(backend, args.interface, mac, args.dry_run)


def cmd_set(backend: Backend, args) -> int:
    mac = normalize(args.mac)
    if not is_valid(mac):
        print(f"[!] '{args.mac}' is not a valid MAC address.", file=sys.stderr)
        return 1
    if int(mac.split(":")[0], 16) & IG_BIT:
        print("[!] Refusing: the I/G bit is set, making this a multicast "
              "address. A station address must be unicast.", file=sys.stderr)
        return 1
    return _apply(backend, args.interface, mac, args.dry_run)


def cmd_restore(backend: Backend, args) -> int:
    state = load_state()
    iface = args.interface
    if iface not in state:
        print(f"[!] No saved address for '{iface}'. Nothing to restore.",
              file=sys.stderr)
        return 1

    original = state[iface]["original"]
    if isinstance(backend, WindowsBackend):
        # On Windows the correct revert is deleting the override so the
        # driver falls back to the burned-in address.
        print(f"Clearing registry override for {iface}...")
        backend.clear_registry_override(iface)
        rc = 0
    else:
        rc = _apply(backend, iface, original, args.dry_run)

    if rc == 0 and not args.dry_run:
        state.pop(iface, None)
        save_state(state)
        print(f"[+] {iface} restored to its permanent address.")
    return rc


def cmd_generate(backend: Backend, args) -> int:
    """Generate addresses without touching any interface - useful for demos."""
    for _ in range(args.count):
        mac = vendor_mac(args.vendor) if args.vendor else random_mac()
        print(f"{mac}   {describe(mac)}")
    return 0


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macmask",
        description="Mask, randomize and restore network interface MAC addresses.",
        epilog="Requires root/administrator privileges for anything except "
               "'list' and 'generate'.",
    )
    p.add_argument("--version", action="version", version=f"macmask {__version__}")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="print the commands that would run, change nothing")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list", help="show interfaces and their addresses")
    s.add_argument("-v", "--verbose", action="store_true",
                   help="decode the U/L and I/G flag bits")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("random", help="assign a random locally-administered address")
    s.add_argument("interface")
    s.set_defaults(func=cmd_random)

    s = sub.add_parser("vendor", help="assign a random address under a real vendor OUI")
    s.add_argument("interface")
    s.add_argument("vendor", choices=sorted(VENDOR_OUIS))
    s.set_defaults(func=cmd_vendor)

    s = sub.add_parser("set", help="assign a specific address")
    s.add_argument("interface")
    s.add_argument("mac")
    s.set_defaults(func=cmd_set)

    s = sub.add_parser("restore", help="revert to the permanent hardware address")
    s.add_argument("interface")
    s.set_defaults(func=cmd_restore)

    s = sub.add_parser("generate", help="print sample addresses without applying them")
    s.add_argument("-c", "--count", type=int, default=5)
    s.add_argument("-V", "--vendor", choices=sorted(VENDOR_OUIS))
    s.set_defaults(func=cmd_generate)

    return p


def main() -> int:
    args = build_parser().parse_args()

    try:
        backend = get_backend(args.dry_run)
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    needs_root = args.command in {"random", "vendor", "set", "restore"}
    if needs_root and not args.dry_run and not is_privileged():
        hint = "Run from an elevated prompt." if os.name == "nt" else "Try sudo."
        print(f"[!] '{args.command}' requires administrator privileges. {hint}",
              file=sys.stderr)
        return 1

    return args.func(backend, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
