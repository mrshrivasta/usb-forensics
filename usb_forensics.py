#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 USB FORENSICS TOOL (USBF)
 USB device history and live inventory for one host - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS DOES
   Reconstructs which USB devices have been attached to this machine, when, and
   for how long, from the evidence the operating system already keeps:

     Linux    /sys/bus/usb/devices for what is attached right now, and the
              kernel log (journalctl -k, /var/log/kern.log, syslog or dmesg)
              for history: vendor and product IDs, serial numbers, the driver
              that bound, and connect/disconnect times.
     Windows  the USBSTOR and USB registry keys, plus setupapi.dev.log for
              first-connection timestamps.
     macOS    system_profiler for the live tree, and the unified log for events.

   It then correlates those events into devices, builds a timeline, compares
   against a baseline of approved devices, and reports what a reviewer should
   look at: mass storage that was never approved, devices with no serial number,
   one serial appearing under two different product IDs, and the composite
   storage-plus-keyboard pattern that a BadUSB device produces.

 WHAT THIS IS NOT
   - Not a disk imager and not a file recovery tool. It never reads the contents
     of any USB device, only the metadata the OS recorded about it.
   - Not a live capture agent. It reads logs that already exist; anything that
     happened before your log rotation window is gone, and the tool says so
     rather than pretending the history is complete.
   - Not proof of anything on its own. A device appearing here means the kernel
     saw it. What a person did with it is a separate question.

 EVIDENCE INTEGRITY
   Nothing is inferred that the evidence does not support. A device with no
   serial number is reported as having no serial, never given a synthetic id. A
   log source that cannot be read is reported as unavailable with the reason,
   and any check depending on it is reported as not performed - never as a pass.
   Where a log format omits the year (classic syslog does), the assumed year is
   recorded and flagged rather than silently guessed.

 PRIVACY NOTICE
   USB serial numbers, device names and attachment times identify people and
   their hardware. On a shared or personal machine this is personal data. It
   stays in your local database, nothing is uploaded, no vendor lookup service
   is contacted, and 'purge' removes it. Tell people if you monitor a machine
   they use - in many places you are legally required to.

 LEGAL DISCLAIMER
   Examine only machines you own or are explicitly authorised in writing to
   examine. Reconstructing device history on someone else's computer without
   authorisation is likely a criminal offence and a serious privacy violation.
   For evidential work, image the machine and analyse the copy; reading logs on
   a live system changes that system. Provided "as is" with no warranty; the
   author accepts no liability for any loss, damage, or reliance on these
   findings.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone

APP_NAME = "USB Forensics Tool"
APP_SHORT = "USBF"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("USBF_DB", "usbf.db")

DISCLAIMER_SHORT = (
    "Reads only the USB metadata the OS already logged - never the contents of any device. "
    "Examine machines you own or are authorised to examine. History is limited by log "
    "retention, and a device appearing here is not proof of what anyone did with it."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    AUTHORISED USE ONLY. Examine only machines you own or have written permission to
    examine. This tool reads the operating system's own records of USB attachment -
    vendor and product IDs, serial numbers, drivers and timestamps. It never reads the
    contents of any connected device. History is bounded by log retention: anything
    rotated away is gone, and the tool reports the window it could actually see rather
    than implying completeness. A device listed here means the kernel enumerated it;
    what a person did with it is a separate question requiring separate evidence. For
    evidential work, image the machine and analyse the copy - reading logs on a live
    system changes that system. Provided "as is" with no warranty; the author accepts no
    liability for any loss, damage, or reliance on these findings."""
)

PRIVACY_NOTICE = (
    "USB serial numbers, device names and attachment times identify people and their "
    "hardware, and on a shared or personal machine they are personal data under GDPR and "
    "similar laws. This stays in your local database, no vendor lookup service is ever "
    "contacted, and 'purge' removes it. Tell people if you monitor a machine they use - "
    "in many places you are legally required to."
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 20.0, "high": 11.0, "medium": 5.0, "low": 1.5, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}

# USB base class codes (from the USB-IF class code list)
USB_CLASSES = {
    0x00: ("per-interface", "class declared per interface, not on the device"),
    0x01: ("audio", "microphone, speaker or audio interface"),
    0x02: ("communications", "modem, or a USB network adapter"),
    0x03: ("HID", "keyboard, mouse or other human interface device"),
    0x05: ("physical", "force feedback and similar"),
    0x06: ("image", "camera or scanner (PTP/MTP)"),
    0x07: ("printer", "printer"),
    0x08: ("mass storage", "flash drive, external disk, card reader"),
    0x09: ("hub", "USB hub"),
    0x0a: ("CDC data", "data interface for a communications device"),
    0x0b: ("smart card", "smart card reader"),
    0x0d: ("content security", "content protection device"),
    0x0e: ("video", "webcam"),
    0x0f: ("healthcare", "personal healthcare device"),
    0x10: ("audio/video", "audio/video device"),
    0xdc: ("diagnostic", "diagnostic device"),
    0xe0: ("wireless", "Bluetooth or wireless controller"),
    0xef: ("miscellaneous", "composite or vendor-defined function"),
    0xfe: ("application", "application-specific, e.g. DFU firmware update"),
    0xff: ("vendor-specific", "vendor defined; the class tells you nothing"),
}

# Driver names seen in kernel logs, mapped to what they imply about the device.
DRIVER_CLASS = {
    "usb-storage": "mass storage", "uas": "mass storage", "usbhid": "HID",
    "hid-generic": "HID", "hid-multitouch": "HID", "cdc_ether": "network",
    "cdc_ncm": "network", "rndis_host": "network", "r8152": "network",
    "ax88179_178a": "network", "cdc_acm": "serial", "ftdi_sio": "serial",
    "ch341": "serial", "cp210x": "serial", "pl2303": "serial",
    "btusb": "wireless", "uvcvideo": "video", "snd-usb-audio": "audio",
    "usblp": "printer", "hub": "hub", "usbfs": "raw access",
}

# Classes worth a second look when they appear unexpectedly.
NOTABLE_CLASSES = {
    "mass storage": ("Data can leave the machine on this device, or arrive on it.",
                     "medium"),
    "HID": ("A device that can type. This is the class a keystroke-injection tool "
            "(Rubber Ducky, Bash Bunny, malicious cable) presents.", "medium"),
    "network": ("A USB network adapter can add an unexpected network path, and can be "
                "used to intercept traffic or serve rogue DHCP.", "medium"),
    "serial": ("A serial adapter is normal for engineering work and unusual elsewhere.",
               "low"),
    "wireless": ("A wireless controller can bridge to networks outside your control.",
                 "low"),
}

# A small built-in fallback so common vendors still resolve when the system has no
# usb.ids file. It is deliberately short, factual and clearly marked as partial -
# nothing is invented, and an unknown id is reported as unknown.
BUILTIN_VENDORS = {
    "046d": "Logitech", "045e": "Microsoft", "05ac": "Apple", "8087": "Intel",
    "0781": "SanDisk", "0951": "Kingston", "090c": "Silicon Motion", "13fe": "Kingston (Phison)",
    "1058": "Western Digital", "0bc2": "Seagate", "152d": "JMicron", "174c": "ASMedia",
    "0480": "Toshiba", "1b1c": "Corsair", "058f": "Alcor Micro", "1f75": "Innostor",
    "0930": "Toshiba", "18a5": "Verbatim", "154b": "PNY", "0409": "NEC",
    "1d6b": "Linux Foundation (root hub)", "0424": "Microchip/SMSC", "2109": "VIA Labs",
    "05e3": "Genesys Logic", "0403": "FTDI", "10c4": "Silicon Labs", "1a86": "QinHeng",
    "067b": "Prolific", "04e8": "Samsung", "18d1": "Google", "2717": "Xiaomi",
    "12d1": "Huawei", "0e0f": "VMware", "80ee": "VirtualBox", "1b36": "Red Hat/QEMU",
    "0627": "QEMU", "413c": "Dell", "03f0": "HP", "17ef": "Lenovo", "1532": "Razer",
    "feed": "unregistered (commonly seen on DIY and injection devices)",
    "16d0": "MCS (shared vendor id, used by many small projects)",
    "239a": "Adafruit", "2341": "Arduino", "1209": "Generic/InterBiometrics (community ids)",
    "0bda": "Realtek Semiconductor", "8564": "Transcend", "125f": "ADATA",
    "1a40": "Terminus Technology (hub)", "04f2": "Chicony Electronics",
    "0c45": "Microdia", "0e8d": "MediaTek", "05c6": "Qualcomm", "0cf3": "Qualcomm Atheros",
    "138a": "Validity Sensors", "27c6": "Goodix", "0b05": "ASUSTek", "148f": "Ralink",
    "0d8c": "C-Media Electronics", "1c4f": "SiGma Micro", "062a": "MosArt Semiconductor",
}

USB_IDS_PATHS = [
    "/usr/share/misc/usb.ids", "/usr/share/hwdata/usb.ids", "/var/lib/usbutils/usb.ids",
    "/usr/share/usb.ids", "/usr/local/share/usb.ids",
    "C:\\Windows\\System32\\usb.ids",
]

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = int(seconds)
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def read_text(path: str, limit: int = 20_000_000) -> tuple[str | None, str | None]:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit), None
    except FileNotFoundError:
        return None, "not present"
    except PermissionError:
        return None, "permission denied (try sudo)"
    except IsADirectoryError:
        return None, "is a directory"
    except Exception as e:
        return None, str(e)


def run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return {"ok": p.returncode == 0, "out": p.stdout or "",
                "err": (p.stderr or "").strip()}
    except FileNotFoundError:
        return {"ok": False, "out": "", "err": f"{cmd[0]}: not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "out": "", "err": f"{cmd[0]}: timed out"}
    except Exception as e:
        return {"ok": False, "out": "", "err": f"{cmd[0]}: {e}"}


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


class Result:
    """A collector's output plus an honest status. Never fabricates."""

    def __init__(self, name: str):
        self.name = name
        self.data: list = []
        self.status = "ok"
        self.detail = ""
        self.source = ""

    def unavailable(self, detail: str):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail: str):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


# =============================================================================
# SECTION 2 - Vendor and product identification
#   Uses the system's usb.ids when present. No network lookup is ever performed:
#   that would leak the hardware inventory of the machine under examination.
# =============================================================================

class UsbIds:
    def __init__(self):
        self.vendors: dict[str, str] = {}
        self.products: dict[tuple[str, str], str] = {}
        self.source = "built-in partial list"
        self.loaded = False

    def load(self, path: str | None = None) -> "UsbIds":
        candidates = [path] if path else USB_IDS_PATHS
        for p in candidates:
            if not p or not os.path.isfile(p):
                continue
            txt, err = read_text(p, 6_000_000)
            if txt is None:
                continue
            vendor = None
            for line in txt.splitlines():
                if not line or line.startswith("#"):
                    continue
                if line.startswith("\t\t"):
                    continue
                if line.startswith("\t"):
                    m = re.match(r"^\t([0-9a-fA-F]{4})\s+(.+)$", line)
                    if m and vendor:
                        self.products[(vendor, m.group(1).lower())] = m.group(2).strip()
                    continue
                m = re.match(r"^([0-9a-fA-F]{4})\s+(.+)$", line)
                if m:
                    vendor = m.group(1).lower()
                    self.vendors[vendor] = m.group(2).strip()
                else:
                    vendor = None
            if self.vendors:
                self.source = p
                self.loaded = True
                break
        return self

    def vendor(self, vid: str) -> tuple[str, bool]:
        """Returns (name, is_known). Unknown ids are reported as unknown."""
        vid = (vid or "").lower()
        if vid in self.vendors:
            return self.vendors[vid], True
        if vid in BUILTIN_VENDORS:
            return BUILTIN_VENDORS[vid], True
        return "unknown vendor", False

    def product(self, vid: str, pid: str) -> tuple[str, bool]:
        key = ((vid or "").lower(), (pid or "").lower())
        if key in self.products:
            return self.products[key], True
        return "", False

    def note(self) -> str:
        if self.loaded:
            return f"vendor names resolved from {self.source} ({len(self.vendors)} vendors)"
        return ("usb.ids is not installed on this machine, so only a short built-in list of "
                "common vendors could be resolved. Install the 'usbutils' or 'hwdata' "
                "package for full names. No online lookup is performed by design.")


USBIDS = UsbIds()


# =============================================================================
# SECTION 3 - Evidence parsers (pure functions over text - fully testable)
# =============================================================================

# Kernel messages the USB stack emits. These formats are stable across kernels.
RE_NEW_DEVICE = re.compile(
    r"usb (?P<port>[\w.\-:]+): New USB device found, idVendor=(?P<vid>[0-9a-fA-F]{4}), "
    r"idProduct=(?P<pid>[0-9a-fA-F]{4})(?:, bcdDevice=\s*(?P<rev>[\d.]+))?")
RE_NEW_CONNECT = re.compile(
    r"usb (?P<port>[\w.\-:]+): new (?P<speed>[\w\- ]+) USB device number (?P<num>\d+)")
RE_STRINGS = re.compile(r"usb (?P<port>[\w.\-:]+): (?P<key>Product|Manufacturer|SerialNumber):"
                        r"(?P<val>.*)$")
RE_DISCONNECT = re.compile(r"usb (?P<port>[\w.\-:]+): USB disconnect, device number "
                           r"(?P<num>\d+)")
RE_DRIVER = re.compile(r"(?P<driver>[\w\-]+) (?P<port>[\w.\-]+:[\d.]+): (?P<msg>.+)$")
RE_SCSI_DISK = re.compile(r"sd \d+:\d+:\d+:\d+: \[(?P<dev>sd[a-z]+)\] Attached SCSI "
                          r"(?P<kind>removable disk|disk)")
RE_HID_INPUT = re.compile(r"input: (?P<name>.+?) as /devices/.*?/(?P<port>[\w.\-]+)/")
RE_HID_BIND = re.compile(r"hid-generic (?P<bus>\d{4}):(?P<vid>[0-9a-fA-F]{4}):"
                         r"(?P<pid>[0-9a-fA-F]{4})\.[0-9a-fA-F]+: input,hid\w+: "
                         r"(?P<desc>.+)$")

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                       r"(?P<time>\d{2}:\d{2}:\d{2})\s")
ISO_TS = re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
                    r"(?P<tz>[+-]\d{2}:?\d{2}|Z)?)\s")
DMESG_TS = re.compile(r"^\[\s*(?P<mono>\d+\.\d+)\]\s")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_log_timestamp(line: str, assume_year: int, boot_time: datetime | None = None
                        ) -> tuple[str | None, bool]:
    """Return (iso_timestamp, year_was_assumed).

    Classic syslog omits the year - a well-known forensic trap. We record which
    year we assumed and flag it rather than presenting a false certainty.
    """
    m = ISO_TS.match(line)
    if m:
        raw = m.group("iso").replace(" ", "T").replace(",", ".")
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.replace(microsecond=0).isoformat(), False
        except ValueError:
            return None, False
    m = SYSLOG_TS.match(line)
    if m:
        try:
            hh, mm, ss = (int(x) for x in m.group("time").split(":"))
            dt = datetime(assume_year, MONTHS[m.group("mon")], int(m.group("day")),
                          hh, mm, ss, tzinfo=timezone.utc)
            return dt.isoformat(), True
        except (ValueError, KeyError):
            return None, True
    m = DMESG_TS.match(line)
    if m and boot_time:
        try:
            dt = boot_time + timedelta(seconds=float(m.group("mono")))
            return dt.replace(microsecond=0).isoformat(), False
        except (ValueError, OverflowError):
            return None, False
    return None, False


def parse_kernel_log(text: str, assume_year: int | None = None,
                     boot_time: datetime | None = None) -> dict:
    """Extract USB attach and detach events from kernel log text.

    Works with journalctl, /var/log/kern.log, syslog and dmesg formats. Returns
    events plus the observed time window, so callers can be honest about how far
    back the evidence actually goes.
    """
    assume_year = assume_year or datetime.now(timezone.utc).year
    events: list[dict] = []
    # port -> partially assembled device record
    pending: dict[str, dict] = {}
    hid_bindings: list[dict] = []
    disks: list[dict] = []
    first_ts = last_ts = None
    assumed_year_used = False
    lines = 0

    for line in text.splitlines():
        lines += 1
        ts, assumed = parse_log_timestamp(line, assume_year, boot_time)
        if assumed:
            assumed_year_used = True
        if ts:
            first_ts = ts if first_ts is None or ts < first_ts else first_ts
            last_ts = ts if last_ts is None or ts > last_ts else last_ts

        m = RE_NEW_CONNECT.search(line)
        if m:
            pending[m.group("port")] = {
                "port": m.group("port"), "speed": m.group("speed").strip(),
                "device_number": m.group("num"), "ts": ts, "vid": None, "pid": None,
                "serial": None, "product": None, "manufacturer": None, "drivers": [],
                "year_assumed": assumed}
            continue

        m = RE_NEW_DEVICE.search(line)
        if m:
            rec = pending.setdefault(m.group("port"), {
                "port": m.group("port"), "speed": None, "device_number": None, "ts": ts,
                "serial": None, "product": None, "manufacturer": None, "drivers": [],
                "year_assumed": assumed})
            rec["vid"] = m.group("vid").lower()
            rec["pid"] = m.group("pid").lower()
            rec["revision"] = m.group("rev")
            rec["ts"] = rec.get("ts") or ts
            continue

        m = RE_STRINGS.search(line)
        if m:
            rec = pending.get(m.group("port"))
            if rec is not None:
                key = {"Product": "product", "Manufacturer": "manufacturer",
                       "SerialNumber": "serial"}[m.group("key")]
                val = m.group("val").strip()
                # an empty descriptor string means the device reported none - record
                # that as None rather than as an empty-string serial
                rec[key] = val or None
                if key == "serial":
                    # the strings block is the last thing emitted for a new device
                    events.append({**rec, "action": "connect", "ts": rec.get("ts") or ts})
                    rec["_emitted"] = True
            continue

        m = RE_DISCONNECT.search(line)
        if m:
            # emit the attach first if the strings block never completed, or the whole
            # device would vanish from the history at the moment it was unplugged
            stale = pending.get(m.group("port"))
            if stale and stale.get("vid") and not stale.get("_emitted"):
                events.append({**stale, "action": "connect"})
                stale["_emitted"] = True
            events.append({"action": "disconnect", "port": m.group("port"),
                           "device_number": m.group("num"), "ts": ts,
                           "vid": None, "pid": None, "serial": None, "product": None,
                           "manufacturer": None, "drivers": [], "year_assumed": assumed})
            pending.pop(m.group("port"), None)
            continue

        m = RE_HID_BIND.search(line)
        if m:
            hid_bindings.append({"vid": m.group("vid").lower(), "pid": m.group("pid").lower(),
                                 "desc": m.group("desc").strip(), "ts": ts})
            continue

        m = RE_SCSI_DISK.search(line)
        if m:
            disks.append({"device": m.group("dev"), "removable": m.group("kind").startswith(
                "removable"), "ts": ts})
            continue

        m = RE_DRIVER.search(line)
        if m:
            drv = m.group("driver")
            port = m.group("port").split(":")[0]
            if drv in DRIVER_CLASS:
                rec = pending.get(port)
                if rec is not None and drv not in rec["drivers"]:
                    rec["drivers"].append(drv)
                for e in reversed(events):
                    if e.get("port") == port and e["action"] == "connect":
                        if drv not in e["drivers"]:
                            e["drivers"].append(drv)
                        break

    # a connect that never produced a SerialNumber line still happened
    for port, rec in pending.items():
        if rec.get("vid") and not rec.get("_emitted"):
            events.append({**rec, "action": "connect"})

    return {"events": events, "hid_bindings": hid_bindings, "disks": disks,
            "first_ts": first_ts, "last_ts": last_ts, "lines": lines,
            "year_assumed": assumed_year_used, "assumed_year": assume_year}


def parse_sysfs_devices(root: str = "/sys/bus/usb/devices") -> Result:
    """Currently attached devices, straight from sysfs."""
    r = Result("live-sysfs")
    r.source = root
    if not os.path.isdir(root):
        return r.unavailable(f"{root} does not exist (no USB subsystem on this kernel, "
                             f"or not a Linux host)")
    try:
        entries = sorted(os.listdir(root))
    except PermissionError:
        return r.unavailable(f"{root}: permission denied")
    except OSError as e:
        return r.unavailable(f"{root}: {e}")

    def attr(base, name):
        v, _ = read_text(os.path.join(base, name), 4096)
        return v.strip() if v else None

    for entry in entries:
        base = os.path.join(root, entry)
        vid = attr(base, "idVendor")
        if not vid:
            continue                      # interfaces and root hubs without ids
        pid = attr(base, "idProduct")
        classes = []
        try:
            for iface in sorted(os.listdir(base)):
                ipath = os.path.join(base, iface)
                if not os.path.isdir(ipath) or ":" not in iface:
                    continue
                cls = attr(ipath, "bInterfaceClass")
                drv = os.path.basename(os.path.realpath(os.path.join(ipath, "driver"))) \
                    if os.path.islink(os.path.join(ipath, "driver")) else None
                if cls:
                    classes.append({"interface": iface, "class": int(cls, 16),
                                    "driver": drv})
        except OSError:
            pass
        dclass = attr(base, "bDeviceClass")
        r.data.append({
            "port": entry, "vid": vid.lower(), "pid": (pid or "").lower(),
            "serial": attr(base, "serial"), "product": attr(base, "product"),
            "manufacturer": attr(base, "manufacturer"),
            "speed": attr(base, "speed"), "version": (attr(base, "version") or "").strip(),
            "device_class": int(dclass, 16) if dclass else None,
            "interfaces": classes,
            "drivers": sorted({c["driver"] for c in classes if c["driver"]}),
            "busnum": attr(base, "busnum"), "devnum": attr(base, "devnum"),
        })
    if not r.data:
        r.partial("no USB devices are currently attached")
    return r


def parse_system_profiler(payload: str) -> Result:
    """macOS: system_profiler SPUSBDataType -json"""
    r = Result("live-macos")
    r.source = "system_profiler SPUSBDataType"
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError as e:
        return r.unavailable(f"system_profiler output was not valid JSON: {e}")
    items = doc.get("SPUSBDataType", [])

    def walk(nodes, depth=0):
        for n in nodes:
            vid = (n.get("vendor_id") or "").split()[0].replace("0x", "").lower()
            pid = (n.get("product_id") or "").split()[0].replace("0x", "").lower()
            if vid:
                r.data.append({
                    "port": n.get("_name", "")[:40], "vid": vid.zfill(4), "pid": pid.zfill(4),
                    "serial": n.get("serial_num"), "product": n.get("_name"),
                    "manufacturer": (n.get("manufacturer") or "").strip() or None,
                    "speed": n.get("device_speed"), "version": n.get("bcd_device"),
                    "device_class": None, "interfaces": [], "drivers": [],
                    "busnum": None, "devnum": n.get("location_id"),
                })
            walk(n.get("_items", []), depth + 1)

    walk(items)
    if not r.data:
        r.partial("system_profiler reported no USB devices")
    return r


def parse_setupapi(text: str) -> Result:
    """Windows: setupapi.dev.log records the first time each device was installed."""
    r = Result("history-setupapi")
    r.source = "setupapi.dev.log"
    cur_ts = None
    for line in text.splitlines():
        m = re.match(r">>>\s+\[Device Install \(Hardware initiated\) - (?P<inst>.+?)\]", line)
        if m:
            inst = m.group("inst")
            vm = re.search(r"USB(?:STOR)?\\+.*?VID_(?P<vid>[0-9A-Fa-f]{4})&PID_"
                           r"(?P<pid>[0-9A-Fa-f]{4})", inst, re.I)
            sm = re.search(r"\\([^\\]+)$", inst)
            r.data.append({"instance": inst,
                           "vid": vm.group("vid").lower() if vm else None,
                           "pid": vm.group("pid").lower() if vm else None,
                           "serial": sm.group(1) if sm else None,
                           "ts": cur_ts, "action": "first-install"})
            continue
        m = re.match(r">>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        if m:
            try:
                cur_ts = datetime.strptime(m.group("ts"), "%Y/%m/%d %H:%M:%S").replace(
                    tzinfo=timezone.utc).isoformat()
                if r.data and r.data[-1]["ts"] is None:
                    r.data[-1]["ts"] = cur_ts
            except ValueError:
                pass
    if not r.data:
        r.partial("no hardware-initiated device installs found in setupapi.dev.log")
    return r


def parse_usbstor_registry() -> Result:
    """Windows: the USBSTOR registry key is the canonical record of attached storage."""
    r = Result("history-registry")
    r.source = r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if not IS_WINDOWS:
        return r.unavailable("the Windows registry is only readable on Windows")
    try:
        import winreg
    except ImportError:
        return r.unavailable("winreg is unavailable")
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
    except PermissionError:
        return r.unavailable("permission denied - run as Administrator")
    except FileNotFoundError:
        return r.unavailable("USBSTOR key not present (no USB storage has been attached)")
    except OSError as e:
        return r.unavailable(f"registry: {e}")
    i = 0
    while True:
        try:
            model = winreg.EnumKey(base, i)
        except OSError:
            break
        i += 1
        try:
            mk = winreg.OpenKey(base, model)
        except OSError:
            continue
        j = 0
        while True:
            try:
                serial = winreg.EnumKey(mk, j)
            except OSError:
                break
            j += 1
            entry = {"model": model, "serial": serial.split("&")[0], "friendly": None,
                     "vid": None, "pid": None, "ts": None,
                     "serial_is_generated": "&" in serial and serial.split("&")[1:2] == ["0"]}
            try:
                sk = winreg.OpenKey(mk, serial)
                try:
                    entry["friendly"] = winreg.QueryValueEx(sk, "FriendlyName")[0]
                except OSError:
                    pass
                try:
                    ts = winreg.QueryInfoKey(sk)[2]
                    entry["ts"] = (datetime(1601, 1, 1, tzinfo=timezone.utc)
                                   + timedelta(microseconds=ts // 10)
                                   ).replace(microsecond=0).isoformat()
                except OSError:
                    pass
            except OSError:
                pass
            m = re.match(r"(?:Disk&Ven_(?P<ven>[^&]*))?&?Prod_(?P<prod>[^&]*)", model)
            if m:
                entry["vendor_name"] = (m.group("ven") or "").replace("_", " ").strip()
                entry["product_name"] = (m.group("prod") or "").replace("_", " ").strip()
            r.data.append(entry)
    if not r.data:
        r.partial("USBSTOR contains no entries")
    return r


# =============================================================================
# SECTION 4 - Collectors (choose the best available evidence, honestly)
# =============================================================================

def boot_time_utc() -> datetime | None:
    """Needed to turn dmesg's monotonic timestamps into wall-clock times."""
    txt, _ = read_text("/proc/stat", 200_000)
    if txt:
        for line in txt.splitlines():
            if line.startswith("btime "):
                try:
                    return datetime.fromtimestamp(int(line.split()[1]), tz=timezone.utc)
                except (ValueError, IndexError):
                    return None
    return None


def collect_live() -> Result:
    if IS_LINUX:
        return parse_sysfs_devices()
    if IS_MAC:
        res = run(["system_profiler", "SPUSBDataType", "-json"], timeout=60)
        if not res["ok"]:
            r = Result("live-macos")
            return r.unavailable(res["err"] or "system_profiler failed")
        return parse_system_profiler(res["out"])
    if IS_WINDOWS:
        r = Result("live-windows")
        r.source = "PowerShell Get-PnpDevice"
        res = run(["powershell", "-NoProfile", "-Command",
                   "Get-PnpDevice -Class USB -PresentOnly | Select-Object "
                   "InstanceId,FriendlyName,Status | ConvertTo-Json -Compress"], timeout=60)
        if not res["ok"] or not res["out"].strip():
            return r.unavailable(res["err"] or "Get-PnpDevice returned nothing")
        try:
            raw = json.loads(res["out"])
        except json.JSONDecodeError as e:
            return r.unavailable(f"Get-PnpDevice output was not valid JSON: {e}")
        if isinstance(raw, dict):
            raw = [raw]
        for d in raw:
            inst = d.get("InstanceId", "") or ""
            m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", inst)
            sm = re.search(r"\\([^\\]+)$", inst)
            r.data.append({
                "port": inst[:60], "vid": m.group(1).lower() if m else "",
                "pid": m.group(2).lower() if m else "",
                "serial": sm.group(1) if sm else None,
                "product": d.get("FriendlyName"), "manufacturer": None,
                "speed": None, "version": None, "device_class": None,
                "interfaces": [], "drivers": [], "busnum": None, "devnum": None})
        if not r.data:
            r.partial("no present USB devices reported")
        return r
    r = Result("live")
    return r.unavailable(f"no live inventory implemented for platform '{sys.platform}'")


def _read_maybe_gzip(path: str) -> tuple[str | None, str | None]:
    if path.endswith(".gz"):
        try:
            import gzip
            with gzip.open(path, "rt", errors="replace") as fh:
                return fh.read(20_000_000), None
        except Exception as e:
            return None, str(e)
    return read_text(path)


def collect_history(max_files: int = 12) -> Result:
    """Reconstruct attach/detach history from whatever log source exists."""
    r = Result("history")
    year = datetime.now(timezone.utc).year
    boot = boot_time_utc()

    if IS_LINUX:
        chunks, used = [], []
        if have("journalctl"):
            res = run(["journalctl", "-k", "-o", "short-iso", "--no-pager"], timeout=90)
            if res["ok"] and res["out"].strip():
                chunks.append(res["out"])
                used.append("journalctl -k")
            elif res["err"]:
                r.partial(f"journalctl: {res['err'][:120]}")
        patterns = ["/var/log/kern.log*", "/var/log/syslog*", "/var/log/messages*"]
        files = []
        for pat in patterns:
            files.extend(sorted(glob.glob(pat)))
        denied = 0
        for path in files[:max_files]:
            txt, err = _read_maybe_gzip(path)
            if txt is None:
                if err and "permission" in err.lower():
                    denied += 1
                continue
            chunks.append(txt)
            used.append(os.path.basename(path))
        if denied:
            r.partial(f"{denied} log file(s) unreadable without root")
        if not chunks and have("dmesg"):
            res = run(["dmesg"], timeout=30)
            if res["ok"]:
                chunks.append(res["out"])
                used.append("dmesg (ring buffer only - covers this boot at most)")
            elif res["err"]:
                r.partial(f"dmesg: {res['err'][:120]}")
        if not chunks:
            return r.unavailable(
                "no readable kernel log source. Tried journalctl, /var/log/kern.log, "
                "/var/log/syslog, /var/log/messages and dmesg. Run with sudo, or point "
                "--log-file at an exported log.")
        parsed = parse_kernel_log("\n".join(chunks), assume_year=year, boot_time=boot)
        r.data = parsed["events"]
        r.source = ", ".join(used)
        r.meta = parsed
        return r

    if IS_WINDOWS:
        reg = parse_usbstor_registry()
        setup = Result("history-setupapi")
        path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "INF",
                            "setupapi.dev.log")
        txt, err = read_text(path, 20_000_000)
        if txt is not None:
            setup = parse_setupapi(txt)
        else:
            setup.unavailable(f"{path}: {err}")
        r.data = []
        for e in reg.data:
            r.data.append({"action": "registry-entry", "ts": e.get("ts"), "vid": e.get("vid"),
                           "pid": e.get("pid"), "serial": e.get("serial"),
                           "product": e.get("product_name") or e.get("friendly"),
                           "manufacturer": e.get("vendor_name"), "port": None,
                           "device_number": None, "drivers": ["usb-storage"],
                           "year_assumed": False})
        for e in setup.data:
            r.data.append({"action": "first-install", "ts": e.get("ts"), "vid": e.get("vid"),
                           "pid": e.get("pid"), "serial": e.get("serial"),
                           "product": None, "manufacturer": None, "port": None,
                           "device_number": None, "drivers": [], "year_assumed": False})
        sources = [s for s, res in (("USBSTOR registry", reg), ("setupapi.dev.log", setup))
                   if res.status != "unavailable"]
        r.source = ", ".join(sources) or "none"
        details = [res.detail for res in (reg, setup) if res.detail]
        if not r.data:
            return r.unavailable("; ".join(details) or "no USB history found")
        if details:
            r.partial("; ".join(details))
        r.meta = {"first_ts": min((e["ts"] for e in r.data if e["ts"]), default=None),
                  "last_ts": max((e["ts"] for e in r.data if e["ts"]), default=None),
                  "year_assumed": False, "assumed_year": year, "hid_bindings": [],
                  "disks": [], "lines": len(r.data)}
        return r

    if IS_MAC:
        res = run(["log", "show", "--style", "syslog", "--last", "7d",
                   "--predicate", 'subsystem == "com.apple.iokit.IOUSBHostFamily"'],
                  timeout=120)
        if not res["ok"] or not res["out"].strip():
            return r.unavailable(
                res["err"] or "the unified log returned no USB records for the last 7 days "
                              "(full access may require Terminal to have Full Disk Access)")
        parsed = parse_kernel_log(res["out"], assume_year=year, boot_time=boot)
        r.data = parsed["events"]
        r.source = "log show (unified log, last 7 days)"
        r.meta = parsed
        if not r.data:
            r.partial("the unified log was read but held no recognisable USB attach records")
        return r

    return r.unavailable(f"no history source implemented for platform '{sys.platform}'")


# =============================================================================
# SECTION 5 - Correlation: events -> devices -> sessions
# =============================================================================

def device_key(vid, pid, serial) -> str:
    return f"{(vid or '????').lower()}:{(pid or '????').lower()}:{serial or ''}"


def correlate(events: list[dict], live: list[dict],
              hid_bindings: list[dict] | None = None) -> dict:
    """Fold raw events and the live inventory into per-device records."""
    devices: dict[str, dict] = {}

    def touch(vid, pid, serial, product=None, manufacturer=None):
        k = device_key(vid, pid, serial)
        d = devices.get(k)
        if d is None:
            vendor_name, vendor_known = USBIDS.vendor(vid or "")
            product_name, _ = USBIDS.product(vid or "", pid or "")
            d = devices[k] = {
                "key": k, "vid": vid, "pid": pid, "serial": serial,
                "product": product, "manufacturer": manufacturer,
                "vendor_name": vendor_name, "vendor_known": vendor_known,
                "product_name": product_name, "classes": set(), "drivers": set(),
                "ports": set(), "first_seen": None, "last_seen": None,
                "connects": 0, "disconnects": 0, "sessions": [], "total_seconds": 0,
                "live": False, "year_assumed": False}
        if product and not d["product"]:
            d["product"] = product
        if manufacturer and not d["manufacturer"]:
            d["manufacturer"] = manufacturer
        return d

    # live devices first, so their richer detail wins
    for l in live:
        d = touch(l["vid"], l["pid"], l.get("serial"), l.get("product"),
                  l.get("manufacturer"))
        d["live"] = True
        if l.get("port"):
            d["ports"].add(l["port"])
        for drv in l.get("drivers") or []:
            d["drivers"].add(drv)
            if drv in DRIVER_CLASS:
                d["classes"].add(DRIVER_CLASS[drv])
        for iface in l.get("interfaces") or []:
            cls = USB_CLASSES.get(iface["class"])
            if cls:
                d["classes"].add(cls[0])
        if l.get("device_class") is not None:
            cls = USB_CLASSES.get(l["device_class"])
            if cls and cls[0] not in ("per-interface",):
                d["classes"].add(cls[0])

    open_by_port: dict[str, dict] = {}
    ordered = sorted([e for e in events if e.get("ts")], key=lambda e: e["ts"])
    ordered += [e for e in events if not e.get("ts")]

    for e in ordered:
        if e["action"] in ("connect", "registry-entry", "first-install"):
            if not e.get("vid"):
                continue
            d = touch(e["vid"], e["pid"], e.get("serial"), e.get("product"),
                      e.get("manufacturer"))
            d["connects"] += 1
            if e.get("year_assumed"):
                d["year_assumed"] = True
            if e.get("port"):
                d["ports"].add(e["port"])
            for drv in e.get("drivers") or []:
                d["drivers"].add(drv)
                if drv in DRIVER_CLASS:
                    d["classes"].add(DRIVER_CLASS[drv])
            ts = e.get("ts")
            if ts:
                if not d["first_seen"] or ts < d["first_seen"]:
                    d["first_seen"] = ts
                if not d["last_seen"] or ts > d["last_seen"]:
                    d["last_seen"] = ts
            if e.get("port"):
                open_by_port[e["port"]] = {"device": d, "ts": ts}
        elif e["action"] == "disconnect":
            port = e.get("port")
            opened = open_by_port.pop(port, None) if port else None
            if opened and opened["device"]:
                d = opened["device"]
                d["disconnects"] += 1
                ts = e.get("ts")
                if ts and not d["last_seen"] or (ts and ts > (d["last_seen"] or "")):
                    d["last_seen"] = ts
                if opened["ts"] and ts:
                    try:
                        dur = (datetime.fromisoformat(ts)
                               - datetime.fromisoformat(opened["ts"])).total_seconds()
                        if dur >= 0:
                            d["sessions"].append({"start": opened["ts"], "end": ts,
                                                  "seconds": int(dur)})
                            d["total_seconds"] += int(dur)
                    except ValueError:
                        pass

    # a hid-generic binding names the vid:pid it bound to, which is direct evidence
    # that this device presented a human interface - merge it in
    for b in (hid_bindings or []):
        for d in devices.values():
            if d["vid"] == b["vid"] and d["pid"] == b["pid"]:
                d["classes"].add("HID")
                d["drivers"].add("hid-generic")
                d.setdefault("hid_descriptions", []).append(b["desc"])

    for d in devices.values():
        d["classes"] = sorted(d["classes"])
        d["drivers"] = sorted(d["drivers"])
        d["ports"] = sorted(d["ports"])
        if not d["classes"] and d["live"]:
            d["classes"] = ["unknown"]
    return devices


# =============================================================================
# SECTION 6 - Findings
# =============================================================================

def F(category, title, severity, description, evidence="", recommendation="",
      reference="", device_key_=None):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:2000],
            "recommendation": recommendation, "reference": reference,
            "device_key": device_key_}


def not_performed(category, title, reason):
    return F(category, f"Check not performed: {title}", "info",
             "This check could not be evaluated, so its result is unknown. It is NOT "
             "counted as a pass.", reason,
             "Re-run with sufficient privileges, or point --log-file at an exported "
             "kernel log.")


def analyse(devices: dict, meta: dict, live_res: Result, hist_res: Result,
            baseline: dict, work_start: int = 8, work_end: int = 19) -> list[dict]:
    out: list[dict] = []

    if live_res.status == "unavailable":
        out.append(not_performed("Inventory", "live device inventory", live_res.detail))
    if hist_res.status == "unavailable":
        out.append(not_performed("History", "attach/detach history", hist_res.detail))
        return out

    # ---- how far back does the evidence actually go? ----
    first, last = meta.get("first_ts"), meta.get("last_ts")
    if first and last:
        try:
            span = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).days
        except ValueError:
            span = None
        if span is not None:
            sev = "medium" if span < 7 else ("low" if span < 30 else "info")
            out.append(F("History", f"Evidence covers about {span} day(s)", sev,
                         "History is bounded by log retention. Anything that happened "
                         "before the earliest surviving log entry is simply not visible "
                         "here, and its absence is not evidence that nothing happened.",
                         f"earliest entry {first[:19]}, latest {last[:19]}, "
                         f"source: {hist_res.source}",
                         "For a longer window, collect logs before rotation, or forward "
                         "kernel logs to a central store."))
    if meta.get("year_assumed"):
        out.append(F("History", "Some timestamps had no year in the log", "low",
                     "Classic syslog omits the year. Those entries were dated to "
                     f"{meta.get('assumed_year')}, which is wrong for anything that "
                     "crossed a new year boundary.",
                     "affected lines used the 'Mon DD HH:MM:SS' format",
                     "Prefer journalctl or an ISO-8601 log format for anything evidential."))

    if not devices:
        out.append(F("Inventory", "No USB devices found in the available evidence", "info",
                     "Neither the live inventory nor the logs recorded any USB device. On a "
                     "virtual machine or a host with no USB controller this is expected.",
                     f"live: {live_res.status}, history: {hist_res.status}",
                     "Nothing to do."))
        return out

    # ---- per device ----
    serial_map: dict[str, set] = {}
    vidpid_serials: dict[str, set] = {}
    for d in devices.values():
        approved = d["key"] in baseline
        label = (d["product"] or d["product_name"] or "unnamed device")
        ident = (f"{d['vid']}:{d['pid']} {label} "
                 f"(serial {d['serial'] or 'none reported'})")
        if d["serial"]:
            serial_map.setdefault(d["serial"], set()).add(f"{d['vid']}:{d['pid']}")
        vidpid_serials.setdefault(f"{d['vid']}:{d['pid']}", set()).add(d["serial"] or "")

        for cls in d["classes"]:
            if cls in NOTABLE_CLASSES and not approved:
                why, sev = NOTABLE_CLASSES[cls]
                out.append(F("Device", f"Unapproved {cls} device: {label}", sev, why,
                             f"{ident}; seen {d['connects']} time(s); "
                             f"first {(d['first_seen'] or '?')[:19]}, "
                             f"last {(d['last_seen'] or '?')[:19]}",
                             f"If this device is expected, approve it: "
                             f"approve --key '{d['key']}'. If not, find out who attached it.",
                             device_key_=d["key"]))

        if not d["serial"] and d["classes"]:
            out.append(F("Device", f"Device reports no serial number: {label}", "medium",
                         "Without a serial number this device cannot be told apart from any "
                         "other unit of the same model. Cheap flash drives often omit it, and "
                         "so do many keystroke-injection tools.",
                         ident,
                         "Track it by model and attachment time instead, and treat repeat "
                         "appearances as possibly different physical devices.",
                         device_key_=d["key"]))

        if "mass storage" in d["classes"] and "HID" in d["classes"]:
            out.append(F("Device", f"Device presents as BOTH storage and a keyboard: {label}",
                         "critical",
                         "A single device exposing mass storage and a human interface device "
                         "is the signature of a BadUSB style tool: it looks like a flash "
                         "drive and can also type commands. Legitimate composite devices "
                         "exist, so confirm the model before acting - but this warrants "
                         "immediate attention.",
                         f"{ident}; interfaces/drivers: {', '.join(d['drivers']) or 'n/a'}; "
                         f"classes: {', '.join(d['classes'])}",
                         "Physically retain the device, identify who attached it, and review "
                         "what ran on the host during the attachment window.",
                         "MITRE ATT&CK T1200 Hardware Additions", d["key"]))

        if not d["vendor_known"] and d["vid"]:
            out.append(F("Device", f"Vendor id {d['vid']} is not recognised", "low",
                         "The vendor id does not appear in the usb.ids database available on "
                         "this machine. That can simply mean usb.ids is old or missing, but "
                         "unregistered ids are also common on hobbyist and purpose-built "
                         "hardware.",
                         f"{ident}; {USBIDS.note()}",
                         "Install the usbutils/hwdata package for a complete vendor list, "
                         "then re-run.", device_key_=d["key"]))

        short = [s for s in d["sessions"] if s["seconds"] < 120]
        if "mass storage" in d["classes"] and short:
            out.append(F("Behaviour", f"Storage device attached only briefly: {label}",
                         "medium",
                         "A storage device connected for under two minutes is consistent with "
                         "a quick copy. It is also consistent with someone plugging in the "
                         "wrong drive. The timing alone does not distinguish them.",
                         "; ".join(f"{s['start'][:19]} for {fmt_duration(s['seconds'])}"
                                   for s in short[:6]),
                         "Correlate with file system and application logs for the same "
                         "window.", device_key_=d["key"]))

        odd = []
        for s in d["sessions"]:
            try:
                hour = datetime.fromisoformat(s["start"]).hour
            except ValueError:
                continue
            if hour < work_start or hour >= work_end:
                odd.append(s)
        if odd and not approved:
            out.append(F("Behaviour", f"Attached outside working hours: {label}", "low",
                         f"Attachment happened outside {work_start:02d}:00-{work_end:02d}:00. "
                         "That is only unusual if it is unusual for this machine and this "
                         "person - shift work and time zones make this a weak signal on its "
                         "own.",
                         "; ".join(s["start"][:19] for s in odd[:6]),
                         "Adjust the working window with --work-hours if this is noise.",
                         device_key_=d["key"]))

    for serial, pairs in serial_map.items():
        if len(pairs) > 1:
            out.append(F("Integrity", "One serial number appears under different product ids",
                         "high",
                         "A serial number is supposed to identify one physical device. The "
                         "same serial under two different vendor/product ids suggests a "
                         "cloned or spoofed descriptor, which is something an attacker does "
                         "deliberately and a manufacturer does by accident.",
                         f"serial {serial} seen as: {', '.join(sorted(pairs))}",
                         "Treat the device identity as untrusted and identify the physical "
                         "hardware."))

    for vidpid, serials in vidpid_serials.items():
        real = {s for s in serials if s}
        if len(real) > 4:
            out.append(F("Integrity", f"Many distinct serials for one model ({vidpid})",
                         "low",
                         "Several physical units of the same model have been attached. Normal "
                         "for a shared machine or an issued fleet; worth a look on a "
                         "single-user workstation.",
                         f"{len(real)} distinct serial numbers for {vidpid}",
                         "Confirm this matches how the machine is used."))

    storage = [d for d in devices.values() if "mass storage" in d["classes"]]
    hid = [d for d in devices.values() if "HID" in d["classes"]]
    out.append(F("Summary", f"{len(devices)} distinct device(s) in the evidence", "info",
                 f"{len(storage)} mass storage, {len(hid)} human interface, "
                 f"{sum(1 for d in devices.values() if d['live'])} attached right now.",
                 f"live inventory: {live_res.status}; history: {hist_res.status} "
                 f"({hist_res.source})",
                 "Approve the devices you expect so future runs highlight only what is new."))
    approved_n = sum(1 for d in devices if d in baseline)
    if baseline:
        out.append(F("Summary", f"{approved_n} of {len(devices)} device(s) are approved",
                     "info", "Approved devices are excluded from the unapproved-device "
                     "findings above.", f"baseline holds {len(baseline)} entries",
                     "Keep the baseline current as hardware changes."))
    else:
        out.append(F("Summary", "No baseline has been set", "low",
                     "Without a baseline every device looks equally noteworthy, so the "
                     "signal-to-noise ratio of this report is poor.",
                     "the approved-device list is empty",
                     "Approve the devices you know are legitimate: "
                     "usbf approve --key <key>, then re-run."))
    return out


def compute_score(counts: dict) -> float:
    penalty = sum(SEV_WEIGHT[s] * counts.get(s, 0) for s in SEVERITIES)
    return round(clamp(100.0 - penalty, 0.0, 100.0), 1)


def risk_label(score: float) -> tuple[str, str]:
    if score >= 90:
        return "clean", "#30a46c"
    if score >= 70:
        return "minor findings", "#5bb98b"
    if score >= 50:
        return "review needed", "#ffb224"
    if score >= 25:
        return "significant findings", "#f76808"
    return "urgent review", "#e5484d"


# =============================================================================
# SECTION 7 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, os_name TEXT, os_version TEXT, mode TEXT,
    live_status TEXT, live_detail TEXT, history_status TEXT, history_detail TEXT,
    history_source TEXT, window_start TEXT, window_end TEXT, log_lines INTEGER,
    year_assumed INTEGER DEFAULT 0, assumed_year INTEGER,
    usbids_source TEXT, devices INTEGER DEFAULT 0, events INTEGER DEFAULT 0,
    score REAL, risk TEXT, total_findings INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    key TEXT, vid TEXT, pid TEXT, serial TEXT, product TEXT, manufacturer TEXT,
    vendor_name TEXT, vendor_known INTEGER DEFAULT 0, product_name TEXT,
    classes TEXT, drivers TEXT, ports TEXT, first_seen TEXT, last_seen TEXT,
    connects INTEGER DEFAULT 0, disconnects INTEGER DEFAULT 0,
    total_seconds INTEGER DEFAULT 0, sessions TEXT, live INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0, year_assumed INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    ts TEXT, action TEXT, vid TEXT, pid TEXT, serial TEXT, product TEXT,
    port TEXT, device_number TEXT, drivers TEXT, device_key TEXT,
    year_assumed INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    recommendation TEXT, reference TEXT, device_key TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY, vid TEXT, pid TEXT, serial TEXT, label TEXT,
    approved_at TEXT, approved_by TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_dev_scan ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_ev_scan ON usb_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_ev_ts ON usb_events(ts);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def load_baseline(conn=None) -> dict:
    return {r["key"]: dict(r) for r in q("SELECT * FROM baseline", (), conn)}


def approve_device(key: str, label: str = "", note: str = "", by: str = "") -> bool:
    parts = key.split(":")
    vid = parts[0] if parts else ""
    pid = parts[1] if len(parts) > 1 else ""
    serial = ":".join(parts[2:]) if len(parts) > 2 else ""
    conn = connect()
    try:
        init_db(conn)
        conn.execute("INSERT INTO baseline (key, vid, pid, serial, label, approved_at,"
                     " approved_by, note) VALUES (?,?,?,?,?,?,?,?) "
                     "ON CONFLICT(key) DO UPDATE SET label=excluded.label, "
                     "note=excluded.note, approved_at=excluded.approved_at",
                     (key, vid, pid, serial, label, now_iso(),
                      by or os.environ.get("USER") or "unknown", note))
        conn.commit()
        log_event("INFO", "baseline", f"Approved device {key}"
                  + (f" ({label})" if label else ""), None, conn)
        return True
    finally:
        conn.close()


def revoke_device(key: str) -> int:
    conn = connect()
    try:
        n = conn.execute("DELETE FROM baseline WHERE key=?", (key,)).rowcount
        conn.commit()
        if n:
            log_event("INFO", "baseline", f"Removed device {key} from the baseline", None, conn)
        return n
    finally:
        conn.close()


def save_scan(devices: dict, events: list, findings: list, meta: dict,
              live_res: Result, hist_res: Result, mode: str, note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        score = compute_score(counts)
        risk, _ = risk_label(score)
        info = {"hostname": socket.gethostname(), "os_name": platform.system(),
                "os_version": platform.platform()}
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, os_name, os_version, mode, live_status,"
            " live_detail, history_status, history_detail, history_source, window_start,"
            " window_end, log_lines, year_assumed, assumed_year, usbids_source, devices,"
            " events, score, risk, total_findings, critical, high, medium, low, info, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), info["hostname"], info["os_name"], info["os_version"], mode,
             live_res.status, live_res.detail, hist_res.status, hist_res.detail,
             hist_res.source, meta.get("first_ts"), meta.get("last_ts"),
             meta.get("lines", 0), int(bool(meta.get("year_assumed"))),
             meta.get("assumed_year"), USBIDS.source if USBIDS.loaded else "built-in list",
             len(devices), len(events), score, risk, len(findings), counts["critical"],
             counts["high"], counts["medium"], counts["low"], counts["info"], note))
        sid = cur.lastrowid
        baseline = load_baseline(conn)
        for d in devices.values():
            conn.execute(
                "INSERT INTO devices (scan_id, key, vid, pid, serial, product, manufacturer,"
                " vendor_name, vendor_known, product_name, classes, drivers, ports,"
                " first_seen, last_seen, connects, disconnects, total_seconds, sessions,"
                " live, approved, year_assumed)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, d["key"], d["vid"], d["pid"], d["serial"], d["product"],
                 d["manufacturer"], d["vendor_name"], int(d["vendor_known"]),
                 d["product_name"], ",".join(d["classes"]), ",".join(d["drivers"]),
                 ",".join(d["ports"]), d["first_seen"], d["last_seen"], d["connects"],
                 d["disconnects"], d["total_seconds"], json.dumps(d["sessions"]),
                 int(d["live"]), int(d["key"] in baseline), int(d.get("year_assumed", False))))
        for e in events:
            conn.execute(
                "INSERT INTO usb_events (scan_id, ts, action, vid, pid, serial, product,"
                " port, device_number, drivers, device_key, year_assumed)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, e.get("ts"), e["action"], e.get("vid"), e.get("pid"), e.get("serial"),
                 e.get("product"), e.get("port"), e.get("device_number"),
                 ",".join(e.get("drivers") or []),
                 device_key(e.get("vid"), e.get("pid"), e.get("serial"))
                 if e.get("vid") else None, int(bool(e.get("year_assumed")))))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, recommendation, reference, device_key)"
                         " VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"], f["description"],
                          f["evidence"], f["recommendation"], f["reference"],
                          f["device_key"]))
        conn.commit()
        log_event("INFO", "scan", f"Scan #{sid}: {len(devices)} device(s), {len(events)} "
                  f"event(s), {len(findings)} finding(s), score {score} "
                  f"(live {live_res.status}, history {hist_res.status})", sid, conn)
        for res in (live_res, hist_res):
            if res.status == "unavailable":
                log_event("WARN", f"collector.{res.name}", res.detail, sid, conn)
        return sid
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(scan_id: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (scan_id,), conn)
    if not row:
        return None
    d = dict(row)
    d["risk_label"], d["risk_colour"] = risk_label(d["score"] or 0)
    return d


# =============================================================================
# SECTION 8 - Charts (hand-drawn SVG: no CDN, no JS charting library, offline)
# =============================================================================

def svg_pie(items, size=200, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 46
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" fill="none" '
                         f'stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'<em>{100.0 * value / total:.0f}%</em></div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="Devices", color="#22b8cf", fmt=lambda v: f"{v:g}"):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 23, 8, 168, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 70
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        lbl = label if len(label) <= 23 else label[:22] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 10}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{color}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 8:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_columns(items, width=470, height=210, title="Attachments by hour",
                color="#22b8cf"):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    pad_l, pad_b, pad_t, pad_r = 34, 26, 16, 8
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    slot = pw / len(items)
    bw = max(3.0, min(30.0, slot * 0.7))
    ymax = max(v for _, v in items) or 1
    bars, grid = [], []
    for f in (0, 0.5, 1.0):
        y = pad_t + ph - ph * f
        grid.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
                    f'class="gl"/><text x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end" '
                    f'class="bl">{ymax * f:g}</text>')
    for i, (label, value) in enumerate(items):
        h = ph * value / ymax
        x = pad_l + slot * i + (slot - bw) / 2
        bars.append(
            f'<rect x="{x:.1f}" y="{pad_t + ph - h:.1f}" width="{bw:.1f}" '
            f'height="{max(h, 1):.1f}" rx="2" fill="{color}">'
            f'<title>{html_escape(label)}: {value:g}</title></rect>')
        if len(items) <= 24 and i % max(1, len(items) // 12) == 0:
            bars.append(f'<text x="{x + bw / 2:.1f}" y="{height - 8}" text-anchor="middle" '
                        f'class="bl">{html_escape(label)}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(grid)}{"".join(bars)}</svg></figure>')


CLASS_COLOR = {"mass storage": "#f76808", "HID": "#e5484d", "network": "#4c6ef5",
               "hub": "#8b8f9b", "audio": "#f06595", "video": "#9775fa",
               "serial": "#ffb224", "wireless": "#22b8cf", "printer": "#30a46c",
               "image": "#9775fa", "unknown": "#6f7685"}


def svg_device_timeline(devices, window_start, window_end, width=980, title="Device timeline"):
    """One row per device, its attachment sessions drawn against the evidence window.
    A single-point marker means an attach with no matching disconnect in the logs."""
    devs = [d for d in devices if d.get("first_seen")]
    if not devs or not window_start or not window_end:
        return (f'<div class="chart-empty">{html_escape(title)}: no timestamped attachments '
                f'in the evidence</div>')
    try:
        t0 = datetime.fromisoformat(window_start).timestamp()
        t1 = datetime.fromisoformat(window_end).timestamp()
    except ValueError:
        return f'<div class="chart-empty">{html_escape(title)}: unparsable window</div>'
    if t1 <= t0:
        t1 = t0 + 1
    devs = sorted(devs, key=lambda d: d["first_seen"])[:24]
    row_h, gap, pad_l, pad_t, pad_b = 20, 6, 210, 10, 26
    height = pad_t + pad_b + len(devs) * (row_h + gap)
    pw = width - pad_l - 14
    rows, grid = [], []
    for f in (0, 0.25, 0.5, 0.75, 1.0):
        x = pad_l + pw * f
        when = datetime.fromtimestamp(t0 + (t1 - t0) * f, tz=timezone.utc)
        grid.append(f'<line x1="{x:.1f}" y1="{pad_t - 4}" x2="{x:.1f}" '
                    f'y2="{height - pad_b + 4}" class="gl"/>'
                    f'<text x="{clamp(x, pad_l + 20, width - 30):.1f}" y="{height - 8}" '
                    f'text-anchor="middle" class="bl">'
                    f'{html_escape(when.strftime("%m-%d %H:%M"))}</text>')
    for i, d in enumerate(devs):
        y = pad_t + i * (row_h + gap)
        cls = (d.get("classes") or ["unknown"])[0] if isinstance(d.get("classes"), list) \
            else (d.get("classes") or "unknown").split(",")[0]
        colour = CLASS_COLOR.get(cls, "#6f7685")
        label = (d.get("product") or d.get("product_name") or f"{d['vid']}:{d['pid']}")[:26]
        rows.append(f'<text x="{pad_l - 10}" y="{y + row_h * 0.72:.1f}" text-anchor="end" '
                    f'class="bl">{html_escape(label)}</text>'
                    f'<rect x="{pad_l}" y="{y}" width="{pw}" height="{row_h}" rx="3" '
                    f'class="btrack"/>')
        sessions = d.get("sessions") or []
        if isinstance(sessions, str):
            try:
                sessions = json.loads(sessions)
            except json.JSONDecodeError:
                sessions = []
        drawn = False
        for s in sessions:
            try:
                a = datetime.fromisoformat(s["start"]).timestamp()
                b = datetime.fromisoformat(s["end"]).timestamp()
            except (ValueError, KeyError):
                continue
            x = pad_l + pw * clamp((a - t0) / (t1 - t0), 0, 1)
            w = max(2.5, pw * clamp((b - a) / (t1 - t0), 0, 1))
            rows.append(f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{row_h}" rx="3" '
                        f'fill="{colour}"><title>{html_escape(label)}: {s["start"][:19]} for '
                        f'{html_escape(fmt_duration(s["seconds"]))}</title></rect>')
            drawn = True
        if not drawn:
            try:
                a = datetime.fromisoformat(d["first_seen"]).timestamp()
                x = pad_l + pw * clamp((a - t0) / (t1 - t0), 0, 1)
                rows.append(f'<circle cx="{x:.1f}" cy="{y + row_h / 2:.1f}" r="4.5" '
                            f'fill="{colour}"><title>{html_escape(label)} attached '
                            f'{d["first_seen"][:19]} - no matching disconnect in the logs'
                            f'</title></circle>')
            except ValueError:
                pass
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'{len(devs)} device(s) over {html_escape(window_start[:16])} to '
            f'{html_escape(window_end[:16])}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(grid)}{"".join(rows)}</svg></figure>')


def svg_gauge(score, label, size=150):
    colour = risk_label(score)[1]
    r = size / 2 - 13
    cx = cy = size / 2
    circ = 2 * math.pi * r
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
            f'aria-label="Score {score} of 100, {label}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#262a33" '
            f'stroke-width="12"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{colour}" '
            f'stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{circ * clamp(score, 0, 100) / 100:.2f} {circ:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" class="g-n" fill="{colour}">'
            f'{score:g}</text>'
            f'<text x="{cx}" y="{cy + 22}" text-anchor="middle" class="g-l">/100</text></svg>')


# =============================================================================
# SECTION 9 - Scan orchestration and the teaching fixture
# =============================================================================

def run_scan(log_file: str | None = None, mode: str = "live", note: str = "",
             work_hours: tuple[int, int] = (8, 19), assume_year: int | None = None) -> int:
    """Collect, correlate, analyse and store. Returns the scan id."""
    USBIDS.load()
    if log_file:
        txt, err = _read_maybe_gzip(log_file)
        hist = Result("history")
        hist.source = log_file
        if txt is None:
            hist.unavailable(f"{log_file}: {err}")
            meta = {"first_ts": None, "last_ts": None, "lines": 0, "year_assumed": False,
                    "assumed_year": assume_year or datetime.now(timezone.utc).year,
                    "hid_bindings": []}
        else:
            parsed = parse_kernel_log(txt, assume_year=assume_year,
                                      boot_time=boot_time_utc())
            hist.data = parsed["events"]
            meta = parsed
        live = Result("live")
        live.unavailable("not collected: analysing an exported log, not this machine")
        if mode == "live":
            mode = "logfile"
    else:
        live = collect_live()
        hist = collect_history()
        meta = getattr(hist, "meta", None) or {
            "first_ts": None, "last_ts": None, "lines": 0, "year_assumed": False,
            "assumed_year": datetime.now(timezone.utc).year, "hid_bindings": []}

    devices = correlate(hist.data, live.data if live.status != "unavailable" else [],
                        meta.get("hid_bindings"))
    baseline = load_baseline()
    findings = analyse(devices, meta, live, hist, baseline, work_hours[0], work_hours[1])
    return save_scan(devices, hist.data, findings, meta, live, hist, mode, note)


SAMPLE_LOG = """\
# Synthetic kernel log written by {app} v{ver} for training and self test.
# These lines are in the real format the Linux USB stack emits, but the events
# never happened - this file is a teaching fixture, not evidence. Scans of it are
# recorded in the database with mode='sample' so they can never be confused with
# a real examination of a real machine.
{lines}"""


def build_sample_log(path: str, year: int = 2026) -> dict:
    """Write a realistic kernel log fixture covering the cases this tool looks for."""
    lines = []

    def block(day, tm, port, num, vid, pid, mfr, product, serial, drivers, speed="high-speed"):
        stamp = f"{day} {tm}"
        lines.append(f"{stamp} lab-ws kernel: usb {port}: new {speed} USB device number "
                     f"{num} using xhci_hcd")
        lines.append(f"{stamp} lab-ws kernel: usb {port}: New USB device found, "
                     f"idVendor={vid}, idProduct={pid}, bcdDevice= 1.00")
        lines.append(f"{stamp} lab-ws kernel: usb {port}: New USB device strings: Mfr=1, "
                     f"Product=2, SerialNumber=3")
        lines.append(f"{stamp} lab-ws kernel: usb {port}: Product: {product}")
        lines.append(f"{stamp} lab-ws kernel: usb {port}: Manufacturer: {mfr}")
        lines.append(f"{stamp} lab-ws kernel: usb {port}: SerialNumber: {serial}")
        for drv in drivers:
            lines.append(f"{stamp} lab-ws kernel: {drv} {port}:1.0: bound to interface")

    def disconnect(day, tm, port, num):
        lines.append(f"{day} {tm} lab-ws kernel: usb {port}: USB disconnect, device "
                     f"number {num}")

    # an ordinary keyboard, plugged in and left alone
    block(f"{year}-03-02T08:41:07+0000", "", "1-1", "2", "046d", "c31c", "Logitech",
          "USB Keyboard", "", ["usbhid"], "full-speed")
    # an approved company flash drive, used during the day for a normal length of time
    block(f"{year}-03-02T09:14:02+0000", "", "1-2", "5", "0781", "5591", "SanDisk",
          "Ultra USB 3.0", "4C530001250607117025", ["usb-storage"])
    lines.append(f"{year}-03-02T09:14:03+0000 lab-ws kernel: sd 2:0:0:0: [sdb] Attached "
                 f"SCSI removable disk")
    disconnect(f"{year}-03-02T10:52:44+0000", "", "1-2", "5")
    # the same drive again a week later
    block(f"{year}-03-09T11:02:00+0000", "", "1-2", "6", "0781", "5591", "SanDisk",
          "Ultra USB 3.0", "4C530001250607117025", ["usb-storage"])
    disconnect(f"{year}-03-09T11:40:19+0000", "", "1-2", "6")
    # an unknown drive plugged in briefly, late at night
    block(f"{year}-03-11T23:12:41+0000", "", "1-3", "9", "090c", "1000", "Silicon Motion",
          "Flash Drive", "0207182100000032", ["usb-storage"])
    disconnect(f"{year}-03-11T23:13:36+0000", "", "1-3", "9")
    # a device presenting as storage AND a keyboard: the BadUSB pattern
    block(f"{year}-03-11T23:47:11+0000", "", "1-4", "11", "feed", "1307", "Generic",
          "USB Storage", "", ["usb-storage", "usbhid"], "full-speed")
    lines.append(f"{year}-03-11T23:47:12+0000 lab-ws kernel: hid-generic "
                 f"0003:FEED:1307.0002: input,hidraw1: USB HID v1.11 Keyboard "
                 f"[Generic USB Storage] on usb-0000:00:14.0-4/input1")
    disconnect(f"{year}-03-11T23:47:29+0000", "", "1-4", "11")
    # a USB network adapter
    block(f"{year}-03-12T14:20:00+0000", "", "2-1", "12", "0bda", "8153", "Realtek",
          "USB 10/100/1000 LAN", "001000001", ["r8152"], "SuperSpeed")
    # classic syslog format with no year, to exercise that path
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.000000] usb 1-5: new high-speed "
                 "USB device number 14 using xhci_hcd")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.100000] usb 1-5: New USB device "
                 "found, idVendor=0781, idProduct=5591, bcdDevice= 1.00")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.100005] usb 1-5: New USB device "
                 "strings: Mfr=1, Product=2, SerialNumber=3")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.100007] usb 1-5: Product: "
                 "Ultra USB 3.0")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.100009] usb 1-5: Manufacturer: "
                 "SanDisk")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.100011] usb 1-5: SerialNumber: "
                 "4C530001250607117025")
    lines.append("Mar 13 07:59:58 lab-ws kernel: [ 9911.200000] usb-storage 1-5:1.0: "
                 "USB Mass Storage device detected")
    lines.append("Mar 13 08:31:02 lab-ws kernel: [11795.000000] usb 1-5: USB disconnect, "
                 "device number 14")
    # a cloned serial: the same serial string under a different product id
    block(f"{year}-03-14T15:00:00+0000", "", "1-6", "16", "1234", "5678", "Unbranded",
          "Storage Device", "4C530001250607117025", ["usb-storage"])

    body = SAMPLE_LOG.format(app=APP_NAME, ver=VERSION, lines="\n".join(lines) + "\n")
    with open(path, "w") as fh:
        fh.write(body)
    return {"path": os.path.abspath(path), "lines": len(lines),
            "bytes": len(body), "year": year}


# =============================================================================
# SECTION 10 - Exports
# =============================================================================

def report_payload(scan_id=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "privacy_notice": PRIVACY_NOTICE,
            "method_note": (
                "Every device and event below came from the operating system's own records. "
                "History is bounded by log retention - the window field states what could "
                "actually be seen. A check whose evidence was unavailable is reported as "
                "not performed, never as a pass."),
            "scan": scan,
            "devices": [dict(r) for r in q("SELECT * FROM devices WHERE scan_id=? "
                                           "ORDER BY first_seen", (sid,), conn)] if sid else [],
            "events": [dict(r) for r in q("SELECT ts,action,vid,pid,serial,product,port,"
                                          "drivers FROM usb_events WHERE scan_id=? "
                                          "ORDER BY ts", (sid,), conn)] if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,recommendation,"
                "reference FROM findings WHERE scan_id=? ORDER BY CASE severity "
                "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, id", (sid,), conn)] if sid else [],
            "baseline": [dict(r) for r in q("SELECT * FROM baseline ORDER BY key", (), conn)],
            "scans": [dict(r) for r in q("SELECT id,ts,mode,devices,events,score,risk,"
                                         "total_findings FROM scans ORDER BY id DESC "
                                         "LIMIT 50", (), conn)],
        }
    finally:
        if own:
            conn.close()


def export_json(scan_id=None) -> str:
    return json.dumps(report_payload(scan_id), indent=2, default=str)


def export_csv(scan_id=None) -> str:
    conn = connect()
    try:
        sid = scan_id or latest_scan_id(conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan_id={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow([f"# PRIVACY: {PRIVACY_NOTICE}"])
        w.writerow(["vid", "pid", "serial", "vendor", "product", "classes", "drivers",
                    "first_seen", "last_seen", "connects", "disconnects", "total_seconds",
                    "live", "approved"])
        for r in q("SELECT * FROM devices WHERE scan_id=? ORDER BY first_seen", (sid,), conn):
            w.writerow([r[k] for k in ("vid", "pid", "serial", "vendor_name", "product",
                                       "classes", "drivers", "first_seen", "last_seen",
                                       "connects", "disconnects", "total_seconds", "live",
                                       "approved")])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(scan_id=None) -> str:
    conn = connect()
    try:
        p = report_payload(scan_id, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        classes = {}
        for d in p["devices"]:
            for c in (d["classes"] or "unknown").split(","):
                if c:
                    classes[c] = classes.get(c, 0) + 1
        pie_cls = svg_pie([(c, n, CLASS_COLOR.get(c, "#6f7685"))
                           for c, n in sorted(classes.items(), key=lambda x: -x[1])],
                          title="Devices by class")
        top = svg_bar([((d["product"] or f"{d['vid']}:{d['pid']}"), d["connects"])
                       for d in sorted(p["devices"], key=lambda x: -x["connects"])[:10]],
                      title="Most frequently attached")
        hours = {f"{h:02d}": 0 for h in range(24)}
        for e in p["events"]:
            if e["action"] == "connect" and e["ts"]:
                try:
                    hours[f"{datetime.fromisoformat(e['ts']).hour:02d}"] += 1
                except (ValueError, KeyError):
                    pass
        cols = svg_columns(sorted(hours.items()), title="Attachments by hour of day (UTC)")
        timeline = svg_device_timeline(p["devices"], scan["window_start"],
                                       scan["window_end"])
        drows = "".join(
            f'<tr><td class="mono">{esc(d["vid"])}:{esc(d["pid"])}</td>'
            f'<td>{esc(d["product"] or d["product_name"] or "-")}'
            f'<div class="sub2">{esc(d["vendor_name"])}</div></td>'
            f'<td class="mono">{esc(d["serial"] or "none reported")}</td>'
            f'<td>{"".join(f"<span class=tag>{esc(c)}</span> " for c in (d["classes"] or "").split(",") if c)}</td>'
            f'<td class="mono">{esc((d["first_seen"] or "-")[:19])}</td>'
            f'<td class="mono">{esc((d["last_seen"] or "-")[:19])}</td>'
            f'<td class="mono">{d["connects"]}</td>'
            f'<td class="mono">{esc(fmt_duration(d["total_seconds"]) if d["total_seconds"] else "-")}</td>'
            f'<td>{"yes" if d["approved"] else "no"}</td></tr>'
            for d in p["devices"])
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td><td class="mono">{esc(f["category"])}</td>'
            f'<td><b>{esc(f["title"])}</b><div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + f'<div class="rec"><b>Next:</b> {esc(f["recommendation"])}</div>'
            + (f'<div class="ref">{esc(f["reference"])}</div>' if f["reference"] else "")
            + "</td></tr>" for f in p["findings"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1120px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:32px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:23px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:13px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:10px 12px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:9px 12px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
 .sub2{{color:#8b8f9b;font-size:11px}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .tag{{font-size:10px;border:1px solid #31363f;border-radius:5px;padding:1px 5px;color:#8b8f9b}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:76ch}}
 .rec{{margin-top:6px;color:#8fd3b0;max-width:76ch}}
 .ref{{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:ui-monospace,monospace}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:8px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:7px 0 0;overflow:auto;
      white-space:pre-wrap;word-break:break-all;color:#b6bac4;max-height:180px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:16px 0;white-space:pre-wrap}}
 .privacy{{background:#1a1226;border:1px solid #4a2f6b;color:#d9c2f0;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .charts{{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:150px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 .lg em{{font-style:normal;color:#8b8f9b;font-size:11px}}
 text.bl{{fill:#8b8f9b;font:11px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}} line.gl{{stroke:#262a33;stroke-width:1}}
 text.pie-n{{fill:#e6e8ee;font:700 17px ui-monospace,monospace}}
 text.g-n{{font:700 26px ui-monospace,monospace}}
 text.g-l{{fill:#8b8f9b;font:10px ui-monospace,monospace}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;padding-top:14px}}
</style></head><body><div class="wrap">
<h1>{APP_NAME} - report</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {esc(scan['os_version'] or '')} &middot;
 mode <b>{esc(scan['mode'])}</b> &middot; {ts_pretty(scan['ts'])}</div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="privacy"><b>Privacy.</b> {esc(PRIVACY_NOTICE)}</div>
<div class="note"><b>How to read this.</b> {esc(p['method_note'])}
 Evidence window: {esc((scan['window_start'] or 'unknown')[:19])} to
 {esc((scan['window_end'] or 'unknown')[:19])}, from {esc(scan['history_source'] or 'n/a')}.
 {'Some timestamps had no year in the log and were dated to '
  + str(scan['assumed_year']) + '.' if scan['year_assumed'] else ''}</div>
<div class="charts">{svg_gauge(scan['score'] or 0, scan['risk'] or '')}
 <div><div style="font-size:24px;font-weight:700">{esc(scan['risk'] or '')}</div>
 <div class="meta">{scan['total_findings']} findings across {scan['devices']} device(s)
 and {scan['events']} event(s)</div></div></div>
<div class="grid">
{"".join(f'<div class="card"><div class="l">{s}</div><div class="n" '
         f'style="color:{SEV_COLOR[s]}">{counts[s]}</div></div>' for s in SEVERITIES)}
</div>
<h2>Device timeline</h2><div class="charts">{timeline}</div>
<h2>Analytics</h2><div class="charts">{pie}{pie_cls}</div>
<div class="charts" style="margin-top:16px">{top}{cols}</div>
<h2>Devices ({len(p['devices'])})</h2>
<table><tr><th>VID:PID</th><th>Device</th><th>Serial</th><th>Classes</th><th>First seen</th>
 <th>Last seen</th><th>Attach</th><th>Total time</th><th>Approved</th></tr>{drows}</table>
<h2>Findings ({len(p['findings'])})</h2>
<table><tr><th>Severity</th><th>Area</th><th>Detail</th></tr>{frows}</table>
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 This report identifies hardware and the times it was attached. Treat it as personal data,
 share it only with authorised parties, and delete it securely when the matter is closed.
</footer></div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 11 - Web application (5 pages, no CDN, no JavaScript libraries)
# =============================================================================

CSS = """
:root{
  --bg:#0f1115; --panel:#171a21; --panel-2:#1c2029; --line:#262a33; --line-2:#31363f;
  --tx:#e6e8ee; --tx-dim:#8b8f9b; --tx-mid:#b6bac4; --accent:#ffa94d; --ok:#30a46c;
  --warn:#ffb224; --crit:#e5484d;
  --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1220px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px;
  flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10.5px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:12px;letter-spacing:.06em;text-transform:uppercase;
  padding:7px 11px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1220px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:10px 14px;
  border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.privacy{background:#1a1226;border-color:#4a2f6b;color:#d9c2f0}
.banner.info{background:#12202a;border-color:#1c4a5e;color:#a8d8e8}
.banner.sample{background:#12261c;border-color:#1e5138;color:#a6e8c4}
.banner b{color:#fff}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--tx-dim);margin:26px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
  border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
select,input[type=text],input[type=number]{font-family:var(--mono);font-size:12px;padding:7px 9px;
  background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px}
input[type=text]{min-width:200px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(138px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--tx-dim)}
.card .n{font-size:24px;font-weight:700;line-height:1.3;font-family:var(--mono)}
.card .s{font-size:11.5px;color:var(--tx-dim)}
.hero{display:flex;gap:22px;align-items:center;flex-wrap:wrap;background:var(--panel);
  border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.hero .meta{flex:1;min-width:250px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12.5px}
.kv dt{color:var(--tx-dim);font-family:var(--mono);font-size:11px;letter-spacing:.07em;
  text-transform:uppercase}
.kv dd{margin:0;word-break:break-word}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
  border-radius:11px;overflow:hidden;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--tx-dim);padding:10px 12px;border-bottom:1px solid var(--line);
  background:var(--panel-2);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:12px}
.num{font-family:var(--mono);font-size:12px;text-align:right}
.sub2{color:var(--tx-dim);font-size:11px}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
  border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:1px 6px;border-radius:5px;
  border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap}
.tag.good{border-color:#1e5138;color:#7fd9ab} .tag.bad{border-color:#5a2326;color:#ff9b9e}
.tag.live{border-color:#1e5138;color:#7fd9ab}
.strip{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.strip div{font-family:var(--mono);font-size:11px;padding:6px 10px;border-radius:7px;
  border:1px solid var(--line);background:var(--panel)}
.strip .ok{border-color:#1e5138} .strip .partial{border-color:#5a3b1c}
.strip .unavailable{border-color:#5a2326}
.strip b{text-transform:uppercase;letter-spacing:.08em}
.desc{color:var(--tx-mid);margin-top:4px;max-width:78ch}
.rec{margin-top:6px;color:#8fd3b0;font-size:12.5px;max-width:78ch}
.ref{margin-top:4px;color:#6f7685;font-size:11.5px;font-family:var(--mono)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px;
  font-family:var(--mono);font-size:11.5px;margin:7px 0 0;max-height:170px;overflow:auto;
  white-space:pre-wrap;word-break:break-all;color:var(--tx-mid)}
details summary{cursor:pointer;color:var(--tx-dim);font-size:12px;font-family:var(--mono)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
  padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:250px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:150px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none}
.lg span{flex:1} .lg b{font-family:var(--mono)}
.lg em{font-style:normal;color:var(--tx-dim);font-family:var(--mono);font-size:11px}
text.bl{fill:#8b8f9b;font:11px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
rect.btrack{fill:#1e222a} line.gl{stroke:#262a33;stroke-width:1}
text.pie-n{fill:#e6e8ee;font:700 17px var(--mono)}
text.g-n{font:700 26px var(--mono)} text.g-l{fill:#8b8f9b;font:10px var(--mono)}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
  text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1220px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
  border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){
  .hd{padding:10px 14px} .wrap{padding:14px 14px 50px} nav{margin-left:0;width:100%}
  .card .n{font-size:20px} table{font-size:12.2px} th,td{padding:8px 9px}
  input[type=text]{min-width:140px}
}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>USBF</b> USB Forensics
  <small>device metadata only &middot; never device contents</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_devices') }}" class="{{ 'on' if nav=='devices' }}">Devices</a>
  <a href="{{ url_for('page_timeline') }}" class="{{ 'on' if nav=='timeline' }}">Timeline</a>
  <a href="{{ url_for('page_analytics') }}" class="{{ 'on' if nav=='analytics' }}">Analytics</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>Authorised use only.</b> """ + DISCLAIMER_SHORT + """</div>
 {% if scan and scan.mode == 'sample' %}
 <div class="banner sample"><b>This is the training fixture, not real evidence.</b>
  These events were generated to demonstrate the tool. Nothing here happened on any real
  machine.</div>
 {% endif %}
 {% if error %}<div class="banner" style="background:#2a1216;border-color:#6b2229;
  color:#ffc9cd"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner info">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 """ + PRIVACY_NOTICE + """<br>
 Runs offline: no API keys, no vendor lookup service, no telemetry. History is bounded by log
 retention - absence of a device here is not evidence it was never attached.</footer>
</body></html>"""

CONTROLS_TPL = """
<div class="bar">
 <form method="post" action="{{ url_for('do_scan') }}">
  <button class="btn primary" type="submit">Scan this machine</button></form>
 <form method="post" action="{{ url_for('do_sample') }}">
  <button class="btn" type="submit">Load training fixture</button></form>
 {% if scan %}
 <form method="get" style="display:flex;gap:8px;align-items:center">
  <label class="mono" style="color:var(--tx-dim)">SCAN</label>
  <select name="scan" onchange="this.form.submit()">
   {% for s in all_scans %}<option value="{{ s.id }}" {{ 'selected' if s.id==scan.id }}>
    #{{ s.id }} &middot; {{ s.ts[:16].replace('T',' ') }} &middot; {{ s.mode }} &middot;
    {{ s.devices }} devices</option>{% endfor %}</select>
 </form>
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + CONTROLS_TPL + """
<div class="empty"><b>No scans yet</b>
 Scan this machine to read its live USB inventory and kernel log history, or load the training
 fixture to see what a populated report looks like. Nothing is shown until real evidence has
 been read - and if a source is unreadable here, it is reported as unavailable rather than
 quietly treated as empty.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 usb_forensics.py scan<br>
  or analyse an exported log: python3 usb_forensics.py scan --log-file kern.log</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Scan #{{ scan.id }} of {{ scan.hostname }} &middot; {{ ts_pretty(scan.ts) }}</div>
""" + CONTROLS_TPL + """
<div class="hero">
 {{ gauge|safe }}
 <div class="meta"><dl class="kv">
  <dt>Risk</dt><dd><b>{{ scan.risk }}</b> - {{ scan.total_findings }} finding(s)</dd>
  <dt>Evidence</dt><dd>{{ scan.history_source or 'none' }}</dd>
  <dt>Window</dt><dd>{{ (scan.window_start or 'unknown')[:19] }} to
   {{ (scan.window_end or 'unknown')[:19] }}
   {% if scan.year_assumed %}<span class="tag bad">some timestamps had no year; assumed
    {{ scan.assumed_year }}</span>{% endif %}</dd>
  <dt>Vendor ids</dt><dd>{{ scan.usbids_source }}</dd>
  <dt>Host</dt><dd>{{ scan.os_version }}</dd>
 </dl></div>
</div>
<h2>Collector status</h2>
<div class="sub">What could actually be read. Anything not "ok" means the matching checks were
 reported as not performed rather than passed.</div>
<div class="strip">
 <div class="{{ scan.live_status }}"><b>live inventory</b> &middot; {{ scan.live_status }}
  {% if scan.live_detail %}&middot; {{ scan.live_detail }}{% endif %}</div>
 <div class="{{ scan.history_status }}"><b>history</b> &middot; {{ scan.history_status }}
  &middot; {{ scan.log_lines }} log lines
  {% if scan.history_detail %}&middot; {{ scan.history_detail }}{% endif %}</div>
</div>
<div class="grid">
 <div class="card"><div class="l">Devices</div><div class="n">{{ scan.devices }}</div>
  <div class="s">{{ n_live }} attached now</div></div>
 <div class="card"><div class="l">Events</div><div class="n">{{ scan.events }}</div></div>
{% for s in severities %}
 <div class="card"><div class="l">{{ s }}</div>
  <div class="n" style="color:{{ sev[s] }}">{{ scan[s] }}</div></div>
{% endfor %}
</div>
<h2>Device timeline</h2>
<div class="charts">{{ timeline|safe }}</div>
<h2>Findings</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Area</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td class="mono">{{ f.category }}</td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<details><summary>Evidence</summary><pre>{{ f.evidence }}</pre></details>
  {% endif %}
  <div class="rec">Next: {{ f.recommendation }}</div>
  {% if f.reference %}<div class="ref">{{ f.reference }}</div>{% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings were raised.</div>{% endif %}
{% endblock %}"""

DEVICES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Devices</h1>
<div class="sub">{{ rows|length }} of {{ scan.devices }} device(s) from scan #{{ scan.id }}.
 Approving a device removes it from the unapproved-device findings on future scans.</div>
<div class="banner privacy"><b>Privacy.</b> """ + PRIVACY_NOTICE + """</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="class"><option value="">All classes</option>
  {% for c in classes %}<option value="{{ c }}" {{ 'selected' if c==f_class }}>{{ c }}</option>
  {% endfor %}</select>
 <select name="approved"><option value="">Approved and not</option>
  <option value="0" {{ 'selected' if f_approved=='0' }}>not approved</option>
  <option value="1" {{ 'selected' if f_approved=='1' }}>approved</option></select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="vendor, product or serial">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_devices') }}?scan={{ scan.id }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>VID:PID</th><th>Device</th><th>Serial</th><th>Classes</th><th>First seen</th>
 <th>Last seen</th><th>Attach</th><th>Total</th><th>Baseline</th></tr>
{% for d in rows %}
<tr><td class="mono">{{ d.vid }}:{{ d.pid }}
  {% if d.live %}<span class="tag live">attached</span>{% endif %}</td>
 <td>{{ d.product or d.product_name or '-' }}
  <div class="sub2">{{ d.vendor_name }}{% if not d.vendor_known %} (id not in usb.ids)
  {% endif %}</div></td>
 <td class="mono">{{ d.serial or '' }}
  {% if not d.serial %}<span class="tag bad">none reported</span>{% endif %}</td>
 <td>{% for c in (d.classes or '').split(',') %}{% if c %}
  <span class="tag">{{ c }}</span> {% endif %}{% endfor %}</td>
 <td class="mono">{{ (d.first_seen or '-')[:19] }}</td>
 <td class="mono">{{ (d.last_seen or '-')[:19] }}</td>
 <td class="num">{{ d.connects }}</td>
 <td class="num">{{ fmt_duration(d.total_seconds) if d.total_seconds else '-' }}</td>
 <td>{% if d.approved %}<span class="tag good">approved</span>
  <form method="post" action="{{ url_for('do_revoke') }}" style="display:inline">
   <input type="hidden" name="key" value="{{ d.key }}">
   <input type="hidden" name="scan" value="{{ scan.id }}">
   <button class="btn tiny" type="submit">remove</button></form>
 {% else %}
  <form method="post" action="{{ url_for('do_approve') }}" style="display:inline">
   <input type="hidden" name="key" value="{{ d.key }}">
   <input type="hidden" name="scan" value="{{ scan.id }}">
   <input type="hidden" name="label" value="{{ d.product or '' }}">
   <button class="btn tiny" type="submit">approve</button></form>
 {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing matches this filter</b></div>{% endif %}
{% if baseline %}
<h2>Baseline ({{ baseline|length }})</h2>
<table><tr><th>Key</th><th>Label</th><th>Approved</th><th>By</th></tr>
{% for b in baseline %}<tr><td class="mono">{{ b.key }}</td><td>{{ b.label or '-' }}</td>
 <td class="mono">{{ (b.approved_at or '')[:19] }}</td><td class="mono">{{ b.approved_by }}</td>
</tr>{% endfor %}</table>
{% endif %}
{% endblock %}"""

TIMELINE_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Timeline</h1>
<div class="sub">Every attach and detach recorded in the evidence, oldest first.
 {% if scan.year_assumed %}Entries from logs with no year were dated to
 {{ scan.assumed_year }}.{% endif %}</div>
<div class="charts">{{ timeline|safe }}</div>
<div class="bar" style="margin-top:16px"><form method="get" style="display:flex;gap:8px;
 flex-wrap:wrap">
 <input type="hidden" name="scan" value="{{ scan.id }}">
 <select name="action"><option value="">All actions</option>
  {% for a in actions %}<option value="{{ a }}" {{ 'selected' if a==f_action }}>{{ a }}</option>
  {% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="vid, serial or product">
 <select name="limit">{% for n in [100,250,500,1000] %}
  <option value="{{ n }}" {{ 'selected' if n==limit }}>last {{ n }}</option>{% endfor %}</select>
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_timeline') }}?scan={{ scan.id }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>When</th><th>Action</th><th>VID:PID</th><th>Device</th><th>Serial</th>
 <th>Port</th><th>Drivers</th></tr>
{% for e in rows %}
<tr><td class="mono">{{ (e.ts or 'no timestamp')[:19].replace('T',' ') }}
 {% if e.year_assumed %}<span class="tag bad">year assumed</span>{% endif %}</td>
 <td>{% if e.action == 'connect' %}<span class="tag good">attach</span>
  {% elif e.action == 'disconnect' %}<span class="tag">detach</span>
  {% else %}<span class="tag">{{ e.action }}</span>{% endif %}</td>
 <td class="mono">{{ (e.vid ~ ':' ~ e.pid) if e.vid else '-' }}</td>
 <td>{{ e.product or '-' }}</td>
 <td class="mono">{{ e.serial or '-' }}</td>
 <td class="mono">{{ e.port or '-' }}</td>
 <td class="mono">{{ e.drivers or '-' }}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>No events match</b>
 {{ 'The history collector reported: ' ~ scan.history_detail if scan.history_detail else '' }}
</div>{% endif %}
{% endblock %}"""

ANALYTICS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Analytics</h1>
<div class="sub">Charts are plain SVG rendered from the SQLite database - no external chart
 library, no network calls.</div>
""" + CONTROLS_TPL + """
{% if scan %}
<div class="charts">{{ pie_sev|safe }}{{ pie_cls|safe }}</div>
<div class="charts" style="margin-top:16px">{{ bar_top|safe }}{{ bar_time|safe }}</div>
<div class="charts" style="margin-top:16px">{{ col_hour|safe }}{{ col_day|safe }}</div>
<h2>Device timeline</h2><div class="charts">{{ timeline|safe }}</div>
{% endif %}
<h2>Scan history</h2>
{% if scans %}
<table><tr><th>#</th><th>When</th><th>Mode</th><th>Devices</th><th>Events</th><th>Score</th>
 <th>Risk</th><th>C</th><th>H</th><th>M</th><th>L</th></tr>
{% for s in scans %}<tr>
 <td class="mono"><a href="{{ url_for('page_overview') }}?scan={{ s.id }}">#{{ s.id }}</a></td>
 <td class="mono">{{ s.ts[:19].replace('T',' ') }}</td>
 <td class="mono">{{ s.mode }}</td><td class="num">{{ s.devices }}</td>
 <td class="num">{{ s.events }}</td>
 <td class="num" style="color:{{ s.colour }}"><b>{{ s.score }}</b></td>
 <td>{{ s.risk }}</td>
 <td class="num" style="color:{{ sev.critical }}">{{ s.critical }}</td>
 <td class="num" style="color:{{ sev.high }}">{{ s.high }}</td>
 <td class="num" style="color:{{ sev.medium }}">{{ s.medium }}</td>
 <td class="num">{{ s.low }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty">No scans yet.</div>{% endif %}
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Every scan, approval and export this tool has performed, stored
 locally in {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <select name="limit">{% for n in [50,100,250,500,1000] %}
  <option value="{{ n }}" {{ 'selected' if n==limit }}>last {{ n }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search message">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
<div class="grid">
 <div class="card"><div class="l">Events</div><div class="n">{{ counts.total }}</div></div>
 <div class="card"><div class="l">Errors</div>
  <div class="n" style="color:var(--crit)">{{ counts.ERROR }}</div></div>
 <div class="card"><div class="l">Warnings</div>
  <div class="n" style="color:var(--warn)">{{ counts.WARN }}</div></div>
 <div class="card"><div class="l">Info</div><div class="n">{{ counts.INFO }}</div></div>
</div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Scan</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "devices.html": DEVICES_TPL, "timeline.html": TIMELINE_TPL,
             "analytics.html": ANALYTICS_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, conn, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty,
                "fmt_duration": fmt_duration, "scan": None,
                "error": request.args.get("error"), "flash": request.args.get("flash"),
                "all_scans": q("SELECT id, ts, mode, devices FROM scans ORDER BY id DESC "
                               "LIMIT 100", (), conn)}
        base.update(kw)
        return base

    def pick_scan(conn):
        try:
            sid = int(request.args.get("scan", "") or 0)
        except ValueError:
            sid = 0
        if sid and scan_summary(sid, conn):
            return scan_summary(sid, conn)
        sid = latest_scan_id(conn)
        return scan_summary(sid, conn) if sid else None

    def timeline_for(scan, conn):
        devs = [dict(r) for r in q("SELECT * FROM devices WHERE scan_id=?",
                                   (scan["id"],), conn)]
        for d in devs:
            d["classes"] = (d["classes"] or "").split(",")
        return svg_device_timeline(devs, scan["window_start"], scan["window_end"])

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("overview", conn))
            return render_template("overview.html", **ctx(
                "overview", conn, scan=scan,
                gauge=svg_gauge(scan["score"] or 0, scan["risk"] or ""),
                timeline=timeline_for(scan, conn),
                n_live=q1("SELECT COUNT(*) c FROM devices WHERE scan_id=? AND live=1",
                          (scan["id"],), conn)["c"],
                findings=q("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
                           "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                           "WHEN 'low' THEN 3 ELSE 4 END, id", (scan["id"],), conn)))
        finally:
            conn.close()

    @app.route("/devices")
    def page_devices():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("devices", conn))
            cls = request.args.get("class", "").strip()
            appr = request.args.get("approved", "").strip()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM devices WHERE scan_id=?", [scan["id"]]
            if cls:
                sql += " AND classes LIKE ?"
                args.append(f"%{cls}%")
            if appr in ("0", "1"):
                sql += " AND approved=?"
                args.append(int(appr))
            if term:
                sql += (" AND (IFNULL(product,'') LIKE ? OR IFNULL(serial,'') LIKE ? "
                        "OR vendor_name LIKE ? OR vid LIKE ?)")
                args += [f"%{term}%"] * 4
            sql += " ORDER BY live DESC, first_seen"
            classes = set()
            for r in q("SELECT classes FROM devices WHERE scan_id=?", (scan["id"],), conn):
                for c in (r["classes"] or "").split(","):
                    if c:
                        classes.add(c)
            return render_template("devices.html", **ctx(
                "devices", conn, scan=scan, rows=q(sql, tuple(args), conn),
                classes=sorted(classes), f_class=cls, f_approved=appr, f_q=term,
                baseline=q("SELECT * FROM baseline ORDER BY approved_at DESC", (), conn)))
        finally:
            conn.close()

    @app.route("/timeline")
    def page_timeline():
        conn = connect()
        try:
            scan = pick_scan(conn)
            if not scan:
                return render_template("empty.html", **ctx("timeline", conn))
            action = request.args.get("action", "").strip()
            term = request.args.get("qq", "").strip()
            try:
                limit = clamp(int(request.args.get("limit", 250)), 10, 2000)
            except ValueError:
                limit = 250
            sql, args = "SELECT * FROM usb_events WHERE scan_id=?", [scan["id"]]
            if action:
                sql += " AND action=?"
                args.append(action)
            if term:
                sql += (" AND (IFNULL(vid,'') LIKE ? OR IFNULL(serial,'') LIKE ? "
                        "OR IFNULL(product,'') LIKE ?)")
                args += [f"%{term}%"] * 3
            sql += " ORDER BY ts IS NULL, ts LIMIT ?"
            args.append(limit)
            actions = [r["action"] for r in q("SELECT DISTINCT action FROM usb_events "
                                              "WHERE scan_id=?", (scan["id"],), conn)]
            return render_template("timeline.html", **ctx(
                "timeline", conn, scan=scan, rows=q(sql, tuple(args), conn),
                actions=sorted(actions), f_action=action, f_q=term, limit=limit,
                timeline=timeline_for(scan, conn)))
        finally:
            conn.close()

    @app.route("/analytics")
    def page_analytics():
        conn = connect()
        try:
            scan = pick_scan(conn)
            kw = {"scan": scan}
            if scan:
                sid = scan["id"]
                devs = [dict(r) for r in q("SELECT * FROM devices WHERE scan_id=?",
                                           (sid,), conn)]
                classes = {}
                for d in devs:
                    for c in (d["classes"] or "").split(","):
                        if c:
                            classes[c] = classes.get(c, 0) + 1
                hours = {f"{h:02d}": 0 for h in range(24)}
                days = {}
                for e in q("SELECT ts FROM usb_events WHERE scan_id=? AND action='connect' "
                           "AND ts IS NOT NULL", (sid,), conn):
                    try:
                        dt = datetime.fromisoformat(e["ts"])
                    except ValueError:
                        continue
                    hours[f"{dt.hour:02d}"] += 1
                    days[dt.strftime("%m-%d")] = days.get(dt.strftime("%m-%d"), 0) + 1
                kw.update(
                    pie_sev=svg_pie([(s, scan[s] or 0, SEV_COLOR[s]) for s in SEVERITIES]),
                    pie_cls=svg_pie([(c, n, CLASS_COLOR.get(c, "#6f7685"))
                                     for c, n in sorted(classes.items(), key=lambda x: -x[1])],
                                    title="Devices by class"),
                    bar_top=svg_bar([((d["product"] or f"{d['vid']}:{d['pid']}"), d["connects"])
                                     for d in sorted(devs, key=lambda x: -x["connects"])[:10]],
                                    title="Most frequently attached"),
                    bar_time=svg_bar([((d["product"] or f"{d['vid']}:{d['pid']}"),
                                       d["total_seconds"])
                                      for d in sorted(devs, key=lambda x: -x["total_seconds"])
                                      [:10] if d["total_seconds"]],
                                     title="Longest total attachment", color="#9775fa",
                                     fmt=fmt_duration),
                    col_hour=svg_columns(sorted(hours.items()),
                                         title="Attachments by hour of day (UTC)"),
                    col_day=svg_columns(sorted(days.items())[-21:], title="Attachments by day",
                                        color="#30a46c"),
                    timeline=timeline_for(scan, conn))
            scans = []
            for s in q("SELECT * FROM scans ORDER BY id DESC LIMIT 25", (), conn):
                d = dict(s)
                d["colour"] = risk_label(d["score"] or 0)[1]
                scans.append(d)
            kw["scans"] = scans
            return render_template("analytics.html", **ctx("analytics", conn, **kw))
        finally:
            conn.close()

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            try:
                limit = clamp(int(request.args.get("limit", 100)), 10, 1000)
            except ValueError:
                limit = 100
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            counts = {"total": q1("SELECT COUNT(*) c FROM audit_log", (), conn)["c"]}
            for lv in ("INFO", "WARN", "ERROR"):
                counts[lv] = q1("SELECT COUNT(*) c FROM audit_log WHERE level=?",
                                (lv,), conn)["c"]
            return render_template("logs.html", **ctx(
                "logs", conn, rows=q(sql, tuple(args), conn), counts=counts, limit=limit,
                f_level=level, f_q=term, dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    # ---- actions ----
    @app.post("/scan")
    def do_scan():
        try:
            sid = run_scan(note="from the web UI")
            return redirect(url_for("page_overview") + f"?scan={sid}")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error="
                            + urllib_quote(str(e)))

    @app.post("/sample")
    def do_sample():
        path = os.path.abspath("usb-sample.log")
        info = build_sample_log(path)
        sid = run_scan(log_file=path, mode="sample", note="training fixture")
        conn = connect()
        try:
            conn.execute("UPDATE scans SET mode='sample' WHERE id=?", (sid,))
            conn.commit()
        finally:
            conn.close()
        log_event("INFO", "sample", f"Loaded the training fixture from {path} "
                  f"({info['lines']} log lines) as scan #{sid}", sid)
        return redirect(url_for("page_overview") + f"?scan={sid}&flash="
                        + urllib_quote(f"Training fixture written to {path} and analysed as "
                                       f"scan #{sid}. These events are synthetic."))

    @app.post("/approve")
    def do_approve():
        key = (request.form.get("key") or "").strip()
        if key:
            approve_device(key, label=(request.form.get("label") or "").strip(),
                           note="approved from the web UI")
        return redirect(url_for("page_devices") + f"?scan={request.form.get('scan', '')}")

    @app.post("/revoke")
    def do_revoke():
        key = (request.form.get("key") or "").strip()
        if key:
            revoke_device(key)
        return redirect(url_for("page_devices") + f"?scan={request.form.get('scan', '')}")

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="usbf-report-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no scans yet"}), 404
        return jsonify({"tool": APP_NAME, "version": VERSION,
                        "disclaimer": DISCLAIMER_SHORT, "scan": scan_summary(sid)})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /devices /timeline "
                        "/analytics /logs", 404, mimetype="text/plain")

    return app


def urllib_quote(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s)


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port} (db={db_path()})")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    print(f"  Pages   : /  /devices  /timeline  /analytics  /logs")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI has no authentication and shows which\n"
              "            hardware has been attached to this machine and when. Use\n"
              "            127.0.0.1 unless you have a specific reason.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 12 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None):
    shown = rows[:limit] if limit else rows
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}   ({f['category']})")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f["evidence"]:
            ev = " ".join(str(f["evidence"]).split())
            print(f"      evidence: {ev[:200]}{'...' if len(ev) > 200 else ''}")
        if f["recommendation"]:
            for l in textwrap.wrap("next: " + f["recommendation"], 70):
                print(f"      {l}")
    if limit and len(rows) > limit:
        print(f"\n  ... {len(rows) - limit} more (use 'findings')")


def _parse_work_hours(text: str) -> tuple[int, int]:
    m = re.match(r"^(\d{1,2})\s*-\s*(\d{1,2})$", (text or "").strip())
    if not m:
        return 8, 19
    return clamp(int(m.group(1)), 0, 23), clamp(int(m.group(2)), 1, 24)


def cmd_scan(a):
    banner()
    if a.log_file:
        print(f"Analysing exported log: {a.log_file}")
        print("The live inventory is not collected in this mode - the log is the evidence.\n")
    else:
        print(f"Reading live inventory and kernel log history on {socket.gethostname()}\n")
    sid = run_scan(log_file=a.log_file, note=a.note or "",
                   work_hours=_parse_work_hours(a.work_hours),
                   assume_year=a.assume_year)
    cmd_show(argparse.Namespace(scan=sid, limit=a.show))
    return 0


def cmd_sample(a):
    banner()
    info = build_sample_log(a.out, year=a.year)
    print(f"Training fixture written to {info['path']}")
    print(f"  {info['lines']} log lines in the real kernel format, {info['bytes']:,} bytes\n")
    print(textwrap.fill(
        "These lines are formatted exactly as the Linux USB stack writes them, but the "
        "events never happened. The fixture exists so you can see a populated report and "
        "so the self test has something deterministic to check against. Scans of it are "
        "stored with mode='sample' and labelled in every view, so they can never be "
        "mistaken for a real examination.", 78))
    sid = run_scan(log_file=info["path"], mode="sample", note="training fixture")
    conn = connect()
    try:
        conn.execute("UPDATE scans SET mode='sample' WHERE id=?", (sid,))
        conn.commit()
    finally:
        conn.close()
    print()
    cmd_show(argparse.Namespace(scan=sid, limit=a.show))
    return 0


def cmd_show(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet. Run:  scan")
        return
    s = scan_summary(sid)
    if not s:
        print(f"Scan #{sid} not found.")
        return
    conn = connect()
    try:
        line("=")
        print(f"  SCAN #{s['id']}  {s['hostname']}  ({s['os_version']})")
        print(f"  {ts_pretty(s['ts'])}  |  mode {s['mode']}")
        if s["mode"] == "sample":
            print("  *** TRAINING FIXTURE - these events are synthetic, not evidence ***")
        line("=")
        bars = int(round((s["score"] or 0) / 5))
        print(f"  [{'#' * bars}{'.' * (20 - bars)}]  {s['score']}/100   {s['risk']}")
        print(f"  {s['devices']} device(s), {s['events']} event(s), "
              f"{s['total_findings']} finding(s)")
        print(f"  critical {s['critical']}   high {s['high']}   medium {s['medium']}   "
              f"low {s['low']}   info {s['info']}")
        line()
        print("  EVIDENCE")
        for name, status, detail in (("live inventory", s["live_status"], s["live_detail"]),
                                     ("history", s["history_status"], s["history_detail"])):
            mark = {"ok": "[ok]", "partial": "[!!]", "unavailable": "[XX]"}.get(status, "[??]")
            print(f"   {mark} {name:<16}{('  ' + detail) if detail else ''}")
        print(f"        source : {s['history_source'] or 'none'}")
        print(f"        window : {(s['window_start'] or 'unknown')[:19]} to "
              f"{(s['window_end'] or 'unknown')[:19]}")
        if s["year_assumed"]:
            print(f"        NOTE   : some log lines had no year; dated to {s['assumed_year']}")
        print(f"        vendors: {s['usbids_source']}")
        line()
        devs = q("SELECT * FROM devices WHERE scan_id=? ORDER BY live DESC, first_seen",
                 (sid,), conn)
        print(f"  DEVICES ({len(devs)})")
        print(f"  {'VID:PID':<11} {'SERIAL':<24} {'CLASSES':<22} {'FIRST SEEN':<20} ATT")
        line()
        for d in devs:
            print(f"  {d['vid']}:{d['pid']:<6} {(d['serial'] or '-')[:23]:<24} "
                  f"{(d['classes'] or '-')[:21]:<22} "
                  f"{(d['first_seen'] or '-')[:19]:<20} {d['connects']}"
                  f"{'  [approved]' if d['approved'] else ''}"
                  f"{'  [attached]' if d['live'] else ''}")
            name = d["product"] or d["product_name"]
            if name:
                print(f"       {name} - {d['vendor_name']}")
        line()
        rows = [dict(r) for r in q(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, id LIMIT ?", (sid, a.limit), conn)]
        print(f"  FINDINGS (showing {len(rows)} of {s['total_findings']})")
        _print_findings(rows)
        line()
        print(f"  Devices : python3 {os.path.basename(__file__)} devices --scan {sid}")
        print(f"  Timeline: python3 {os.path.basename(__file__)} timeline --scan {sid}")
        print(f"  Web app : python3 {os.path.basename(__file__)} serve")
        line()
    finally:
        conn.close()


def cmd_devices(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM devices WHERE scan_id=?", [sid]
    if a.klass:
        sql += " AND classes LIKE ?"
        args.append(f"%{a.klass}%")
    if a.approved:
        sql += " AND approved=1"
    if a.unapproved:
        sql += " AND approved=0"
    if a.live:
        sql += " AND live=1"
    sql += " ORDER BY live DESC, first_seen"
    rows = q(sql, tuple(args))
    if not rows:
        print("No devices match that filter.")
        return
    for d in rows:
        print(f"\n  {d['vid']}:{d['pid']}  {d['product'] or d['product_name'] or 'unnamed'}")
        print(f"    vendor    : {d['vendor_name']}"
              f"{'' if d['vendor_known'] else '  (id not in usb.ids)'}")
        print(f"    serial    : {d['serial'] or 'none reported'}")
        print(f"    classes   : {d['classes'] or 'unknown'}")
        print(f"    drivers   : {d['drivers'] or '-'}")
        print(f"    first seen: {(d['first_seen'] or '-')[:19]}")
        print(f"    last seen : {(d['last_seen'] or '-')[:19]}")
        print(f"    attached  : {d['connects']} time(s), "
              f"{fmt_duration(d['total_seconds']) if d['total_seconds'] else 'duration unknown'}")
        print(f"    baseline  : {'approved' if d['approved'] else 'not approved'}"
              f"{'   [attached now]' if d['live'] else ''}")
        print(f"    key       : {d['key']}")
    print(f"\n{len(rows)} device(s) from scan #{sid}")


def cmd_timeline(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM usb_events WHERE scan_id=?", [sid]
    if a.action:
        sql += " AND action=?"
        args.append(a.action)
    sql += " ORDER BY ts IS NULL, ts LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No events recorded for that scan.")
        s = scan_summary(sid)
        if s and s["history_detail"]:
            print(f"History collector said: {s['history_detail']}")
        return
    print(f"{'WHEN':<21} {'ACTION':<11} {'VID:PID':<11} {'SERIAL':<22} PRODUCT")
    line()
    for e in rows:
        print(f"{(e['ts'] or 'no timestamp')[:19].replace('T', ' '):<21} "
              f"{e['action']:<11} {(e['vid'] + ':' + e['pid']) if e['vid'] else '-':<11} "
              f"{(e['serial'] or '-')[:21]:<22} {e['product'] or ''}"
              f"{'   [year assumed]' if e['year_assumed'] else ''}")
    print(f"\n{len(rows)} event(s) from scan #{sid}")


def cmd_findings(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans yet.")
        return
    sql, args = "SELECT * FROM findings WHERE scan_id=?", [sid]
    if a.severity:
        sql += " AND severity=?"
        args.append(a.severity)
    sql += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id")
    rows = [dict(r) for r in q(sql, tuple(args))]
    if not rows:
        print("No findings match that filter.")
        return
    print(f"Scan #{sid} - {len(rows)} finding(s)")
    _print_findings(rows)


def cmd_approve(a):
    approve_device(a.key, label=a.label or "", note=a.note or "")
    print(f"Approved {a.key}")
    print("Future scans will exclude it from the unapproved-device findings.")


def cmd_revoke(a):
    n = revoke_device(a.key)
    print(f"Removed {n} entry(ies) from the baseline." if n
          else f"{a.key} was not in the baseline.")


def cmd_baseline(a):
    rows = q("SELECT * FROM baseline ORDER BY approved_at DESC")
    if not rows:
        print("The baseline is empty. Approve devices with:  approve --key <key>")
        return
    print(f"{'KEY':<40} {'LABEL':<26} {'APPROVED':<20} BY")
    line()
    for r in rows:
        print(f"{r['key'][:39]:<40} {(r['label'] or '-')[:25]:<26} "
              f"{(r['approved_at'] or '')[:19]:<20} {r['approved_by'] or ''}")
    print(f"\n{len(rows)} approved device(s)")


def cmd_watch(a):
    banner()
    first = parse_sysfs_devices()
    if first.status == "unavailable":
        print(f"Cannot watch: {first.detail}")
        print("\nWatching needs a live USB subsystem. On a machine without one there is "
              "nothing to poll.")
        return 1
    print(f"Polling {first.source} every {a.interval}s. Ctrl+C to stop.\n")
    seen = {device_key(d["vid"], d["pid"], d.get("serial")): d for d in first.data}
    for k, d in seen.items():
        print(f"  present  {k}  {d.get('product') or ''}")
    print()
    try:
        while True:
            time.sleep(a.interval)
            cur = parse_sysfs_devices()
            if cur.status == "unavailable":
                print(f"  [!] {cur.detail}")
                continue
            now = {device_key(d["vid"], d["pid"], d.get("serial")): d for d in cur.data}
            for k, d in now.items():
                if k not in seen:
                    vendor, _ = USBIDS.vendor(d["vid"])
                    print(f"  {datetime.now().strftime('%H:%M:%S')}  ATTACH   {k}  "
                          f"{d.get('product') or ''} ({vendor})")
                    log_event("INFO", "watch", f"Attached {k} {d.get('product') or ''}")
            for k, d in seen.items():
                if k not in now:
                    print(f"  {datetime.now().strftime('%H:%M:%S')}  DETACH   {k}  "
                          f"{d.get('product') or ''}")
                    log_event("INFO", "watch", f"Detached {k} {d.get('product') or ''}")
            seen = now
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("No scans yet.")
        return
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'MODE':<8} {'DEV':>4} {'EVT':>5} {'SCORE':>6}  RISK")
    line()
    for s in rows:
        print(f"{s['id']:>4}  {s['ts'][:19].replace('T', ' '):<20} {s['mode']:<8} "
              f"{s['devices']:>4} {s['events']:>5} {s['score']:>6}  {s['risk']}")


def cmd_explain(_a):
    banner()
    print(textwrap.dedent("""\
        WHERE USB HISTORY ACTUALLY LIVES
          Linux    The kernel logs every enumeration. Each attach produces a block:
                     usb 1-2: new high-speed USB device number 5 using xhci_hcd
                     usb 1-2: New USB device found, idVendor=0781, idProduct=5591
                     usb 1-2: Product: Ultra USB 3.0
                     usb 1-2: Manufacturer: SanDisk
                     usb 1-2: SerialNumber: 4C530001250607117025
                     usb-storage 1-2:1.0: USB Mass Storage device detected
                   and a matching 'USB disconnect, device number 5' on removal. That
                   pair gives you an attachment window. /sys/bus/usb/devices shows
                   what is attached right now.
          Windows  HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR keeps one subkey per
                   storage device ever attached, and setupapi.dev.log records the
                   first installation time.
          macOS    system_profiler SPUSBDataType for the live tree, and the unified
                   log for events.

        WHAT THE EVIDENCE DOES AND DOES NOT SUPPORT
          It shows that the kernel enumerated a device, and when. It does not show
          what was copied, by whom, or whether anything was copied at all. Pair it
          with filesystem, application and authentication logs before drawing any
          conclusion.

        THE LIMITS THAT MATTER MOST
          1. Log retention. Rotation quietly ends your history. This tool reports the
             window it could actually see; absence of a device is not evidence it was
             never attached.
          2. No serial number. Many cheap drives and most injection tools report none.
             Two appearances of a serial-less model may be two different objects.
          3. Classic syslog has no year. Entries crossing a new year get misdated
             unless you know the log's age. Flagged here rather than hidden.
          4. A serial is just a string the device claims. It can be cloned. Two
             different products sharing one serial is a strong tampering signal.

        THE PATTERN WORTH LOOKING FOR
          A device that registers BOTH mass storage and a human interface device is
          the shape of a BadUSB tool: it presents as a flash drive and can also type.
          Legitimate composite devices exist, so confirm the model - but this is the
          single highest-value signal in USB telemetry, and it is why the tool treats
          it as critical.
        """))
    line()
    print(PRIVACY_NOTICE)
    line()


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("No scans to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"usbf-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported scan #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("This report identifies hardware and attachment times - treat it as personal data.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<14} "
              f"{e['message']}")


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "usb_events", "devices", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.baseline:
                conn.execute("DELETE FROM baseline")
            conn.commit()
            print("All scans, devices, events and logs deleted."
                  + (" The baseline was cleared too." if a.baseline
                     else " The approved-device baseline was kept."))
            return
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "usb_events", "devices"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        log_event("INFO", "purge", f"Purged {len(drop)} scan(s), kept the newest {a.keep}",
                  None, conn)
        print(f"Purged {len(drop)} scan(s); kept the newest {a.keep}.")
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    USBIDS.load()
    banner()
    print(f"  Python    : {platform.python_version()} ({sys.platform})")
    print(f"  Flask     : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  usb.ids   : {USBIDS.note()}")
    print(f"  Database  : {os.path.abspath(db_path())}")
    print(f"  GitHub    : {GITHUB}")
    print(f"  LinkedIn  : {LINKEDIN}")
    line()
    print(DISCLAIMER_LONG)
    line()
    print(PRIVACY_NOTICE)
    line()


# =============================================================================
# SECTION 13 - Self test
#   Parsers are checked against fixtures in the real kernel log format, and the
#   live collectors are run against this machine and reported honestly. Runs in a
#   throwaway database; your own data is never touched.
# =============================================================================

def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - parsers against real-format fixtures, collectors against this host.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="usbf-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Unit checks")
        check("device keys combine vid, pid and serial",
              device_key("0781", "5591", "ABC") == "0781:5591:ABC")
        check("a missing serial still produces a stable key",
              device_key("0781", "5591", None) == "0781:5591:")
        check("durations format", fmt_duration(90) == "1m 30s" and fmt_duration(None) == "-")
        check("html escaping blocks tag injection",
              "<script>" not in html_escape("<script>alert(1)</script>"))
        check("scoring: clean is 100 and one critical costs 20",
              compute_score({}) == 100.0 and compute_score({"critical": 1}) == 80.0)
        check("scoring floors at 0", compute_score({"critical": 99}) == 0.0)
        check("info findings never reduce the score", compute_score({"info": 40}) == 100.0)

        print("\n Timestamp handling")
        iso, assumed = parse_log_timestamp("2026-03-02T09:14:02+0000 host kernel: x", 2026)
        check("ISO-8601 timestamps parse exactly",
              iso and iso.startswith("2026-03-02T09:14:02") and not assumed, iso)
        sys_ts, assumed = parse_log_timestamp("Mar 13 07:59:58 host kernel: x", 2025)
        check("classic syslog parses and reports that the year was assumed",
              sys_ts and sys_ts.startswith("2025-03-13T07:59:58") and assumed, sys_ts)
        boot = datetime(2026, 1, 1, tzinfo=timezone.utc)
        dm, _ = parse_log_timestamp("[  120.500000] usb 1-1: x", 2026, boot)
        check("dmesg monotonic timestamps resolve against boot time",
              dm and dm.startswith("2026-01-01T00:02:00"), dm)
        none_ts, _ = parse_log_timestamp("no timestamp here", 2026)
        check("an unparsable line yields no timestamp rather than a guess", none_ts is None)

        print("\n Kernel log parsing (real format fixtures)")
        fixture = os.path.join(tmp, "sample.log")
        info = build_sample_log(fixture, year=2026)
        check("fixture written", os.path.exists(fixture) and info["lines"] > 20)
        txt, _ = read_text(fixture)
        parsed = parse_kernel_log(txt, assume_year=2025)
        connects = [e for e in parsed["events"] if e["action"] == "connect"]
        disconnects = [e for e in parsed["events"] if e["action"] == "disconnect"]
        check(f"attach events extracted ({len(connects)})", len(connects) >= 7)
        check(f"detach events extracted ({len(disconnects)})", len(disconnects) >= 5)
        check("vendor and product ids are captured",
              all(re.fullmatch(r"[0-9a-f]{4}", e["vid"]) for e in connects))
        check("a device that reports an empty serial is recorded as having none",
              any(e["serial"] is None for e in connects))
        check("a device with a serial keeps it exactly",
              any(e["serial"] == "4C530001250607117025" for e in connects))
        check("a device unplugged before its strings block still appears",
              any(e["vid"] == "feed" for e in connects),
              [e["vid"] for e in connects])
        check("driver bindings are attached to the right device",
              any("usb-storage" in (e["drivers"] or []) for e in connects))
        check("hid-generic bindings are captured separately",
              len(parsed["hid_bindings"]) >= 1)
        check("the evidence window is reported",
              parsed["first_ts"] and parsed["last_ts"]
              and parsed["first_ts"] <= parsed["last_ts"])
        check("mixing ISO and syslog lines flags the assumed year",
              parsed["year_assumed"] is True)

        print("\n Correlation")
        devices = correlate(parsed["events"], [], parsed["hid_bindings"])
        check(f"events fold into distinct devices ({len(devices)})", len(devices) >= 6)
        sandisk = next((d for d in devices.values()
                        if d["serial"] == "4C530001250607117025" and d["vid"] == "0781"), None)
        check("a device seen three times is counted once with three attachments",
              sandisk and sandisk["connects"] == 3, sandisk["connects"] if sandisk else None)
        check("attachment sessions are paired and timed",
              sandisk and len(sandisk["sessions"]) >= 2 and sandisk["total_seconds"] > 0)
        check("session duration matches the log",
              sandisk and any(s["seconds"] == 5922 for s in sandisk["sessions"]),
              [s["seconds"] for s in sandisk["sessions"]] if sandisk else None)
        badusb = next((d for d in devices.values() if d["vid"] == "feed"), None)
        check("the composite device carries both classes",
              badusb and "mass storage" in badusb["classes"] and "HID" in badusb["classes"],
              badusb["classes"] if badusb else None)
        check("vendor names resolve from the built-in list when usb.ids is absent",
              devices and any(d["vendor_name"] != "unknown vendor" for d in devices.values()))
        lan = next((d for d in devices.values() if d["vid"] == "0bda"), None)
        check("a driver-only class is inferred (r8152 -> network)",
              lan and "network" in lan["classes"], lan["classes"] if lan else None)

        print("\n Findings")
        live_na = Result("live").unavailable("no USB subsystem on this kernel")
        hist = Result("history")
        hist.source = fixture
        findings = analyse(devices, parsed, live_na, hist, {})
        def has(sub):
            return any(sub.lower() in f["title"].lower() for f in findings)
        check("an unavailable collector is reported as not performed, never as a pass",
              has("Check not performed"))
        check("the storage-plus-keyboard device is critical",
              any(f["severity"] == "critical" and "storage and a keyboard" in f["title"]
                  for f in findings))
        check("a cloned serial across two product ids is high",
              any(f["severity"] == "high" and "serial number appears under" in f["title"]
                  for f in findings))
        check("unapproved mass storage is reported", has("Unapproved mass storage"))
        check("unapproved HID is reported", has("Unapproved HID"))
        check("a USB network adapter is reported", has("Unapproved network"))
        check("a device with no serial is reported", has("no serial number"))
        check("a brief storage attachment is reported", has("attached only briefly"))
        check("out-of-hours attachment is reported", has("outside working hours"))
        check("the evidence window is stated as a finding", has("Evidence covers"))
        check("the assumed year is disclosed as a finding", has("no year in the log"))
        check("an empty baseline is called out", has("No baseline has been set"))
        check("every finding carries a recommendation",
              all(f["recommendation"] for f in findings if f["severity"] != "info"))
        check("every finding has a severity we recognise",
              all(f["severity"] in SEVERITIES for f in findings))

        print("\n Baseline")
        init_db()
        sid = save_scan(devices, parsed["events"], findings, parsed, live_na, hist, "sample")
        check("scan stored", sid and scan_summary(sid)["devices"] == len(devices))
        key = sandisk["key"]
        approve_device(key, label="Company flash drive")
        check("a device can be approved", key in load_baseline())
        findings2 = analyse(devices, parsed, live_na, hist, load_baseline())
        before = sum(1 for f in findings if "Unapproved mass storage" in f["title"])
        after = sum(1 for f in findings2 if "Unapproved mass storage" in f["title"])
        check("approving a device removes its unapproved finding", after == before - 1,
              f"{before} -> {after}")
        check("approving does not suppress findings for other devices", after >= 1)
        check("a baseline entry can be revoked", revoke_device(key) == 1
              and key not in load_baseline())

        print("\n Live collectors (this machine, read-only)")
        live = collect_live()
        check(f"live inventory -> {live.status} ({len(live.data)} device(s))",
              live.status in ("ok", "partial", "unavailable"))
        check("an unavailable live collector explains why",
              live.status != "unavailable" or bool(live.detail), live.detail)
        hist_live = collect_history()
        check(f"history collector -> {hist_live.status}",
              hist_live.status in ("ok", "partial", "unavailable"))
        check("an unavailable history collector explains why",
              hist_live.status != "unavailable" or bool(hist_live.detail), hist_live.detail)
        empty = analyse({}, {"first_ts": None, "last_ts": None}, live, hist_live, {})
        check("a host with no USB evidence produces an honest, non-alarming report",
              all(f["severity"] == "info" for f in empty), [f["title"] for f in empty
                                                            if f["severity"] != "info"])

        print("\n Charts")
        check("pie renders slices", svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]
                                            ).count("<path") == 2)
        check("pie with no data says so", "nothing to show" in svg_pie([]))
        check("bar renders rows", svg_bar([("x", 2), ("y", 1)]).count("<rect") == 4)
        check("columns render", svg_columns([("01", 3), ("02", 1)]).count("<rect") == 2)
        check("gauge renders", "<circle" in svg_gauge(72, "review needed"))
        devs_for_chart = [dict(d, classes=d["classes"]) for d in devices.values()]
        tl = svg_device_timeline(devs_for_chart, parsed["first_ts"], parsed["last_ts"])
        check("device timeline draws a row per device", tl.count("<rect") > len(devices))
        check("a device with no matching disconnect is drawn as a point",
              "<circle" in tl)
        check("the timeline refuses to draw without a window",
              "no timestamped" in svg_device_timeline(devs_for_chart, None, None))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export is valid and carries the disclaimer",
              "AUTHORISED" in j["disclaimer"].upper() and j["scan"]["id"] == sid)
        check("JSON export carries the privacy notice", "personal data" in j["privacy_notice"])
        check("JSON export lists devices, events and findings",
              len(j["devices"]) == len(devices) and j["events"] and j["findings"])
        c = export_csv(sid)
        rows = [r for r in csv.reader(io.StringIO(c)) if r and not r[0].startswith("#")]
        check("CSV export has a header plus one row per device",
              rows[0][0] == "vid" and len(rows) == len(devices) + 1)
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts, disclaimer, privacy notice and author",
              "<svg" in h and "AUTHORISED USE ONLY" in h and "Privacy" in h and AUTHOR in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/devices", "Devices"),
                               ("/timeline", "Timeline"), ("/analytics", "Analytics"),
                               ("/logs", "Logs")):
                r = cl.get(path)
                body = r.get_data(as_text=True)
                check(f"page {path} returns 200 and renders",
                      r.status_code == 200 and must in body, f"status={r.status_code}")
                check(f"page {path} shows the disclaimer", "Authorised use only" in body)
            check("a sample-mode scan is labelled as a fixture everywhere",
                  "training fixture, not real evidence" in cl.get("/").get_data(as_text=True))
            check("the devices page carries the privacy notice",
                  "Privacy" in cl.get("/devices").get_data(as_text=True))
            check("device filters apply",
                  cl.get("/devices?class=mass%20storage").status_code == 200
                  and cl.get("/devices?approved=0&qq=sandisk").status_code == 200)
            check("timeline filters apply",
                  cl.get("/timeline?action=connect&limit=100&qq=0781").status_code == 200)
            check("analytics renders SVG charts",
                  cl.get("/analytics").get_data(as_text=True).count("<svg") >= 5)
            check("logs filters apply",
                  cl.get("/logs?level=INFO&limit=50&qq=scan").status_code == 200)
            r = cl.post("/approve", data={"key": key, "scan": str(sid), "label": "test"})
            check("approving from the web works",
                  r.status_code == 302 and key in load_baseline())
            r = cl.post("/revoke", data={"key": key, "scan": str(sid)})
            check("revoking from the web works",
                  r.status_code == 302 and key not in load_baseline())
            n_before = q1("SELECT COUNT(*) c FROM scans", ())["c"]
            r = cl.post("/sample")
            check("the web fixture button runs a scan",
                  r.status_code == 302
                  and q1("SELECT COUNT(*) c FROM scans", ())["c"] == n_before + 1)
            check("the fixture scan is recorded with mode='sample'",
                  q1("SELECT mode FROM scans ORDER BY id DESC LIMIT 1", ())["mode"] == "sample")
            r = cl.post("/scan")
            check("scanning this machine from the web completes even with no USB subsystem",
                  r.status_code == 302)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r.status_code == 200 and ctype in r.headers["Content-Type"]
                      and "attachment" in r.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            check("api summary returns JSON", cl.get("/api/summary").status_code == 200)
            check("empty-state page renders with no scans",
                  "No scans yet" in _empty_state_probe())

        print("\n Retention")
        approve_device("keepme:0000:X", label="survives a purge")
        cmd_purge(argparse.Namespace(all=False, keep=1, baseline=False))
        check("purge keeps exactly the newest scan",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned devices and events",
              q1("SELECT COUNT(*) c FROM devices WHERE scan_id NOT IN "
                 "(SELECT id FROM scans)", ())["c"] == 0
              and q1("SELECT COUNT(*) c FROM usb_events WHERE scan_id NOT IN "
                     "(SELECT id FROM scans)", ())["c"] == 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=False))
        check("purge --all clears the scans", q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the approved-device baseline survives unless explicitly cleared",
              "keepme:0000:X" in load_baseline())
        cmd_purge(argparse.Namespace(all=True, keep=1, baseline=True))
        check("purge --all --baseline clears the baseline too", not load_baseline())
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. The temporary database and fixture have been removed;\n"
              "  your own data was never touched.")
    line("=")
    return 0 if not failed else 1


def _empty_state_probe() -> str:
    import tempfile
    original = db_path()
    d = tempfile.mkdtemp(prefix="usbf-empty-")
    try:
        set_db_path(os.path.join(d, "empty.db"))
        init_db()
        app = build_app()
        app.config["TESTING"] = True
        return app.test_client().get("/").get_data(as_text=True)
    finally:
        set_db_path(original)
        shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# SECTION 14 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - USB attachment history and live inventory "
                    f"for one host, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s explain                    where USB history lives and what it proves
              %(prog)s sample                     build and analyse the training fixture
              %(prog)s scan                       read this machine's live inventory + logs
              %(prog)s scan --log-file kern.log   analyse an exported log instead
              %(prog)s devices --unapproved
              %(prog)s approve --key 0781:5591:4C53000125
              %(prog)s watch                      live attach/detach monitor
              %(prog)s serve                      web app on http://127.0.0.1:5000
              %(prog)s selftest                   verify every component end to end

            {PRIVACY_NOTICE}

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env USBF_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} by {AUTHOR}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="collect the live inventory and log history")
    s.add_argument("--log-file", help="analyse an exported kernel log instead of this machine")
    s.add_argument("--work-hours", default="8-19",
                   help="working window for the out-of-hours check (default 8-19)")
    s.add_argument("--assume-year", type=int,
                   help="year to apply to syslog lines that omit one")
    s.add_argument("--show", type=int, default=10, help="findings to print")
    s.add_argument("--note")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("sample", help="write and analyse the training fixture")
    s.add_argument("--out", default="usb-sample.log")
    s.add_argument("--year", type=int, default=2026)
    s.add_argument("--show", type=int, default=10)
    s.set_defaults(func=cmd_sample)

    s = sub.add_parser("show", help="summary of one scan")
    s.add_argument("scan", nargs="?", type=int)
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("devices", help="device inventory from a scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--class", dest="klass", help="filter by class, e.g. 'mass storage'")
    s.add_argument("--approved", action="store_true")
    s.add_argument("--unapproved", action="store_true")
    s.add_argument("--live", action="store_true", help="only devices attached right now")
    s.set_defaults(func=cmd_devices)

    s = sub.add_parser("timeline", help="attach and detach events")
    s.add_argument("--scan", type=int)
    s.add_argument("--action", choices=["connect", "disconnect", "registry-entry",
                                        "first-install"])
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(func=cmd_timeline)

    s = sub.add_parser("findings", help="findings from a scan")
    s.add_argument("--scan", type=int)
    s.add_argument("--severity", choices=SEVERITIES)
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("approve", help="add a device to the approved baseline")
    s.add_argument("--key", required=True, help="vid:pid:serial, as shown by 'devices'")
    s.add_argument("--label")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="remove a device from the baseline")
    s.add_argument("--key", required=True)
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("baseline", help="list approved devices")
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("watch", help="live attach/detach monitor")
    s.add_argument("--interval", type=float, default=2.0)
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("scans", help="list previous scans")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("explain", help="where USB history lives and what it proves")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("serve", help="start the web app (5 pages)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored scans")
    s.add_argument("--keep", type=int, default=10)
    s.add_argument("--all", action="store_true")
    s.add_argument("--baseline", action="store_true",
                   help="with --all, also clear the approved-device baseline")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, dependencies and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}\nSome log sources need root; try sudo.")
        return 1
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}\nIs another copy running against {db_path()}?")
        return 1


if __name__ == "__main__":
    sys.exit(main())
