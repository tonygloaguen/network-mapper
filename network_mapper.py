#!/usr/bin/env python3
"""Cartographie simple d'un réseau local avec Nmap."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_PORTS = (
    "21,22,23,25,53,67,68,80,110,123,135,137,138,139,143,161,162,389,443,"
    "445,465,500,515,548,587,631,993,995,1433,1883,3306,3389,4500,5000,"
    "5001,5353,5432,5900,5985,5986,8000,8080,8123,8443,8554,8883,9000,"
    "9090,9100"
)
MAX_PREFIX_WITHOUT_CONFIRMATION = 16


@dataclass
class Device:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    status: str = ""
    os_guess: str = ""
    os_accuracy: str = ""
    ports: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    device_type: str = ""
    notes: str = ""


@dataclass(frozen=True)
class MacObservation:
    ip: str
    mac: str
    source: str
    sample: int
    vendor: str = ""
    hostname: str = ""
    timestamp: str = ""


@dataclass(frozen=True)
class IpConflict:
    ip: str
    mac_addresses: list[str]
    vendors: list[str]
    hostnames: list[str]
    sources: list[str]
    samples: list[str]
    severity: str
    notes: str


def run_command(
    cmd: list[str],
    *,
    timeout: int,
    log_file: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if log_file:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write("\n$ " + format_command(cmd) + "\n")

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Commande trop longue / timeout : {format_command(cmd)}") from exc

    if log_file:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[exit-code] {proc.returncode}\n")
            if proc.stdout:
                handle.write(proc.stdout + "\n")
            if proc.stderr:
                handle.write("[stderr]\n" + proc.stderr + "\n")

    return proc


def format_command(cmd: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def require_nmap() -> str:
    nmap = shutil.which("nmap")
    if not nmap:
        print("ERREUR : nmap est introuvable dans le PATH.", file=sys.stderr)
        print("Installe Nmap puis vérifie que la commande 'nmap' fonctionne.", file=sys.stderr)
        sys.exit(2)
    return nmap


def mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def normalize_ipv4(value: str) -> str:
    return value.replace("(Preferred)", "").replace("(Préféré)", "").strip()


def is_local_scan_network(net: ipaddress.IPv4Network) -> bool:
    return (
        net.version == 4
        and not net.is_loopback
        and not net.is_link_local
        and not net.is_multicast
        and not net.is_reserved
    )


def detect_local_networks(timeout: int = 30) -> list[str]:
    if platform.system().lower() == "windows":
        return detect_windows_networks(timeout=timeout)
    return detect_unix_networks(timeout=timeout)


def detect_windows_networks(timeout: int = 30) -> list[str]:
    proc = run_command(["ipconfig", "/all"], timeout=timeout)
    return parse_windows_ipconfig_networks(proc.stdout)


def parse_windows_ipconfig_networks(text: str) -> list[str]:
    ipv4_pat = re.compile(r"(?:IPv4 Address|Adresse IPv4)[^:\n]*:\s*([0-9.()A-Za-zéÉèÈêÊ -]+)")
    mask_pat = re.compile(r"(?:Subnet Mask|Masque de sous-réseau)[^:\n]*:\s*([0-9.]+)")

    found: list[str] = []
    current_ip: str | None = None

    for line in text.splitlines():
        ip_m = ipv4_pat.search(line)
        if ip_m:
            current_ip = normalize_ipv4(ip_m.group(1))
            continue

        mask_m = mask_pat.search(line)
        if mask_m and current_ip:
            try:
                ip = ipaddress.IPv4Address(current_ip)
                net = ipaddress.IPv4Network(f"{ip}/{mask_m.group(1)}", strict=False)
                if ip.is_private and is_local_scan_network(net):
                    found.append(str(net))
            except ValueError:
                pass
            current_ip = None

    return deduplicate(found)


def detect_unix_networks(timeout: int = 30) -> list[str]:
    ip_cmd = shutil.which("ip")
    if ip_cmd:
        proc = run_command([ip_cmd, "-o", "-4", "addr", "show", "scope", "global"], timeout=timeout)
        networks = parse_ip_addr_networks(proc.stdout)
        if networks:
            return networks

    ifconfig_cmd = shutil.which("ifconfig")
    if ifconfig_cmd:
        proc = run_command([ifconfig_cmd], timeout=timeout)
        return parse_ifconfig_networks(proc.stdout)

    return []


def parse_ip_addr_networks(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"\binet\s+([0-9.]+/\d+)\b", text):
        try:
            interface = ipaddress.IPv4Interface(match.group(1))
            if interface.ip.is_private and is_local_scan_network(interface.network):
                found.append(str(interface.network))
        except ValueError:
            continue
    return deduplicate(found)


def parse_ifconfig_networks(text: str) -> list[str]:
    found: list[str] = []
    ip_value: str | None = None
    mask_value: str | None = None

    for line in text.splitlines():
        ip_m = re.search(r"\binet\s(?:addr:)?([0-9.]+)", line)
        mask_m = re.search(r"(?:netmask\s(?:0x[0-9a-fA-F]+|[0-9.]+)|Mask:([0-9.]+))", line)

        if ip_m:
            ip_value = ip_m.group(1)
        if mask_m:
            raw = mask_m.group(1) or mask_m.group(0).split()[-1]
            mask_value = str(ipaddress.IPv4Address(int(raw, 16))) if raw.startswith("0x") else raw

        if ip_value and mask_value:
            try:
                interface = ipaddress.IPv4Interface(f"{ip_value}/{mask_to_prefix(mask_value)}")
                if interface.ip.is_private and is_local_scan_network(interface.network):
                    found.append(str(interface.network))
            except ValueError:
                pass
            ip_value = None
            mask_value = None

    return deduplicate(found)


def detect_default_gateways(timeout: int = 30) -> dict[str, str]:
    if platform.system().lower() == "windows":
        proc = run_command(["ipconfig", "/all"], timeout=timeout)
        return parse_windows_gateways(proc.stdout)
    return detect_unix_gateways(timeout=timeout)


def parse_windows_gateways(text: str) -> dict[str, str]:
    gateways: dict[str, str] = {}
    current_ip: str | None = None
    expect_gateway_continuation = False

    ipv4_pat = re.compile(r"(?:IPv4 Address|Adresse IPv4)[^:\n]*:\s*([0-9.()A-Za-zéÉèÈêÊ -]+)")
    gw_pat = re.compile(r"(?:Default Gateway|Passerelle par défaut)[^:\n]*:\s*([0-9.]+)?")

    for line in text.splitlines():
        ip_m = ipv4_pat.search(line)
        if ip_m:
            current_ip = normalize_ipv4(ip_m.group(1))

        gw_m = gw_pat.search(line)
        if gw_m:
            gw = gw_m.group(1)
            if gw:
                gateways[current_ip or "default"] = gw
                expect_gateway_continuation = False
            else:
                expect_gateway_continuation = True
            continue

        if expect_gateway_continuation:
            m = re.search(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*$", line)
            if m:
                gateways[current_ip or "default"] = m.group(1)
                expect_gateway_continuation = False

    return gateways


def detect_unix_gateways(timeout: int = 30) -> dict[str, str]:
    ip_cmd = shutil.which("ip")
    if ip_cmd:
        proc = run_command([ip_cmd, "route", "show", "default"], timeout=timeout)
        gateways = parse_ip_route_gateways(proc.stdout)
        if gateways:
            return gateways

    route_cmd = shutil.which("route")
    if route_cmd:
        proc = run_command([route_cmd, "-n"], timeout=timeout)
        return parse_route_n_gateways(proc.stdout)

    return {}


def parse_ip_route_gateways(text: str) -> dict[str, str]:
    gateways: dict[str, str] = {}
    for line in text.splitlines():
        match = re.search(r"\bdefault\s+via\s+([0-9.]+)(?:\s+dev\s+(\S+))?", line)
        if match:
            gateways[match.group(2) or "default"] = match.group(1)
    return gateways


def parse_route_n_gateways(text: str) -> dict[str, str]:
    gateways: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0] in {"0.0.0.0", "default"}:
            gateways[parts[-1]] = parts[1]
    return gateways


def deduplicate(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def parse_nmap_xml(path: Path) -> dict[str, Device]:
    if not path.exists():
        return {}

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return {}

    return parse_nmap_root(root)


def parse_nmap_root(root: ET.Element) -> dict[str, Device]:
    devices: dict[str, Device] = {}

    for host in root.findall("host"):
        device = parse_nmap_host(host)
        if not device:
            continue
        devices[device.ip] = merge_device(devices.get(device.ip), device)

    for device in devices.values():
        classify_device(device)

    return devices


def parse_nmap_host(host: ET.Element) -> Device | None:
    status_el = host.find("status")
    status = status_el.attrib.get("state", "") if status_el is not None else ""

    ip = ""
    mac = ""
    vendor = ""
    for addr in host.findall("address"):
        addr_type = addr.attrib.get("addrtype")
        if addr_type == "ipv4":
            ip = addr.attrib.get("addr", "")
        elif addr_type == "mac":
            mac = addr.attrib.get("addr", "")
            vendor = addr.attrib.get("vendor", "")

    if not ip:
        return None

    device = Device(ip=ip, status=status, mac=mac, vendor=vendor)
    device.hostname = parse_hostnames(host)
    parse_ports(host, device)
    parse_os_guess(host, device)
    classify_device(device)
    return device


def parse_hostnames(host: ET.Element) -> str:
    hostnames: list[str] = []
    hn_parent = host.find("hostnames")
    if hn_parent is not None:
        for hn in hn_parent.findall("hostname"):
            name = hn.attrib.get("name")
            if name:
                hostnames.append(name)
    return ", ".join(deduplicate(hostnames))


def parse_ports(host: ET.Element, device: Device) -> None:
    ports_parent = host.find("ports")
    if ports_parent is None:
        return

    for port in ports_parent.findall("port"):
        state_el = port.find("state")
        state = state_el.attrib.get("state", "") if state_el is not None else ""
        if state != "open":
            continue

        proto = port.attrib.get("protocol", "")
        portid = port.attrib.get("portid", "")
        if not portid:
            continue

        service_label = build_service_label(portid, proto, port.find("service"))
        port_label = f"{portid}/{proto}" if proto else portid

        if port_label not in device.ports:
            device.ports.append(port_label)
        if service_label and service_label not in device.services:
            device.services.append(service_label)


def build_service_label(portid: str, proto: str, service_el: ET.Element | None) -> str:
    parts = [f"{portid}/{proto}" if proto else portid]
    if service_el is not None:
        parts.extend(service_el.attrib.get(name, "") for name in ("name", "product", "version", "extrainfo", "ostype"))
    return " ".join(part for part in parts if part).strip()


def parse_os_guess(host: ET.Element, device: Device) -> None:
    os_parent = host.find("os")
    if os_parent is None:
        return

    matches = os_parent.findall("osmatch")
    if not matches:
        return

    best = max(matches, key=lambda item: int(item.attrib.get("accuracy", "0") or "0"))
    device.os_guess = best.attrib.get("name", device.os_guess)
    device.os_accuracy = best.attrib.get("accuracy", device.os_accuracy)


def classify_device(device: Device, gateway_ips: set[str] | None = None) -> None:
    ports = {port.split("/")[0] for port in device.ports}
    text = " ".join([device.hostname, device.vendor, device.os_guess, " ".join(device.services)]).lower()
    gateway_ips = gateway_ips or set()
    scores: dict[str, int] = {}

    def add(label: str, points: int = 1) -> None:
        scores[label] = scores.get(label, 0) + points

    if device.ip in gateway_ips:
        add("routeur", 5)
    if {"53", "67", "68", "500", "4500", "1701", "1723"} & ports:
        add("routeur", 2)
    if any(token in text for token in ("router", "gateway", "box", "livebox", "freebox", "fritz", "mikrotik")):
        add("routeur", 3)
    firewall_tokens = ("pfsense", "opnsense", "fortinet", "fortigate", "sophos", "watchguard", "firewall")
    if any(token in text for token in firewall_tokens):
        add("firewall", 4)
    if any(token in text for token in ("switch", "catalyst", "procurve", "netgear gs", "aruba", "d-link")):
        add("switch", 3)
    if "161" in ports and any(token in text for token in ("cisco", "juniper", "hpe", "aruba", "netgear", "zyxel")):
        add("switch", 2)
    wifi_tokens = ("unifi", "ubiquiti", "ruckus", "meraki", "access point", "wifi", "wi-fi", "wlan")
    if any(token in text for token in wifi_tokens):
        add("borne Wi-Fi", 4)
    printer_tokens = ("printer", "imprimante", "hewlett", "laserjet", "officejet", "brother", "epson", "canon")
    if {"9100", "631", "515"} & ports or any(token in text for token in printer_tokens):
        add("imprimante", 5)
    if {"5000", "5001", "548", "2049"} & ports or any(
        token in text for token in ("synology", "qnap", "truenas", "freenas", "nas", "diskstation", "samba")
    ):
        add("NAS", 4)
    if {"445", "139"} & ports and not scores.get("imprimante"):
        add("NAS", 1)
    if "3389" in ports or "microsoft" in text or "windows" in text or "winrm" in text:
        add("poste Windows", 4)
    if "22" in ports or any(token in text for token in ("linux", "openssh", "ubuntu", "debian", "centos", "red hat")):
        add("serveur Linux", 2)
    if {"80", "443", "8080", "8443"} & ports and "serveur Linux" in scores:
        add("serveur Linux", 1)
    camera_tokens = ("rtsp", "onvif", "hikvision", "dahua", "axis camera")
    if {"554", "8554"} & ports or any(token in text for token in camera_tokens):
        add("caméra", 5)
    if {"1883", "8883", "5683"} & ports or any(
        token in text for token in ("mqtt", "home assistant", "shelly", "sonoff", "esp32", "esp8266", "iot")
    ):
        add("IoT", 4)

    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    selected = [label for label, score in ordered if score >= 2][:3]
    device.device_type = " / ".join(selected) if selected else "équipement inconnu à qualifier"

    if not device.notes:
        device.notes = "" if device.ports else "Hôte actif, aucun port ouvert dans la liste scannée."


def merge_device(dst: Device | None, src: Device) -> Device:
    if dst is None:
        return src

    for attr in ("hostname", "mac", "vendor", "status", "os_guess", "os_accuracy", "device_type", "notes"):
        val = getattr(src, attr)
        if val:
            setattr(dst, attr, val)
    append_unique(dst.ports, src.ports)
    append_unique(dst.services, src.services)
    classify_device(dst)
    return dst


def append_unique(target: list[str], values: Iterable[str]) -> None:
    for value in values:
        if value and value not in target:
            target.append(value)


def merge_devices(*maps: dict[str, Device]) -> dict[str, Device]:
    merged: dict[str, Device] = {}
    for device_map in maps:
        for ip, src in device_map.items():
            merged[ip] = merge_device(merged.get(ip), src)
    return dict(sorted(merged.items(), key=lambda kv: ipaddress.IPv4Address(kv[0])))


def apply_gateway_classification(devices: dict[str, Device], gateways: dict[str, str]) -> None:
    gateway_ips = set(gateways.values())
    for device in devices.values():
        classify_device(device, gateway_ips=gateway_ips)


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) != 12:
        return ""
    mac = ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()
    if mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
        return ""
    return mac


def normalize_observation(
    *,
    ip: str,
    mac: str,
    source: str,
    sample: int,
    vendor: str = "",
    hostname: str = "",
) -> MacObservation | None:
    try:
        normalized_ip = str(ipaddress.IPv4Address(ip.strip()))
    except ValueError:
        return None

    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        return None

    return MacObservation(
        ip=normalized_ip,
        mac=normalized_mac,
        source=source,
        sample=sample,
        vendor=vendor.strip(),
        hostname=hostname.strip(),
        timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    )


def nmap_observations_from_devices(devices: dict[str, Device], *, sample: int = 0) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for device in devices.values():
        observation = normalize_observation(
            ip=device.ip,
            mac=device.mac,
            source="nmap",
            sample=sample,
            vendor=device.vendor,
            hostname=device.hostname,
        )
        if observation:
            observations.append(observation)
    return observations


def parse_windows_arp_observations(text: str, *, sample: int) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        observation = normalize_observation(ip=parts[0], mac=parts[1], source="arp", sample=sample)
        if observation:
            observations.append(observation)
    return observations


def parse_ip_neigh_observations(text: str, *, sample: int) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or "lladdr" not in parts:
            continue
        state = parts[-1].lower()
        if state in {"failed", "incomplete"}:
            continue
        mac_index = parts.index("lladdr") + 1
        if mac_index >= len(parts):
            continue
        observation = normalize_observation(ip=parts[0], mac=parts[mac_index], source="ip_neigh", sample=sample)
        if observation:
            observations.append(observation)
    return observations


def parse_linux_arp_n_observations(text: str, *, sample: int) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].lower() in {"address", "ip"}:
            continue
        observation = normalize_observation(ip=parts[0], mac=parts[2], source="arp", sample=sample)
        if observation:
            observations.append(observation)
    return observations


def collect_arp_observations_windows(
    *,
    sample: int,
    timeout: int = 10,
    log_file: Path | None = None,
) -> list[MacObservation]:
    if not shutil.which("arp"):
        print("[WARN] Commande arp introuvable, collecte ARP ignorée.")
        return []

    proc = run_command(["arp", "-a"], timeout=timeout, log_file=log_file)
    if proc.returncode != 0:
        print("[WARN] Collecte ARP Windows en échec, poursuite sans ces observations.")
        return []
    return parse_windows_arp_observations(proc.stdout, sample=sample)


def collect_arp_observations_linux(
    *,
    sample: int,
    timeout: int = 10,
    log_file: Path | None = None,
) -> list[MacObservation]:
    if not shutil.which("arp"):
        print("[WARN] Commande arp introuvable, fallback ARP Linux ignoré.")
        return []

    proc = run_command(["arp", "-n"], timeout=timeout, log_file=log_file)
    if proc.returncode != 0:
        print("[WARN] Collecte arp -n en échec, poursuite sans ces observations.")
        return []
    return parse_linux_arp_n_observations(proc.stdout, sample=sample)


def collect_neighbor_observations(
    *,
    sample: int,
    timeout: int = 10,
    log_file: Path | None = None,
) -> list[MacObservation]:
    if platform.system().lower() == "windows":
        return collect_arp_observations_windows(sample=sample, timeout=timeout, log_file=log_file)

    ip_cmd = shutil.which("ip")
    if ip_cmd:
        proc = run_command([ip_cmd, "neigh"], timeout=timeout, log_file=log_file)
        if proc.returncode == 0:
            observations = parse_ip_neigh_observations(proc.stdout, sample=sample)
            if observations:
                return observations
        else:
            print("[WARN] Collecte ip neigh en échec, tentative avec arp -n.")

    return collect_arp_observations_linux(sample=sample, timeout=timeout, log_file=log_file)


def sample_neighbor_observations(
    *,
    samples: int,
    interval: int,
    timeout: int,
    log_file: Path | None = None,
) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for sample in range(1, samples + 1):
        observations.extend(collect_neighbor_observations(sample=sample, timeout=timeout, log_file=log_file))
        if sample < samples:
            time.sleep(interval)
    return observations


def detect_ip_conflicts(observations: Iterable[MacObservation]) -> list[IpConflict]:
    by_ip: dict[str, list[MacObservation]] = {}
    for observation in observations:
        normalized = normalize_observation(
            ip=observation.ip,
            mac=observation.mac,
            source=observation.source,
            sample=observation.sample,
            vendor=observation.vendor,
            hostname=observation.hostname,
        )
        if normalized:
            by_ip.setdefault(normalized.ip, []).append(normalized)

    conflicts: list[IpConflict] = []
    for ip, ip_observations in by_ip.items():
        macs = sorted({observation.mac for observation in ip_observations})
        if len(macs) <= 1:
            continue

        sources = sorted({observation.source for observation in ip_observations if observation.source})
        samples = sorted({str(observation.sample) for observation in ip_observations})
        vendors = sorted({observation.vendor for observation in ip_observations if observation.vendor})
        hostnames = sorted({observation.hostname for observation in ip_observations if observation.hostname})
        severity = classify_conflict_severity(sources=sources, samples=samples)
        conflicts.append(
            IpConflict(
                ip=ip,
                mac_addresses=macs,
                vendors=vendors,
                hostnames=hostnames,
                sources=sources,
                samples=samples,
                severity=severity,
                notes="Conflit IP probable : plusieurs adresses MAC distinctes observées pour la même IPv4.",
            )
        )

    return sorted(conflicts, key=lambda conflict: ipaddress.IPv4Address(conflict.ip))


def classify_conflict_severity(*, sources: list[str], samples: list[str]) -> str:
    if len(sources) > 1 or len(samples) > 1:
        return "high"
    if sources:
        return "medium"
    return "low"


def conflict_to_row(conflict: IpConflict) -> dict[str, str]:
    return {
        "ip": conflict.ip,
        "mac_addresses": ", ".join(conflict.mac_addresses),
        "vendors": ", ".join(conflict.vendors),
        "hostnames": ", ".join(conflict.hostnames),
        "sources": ", ".join(conflict.sources),
        "samples": ", ".join(conflict.samples),
        "severity": conflict.severity,
        "notes": conflict.notes,
    }


def write_ip_conflicts_csv(conflicts: list[IpConflict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "mac_addresses", "vendors", "hostnames", "sources", "samples", "severity", "notes"],
            delimiter=";",
        )
        writer.writeheader()
        for conflict in conflicts:
            writer.writerow(conflict_to_row(conflict))


def conflict_to_dict(conflict: IpConflict) -> dict[str, object]:
    return asdict(conflict)


def build_discovery_command(nmap: str, subnet: str, out_xml: Path) -> list[str]:
    return [nmap, "-sn", subnet, "-oX", str(out_xml)]


def build_services_command(
    nmap: str,
    subnet: str,
    out_xml: Path,
    *,
    ports: str | None,
    top_ports: int | None,
    skip_os: bool,
) -> list[str]:
    cmd = [nmap, "-sV", "--open"]
    if not skip_os:
        cmd.extend(["-O", "--osscan-guess"])
    if top_ports is not None:
        cmd.extend(["--top-ports", str(top_ports)])
    else:
        cmd.extend(["-p", ports or DEFAULT_PORTS])
    cmd.extend([subnet, "-oX", str(out_xml)])
    return cmd


def nmap_discovery(nmap: str, subnet: str, out_dir: Path, log_file: Path, timeout: int) -> Path:
    out_xml = out_dir / f"discovery_{safe_name(subnet)}.xml"
    proc = run_command(build_discovery_command(nmap, subnet, out_xml), timeout=timeout, log_file=log_file)
    if proc.returncode != 0:
        print(f"[WARN] Découverte Nmap en échec sur {subnet}. Voir {log_file}")
    return out_xml


def nmap_services(
    nmap: str,
    subnet: str,
    out_dir: Path,
    log_file: Path,
    *,
    ports: str | None,
    top_ports: int | None,
    skip_os: bool,
    timeout: int,
) -> Path:
    out_xml = out_dir / f"services_{safe_name(subnet)}.xml"
    cmd = build_services_command(nmap, subnet, out_xml, ports=ports, top_ports=top_ports, skip_os=skip_os)
    proc = run_command(cmd, timeout=timeout, log_file=log_file)

    if proc.returncode != 0 and not skip_os:
        print(f"[WARN] Scan OS en échec sur {subnet}. Relance sans -O.")
        fallback = build_services_command(nmap, subnet, out_xml, ports=ports, top_ports=top_ports, skip_os=True)
        proc = run_command(fallback, timeout=timeout, log_file=log_file)

    if proc.returncode != 0:
        print(f"[WARN] Scan services Nmap en échec sur {subnet}. Voir {log_file}")
    return out_xml


def write_csv(devices: dict[str, Device], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "hostname",
                "mac",
                "vendor",
                "status",
                "device_type",
                "os_guess",
                "os_accuracy",
                "ports",
                "services",
                "notes",
            ],
            delimiter=";",
        )
        writer.writeheader()
        for device in devices.values():
            writer.writerow(device_to_row(device))


def device_to_row(device: Device) -> dict[str, str]:
    return {
        "ip": device.ip,
        "hostname": device.hostname,
        "mac": device.mac,
        "vendor": device.vendor,
        "status": device.status,
        "device_type": device.device_type,
        "os_guess": device.os_guess,
        "os_accuracy": device.os_accuracy,
        "ports": ", ".join(device.ports),
        "services": " | ".join(device.services),
        "notes": device.notes,
    }


def write_json(devices: dict[str, Device], conflicts: list[IpConflict], path: Path) -> None:
    payload = {
        "devices": [asdict(device) for device in devices.values()],
        "ip_conflicts": [conflict_to_dict(conflict) for conflict in conflicts],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def mermaid_id(value: str) -> str:
    return "n" + re.sub(r"[^A-Za-z0-9_]", "_", value)


def write_mermaid(devices: dict[str, Device], subnets: list[str], gateways: dict[str, str], path: Path) -> None:
    lines = ["flowchart TD", "    SCAN[Poste de scan]"]
    gw_ips = set(gateways.values())

    for subnet in subnets:
        sid = mermaid_id("subnet_" + subnet)
        lines.append(f'    {sid}["{subnet}"]')
        subnet_net = ipaddress.IPv4Network(subnet, strict=False)
        subnet_gateways = [gw for gw in gw_ips if ipaddress.IPv4Address(gw) in subnet_net]

        if subnet_gateways:
            for gw in subnet_gateways:
                gwid = mermaid_id(gw)
                label = gw
                if gw in devices:
                    d = devices[gw]
                    label = f"{gw}\\n{d.hostname or d.vendor or d.device_type}"
                lines.append(f'    {gwid}["{escape_mermaid_label(label)}"]')
                lines.append(f"    SCAN --> {gwid}")
                lines.append(f"    {gwid} --> {sid}")
        else:
            lines.append(f"    SCAN --> {sid}")

        for device in devices.values():
            try:
                if ipaddress.IPv4Address(device.ip) not in subnet_net:
                    continue
            except ValueError:
                continue

            did = mermaid_id(device.ip)
            label_parts = [device.ip, device.hostname, device.vendor, device.device_type]
            label = "\\n".join(part for part in label_parts if part)
            lines.append(f'    {did}["{escape_mermaid_label(label)}"]')
            lines.append(f"    {sid} --> {did}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def escape_mermaid_label(value: str) -> str:
    return value.replace('"', "'")


def write_report(
    devices: dict[str, Device],
    subnets: list[str],
    gateways: dict[str, str],
    conflicts: list[IpConflict],
    path: Path,
    *,
    mermaid_text: str,
) -> None:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = build_markdown_report(
        devices,
        subnets,
        gateways,
        conflicts,
        generated_at=now,
        mermaid_text=mermaid_text,
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_markdown_report(
    devices: dict[str, Device],
    subnets: list[str],
    gateways: dict[str, str],
    conflicts: list[IpConflict],
    *,
    generated_at: str,
    mermaid_text: str,
) -> list[str]:
    lines: list[str] = [
        "# Rapport de cartographie réseau",
        "",
        f"Généré le : {generated_at}",
        "",
        "## Sous-réseaux scannés",
        "",
    ]
    lines.extend(f"- `{subnet}`" for subnet in subnets)
    lines.extend(["", "## Passerelles détectées", ""])
    if gateways:
        lines.extend(f"- `{source}` -> `{gateway}`" for source, gateway in gateways.items())
    else:
        lines.append("- Aucune passerelle détectée automatiquement.")

    lines.extend(
        [
            "",
            "## Inventaire des équipements",
            "",
            "| IP | Nom | MAC | Constructeur | Type supposé | OS probable | Ports ouverts |",
            "|---|---|---|---|---|---|---|",
        ]
    )

    for device in devices.values():
        lines.append(
            "| "
            + " | ".join(
                sanitize_markdown_cell(value)
                for value in [
                    device.ip,
                    device.hostname,
                    device.mac,
                    device.vendor,
                    device.device_type,
                    device.os_guess,
                    ", ".join(device.ports),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Détail services", ""])
    for device in devices.values():
        title = device.ip if not device.hostname else f"{device.ip} - {device.hostname}"
        lines.extend([f"### {title}", "", f"- Type supposé : {device.device_type or 'à qualifier'}"])
        if device.vendor:
            lines.append(f"- Constructeur : {device.vendor}")
        if device.mac:
            lines.append(f"- MAC : `{device.mac}`")
        if device.os_guess:
            acc = f" ({device.os_accuracy}%)" if device.os_accuracy else ""
            lines.append(f"- OS probable : {device.os_guess}{acc}")
        if device.services:
            lines.append("- Services ouverts :")
            lines.extend(f"  - `{service}`" for service in device.services)
        else:
            lines.append("- Aucun service ouvert trouvé dans la liste de ports scannée.")
        if device.notes:
            lines.append(f"- Note : {device.notes}")
        lines.append("")

    lines.extend(["## Conflits IP probables", ""])
    if conflicts:
        lines.extend(
            [
                "| IP | MAC observées | Sources | Samples | Sévérité | Notes |",
                "|---|---|---|---|---|---|",
            ]
        )
        for conflict in conflicts:
            lines.append(
                "| "
                + " | ".join(
                    sanitize_markdown_cell(value)
                    for value in [
                        conflict.ip,
                        ", ".join(conflict.mac_addresses),
                        ", ".join(conflict.sources),
                        ", ".join(conflict.samples),
                        conflict.severity,
                        conflict.notes,
                    ]
                )
                + " |"
            )
        lines.extend(
            [
                "",
                "Ces résultats indiquent un conflit IP probable, pas une certitude absolue. ",
                "Confirme avec les journaux DHCP, la table ARP du routeur et les tables MAC des switchs.",
            ]
        )
    else:
        lines.append("Aucun conflit IP probable n'a été observé dans les sources collectées.")

    lines.extend(
        [
            "",
            "## Limites d'interprétation",
            "",
            "Ce rapport donne une topologie logique approximative. Pour une topologie physique fiable, "
            "il faut interroger les switchs, points d'accès et routeurs manageables via LLDP, CDP, SNMP, "
            "table MAC, table ARP et baux DHCP.",
            "",
            "## Schéma Mermaid",
            "",
            "```mermaid",
            mermaid_text.strip(),
            "```",
            "",
        ]
    )
    return lines


def sanitize_markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def write_html_report(
    devices: dict[str, Device],
    subnets: list[str],
    gateways: dict[str, str],
    conflicts: list[IpConflict],
    path: Path,
) -> None:
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(device.ip)}</td>"
        f"<td>{html.escape(device.hostname)}</td>"
        f"<td>{html.escape(device.mac)}</td>"
        f"<td>{html.escape(device.vendor)}</td>"
        f"<td>{html.escape(device.device_type)}</td>"
        f"<td>{html.escape(device.os_guess)}</td>"
        f"<td>{html.escape(', '.join(device.ports))}</td>"
        "</tr>"
        for device in devices.values()
    )
    subnet_items = "".join(f"<li><code>{html.escape(subnet)}</code></li>" for subnet in subnets)
    gateway_items = (
        "".join(
            f"<li><code>{html.escape(source)}</code> -> <code>{html.escape(gateway)}</code></li>"
            for source, gateway in gateways.items()
        )
        or "<li>Aucune passerelle détectée automatiquement.</li>"
    )
    conflict_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(conflict.ip)}</td>"
        f"<td>{html.escape(', '.join(conflict.mac_addresses))}</td>"
        f"<td>{html.escape(', '.join(conflict.sources))}</td>"
        f"<td>{html.escape(', '.join(conflict.samples))}</td>"
        f"<td>{html.escape(conflict.severity)}</td>"
        f"<td>{html.escape(conflict.notes)}</td>"
        "</tr>"
        for conflict in conflicts
    )
    conflict_section = (
        "<p>Aucun conflit IP probable n'a été observé dans les sources collectées.</p>"
        if not conflicts
        else f"""<table>
    <thead>
      <tr><th>IP</th><th>MAC observées</th><th>Sources</th><th>Samples</th><th>Sévérité</th><th>Notes</th></tr>
    </thead>
    <tbody>{conflict_rows}</tbody>
  </table>
  <p>Ces résultats indiquent un conflit IP probable, pas une certitude absolue.</p>"""
    )

    document = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport de cartographie réseau</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; color: #1f2933; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #cbd5e1; padding: .45rem .6rem; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    code {{ background: #eef2f7; padding: .1rem .25rem; border-radius: .2rem; }}
  </style>
</head>
<body>
  <h1>Rapport de cartographie réseau</h1>
  <p>Généré le : {html.escape(generated_at)}</p>
  <h2>Sous-réseaux scannés</h2>
  <ul>{subnet_items}</ul>
  <h2>Passerelles détectées</h2>
  <ul>{gateway_items}</ul>
  <h2>Inventaire des équipements</h2>
  <table>
    <thead>
      <tr>
        <th>IP</th><th>Nom</th><th>MAC</th><th>Constructeur</th>
        <th>Type supposé</th><th>OS probable</th><th>Ports ouverts</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <h2>Conflits IP probables</h2>
  {conflict_section}
  <h2>Limites</h2>
  <p>Ce rapport présente une topologie logique approximative. Une topologie physique fiable nécessite SNMP,
  LLDP, CDP, table MAC, ARP et DHCP.</p>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def validate_subnets(raw_subnets: Iterable[str]) -> list[str]:
    valid: list[str] = []
    for raw in raw_subnets:
        try:
            net = ipaddress.IPv4Network(raw, strict=False)
        except ValueError:
            print(f"[WARN] Sous-réseau ignoré, format invalide : {raw}")
            continue

        if net.prefixlen < MAX_PREFIX_WITHOUT_CONFIRMATION:
            print(
                f"[WARN] Sous-réseau ignoré, trop large : {raw}. "
                "Limite volontaire sans confirmation : /16 ou plus précis."
            )
            continue
        if not is_local_scan_network(net):
            print(f"[WARN] Sous-réseau ignoré, non adapté à un scan local : {raw}")
            continue

        valid.append(str(net))

    return deduplicate(valid)


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("valeur entière attendue") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("valeur strictement positive attendue")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cartographie réseau locale avec Nmap : découverte, services, OS, CSV, Markdown, Mermaid."
    )
    parser.add_argument(
        "--subnet",
        action="append",
        default=[],
        help="Sous-réseau à scanner, ex: 192.168.20.0/24. Répétable.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Détecte automatiquement les sous-réseaux IPv4 privés du PC.",
    )
    parser.add_argument("--ports", default=None, help=f"Ports à scanner, format Nmap. Défaut : {DEFAULT_PORTS}")
    parser.add_argument(
        "--top-ports",
        type=positive_int,
        default=None,
        help="Utilise les N ports les plus courants selon Nmap.",
    )
    parser.add_argument("--out", default="network_map_output", help="Dossier de sortie.")
    parser.add_argument(
        "--skip-os",
        "--no-os-detection",
        action="store_true",
        dest="skip_os",
        help="Ne tente pas l'identification OS Nmap (-O).",
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Ne lance que la découverte hôtes, sans scan services.",
    )
    parser.add_argument("--json", action="store_true", help="Génère aussi devices.json.")
    parser.add_argument("--html-report", action="store_true", help="Génère aussi report.html.")
    parser.add_argument(
        "--detect-ip-conflicts",
        action="store_true",
        help="Échantillonne la table ARP/neigh locale pour détecter des conflits IP probables.",
    )
    parser.add_argument(
        "--conflict-samples",
        type=positive_int,
        default=3,
        help="Nombre d'échantillons ARP/neigh pour --detect-ip-conflicts. Défaut : 3.",
    )
    parser.add_argument(
        "--conflict-interval",
        type=positive_int,
        default=2,
        help="Intervalle en secondes entre deux échantillons ARP/neigh. Défaut : 2.",
    )
    parser.add_argument(
        "--timeout",
        type=positive_int,
        default=1800,
        help="Timeout par commande Nmap, en secondes. Défaut : 1800.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    nmap = require_nmap()

    subnets: list[str] = []
    if args.auto:
        subnets.extend(detect_local_networks())
    subnets.extend(args.subnet)
    subnets = validate_subnets(subnets)

    if not subnets:
        print("Aucun sous-réseau à scanner.")
        print("Exemples :")
        print("  python .\\network_mapper.py --auto")
        print("  python .\\network_mapper.py --subnet 192.168.20.0/24")
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "commands.log"
    gateways = detect_default_gateways(timeout=min(args.timeout, 30))
    selected_ports = args.ports or DEFAULT_PORTS

    print(f"[INFO] Nmap : {nmap}")
    print(f"[INFO] Sous-réseaux : {', '.join(subnets)}")
    print(f"[INFO] Sortie : {out_dir.resolve()}")
    print(f"[INFO] Détection OS : {'désactivée' if args.skip_os else 'activée avec fallback sans -O'}")
    ports_message = (
        f"[INFO] Ports : top {args.top_ports} Nmap"
        if args.top_ports is not None
        else f"[INFO] Ports : {selected_ports}"
    )
    print(ports_message)

    all_maps: list[dict[str, Device]] = []
    conflict_observations: list[MacObservation] = []
    nmap_sample = 0
    for subnet in subnets:
        print(f"[INFO] Découverte : {subnet}")
        discovery_xml = nmap_discovery(nmap, subnet, out_dir, log_file, timeout=args.timeout)
        discovery_devices = parse_nmap_xml(discovery_xml)
        all_maps.append(discovery_devices)
        conflict_observations.extend(nmap_observations_from_devices(discovery_devices, sample=nmap_sample))
        nmap_sample += 1

        if not args.discover_only:
            print(f"[INFO] Scan services : {subnet}")
            services_xml = nmap_services(
                nmap,
                subnet,
                out_dir,
                log_file,
                ports=selected_ports,
                top_ports=args.top_ports,
                skip_os=args.skip_os,
                timeout=args.timeout,
            )
            service_devices = parse_nmap_xml(services_xml)
            all_maps.append(service_devices)
            conflict_observations.extend(nmap_observations_from_devices(service_devices, sample=nmap_sample))
            nmap_sample += 1

    devices = merge_devices(*all_maps)
    apply_gateway_classification(devices, gateways)

    if args.detect_ip_conflicts:
        print(
            f"[INFO] Détection conflits IP : {args.conflict_samples} échantillons, intervalle {args.conflict_interval}s"
        )
        conflict_observations.extend(
            sample_neighbor_observations(
                samples=args.conflict_samples,
                interval=args.conflict_interval,
                timeout=min(args.timeout, 30),
                log_file=log_file,
            )
        )

    ip_conflicts = detect_ip_conflicts(conflict_observations)
    if ip_conflicts:
        print(f"[WARN] Conflits IP probables détectés : {len(ip_conflicts)}")

    csv_path = out_dir / "devices.csv"
    conflicts_csv_path = out_dir / "ip_conflicts.csv"
    mermaid_path = out_dir / "topology.mmd"
    report_path = out_dir / "report.md"
    write_csv(devices, csv_path)
    write_ip_conflicts_csv(ip_conflicts, conflicts_csv_path)
    write_mermaid(devices, subnets, gateways, mermaid_path)
    mermaid_text = mermaid_path.read_text(encoding="utf-8")
    write_report(devices, subnets, gateways, ip_conflicts, report_path, mermaid_text=mermaid_text)

    json_path = out_dir / "devices.json"
    html_path = out_dir / "report.html"
    if args.json:
        write_json(devices, ip_conflicts, json_path)
    if args.html_report:
        write_html_report(devices, subnets, gateways, ip_conflicts, html_path)

    print("")
    print("[OK] Cartographie terminée.")
    print(f"- CSV      : {csv_path.resolve()}")
    print(f"- Conflits : {conflicts_csv_path.resolve()}")
    print(f"- Rapport  : {report_path.resolve()}")
    print(f"- Mermaid  : {mermaid_path.resolve()}")
    print(f"- Logs     : {log_file.resolve()}")
    if args.json:
        print(f"- JSON     : {json_path.resolve()}")
    if args.html_report:
        print(f"- HTML     : {html_path.resolve()}")
    print("")
    print("Conseil : ouvre report.md dans VS Code ou colle topology.mmd dans https://mermaid.live")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
