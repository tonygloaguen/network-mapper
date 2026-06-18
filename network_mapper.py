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

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only when optional dependency is absent
    yaml = None

DEFAULT_PORTS = (
    "21,22,23,25,53,67,68,80,110,123,135,137,138,139,143,161,162,389,443,"
    "445,465,500,515,548,587,631,993,995,1433,1883,3306,3389,4500,5000,"
    "5001,5353,5432,5900,5985,5986,8000,8080,8123,8443,8554,8883,9000,"
    "9090,9100"
)
MAX_PREFIX_WITHOUT_CONFIRMATION = 16
NO_OPEN_PORT_NOTE = "Hôte actif, aucun port ouvert dans la liste scannée."
RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
DEFAULT_VIRTUAL_SUBNETS = (
    ipaddress.IPv4Network("192.168.56.0/24"),
    ipaddress.IPv4Network("192.168.14.0/24"),
    ipaddress.IPv4Network("192.168.178.0/24"),
    ipaddress.IPv4Network("172.16.0.0/12"),
)


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
    role: str = ""
    vmid: str = ""
    ctid: str = ""
    bridges: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)


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
    conflict_type: str = "same_ip_multiple_macs"


@dataclass(frozen=True)
class AutoDetectedInterface:
    source: str
    ip_address: str
    prefix_length: int | None
    interface_alias: str = ""
    status: str = ""
    network: str = ""
    accepted: bool = False
    reason: str = ""


@dataclass(frozen=True)
class KnownInterface:
    name: str = ""
    ip: str = ""
    network: str = ""
    mac: str = ""
    bridge: str = ""


@dataclass(frozen=True)
class KnownNode:
    name: str
    role: str = ""
    ips: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    vmid: str = ""
    ctid: str = ""
    bridges: list[str] = field(default_factory=list)
    interfaces: list[KnownInterface] = field(default_factory=list)


@dataclass(frozen=True)
class KnownBridge:
    name: str
    role: str = "bridge"
    networks: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KnownTopology:
    nodes: list[KnownNode] = field(default_factory=list)
    bridges: list[KnownBridge] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerabilityFinding:
    ip: str
    host: str
    port: str
    service: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    source: str


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


def is_rfc1918_address(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in network for network in RFC1918_NETWORKS)


def is_rfc1918_network(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(network) for network in RFC1918_NETWORKS)


def is_default_virtual_subnet(subnet: str) -> bool:
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return False
    return any(net.subnet_of(virtual_net) for virtual_net in DEFAULT_VIRTUAL_SUBNETS)


def detect_local_networks(timeout: int = 30, *, debug_auto: bool = False) -> list[str]:
    if platform.system().lower() == "windows":
        return detect_windows_networks(timeout=timeout, debug_auto=debug_auto)
    return detect_unix_networks(timeout=timeout)


def detect_windows_networks(timeout: int = 30, *, debug_auto: bool = False) -> list[str]:
    try:
        interfaces = detect_windows_powershell_interfaces(timeout=timeout)
        networks = networks_from_auto_interfaces(interfaces)
        if debug_auto:
            print_auto_detection_debug("PowerShell Get-NetIPAddress", interfaces, networks)
        return networks
    except (OSError, RuntimeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if debug_auto:
            print(f"[DEBUG auto] PowerShell Get-NetIPAddress en échec : {exc}")

    proc = run_command(["ipconfig", "/all"], timeout=timeout)
    networks = parse_windows_ipconfig_networks(proc.stdout)
    if debug_auto:
        print("[DEBUG auto] Fallback ipconfig /all")
        for network in networks:
            print(f"[DEBUG auto]  réseau retenu : {network}")
        if not networks:
            print("[DEBUG auto]  aucun réseau retenu")
    return networks


def windows_powershell_ipaddress_command() -> list[str]:
    ps_executable = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    script = (
        "$ErrorActionPreference='Stop'; "
        "$hasGetNetAdapter = [bool](Get-Command Get-NetAdapter -ErrorAction SilentlyContinue); "
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object IPAddress,PrefixLength,InterfaceAlias,AddressState,"
        "@{Name='InterfaceOperationalStatus';Expression={"
        "if ($hasGetNetAdapter) { "
        "(Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Status "
        "} else { $null }"
        "}} | ConvertTo-Json -Depth 3"
    )
    return [ps_executable, "-NoProfile", "-NonInteractive", "-Command", script]


def detect_windows_powershell_interfaces(timeout: int = 30) -> list[AutoDetectedInterface]:
    proc = run_command(windows_powershell_ipaddress_command(), timeout=timeout)
    if proc.returncode != 0:
        error = proc.stderr.strip() or f"code retour {proc.returncode}"
        raise RuntimeError(error)
    return parse_windows_powershell_interfaces(proc.stdout)


def parse_windows_powershell_networks(text: str) -> list[str]:
    return networks_from_auto_interfaces(parse_windows_powershell_interfaces(text))


def parse_windows_powershell_interfaces(text: str) -> list[AutoDetectedInterface]:
    raw = text.strip()
    if not raw:
        return []

    data = json.loads(raw)
    if data is None:
        return []
    if isinstance(data, dict):
        records = [data]
    elif isinstance(data, list):
        records = data
    else:
        raise TypeError("JSON PowerShell inattendu")

    interfaces: list[AutoDetectedInterface] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        interfaces.append(build_windows_powershell_interface(record))
    return interfaces


def build_windows_powershell_interface(record: dict[str, object]) -> AutoDetectedInterface:
    lowered = {str(key).lower(): value for key, value in record.items()}
    ip_value = str(lowered.get("ipaddress") or "").strip()
    alias = str(lowered.get("interfacealias") or "").strip()
    status = str(
        lowered.get("interfaceoperationalstatus") or lowered.get("status") or lowered.get("addressstate") or ""
    ).strip()
    prefix_value = lowered.get("prefixlength")

    try:
        prefix = int(str(prefix_value).strip())
    except (TypeError, ValueError):
        return AutoDetectedInterface(
            source="powershell",
            ip_address=ip_value,
            prefix_length=None,
            interface_alias=alias,
            status=status,
            reason="préfixe IPv4 absent ou invalide",
        )

    try:
        ip = ipaddress.IPv4Address(ip_value)
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    except ValueError as exc:
        return AutoDetectedInterface(
            source="powershell",
            ip_address=ip_value,
            prefix_length=prefix,
            interface_alias=alias,
            status=status,
            reason=f"adresse IPv4 invalide : {exc}",
        )

    reason = accepted_auto_network_reason(ip, net, status)
    return AutoDetectedInterface(
        source="powershell",
        ip_address=str(ip),
        prefix_length=prefix,
        interface_alias=alias,
        status=status,
        network=str(net),
        accepted=reason == "",
        reason=reason,
    )


def accepted_auto_network_reason(ip: ipaddress.IPv4Address, net: ipaddress.IPv4Network, status: str) -> str:
    lowered_status = status.strip().lower()
    if lowered_status in {"down", "disabled", "disconnected", "not present", "notpresent"}:
        return "interface inactive"
    if ip == ipaddress.IPv4Address("0.0.0.0"):
        return "adresse non configurée"
    if ip.is_loopback:
        return "loopback ignoré"
    if ip.is_link_local:
        return "link-local ignoré"
    if not is_rfc1918_address(ip):
        return "adresse non RFC1918 ignorée"
    if not is_local_scan_network(net):
        return "réseau local non scannable"
    if not is_rfc1918_network(net):
        return "réseau non RFC1918 ignoré"
    return ""


def networks_from_auto_interfaces(interfaces: Iterable[AutoDetectedInterface]) -> list[str]:
    return deduplicate(interface.network for interface in interfaces if interface.accepted and interface.network)


def print_auto_detection_debug(
    source: str,
    interfaces: Iterable[AutoDetectedInterface],
    networks: Iterable[str],
) -> None:
    print(f"[DEBUG auto] Source : {source}")
    seen_interface = False
    for interface in interfaces:
        seen_interface = True
        prefix = "" if interface.prefix_length is None else f"/{interface.prefix_length}"
        status = f" status={interface.status}" if interface.status else ""
        alias = f" alias={interface.interface_alias}" if interface.interface_alias else ""
        decision = "retenue" if interface.accepted else f"ignorée ({interface.reason})"
        network = f" réseau={interface.network}" if interface.network else ""
        print(f"[DEBUG auto]  {interface.ip_address}{prefix}{alias}{status}{network} -> {decision}")
    if not seen_interface:
        print("[DEBUG auto]  aucune interface IPv4 détectée")

    retained = list(networks)
    if retained:
        for network in retained:
            print(f"[DEBUG auto]  réseau retenu : {network}")
    else:
        print("[DEBUG auto]  aucun réseau retenu")


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
                if is_rfc1918_address(ip) and is_local_scan_network(net) and is_rfc1918_network(net):
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


def as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def normalize_known_ip(value: str) -> tuple[str, str]:
    raw = value.strip()
    if not raw:
        return "", ""
    try:
        if "/" in raw:
            interface = ipaddress.IPv4Interface(raw)
            return str(interface.ip), str(interface.network)
        return str(ipaddress.IPv4Address(raw)), ""
    except ValueError:
        return "", ""


def normalize_known_network(value: str) -> str:
    try:
        return str(ipaddress.IPv4Network(value.strip(), strict=False))
    except ValueError:
        return ""


def records_from_yaml_section(section: object) -> list[dict[str, object]]:
    if section is None:
        return []
    if isinstance(section, dict):
        records: list[dict[str, object]] = []
        for name, raw_record in section.items():
            record = dict(raw_record) if isinstance(raw_record, dict) else {}
            record.setdefault("name", str(name))
            records.append(record)
        return records
    if isinstance(section, list):
        return [dict(item) for item in section if isinstance(item, dict)]
    return []


def parse_known_interface(raw: object) -> KnownInterface | None:
    if isinstance(raw, str):
        return KnownInterface(name=raw)
    if not isinstance(raw, dict):
        return None

    ip = ""
    network = ""
    for key in ("ip", "address"):
        for value in as_string_list(raw.get(key)):
            ip, network = normalize_known_ip(value)
            if ip:
                break
        if ip:
            break
    explicit_networks = [
        normalize_known_network(value) for value in as_string_list(raw.get("network") or raw.get("subnet"))
    ]
    explicit_networks = [value for value in explicit_networks if value]
    return KnownInterface(
        name=str(raw.get("name") or raw.get("interface") or raw.get("ifname") or "").strip(),
        ip=ip,
        network=network or (explicit_networks[0] if explicit_networks else ""),
        mac=normalize_mac(str(raw.get("mac") or "")),
        bridge=str(raw.get("bridge") or "").strip(),
    )


def parse_known_node(record: dict[str, object]) -> KnownNode:
    ips: list[str] = []
    networks: list[str] = []
    for key in ("ip", "ips", "addresses"):
        for value in as_string_list(record.get(key)):
            ip, network = normalize_known_ip(value)
            if ip:
                ips.append(ip)
            if network:
                networks.append(network)
    for key in ("network", "networks", "subnet", "subnets"):
        parsed_networks = (normalize_known_network(value) for value in as_string_list(record.get(key)))
        networks.extend(network for network in parsed_networks if network)

    raw_interfaces = record.get("interfaces")
    if isinstance(raw_interfaces, dict):
        raw_interface_values: list[object] = []
        for name, value in raw_interfaces.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("name", name)
                raw_interface_values.append(item)
            else:
                raw_interface_values.append(str(name))
    elif isinstance(raw_interfaces, list):
        raw_interface_values = raw_interfaces
    else:
        raw_interface_values = []
    parsed_interfaces = (parse_known_interface(item) for item in raw_interface_values)
    interfaces = [interface for interface in parsed_interfaces if interface]

    for interface in interfaces:
        if interface.ip:
            ips.append(interface.ip)
        if interface.network:
            networks.append(interface.network)

    macs = [normalize_mac(value) for value in as_string_list(record.get("mac") or record.get("macs"))]
    macs.extend(interface.mac for interface in interfaces if interface.mac)
    bridges = as_string_list(record.get("bridge") or record.get("bridges"))
    bridges.extend(interface.bridge for interface in interfaces if interface.bridge)

    return KnownNode(
        name=str(record.get("name") or "").strip(),
        role=str(record.get("role") or record.get("type") or "").strip(),
        ips=deduplicate(ips),
        networks=deduplicate(networks),
        macs=deduplicate(mac for mac in macs if mac),
        vmid=str(record.get("vmid") or "").strip(),
        ctid=str(record.get("ctid") or "").strip(),
        bridges=deduplicate(bridge for bridge in bridges if bridge),
        interfaces=interfaces,
    )


def parse_known_bridge(record: dict[str, object]) -> KnownBridge:
    networks: list[str] = []
    for key in ("network", "networks", "subnet", "subnets"):
        parsed_networks = (normalize_known_network(value) for value in as_string_list(record.get(key)))
        networks.extend(network for network in parsed_networks if network)
    return KnownBridge(
        name=str(record.get("name") or "").strip(),
        role=str(record.get("role") or "bridge").strip() or "bridge",
        networks=deduplicate(networks),
        interfaces=deduplicate(as_string_list(record.get("interface") or record.get("interfaces"))),
    )


def parse_known_topology(data: object) -> KnownTopology:
    if not isinstance(data, dict):
        return KnownTopology()

    node_records = records_from_yaml_section(data.get("nodes") or data.get("devices") or data.get("hosts"))
    bridge_records = records_from_yaml_section(data.get("bridges"))
    parsed_nodes = (parse_known_node(record) for record in node_records)
    nodes = [node for node in parsed_nodes if node.name or node.ips or node.macs]
    bridges = [bridge for bridge in (parse_known_bridge(record) for record in bridge_records) if bridge.name]

    networks: list[str] = []
    for key in ("network", "networks", "subnet", "subnets"):
        parsed_networks = (normalize_known_network(value) for value in as_string_list(data.get(key)))
        networks.extend(network for network in parsed_networks if network)
    for node in nodes:
        networks.extend(node.networks)
    for bridge in bridges:
        networks.extend(bridge.networks)

    return KnownTopology(nodes=nodes, bridges=bridges, networks=deduplicate(networks))


def load_known_topology(path: Path | None) -> KnownTopology:
    if path is None:
        return KnownTopology()
    if yaml is None:
        raise RuntimeError("PyYAML est requis pour --known-topology. Installe le paquet 'PyYAML'.")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Impossible de lire known_topology.yml : {exc}") from exc
    return parse_known_topology(data or {})


def role_label(role: str, *, vmid: str = "", ctid: str = "") -> str:
    normalized = role.strip().lower()
    if normalized in {"pfsense", "firewall_pfsense"}:
        return "firewall pfSense"
    if normalized in {"firewall", "router", "routeur"}:
        return "firewall" if normalized == "firewall" else "routeur"
    if normalized in {"proxmox", "pve", "hypervisor", "hyperviseur"}:
        return "hôte Proxmox"
    if normalized in {"vm", "virtual_machine"} or vmid:
        return "VM Proxmox"
    if normalized in {"ct", "lxc", "container", "conteneur"} or ctid:
        return "conteneur Proxmox"
    return role.strip()


def known_node_note(node: KnownNode) -> str:
    details: list[str] = []
    if node.vmid:
        details.append(f"VMID {node.vmid}")
    if node.ctid:
        details.append(f"CTID {node.ctid}")
    if node.bridges:
        details.append("bridges " + ", ".join(node.bridges))
    interface_names = [interface.name for interface in node.interfaces if interface.name]
    if interface_names:
        details.append("interfaces " + ", ".join(interface_names))
    return "Topologie connue : " + "; ".join(details) if details else "Topologie connue."


def apply_known_node_to_device(device: Device, node: KnownNode, *, ip: str | None = None) -> None:
    if node.name:
        device.hostname = node.name
    matching_interface = next((interface for interface in node.interfaces if interface.ip == ip), None)
    if matching_interface and matching_interface.mac:
        device.mac = matching_interface.mac
    elif node.macs:
        device.mac = node.macs[0]
    if not device.status:
        device.status = "known"
    if node.role:
        device.role = node.role
        label = role_label(node.role, vmid=node.vmid, ctid=node.ctid)
        if label:
            device.device_type = label
    if node.vmid:
        device.vmid = node.vmid
    if node.ctid:
        device.ctid = node.ctid
    append_unique(device.bridges, node.bridges)
    if matching_interface and matching_interface.bridge:
        append_unique(device.bridges, [matching_interface.bridge])
    append_unique(device.interfaces, [interface.name for interface in node.interfaces if interface.name])
    note = known_node_note(node)
    if device.notes in {"", NO_OPEN_PORT_NOTE}:
        device.notes = note
    elif note not in device.notes:
        device.notes = f"{device.notes} {note}"


def apply_known_topology(devices: dict[str, Device], topology: KnownTopology) -> dict[str, Device]:
    by_mac = {normalize_mac(device.mac): device for device in devices.values() if normalize_mac(device.mac)}
    for node in topology.nodes:
        for ip in node.ips:
            device = devices.get(ip)
            if device is None:
                device = Device(ip=ip, status="known")
                devices[ip] = device
            apply_known_node_to_device(device, node, ip=ip)
        if not node.ips:
            for mac in node.macs:
                device = by_mac.get(mac)
                if device:
                    apply_known_node_to_device(device, node)
    clear_known_macs_from_other_ips(devices, topology)
    return dict(sorted(devices.items(), key=lambda kv: ipaddress.IPv4Address(kv[0])))


def known_gateway_ips(topology: KnownTopology) -> dict[str, str]:
    gateways: dict[str, str] = {}
    for node in topology.nodes:
        role = node.role.lower()
        if not any(token in role for token in ("pfsense", "firewall", "router", "routeur")):
            continue
        for ip in node.ips:
            gateways[f"known:{node.name or ip}"] = ip
    return gateways


def known_observations_from_topology(topology: KnownTopology) -> list[MacObservation]:
    observations: list[MacObservation] = []
    for node in topology.nodes:
        for interface in node.interfaces:
            if not interface.ip or not interface.mac:
                continue
            observation = normalize_observation(
                ip=interface.ip,
                mac=interface.mac,
                source="known_topology",
                sample=0,
                hostname=node.name,
            )
            if observation:
                observations.append(observation)
    return observations


def known_mac_ip_owners(topology: KnownTopology) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    for node in topology.nodes:
        for interface in node.interfaces:
            if interface.ip and interface.mac:
                owners.setdefault(interface.mac, set()).add(interface.ip)
        if len(node.macs) == 1 and node.ips:
            owners.setdefault(node.macs[0], set()).update(node.ips)
    return owners


def clear_known_macs_from_other_ips(devices: dict[str, Device], topology: KnownTopology) -> None:
    owners = known_mac_ip_owners(topology)
    if not owners:
        return
    for device in devices.values():
        normalized_mac = normalize_mac(device.mac)
        if not normalized_mac:
            continue
        known_ips = owners.get(normalized_mac)
        if known_ips and device.ip not in known_ips:
            device.mac = ""
            device.vendor = ""
            classify_device(device)


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

    known_label = ""
    if device.role or device.vmid or device.ctid:
        known_label = role_label(device.role, vmid=device.vmid, ctid=device.ctid)
    if known_label:
        add(known_label, 10)
    if device.ip in gateway_ips:
        add("routeur", 5)
    if {"53", "67", "68", "500", "4500", "1701", "1723"} & ports:
        add("routeur", 2)
    if any(token in text for token in ("router", "gateway", "box", "livebox", "freebox", "fritz", "mikrotik")):
        add("routeur", 3)
    if "main_login.asp" in text or "httpd/3.0" in text:
        add("routeur/AP ASUS probable", 6)
    firewall_tokens = ("pfsense", "opnsense", "fortinet", "fortigate", "sophos", "watchguard", "firewall")
    if any(token in text for token in firewall_tokens):
        add("firewall", 4)
    if (
        device.ip in gateway_ips
        and "freebsd" in text
        and "unbound" in text
        and "nginx" in text
        and ("22" in ports or "ssh" in text or "openssh" in text)
    ):
        add("firewall pfSense", 8)
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

    if device.ports and device.notes == NO_OPEN_PORT_NOTE:
        device.notes = ""
    if not device.notes:
        device.notes = "" if device.ports else NO_OPEN_PORT_NOTE


def merge_device(dst: Device | None, src: Device) -> Device:
    if dst is None:
        return src

    merge_attrs = ("hostname", "mac", "vendor", "status", "os_guess", "os_accuracy", "device_type", "notes")
    for attr in (*merge_attrs, "role", "vmid", "ctid"):
        val = getattr(src, attr)
        if val:
            setattr(dst, attr, val)
    append_unique(dst.ports, src.ports)
    append_unique(dst.services, src.services)
    append_unique(dst.bridges, src.bridges)
    append_unique(dst.interfaces, src.interfaces)
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
    normalized_observations: list[MacObservation] = []
    by_ip: dict[str, list[MacObservation]] = {}
    by_mac: dict[str, list[MacObservation]] = {}
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
            normalized_observations.append(normalized)
            by_ip.setdefault(normalized.ip, []).append(normalized)
            by_mac.setdefault(normalized.mac, []).append(normalized)

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
                conflict_type="same_ip_multiple_macs",
            )
        )

    for mac, mac_observations in by_mac.items():
        ips = sorted({observation.ip for observation in mac_observations}, key=ipaddress.IPv4Address)
        if len(ips) <= 1:
            continue

        sources = sorted({observation.source for observation in mac_observations if observation.source})
        samples = sorted({str(observation.sample) for observation in mac_observations})
        vendors = sorted({observation.vendor for observation in mac_observations if observation.vendor})
        hostnames = sorted({observation.hostname for observation in mac_observations if observation.hostname})
        severity = classify_conflict_severity(sources=sources, samples=samples)
        conflicts.append(
            IpConflict(
                ip=", ".join(ips),
                mac_addresses=[mac],
                vendors=vendors,
                hostnames=hostnames,
                sources=sources,
                samples=samples,
                severity=severity,
                notes="Anomalie probable : une même adresse MAC a été observée sur plusieurs IPv4.",
                conflict_type="same_mac_multiple_ips",
            )
        )

    return sorted(conflicts, key=conflict_sort_key)


def conflict_sort_key(conflict: IpConflict) -> tuple[ipaddress.IPv4Address, str]:
    first_ip = conflict.ip.split(",", maxsplit=1)[0].strip()
    try:
        return ipaddress.IPv4Address(first_ip), conflict.conflict_type
    except ValueError:
        return ipaddress.IPv4Address("255.255.255.255"), conflict.conflict_type


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
        "conflict_type": conflict.conflict_type,
    }


def write_ip_conflicts_csv(conflicts: list[IpConflict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "conflict_type",
                "ip",
                "mac_addresses",
                "vendors",
                "hostnames",
                "sources",
                "samples",
                "severity",
                "notes",
            ],
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


def build_vuln_command(nmap: str, subnet: str, out_xml: Path, *, mode: str) -> list[str]:
    script = "safe" if mode == "safe" else "vuln"
    return [nmap, "-sV", "--script", script, subnet, "-oX", str(out_xml)]


def nmap_vulnerability_scan(
    nmap: str,
    subnet: str,
    out_dir: Path,
    log_file: Path,
    *,
    mode: str,
    timeout: int,
) -> Path:
    out_xml = out_dir / f"vuln_{mode}_{safe_name(subnet)}.xml"
    proc = run_command(build_vuln_command(nmap, subnet, out_xml, mode=mode), timeout=timeout, log_file=log_file)
    if proc.returncode != 0:
        print(f"[WARN] Scan vulnérabilités Nmap en échec sur {subnet}. Voir {log_file}")
    return out_xml


def passive_vulnerability_findings(devices: dict[str, Device]) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for device in devices.values():
        ports = {port.split("/")[0]: port for port in device.ports}
        services = " | ".join(device.services)
        host = device.hostname
        if "22" in ports:
            findings.append(
                VulnerabilityFinding(
                    ip=device.ip,
                    host=host,
                    port=ports["22"],
                    service=matching_service(device, "22"),
                    severity="low",
                    title="SSH exposé",
                    evidence=matching_service(device, "22") or services,
                    recommendation=(
                        "Restreindre SSH aux réseaux d'administration, imposer clés fortes "
                        "et désactiver les mots de passe si possible."
                    ),
                    source="passive",
                )
            )
        if "80" in ports:
            findings.append(
                VulnerabilityFinding(
                    ip=device.ip,
                    host=host,
                    port=ports["80"],
                    service=matching_service(device, "80"),
                    severity="medium",
                    title="HTTP non chiffré exposé",
                    evidence=matching_service(device, "80") or services,
                    recommendation=(
                        "Privilégier HTTPS, limiter l'accès d'administration et vérifier "
                        "les en-têtes/session côté application."
                    ),
                    source="passive",
                )
            )
        smb_ports = [ports[port] for port in ("139", "445") if port in ports]
        if smb_ports:
            findings.append(
                VulnerabilityFinding(
                    ip=device.ip,
                    host=host,
                    port=", ".join(smb_ports),
                    service=" | ".join(
                        service
                        for service in [matching_service(device, "139"), matching_service(device, "445")]
                        if service
                    ),
                    severity="high",
                    title="SMB exposé",
                    evidence="Ports SMB ouverts : " + ", ".join(smb_ports),
                    recommendation=(
                        "Limiter SMB aux hôtes nécessaires, vérifier SMBv1, signatures SMB, "
                        "comptes invités et partages anonymes."
                    ),
                    source="passive",
                )
            )
        if "9100" in ports:
            findings.append(
                VulnerabilityFinding(
                    ip=device.ip,
                    host=host,
                    port=ports["9100"],
                    service=matching_service(device, "9100"),
                    severity="medium",
                    title="Port impression RAW 9100 exposé",
                    evidence=matching_service(device, "9100") or services,
                    recommendation=(
                        "Limiter JetDirect/RAW 9100 aux serveurs d'impression autorisés "
                        "et filtrer depuis les VLAN utilisateurs."
                    ),
                    source="passive",
                )
            )
    return findings


def matching_service(device: Device, port: str) -> str:
    prefix = f"{port}/"
    return next((service for service in device.services if service.startswith(prefix)), "")


def parse_nmap_vulnerability_xml(path: Path) -> list[VulnerabilityFinding]:
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []

    findings: list[VulnerabilityFinding] = []
    for host in root.findall("host"):
        ip = ""
        hostname = parse_hostnames(host)
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr", "")
                break
        if not ip:
            continue
        for port in host.findall("ports/port"):
            proto = port.attrib.get("protocol", "")
            portid = port.attrib.get("portid", "")
            port_label = f"{portid}/{proto}" if proto else portid
            service = build_service_label(portid, proto, port.find("service"))
            for script in port.findall("script"):
                findings.append(nmap_script_finding(ip, hostname, port_label, service, script))
        for script in host.findall("hostscript/script"):
            findings.append(nmap_script_finding(ip, hostname, "host", "hostscript", script))
    return findings


def nmap_script_finding(
    ip: str,
    hostname: str,
    port: str,
    service: str,
    script: ET.Element,
) -> VulnerabilityFinding:
    script_id = script.attrib.get("id", "nmap-script")
    output = script.attrib.get("output", "").strip()
    severity = "medium"
    lowered = f"{script_id} {output}".lower()
    if any(token in lowered for token in ("vulnerable", "cve-", "critical")):
        severity = "high"
    elif any(token in lowered for token in ("not vulnerable", "false")):
        severity = "info"
    return VulnerabilityFinding(
        ip=ip,
        host=hostname,
        port=port,
        service=service,
        severity=severity,
        title=f"Nmap NSE {script_id}",
        evidence=output[:500],
        recommendation="Examiner la sortie NSE, confirmer manuellement et corriger selon l'avis éditeur/CVE concerné.",
        source="nmap-nse",
    )


def write_vulnerabilities_csv(findings: list[VulnerabilityFinding], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "host", "port", "service", "severity", "title", "evidence", "recommendation", "source"],
            delimiter=";",
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def write_vulnerabilities_json(findings: list[VulnerabilityFinding], path: Path) -> None:
    payload = json.dumps([asdict(finding) for finding in findings], ensure_ascii=False, indent=2)
    path.write_text(payload + "\n", encoding="utf-8")


def write_vulnerability_report(findings: list[VulnerabilityFinding], path: Path) -> None:
    lines = ["# Rapport vulnérabilités", ""]
    if not findings:
        lines.append("Aucune vulnérabilité ou exposition notable détectée par le mode sélectionné.")
    else:
        lines.extend(["| Sévérité | IP | Port | Titre | Source |", "|---|---|---|---|---|"])
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    sanitize_markdown_cell(value)
                    for value in [finding.severity, finding.ip, finding.port, finding.title, finding.source]
                )
                + " |"
            )
        lines.append("")
        for finding in findings:
            title = f"{finding.ip} {finding.port} - {finding.title}"
            lines.extend(
                [
                    f"## {title}",
                    "",
                    f"- Sévérité : {finding.severity}",
                    f"- Hôte : {finding.host or '-'}",
                    f"- Service : {finding.service or '-'}",
                    f"- Source : {finding.source}",
                    f"- Preuve : {finding.evidence or '-'}",
                    f"- Recommandation : {finding.recommendation}",
                    "",
                ]
            )
    path.write_text("\n".join(lines), encoding="utf-8")


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


def write_mermaid(
    devices: dict[str, Device],
    subnets: list[str],
    gateways: dict[str, str],
    path: Path,
    *,
    topology: KnownTopology | None = None,
) -> None:
    path.write_text(build_mermaid(devices, subnets, gateways, topology=topology) + "\n", encoding="utf-8")


def build_mermaid(
    devices: dict[str, Device],
    subnets: list[str],
    gateways: dict[str, str],
    *,
    topology: KnownTopology | None = None,
) -> str:
    topology = topology or KnownTopology()
    lines = ["flowchart TD", "    SCAN[Poste de scan]"]
    seen_lines = set(lines)

    def add(line: str) -> None:
        if line not in seen_lines:
            lines.append(line)
            seen_lines.add(line)

    subnet_ids: dict[str, str] = {}
    subnet_nets: dict[str, ipaddress.IPv4Network] = {}
    for subnet in subnets:
        sid = mermaid_id("subnet_" + subnet)
        subnet_ids[subnet] = sid
        subnet_nets[subnet] = ipaddress.IPv4Network(subnet, strict=False)
        add(f'    {sid}["{subnet}"]')

    bridge_networks: dict[str, set[str]] = {bridge.name: set(bridge.networks) for bridge in topology.bridges}
    bridge_interfaces: dict[str, list[str]] = {bridge.name: bridge.interfaces for bridge in topology.bridges}
    for device in devices.values():
        for bridge in device.bridges:
            bridge_networks.setdefault(bridge, set())
            bridge_interfaces.setdefault(bridge, [])
            for subnet, subnet_net in subnet_nets.items():
                try:
                    if ipaddress.IPv4Address(device.ip) in subnet_net:
                        bridge_networks[bridge].add(subnet)
                except ValueError:
                    continue

    for bridge_name, networks in bridge_networks.items():
        bid = mermaid_id("bridge_" + bridge_name)
        interface_label = ", ".join(bridge_interfaces.get(bridge_name, [])[:6])
        label = "\n".join(part for part in [bridge_name, "bridge", interface_label] if part)
        add(f'    {bid}["{escape_mermaid_label(label)}"]')
        for network in networks:
            if network in subnet_ids:
                add(f"    {subnet_ids[network]} --> {bid}")

    router_ips = set()
    for node in topology.nodes:
        role = node.role.lower()
        if not any(token in role for token in ("pfsense", "firewall", "router", "routeur")):
            continue
        rid = mermaid_id("known_router_" + (node.name or "_".join(node.ips)))
        label = "\n".join(part for part in [node.name, role_label(node.role), ", ".join(node.ips)] if part)
        add(f'    {rid}["{escape_mermaid_label(label)}"]')
        add(f"    SCAN --> {rid}")
        connected_subnets: list[str] = []
        for ip in node.ips:
            router_ips.add(ip)
            try:
                router_ip = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            for subnet, subnet_net in subnet_nets.items():
                if router_ip in subnet_net and subnet not in connected_subnets:
                    connected_subnets.append(subnet)
        if len(connected_subnets) > 1:
            add(f"    {subnet_ids[connected_subnets[0]]} --> {rid}")
            for subnet in connected_subnets[1:]:
                add(f"    {rid} --> {subnet_ids[subnet]}")
        else:
            for subnet in connected_subnets:
                add(f"    {rid} --> {subnet_ids[subnet]}")

    gw_ips = set(gateways.values()) - router_ips
    for subnet, subnet_net in subnet_nets.items():
        subnet_gateways = [gw for gw in gw_ips if ipaddress.IPv4Address(gw) in subnet_net]
        if subnet_gateways:
            for gw in subnet_gateways:
                gwid = mermaid_id(gw)
                label = gw
                if gw in devices:
                    d = devices[gw]
                    label = f"{gw}\n{d.hostname or d.vendor or d.device_type}"
                add(f'    {gwid}["{escape_mermaid_label(label)}"]')
                add(f"    SCAN --> {gwid}")
                add(f"    {gwid} --> {subnet_ids[subnet]}")
        elif not router_ips:
            add(f"    SCAN --> {subnet_ids[subnet]}")

    for subnet, subnet_net in subnet_nets.items():
        for device in devices.values():
            if device.ip in router_ips:
                continue
            try:
                if ipaddress.IPv4Address(device.ip) not in subnet_net:
                    continue
            except ValueError:
                continue

            did = mermaid_id(device.ip)
            label_parts = [device.ip, device.hostname, device.vendor, device.device_type]
            label = "\n".join(part for part in label_parts if part)
            add(f'    {did}["{escape_mermaid_label(label)}"]')
            parent = ""
            for bridge in device.bridges:
                if bridge in bridge_networks:
                    parent = mermaid_id("bridge_" + bridge)
                    break
            add(f"    {parent or subnet_ids[subnet]} --> {did}")

    return "\n".join(lines)


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
                "| Type | IP | MAC observées | Sources | Samples | Sévérité | Notes |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for conflict in conflicts:
            lines.append(
                "| "
                + " | ".join(
                    sanitize_markdown_cell(value)
                    for value in [
                        conflict.conflict_type,
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
        f"<td>{html.escape(conflict.conflict_type)}</td>"
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
      <tr>
        <th>Type</th><th>IP</th><th>MAC observées</th><th>Sources</th>
        <th>Samples</th><th>Sévérité</th><th>Notes</th>
      </tr>
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


def resolve_scan_subnets(
    *,
    auto_subnets: Iterable[str] = (),
    explicit_subnets: Iterable[str] = (),
    extra_subnets: Iterable[str] = (),
    known_subnets: Iterable[str] = (),
    exclude_virtual_subnets: bool = True,
) -> list[str]:
    auto_valid = validate_subnets(auto_subnets)
    if exclude_virtual_subnets:
        auto_valid = [subnet for subnet in auto_valid if not is_default_virtual_subnet(subnet)]

    requested_valid = validate_subnets([*explicit_subnets, *extra_subnets])
    known_valid = validate_subnets(known_subnets)
    return deduplicate([*auto_valid, *requested_valid, *known_valid])


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
        "--extra-subnet",
        action="append",
        default=[],
        help="Sous-réseau à ajouter explicitement, utile avec --auto. Répétable.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Détecte automatiquement les sous-réseaux IPv4 privés du PC.",
    )
    parser.add_argument(
        "--debug-auto",
        action="store_true",
        help="Affiche les interfaces détectées automatiquement et les réseaux retenus.",
    )
    parser.add_argument(
        "--exclude-virtual-subnets",
        action="store_true",
        default=True,
        help=(
            "Ignore les sous-réseaux virtuels auto-détectés Windows/VMware/WSL "
            "(comportement par défaut ; les réseaux demandés explicitement restent inclus)."
        ),
    )
    parser.add_argument(
        "--include-virtual-subnets",
        action="store_false",
        dest="exclude_virtual_subnets",
        help="Conserve aussi les sous-réseaux virtuels auto-détectés.",
    )
    parser.add_argument(
        "--known-topology",
        type=Path,
        default=None,
        help="Fichier YAML de topologie connue pour surcharger noms, rôles, IP, MAC, VMID/CTID et bridges.",
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
        "--vuln",
        choices=["passive", "safe", "nse"],
        default=None,
        help="Analyse vulnérabilités : passive sans scan, safe avec NSE safe, nse avec scripts vuln confirmés.",
    )
    parser.add_argument(
        "--confirm-vuln-scan",
        action="store_true",
        help="Confirmation obligatoire pour --vuln nse.",
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
    if args.vuln == "nse" and not args.confirm_vuln_scan:
        parser.error("--vuln nse nécessite --confirm-vuln-scan")

    nmap = require_nmap()
    try:
        known_topology = load_known_topology(args.known_topology)
    except RuntimeError as exc:
        print(f"ERREUR : {exc}", file=sys.stderr)
        return 2

    auto_subnets: list[str] = []
    if args.auto:
        auto_subnets = detect_local_networks(timeout=min(args.timeout, 30), debug_auto=args.debug_auto)
    subnets = resolve_scan_subnets(
        auto_subnets=auto_subnets,
        explicit_subnets=args.subnet,
        extra_subnets=args.extra_subnet,
        known_subnets=known_topology.networks,
        exclude_virtual_subnets=args.exclude_virtual_subnets,
    )

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
    gateways.update(known_gateway_ips(known_topology))
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
    conflict_observations: list[MacObservation] = known_observations_from_topology(known_topology)
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
    devices = apply_known_topology(devices, known_topology)
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

    vulnerability_findings: list[VulnerabilityFinding] = []
    if args.vuln:
        vulnerability_findings.extend(passive_vulnerability_findings(devices))
        if args.vuln in {"safe", "nse"}:
            print(f"[INFO] Scan vulnérabilités Nmap : mode {args.vuln}")
            for subnet in subnets:
                vuln_xml = nmap_vulnerability_scan(
                    nmap,
                    subnet,
                    out_dir,
                    log_file,
                    mode=args.vuln,
                    timeout=args.timeout,
                )
                vulnerability_findings.extend(parse_nmap_vulnerability_xml(vuln_xml))

    csv_path = out_dir / "devices.csv"
    conflicts_csv_path = out_dir / "ip_conflicts.csv"
    mermaid_path = out_dir / "topology.mmd"
    report_path = out_dir / "report.md"
    vulnerabilities_csv_path = out_dir / "vulnerabilities.csv"
    vulnerabilities_json_path = out_dir / "vulnerabilities.json"
    vulnerabilities_report_path = out_dir / "vulnerability_report.md"
    write_csv(devices, csv_path)
    write_ip_conflicts_csv(ip_conflicts, conflicts_csv_path)
    if args.vuln:
        write_vulnerabilities_csv(vulnerability_findings, vulnerabilities_csv_path)
        write_vulnerabilities_json(vulnerability_findings, vulnerabilities_json_path)
        write_vulnerability_report(vulnerability_findings, vulnerabilities_report_path)
    write_mermaid(devices, subnets, gateways, mermaid_path, topology=known_topology)
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
    if args.vuln:
        print(f"- Vuln CSV : {vulnerabilities_csv_path.resolve()}")
        print(f"- Vuln JSON: {vulnerabilities_json_path.resolve()}")
        print(f"- Vuln MD  : {vulnerabilities_report_path.resolve()}")
    print("")
    print("Conseil : ouvre report.md dans VS Code ou colle topology.mmd dans https://mermaid.live")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
