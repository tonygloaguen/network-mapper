from pathlib import Path

from network_mapper import Device, classify_device, merge_devices, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_discovery_ip_mac_vendor_hostname() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_discovery_sample.xml")

    gateway = devices["192.168.20.1"]
    assert gateway.ip == "192.168.20.1"
    assert gateway.mac == "00:11:22:33:44:55"
    assert gateway.vendor == "pfSense"
    assert gateway.hostname == "gateway.local"
    assert gateway.status == "up"


def test_parse_open_ports_services_and_os() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_services_sample.xml")

    nas = devices["192.168.20.60"]
    assert "22/tcp" in nas.ports
    assert "445/tcp" in nas.ports
    assert any("OpenSSH" in service for service in nas.services)
    assert any("Samba" in service for service in nas.services)
    assert nas.os_guess == "Linux 4.4 - 5.4"
    assert nas.os_accuracy == "98"


def test_classification_router_firewall() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_services_sample.xml")

    gateway = devices["192.168.20.1"]
    assert "routeur" in gateway.device_type
    assert "firewall" in gateway.device_type


def test_classification_printer() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_services_sample.xml")

    printer = devices["192.168.20.50"]
    assert printer.device_type == "imprimante"


def test_classification_nas_or_linux_server() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_services_sample.xml")

    nas = devices["192.168.20.60"]
    assert "NAS" in nas.device_type
    assert "serveur Linux" in nas.device_type


def test_empty_or_incomplete_xml(tmp_path: Path) -> None:
    empty = tmp_path / "empty.xml"
    empty.write_text("", encoding="utf-8")
    assert parse_nmap_xml(empty) == {}

    incomplete = tmp_path / "incomplete.xml"
    incomplete.write_text("<nmaprun><host><status state='up'/></host></nmaprun>", encoding="utf-8")
    assert parse_nmap_xml(incomplete) == {}


def test_merge_discovery_and_services() -> None:
    discovery = parse_nmap_xml(FIXTURES / "nmap_discovery_sample.xml")
    services = parse_nmap_xml(FIXTURES / "nmap_services_sample.xml")

    merged = merge_devices(discovery, services)
    assert merged["192.168.20.1"].hostname == "fw-gateway.local"
    assert "443/tcp" in merged["192.168.20.1"].ports


def test_unknown_device_classification() -> None:
    device = Device(ip="192.168.20.200", status="up")
    classify_device(device)

    assert device.device_type == "équipement inconnu à qualifier"
    assert "aucun port" in device.notes
