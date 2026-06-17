from pathlib import Path

from network_mapper import (
    MacObservation,
    detect_ip_conflicts,
    nmap_observations_from_devices,
    normalize_mac,
    parse_ip_neigh_observations,
    parse_linux_arp_n_observations,
    parse_nmap_xml,
    parse_windows_arp_observations,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_windows_arp_a() -> None:
    text = """
Interface: 192.168.20.10 --- 0x6
  Internet Address      Physical Address      Type
  192.168.20.1          aa-bb-cc-dd-ee-ff     dynamic
  192.168.20.20         11-22-33-44-55-66     static
  192.168.20.30         ff-ff-ff-ff-ff-ff     static
"""

    observations = parse_windows_arp_observations(text, sample=1)

    assert [observation.ip for observation in observations] == ["192.168.20.1", "192.168.20.20"]
    assert observations[0].mac == "AA:BB:CC:DD:EE:FF"
    assert observations[0].source == "arp"
    assert observations[0].sample == 1


def test_parse_linux_ip_neigh() -> None:
    text = """
192.168.20.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.20.2 dev eth0 INCOMPLETE
192.168.20.3 dev eth0 lladdr 11:22:33:44:55:66 STALE
"""

    observations = parse_ip_neigh_observations(text, sample=2)

    assert [(observation.ip, observation.mac) for observation in observations] == [
        ("192.168.20.1", "AA:BB:CC:DD:EE:FF"),
        ("192.168.20.3", "11:22:33:44:55:66"),
    ]
    assert {observation.source for observation in observations} == {"ip_neigh"}


def test_parse_linux_arp_n() -> None:
    text = """
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.20.1             ether   aa:bb:cc:dd:ee:ff   C                     eth0
192.168.20.2             ether   (incomplete)         C                     eth0
"""

    observations = parse_linux_arp_n_observations(text, sample=3)

    assert len(observations) == 1
    assert observations[0].ip == "192.168.20.1"
    assert observations[0].mac == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_formats_and_invalid_values() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("ff:ff:ff:ff:ff:ff") == ""
    assert normalize_mac("00:00:00:00:00:00") == ""
    assert normalize_mac("aa:bb:cc") == ""
    assert normalize_mac("not-a-mac") == ""


def test_detect_conflict_same_ip_two_macs() -> None:
    conflicts = detect_ip_conflicts(
        [
            MacObservation(ip="192.168.20.10", mac="AA:BB:CC:DD:EE:01", source="arp", sample=1),
            MacObservation(ip="192.168.20.10", mac="AA:BB:CC:DD:EE:02", source="arp", sample=1),
        ]
    )

    assert len(conflicts) == 1
    assert conflicts[0].ip == "192.168.20.10"
    assert conflicts[0].mac_addresses == ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
    assert conflicts[0].severity == "medium"


def test_no_conflict_when_same_ip_keeps_same_mac() -> None:
    conflicts = detect_ip_conflicts(
        [
            MacObservation(ip="192.168.20.10", mac="AA:BB:CC:DD:EE:01", source="arp", sample=1),
            MacObservation(ip="192.168.20.10", mac="aa-bb-cc-dd-ee-01", source="ip_neigh", sample=2),
        ]
    )

    assert conflicts == []


def test_conflict_with_multiple_sources_is_high_severity() -> None:
    conflicts = detect_ip_conflicts(
        [
            MacObservation(ip="192.168.20.10", mac="AA:BB:CC:DD:EE:01", source="nmap", sample=0),
            MacObservation(ip="192.168.20.10", mac="AA:BB:CC:DD:EE:02", source="ip_neigh", sample=1),
        ]
    )

    assert len(conflicts) == 1
    assert conflicts[0].sources == ["ip_neigh", "nmap"]
    assert conflicts[0].samples == ["0", "1"]
    assert conflicts[0].severity == "high"


def test_nmap_observations_integration() -> None:
    devices = parse_nmap_xml(FIXTURES / "nmap_discovery_sample.xml")
    observations = nmap_observations_from_devices(devices, sample=0)

    assert any(
        observation.ip == "192.168.20.1"
        and observation.mac == "00:11:22:33:44:55"
        and observation.vendor == "pfSense"
        and observation.hostname == "gateway.local"
        and observation.source == "nmap"
        for observation in observations
    )


def test_detect_conflict_same_mac_multiple_ips() -> None:
    conflicts = detect_ip_conflicts(
        [
            MacObservation(ip="192.168.20.18", mac="30:C5:99:DD:81:CC", source="arp", sample=1),
            MacObservation(ip="192.168.20.60", mac="30-C5-99-DD-81-CC", source="ip_neigh", sample=2),
        ]
    )

    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == "same_mac_multiple_ips"
    assert conflicts[0].ip == "192.168.20.18, 192.168.20.60"
    assert conflicts[0].mac_addresses == ["30:C5:99:DD:81:CC"]
    assert conflicts[0].severity == "high"
