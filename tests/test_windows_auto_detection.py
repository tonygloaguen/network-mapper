import json

from network_mapper import parse_windows_powershell_interfaces, parse_windows_powershell_networks


def powershell_json(value: object) -> str:
    return json.dumps(value)


def test_parse_powershell_json_single_interface() -> None:
    payload = {
        "IPAddress": "192.168.20.12",
        "PrefixLength": 24,
        "InterfaceAlias": "Ethernet",
        "InterfaceOperationalStatus": "Up",
    }

    interfaces = parse_windows_powershell_interfaces(powershell_json(payload))

    assert parse_windows_powershell_networks(powershell_json(payload)) == ["192.168.20.0/24"]
    assert interfaces[0].interface_alias == "Ethernet"
    assert interfaces[0].accepted is True


def test_parse_powershell_json_multiple_interfaces_deduplicates_networks() -> None:
    payload = [
        {
            "IPAddress": "192.168.20.12",
            "PrefixLength": 24,
            "InterfaceAlias": "Ethernet",
            "InterfaceOperationalStatus": "Up",
        },
        {
            "IPAddress": "10.1.2.3",
            "PrefixLength": 8,
            "InterfaceAlias": "VPN",
            "InterfaceOperationalStatus": "Up",
        },
        {
            "IPAddress": "192.168.20.99",
            "PrefixLength": 24,
            "InterfaceAlias": "Wi-Fi",
            "InterfaceOperationalStatus": "Up",
        },
    ]

    assert parse_windows_powershell_networks(powershell_json(payload)) == ["192.168.20.0/24", "10.0.0.0/8"]


def test_parse_powershell_json_excludes_link_local_169_254() -> None:
    payload = {
        "IPAddress": "169.254.10.20",
        "PrefixLength": 16,
        "InterfaceAlias": "Ethernet",
        "InterfaceOperationalStatus": "Up",
    }

    assert parse_windows_powershell_networks(powershell_json(payload)) == []


def test_parse_powershell_json_excludes_loopback_127() -> None:
    payload = {
        "IPAddress": "127.0.0.1",
        "PrefixLength": 8,
        "InterfaceAlias": "Loopback",
        "InterfaceOperationalStatus": "Up",
    }

    assert parse_windows_powershell_networks(powershell_json(payload)) == []


def test_parse_powershell_json_calculates_192_168_20_12_24() -> None:
    payload = {
        "IPAddress": "192.168.20.12",
        "PrefixLength": 24,
        "InterfaceAlias": "Ethernet",
        "InterfaceOperationalStatus": "Up",
    }

    assert parse_windows_powershell_networks(powershell_json(payload)) == ["192.168.20.0/24"]
