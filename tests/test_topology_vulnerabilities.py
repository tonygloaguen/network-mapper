from network_mapper import (
    Device,
    apply_known_topology,
    build_mermaid,
    merge_devices,
    parse_known_topology,
    passive_vulnerability_findings,
)


def test_merge_known_topology_overrides_nmap_results() -> None:
    topology = parse_known_topology(
        {
            "nodes": [
                {
                    "name": "FacturX-debian",
                    "role": "vm",
                    "vmid": 102,
                    "interfaces": [
                        {
                            "name": "ens18",
                            "ip": "192.168.20.28/24",
                            "mac": "BC:24:11:69:F4:A9",
                            "bridge": "vmbr1",
                        }
                    ],
                }
            ]
        }
    )
    devices = {
        "192.168.20.28": Device(
            ip="192.168.20.28",
            hostname="nmap-name",
            mac="AA:AA:AA:AA:AA:AA",
            ports=["22/tcp"],
            services=["22/tcp ssh OpenSSH"],
        )
    }

    merged = apply_known_topology(devices, topology)

    device = merged["192.168.20.28"]
    assert device.hostname == "FacturX-debian"
    assert device.mac == "BC:24:11:69:F4:A9"
    assert device.vmid == "102"
    assert device.bridges == ["vmbr1"]
    assert device.ports == ["22/tcp"]
    assert device.device_type == "VM Proxmox"


def test_merge_device_clears_no_open_port_note_when_ports_arrive() -> None:
    discovery = {"192.168.20.28": Device(ip="192.168.20.28", status="up")}
    service = {"192.168.20.28": Device(ip="192.168.20.28", ports=["22/tcp"], services=["22/tcp ssh"])}

    merged = merge_devices(discovery, service)

    assert merged["192.168.20.28"].ports == ["22/tcp"]
    assert "aucun port ouvert" not in merged["192.168.20.28"].notes


def test_mermaid_places_pfsense_between_wan_and_lan() -> None:
    topology = parse_known_topology(
        {
            "bridges": {
                "vmbr0": {"network": "192.168.1.0/24", "interfaces": ["tap100i0"]},
                "vmbr1": {"network": "192.168.20.0/24", "interfaces": ["tap100i1", "tap102i0"]},
            },
            "nodes": [
                {
                    "name": "pfSense",
                    "role": "pfsense",
                    "interfaces": [
                        {"name": "em0", "ip": "192.168.1.56/24", "bridge": "vmbr0"},
                        {"name": "em1", "ip": "192.168.20.1/24", "bridge": "vmbr1"},
                    ],
                },
                {"name": "FacturX-debian", "role": "vm", "ip": "192.168.20.28/24", "bridge": "vmbr1"},
            ],
        }
    )
    devices = apply_known_topology({}, topology)

    mermaid = build_mermaid(devices, ["192.168.1.0/24", "192.168.20.0/24"], {}, topology=topology)

    assert "pfSense" in mermaid
    assert "vmbr0" in mermaid
    assert "vmbr1" in mermaid
    assert "nknown_router_pfSense --> nsubnet_192_168_1_0_24" in mermaid
    assert "nknown_router_pfSense --> nsubnet_192_168_20_0_24" in mermaid
    assert "nsubnet_192_168_20_0_24 --> nbridge_vmbr1" in mermaid


def test_vuln_passive_on_common_exposed_ports() -> None:
    devices = {
        "192.168.20.50": Device(
            ip="192.168.20.50",
            hostname="printer",
            ports=["22/tcp", "80/tcp", "139/tcp", "445/tcp", "9100/tcp"],
            services=[
                "22/tcp ssh OpenSSH",
                "80/tcp http",
                "139/tcp netbios-ssn",
                "445/tcp microsoft-ds",
                "9100/tcp jetdirect",
            ],
        )
    }

    findings = passive_vulnerability_findings(devices)

    assert {finding.title for finding in findings} == {
        "SSH exposé",
        "HTTP non chiffré exposé",
        "SMB exposé",
        "Port impression RAW 9100 exposé",
    }
    assert {finding.port for finding in findings} >= {"22/tcp", "80/tcp", "139/tcp, 445/tcp", "9100/tcp"}
