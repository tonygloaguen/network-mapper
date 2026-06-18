from pathlib import Path

from network_mapper import (
    Device,
    build_markdown_report,
    build_parser,
    collect_routed_subnet_candidates,
    filter_active_routed_subnets,
    parse_known_topology,
    parse_traceroute_candidate_subnets,
    resolve_scan_subnet_sources,
    resolve_scan_subnets,
)


def test_explicit_scanned_subnet_is_preserved_in_final_report() -> None:
    subnets = resolve_scan_subnets(
        auto_subnets=["192.168.56.0/24"],
        explicit_subnets=["192.168.20.0/24", "192.168.1.0/24"],
    )

    assert subnets == ["192.168.20.0/24", "192.168.1.0/24"]

    report = "\n".join(
        build_markdown_report(
            {"192.168.1.1": Device(ip="192.168.1.1", status="up")},
            subnets,
            {},
            [],
            generated_at="test",
            mermaid_text="flowchart TD",
        )
    )
    assert "- `192.168.1.0/24`" in report
    assert "| 192.168.1.1 |" in report


def test_multiple_subnet_arguments_are_kept_in_order() -> None:
    args = build_parser().parse_args(["--subnet", "192.168.20.0/24", "--subnet", "192.168.1.0/24"])

    subnets = resolve_scan_subnets(explicit_subnets=args.subnet)

    assert subnets == ["192.168.20.0/24", "192.168.1.0/24"]


def test_auto_extra_subnet_is_included() -> None:
    args = build_parser().parse_args(["--auto", "--extra-subnet", "192.168.1.0/24"])

    subnets = resolve_scan_subnets(
        auto_subnets=["192.168.20.0/24"],
        extra_subnets=args.extra_subnet,
        exclude_virtual_subnets=args.exclude_virtual_subnets,
    )

    assert subnets == ["192.168.20.0/24", "192.168.1.0/24"]


def test_known_topology_subnet_forces_inclusion() -> None:
    topology = parse_known_topology({"subnets": ["192.168.1.0/24"]})

    subnets = resolve_scan_subnets(auto_subnets=["192.168.20.0/24"], known_subnets=topology.networks)

    assert subnets == ["192.168.20.0/24", "192.168.1.0/24"]


def test_virtual_subnets_are_excluded_from_auto_unless_requested() -> None:
    subnets = resolve_scan_subnets(
        auto_subnets=[
            "192.168.56.0/24",
            "192.168.14.0/24",
            "192.168.178.0/24",
            "172.27.48.0/20",
            "192.168.20.0/24",
        ],
        explicit_subnets=["192.168.56.0/24"],
    )

    assert subnets == ["192.168.20.0/24", "192.168.56.0/24"]



def test_traceroute_private_hop_produces_24_candidate() -> None:
    traceroute = """
traceroute to 1.1.1.1 (1.1.1.1), 8 hops max
 1  192.168.1.1  1.123 ms
 2  203.0.113.1  4.456 ms
"""

    assert parse_traceroute_candidate_subnets(traceroute) == ["192.168.1.0/24"]


def test_virtual_routed_candidates_are_excluded() -> None:
    candidates = collect_routed_subnet_candidates(
        traceroute_texts=["1 192.168.56.1 1 ms\n2 192.168.20.1 2 ms"],
        exclude_virtual_subnets=True,
    )

    assert candidates == {"192.168.20.0/24": "traceroute_hint"}


def test_routed_candidates_without_active_host_are_rejected(tmp_path: Path) -> None:
    candidates = filter_active_routed_subnets(
        {"192.168.1.0/24": "traceroute_hint"},
        nmap="nmap",
        out_dir=tmp_path,
        log_file=tmp_path / "commands.log",
        timeout=1,
        active_checker=lambda subnet: False,
    )

    assert candidates == {}


def test_known_topology_subnets_are_always_included_with_source() -> None:
    topology = parse_known_topology({"subnets": ["192.168.77.0/24"]})

    sources = resolve_scan_subnet_sources(
        auto_subnets=["192.168.20.0/24"],
        known_subnets=topology.networks,
    )

    assert list(sources) == ["192.168.20.0/24", "192.168.77.0/24"]
    assert sources["192.168.77.0/24"] == "known_topology"


def test_report_displays_subnet_source() -> None:
    report = "\n".join(
        build_markdown_report(
            {"192.168.1.1": Device(ip="192.168.1.1", status="up")},
            ["192.168.1.0/24"],
            {},
            [],
            generated_at="test",
            mermaid_text="flowchart TD",
            subnet_sources={"192.168.1.0/24": "traceroute_hint"},
        )
    )

    assert "- `192.168.1.0/24` (source: `traceroute_hint`)" in report
