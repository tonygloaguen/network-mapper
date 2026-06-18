from network_mapper import (
    Device,
    build_markdown_report,
    build_parser,
    parse_known_topology,
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
