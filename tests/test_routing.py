"""Unit tests for longest-prefix-match route evaluation (pure functions)."""

from __future__ import annotations

import ipaddress

import pytest

from app import routing
from app.routing import NextHopError, RouteSpec, RoutingError
from app.subnets import usable_bounds

BRANCH = "192.0.2.1"
OTHER = "198.51.100.7"


def table(*specs: RouteSpec) -> routing.RouteTable:
    return routing.parse_table(specs)


def uncovered(cidr: str, parsed: routing.RouteTable) -> tuple[list[str], int]:
    first, last = usable_bounds(ipaddress.IPv4Network(cidr))
    segments, count = parsed.uncovered_segments(
        first, last, ipaddress.IPv4Address(BRANCH)
    )
    return [str(segment) for segment in segments], count


def test_branch_default_route_covers_everything() -> None:
    parsed = table(RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH))
    assert uncovered("10.30.0.0/24", parsed) == ([], 0)


def test_no_route_at_all_covers_nothing() -> None:
    # /30 usable range is .1-.2 (network/broadcast excluded).
    assert uncovered("10.30.0.0/30", table()) == (["10.30.0.1/32", "10.30.0.2/32"], 2)


def test_more_specific_discard_overrides_branch_default() -> None:
    parsed = table(
        RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH),
        RouteSpec(prefix="10.30.0.8/29", discard=True),
    )
    # /28 usable range is .1-.14; .8-.15 discard intersects it at .8-.14.
    assert uncovered("10.30.0.0/28", parsed) == (
        ["10.30.0.8/30", "10.30.0.12/31", "10.30.0.14/32"],
        7,
    )


def test_route_to_another_branch_is_not_reachable() -> None:
    parsed = table(RouteSpec(prefix="10.30.0.0/28", next_hop=OTHER))
    assert uncovered("10.30.0.0/28", parsed)[1] == 14


def test_less_specific_other_hop_loses_to_more_specific_branch_route() -> None:
    parsed = table(
        RouteSpec(prefix="10.0.0.0/8", next_hop=OTHER),
        RouteSpec(prefix="10.30.0.0/29", next_hop=BRANCH),
    )
    assert uncovered("10.30.0.0/29", parsed) == ([], 0)
    assert uncovered("10.30.0.1", parsed) == ([], 0)  # usable address of /29


def test_more_specific_other_hop_wins_over_branch_route() -> None:
    parsed = table(
        RouteSpec(prefix="10.30.0.0/28", next_hop=BRANCH),
        RouteSpec(prefix="10.30.0.2/31", next_hop=OTHER),
    )
    segments, count = uncovered("10.30.0.0/28", parsed)
    assert segments == ["10.30.0.2/31"]
    assert count == 2


def test_branch_route_nested_inside_other_hop_region() -> None:
    parsed = table(
        RouteSpec(prefix="10.30.0.0/29", next_hop=OTHER),
        RouteSpec(prefix="10.30.0.4/31", next_hop=BRANCH),
    )
    assert uncovered("10.30.0.4/31", parsed) == ([], 0)
    # /29 usable range .1-.6; .4 and .5 are routed here.
    assert uncovered("10.30.0.0/29", parsed) == (
        ["10.30.0.1/32", "10.30.0.2/31", "10.30.0.6/32"],
        4,
    )


def test_host_prefix_and_31_are_supported() -> None:
    parsed = table(RouteSpec(prefix="10.30.0.1/32", next_hop=BRANCH))
    assert parsed.points_to("10.30.0.1", ipaddress.IPv4Address(BRANCH))
    # A /31 has two usable addresses; .1 is routed here, .0 is not.
    assert uncovered("10.30.0.0/31", parsed) == (["10.30.0.0/32"], 1)


def test_full_ipv4_pool_is_summarised_not_enumerated() -> None:
    parsed = table(RouteSpec(prefix="0.0.0.0/1", next_hop=BRANCH))
    segments, count = uncovered("0.0.0.0/0", parsed)
    # /0 usable space is 0.0.0.1-255.255.255.254; only the lower /1 is routed.
    assert count == 2**31 - 1
    assert segments[0] == "128.0.0.0/2"
    assert segments[-1] == "255.255.255.254/32"
    assert len(segments) == 31


def test_empty_table_on_full_ipv4_pool_is_summarised() -> None:
    # No enumeration: the whole usable IPv4 space collapses to 62 prefixes.
    segments, count = uncovered("0.0.0.0/0", table())
    assert count == 2**32 - 2
    assert len(segments) == 62
    assert segments[0] == "0.0.0.1/32"
    assert segments[-1] == "255.255.255.254/32"


def test_wide_uncovered_space_has_few_segments() -> None:
    parsed = table(
        RouteSpec(prefix="10.0.0.0/8", next_hop=BRANCH),
        RouteSpec(prefix="10.1.0.0/16", discard=True),
    )
    segments, count = uncovered("10.0.0.0/8", parsed)
    # Only 10.1.0.0/16 is not routed to the branch; inside a /8 pool every
    # address of that /16 is usable (only the pool's own net/broadcast are not).
    assert count == 2**16
    assert len(segments) < 40
    assert all(segment.startswith("10.1.") for segment in segments)


@pytest.mark.parametrize(
    ("specs", "message"),
    [
        ([RouteSpec(prefix="10.0.0.0/8")], "specify a next hop or discard"),
        (
            [RouteSpec(prefix="10.0.0.0/8", next_hop="not-an-ip")],
            "next_hop must be an IPv4 address",
        ),
        (
            [RouteSpec(prefix="10.0.0.0/8", next_hop=BRANCH, discard=True)],
            "discard cannot be combined",
        ),
        ([RouteSpec(prefix="10.0.0.0")], "prefix must be an IPv4 CIDR"),
        ([RouteSpec(prefix="2001:db8::/32", next_hop=BRANCH)], "invalid IPv4 prefix"),
        (
            [
                RouteSpec(prefix="10.0.0.0/8", next_hop=BRANCH),
                RouteSpec(prefix="10.1.2.3/8", next_hop=BRANCH),
            ],
            "duplicate prefix 10.0.0.0/8",
        ),
    ],
)
def test_invalid_routes(specs: list[RouteSpec], message: str) -> None:
    with pytest.raises(RoutingError) as exc:
        routing.parse_table(specs)
    assert message in str(exc.value)
    assert exc.value.code == "invalid_routes"


def test_more_than_128_routes_is_rejected() -> None:
    specs = [RouteSpec(prefix=f"10.{i}.0.0/16", next_hop=BRANCH) for i in range(129)]
    with pytest.raises(RoutingError) as exc:
        routing.parse_table(specs)
    assert "at most 128" in str(exc.value)


def test_literal_discard_next_hop_means_discard() -> None:
    parsed = table(RouteSpec(prefix="10.0.0.0/8", next_hop="discard"))
    assert parsed.resolve("10.1.1.1").next_hop is None


def test_invalid_branch_next_hop() -> None:
    for bad in ("", "   ", "10.0.0.256", "10.0.0.1/24", "nope"):
        with pytest.raises(NextHopError) as exc:
            routing.parse_branch_next_hop(bad)
        assert exc.value.code == "invalid_next_hop"
