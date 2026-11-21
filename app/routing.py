"""IPv4 longest-prefix-match checks for guarded pool switches.

The branch receives a forwarding table from headquarters.  Before moving to a
new pool the operator must prove that *every usable address of the target
pool* and *every lease that is still valid at the decision point* is
forwarded back to this branch, otherwise clients that keep an old address
would become unreachable.

The proof is prefix based, never address based: routes form a laminar family
(IPv4 prefixes are either disjoint or nested), so the region covered by
branch-directed routes can be subtracted from the target range in a number
of interval operations bounded by the size of the table, not by the size of
the pool.  That keeps a check of e.g. ``0.0.0.0/0`` cheap.

Longest-prefix match (LPM): a more specific route overrides every less
specific route, regardless of whether its action is a next hop or discard.
"Discard" and "no route at all" both fail the check: only a route whose next
hop is exactly the branch next hop counts as reachable.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeAlias

MAX_ROUTES = 128

Interval: TypeAlias = tuple[int, int]  # inclusive integer address bounds


class RoutingError(ValueError):
    """Invalid forwarding table; mapped to HTTP 422 by the store."""

    code = "invalid_routes"


class NextHopError(RoutingError):
    """Invalid branch next hop; mapped to HTTP 422 by the store."""

    code = "invalid_next_hop"


@dataclass(frozen=True)
class RouteSpec:
    """A route as supplied by the caller (strings are validated/parsed here)."""

    prefix: str
    next_hop: str | None = None
    discard: bool = False


@dataclass(frozen=True)
class Route:
    network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address | None  # ``None`` means discard


@dataclass(frozen=True)
class RouteTable:
    """Routes sorted most-specific first, so the first match is the LPM."""

    routes: tuple[Route, ...]

    def resolve(self, address: str | ipaddress.IPv4Address) -> Route | None:
        """Return the longest-prefix route covering ``address`` (or ``None``)."""
        ip = ipaddress.IPv4Address(address)
        for route in self.routes:
            if ip in route.network:
                return route
        return None

    def points_to(self, address: str | ipaddress.IPv4Address,
                  next_hop: ipaddress.IPv4Address) -> bool:
        """True when LPM resolves ``address`` to ``next_hop`` (not discard)."""
        route = self.resolve(address)
        return route is not None and route.next_hop == next_hop

    def _branch_intervals(
        self, branch_next_hop: ipaddress.IPv4Address
    ) -> list[Interval]:
        """Address ranges whose LPM result is ``branch_next_hop``.

        For every branch-directed route, subtract all more specific routes
        (they override it).  Because prefixes are laminar the resulting
        interval count is linear in the number of routes.
        """
        covered: list[Interval] = []
        for route in self.routes:
            if route.next_hop != branch_next_hop:
                continue
            base: list[Interval] = [_interval(route.network)]
            cuts = [
                _interval(other.network)
                for other in self.routes
                if other.network.prefixlen > route.network.prefixlen
                and other.network.subnet_of(route.network)
            ]
            covered.extend(_subtract_many(base, cuts))
        return _merge(covered)

    def uncovered_intervals(
        self, first: int, last: int, branch_next_hop: ipaddress.IPv4Address
    ) -> list[Interval]:
        """Parts of inclusive range ``[first, last]`` not routed to the branch."""
        if first > last:
            return []
        covered = self._branch_intervals(branch_next_hop)
        return _subtract_sorted((first, last), covered)

    def uncovered_segments(
        self, first: int, last: int, branch_next_hop: ipaddress.IPv4Address
    ) -> tuple[list[ipaddress.IPv4Network], int]:
        """Minimal CIDR summary of the uncovered range plus its address count.

        Summarising intervals (rather than iterating addresses) keeps the
        cost independent of the target pool size.
        """
        intervals = self.uncovered_intervals(first, last, branch_next_hop)
        segments: list[ipaddress.IPv4Network] = []
        count = 0
        for start, end in intervals:
            count += end - start + 1
            segments.extend(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                )
            )
        return segments, count


def parse_branch_next_hop(text: str) -> ipaddress.IPv4Address:
    """Validate the branch's own next hop (must be a real IPv4 address)."""
    value = text.strip() if isinstance(text, str) else ""
    if not value:
        raise NextHopError("next_hop must be an IPv4 address")
    try:
        return ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise NextHopError(
            f"next_hop must be an IPv4 address, got {text!r}"
        ) from exc


def _parse_route_prefix(text: str, index: int) -> ipaddress.IPv4Network:
    value = text.strip() if isinstance(text, str) else ""
    if "/" not in value:
        raise RoutingError(
            f"route #{index}: prefix must be an IPv4 CIDR such as 10.0.0.0/8"
        )
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ValueError as exc:
        raise RoutingError(
            f"route #{index}: invalid IPv4 prefix {text!r}"
        ) from exc
    return network


def parse_table(specs: Sequence[RouteSpec]) -> RouteTable:
    """Validate a forwarding table: <= 128 entries, distinct normalised prefixes.

    Each entry selects exactly one action: a next hop (an IPv4 address, or
    the literal ``"discard"``) or ``discard: true``.
    """
    if len(specs) > MAX_ROUTES:
        raise RoutingError(f"the forwarding table may hold at most {MAX_ROUTES} routes")

    by_prefix: dict[ipaddress.IPv4Network, Route] = {}
    for index, spec in enumerate(specs):
        network = _parse_route_prefix(spec.prefix, index)
        if network in by_prefix:
            raise RoutingError(f"route #{index}: duplicate prefix {network}")

        hop_text = spec.next_hop.strip() if isinstance(spec.next_hop, str) else None
        hop_is_discard = hop_text is not None and hop_text.lower() == "discard"
        if spec.discard:
            if hop_text is not None and not hop_is_discard:
                raise RoutingError(
                    f"route #{index}: discard cannot be combined with a next hop"
                )
            next_hop = None
        elif hop_text is None or not hop_text:
            raise RoutingError(
                f"route #{index}: specify a next hop or discard"
            )
        elif hop_is_discard:
            next_hop = None
        else:
            try:
                next_hop = ipaddress.IPv4Address(hop_text)
            except ValueError as exc:
                raise RoutingError(
                    f"route #{index}: next_hop must be an IPv4 address "
                    f"or 'discard', got {spec.next_hop!r}"
                ) from exc
        by_prefix[network] = Route(network=network, next_hop=next_hop)

    ordered = tuple(
        sorted(by_prefix.values(), key=lambda route: route.network.prefixlen,
               reverse=True)
    )
    return RouteTable(ordered)


# --------------------------------------------------------------- intervals


def _interval(network: ipaddress.IPv4Network) -> Interval:
    return int(network.network_address), int(network.broadcast_address)


def _subtract(intervals: list[Interval], cut: Interval) -> list[Interval]:
    result: list[Interval] = []
    cut_start, cut_end = cut
    for start, end in intervals:
        if cut_end < start or cut_start > end:
            result.append((start, end))
            continue
        if start < cut_start:
            result.append((start, cut_start - 1))
        if end > cut_end:
            result.append((cut_end + 1, end))
    return result


def _subtract_many(
    intervals: list[Interval], cuts: Sequence[Interval]
) -> list[Interval]:
    result = intervals
    for cut in cuts:
        result = _subtract(result, cut)
        if not result:
            break
    return result


def _subtract_sorted(target: Interval, cuts: Sequence[Interval]) -> list[Interval]:
    """Subtract pre-sorted, merged ``cuts`` from a single interval."""
    result: list[Interval] = []
    start, end = target
    for cut_start, cut_end in cuts:
        if cut_end < start:
            continue
        if cut_start > end:
            break
        if cut_start > start:
            result.append((start, cut_start - 1))
        start = max(start, cut_end + 1)
        if start > end:
            return result
    result.append((start, end))
    return result


def _merge(intervals: list[Interval]) -> list[Interval]:
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged: list[list[int]] = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]
