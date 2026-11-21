"""Serializability tests: pool switches racing with lease operations.

The contract is "outcome equals some sequential order".  Each test races a
pool switch against a lease operation and then checks the final state
against both possible serial orders, plus invariants that no interleaving
may violate (an address is never issued twice, a lease issued from a pool is
always inside that pool, a renewal never resurrects an out-of-pool lease).
"""

from __future__ import annotations

import ipaddress
import itertools
import os
import tempfile
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.config import Settings
from app.db import LeaseError, Store
from app.routing import RouteSpec
from app.subnets import usable_bounds

OLD = "10.20.0.0/29"
NEW = "10.40.0.0/29"
BRANCH = "192.0.2.1"
OTHER = "198.51.100.9"

_counter = itertools.count()


def fresh_store(base: Settings) -> Store:
    directory = tempfile.mkdtemp(prefix="lease-race-")
    store = Store(
        base.with_(db_path=os.path.join(directory, f"db-{next(_counter)}.db"))
    )
    store.initialize()
    return store


def _in_pool(cidr: str, ip: str) -> bool:
    first, last = usable_bounds(ipaddress.IPv4Network(cidr))
    return first <= int(ipaddress.IPv4Address(ip)) <= last


def _run_pair(
    left: Callable[[], Any], right: Callable[[], Any]
) -> tuple[tuple[str, Any], tuple[str, Any]]:
    barrier = threading.Barrier(2)

    def wrap(fn: Callable[[], Any]) -> Callable[[], tuple[str, Any]]:
        def inner() -> tuple[str, Any]:
            barrier.wait()
            try:
                return "ok", fn()
            except LeaseError as exc:
                return "err", exc.code

        return inner

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(wrap(left)), pool.submit(wrap(right))]
        return futures[0].result(), futures[1].result()


def test_acquire_racing_switch_is_equivalent_to_serial(settings: Settings) -> None:
    for _ in range(25):
        store = fresh_store(settings)
        start_pool = store.pool_info()["cidr"]
        target = NEW if start_pool == OLD else OLD

        (acquire_kind, acquire_val), (switch_kind, switch_val) = _run_pair(
            lambda: store.acquire("client-a"),
            lambda: store.switch_pool(target),
        )

        assert switch_kind == "ok"
        assert switch_val["changed"] is True
        assert store.pool_info()["cidr"] == target

        assert acquire_kind == "ok", acquire_val
        lease, _reused = acquire_val
        # Serial order 1: acquire first -> lease came from the old pool.
        # Serial order 2: switch first  -> lease came from the new pool.
        assert lease["pool_cidr"] in {start_pool, target}
        assert _in_pool(lease["pool_cidr"], lease["ip"])
        if lease["pool_cidr"] == start_pool:
            first, _ = usable_bounds(ipaddress.IPv4Network(start_pool))
            assert int(ipaddress.IPv4Address(lease["ip"])) == first

        current = store.get_lease(lease["lease_id"])
        assert current["status"] == "active"
        out = {item["lease_id"] for item in store.out_of_pool_leases()}
        assert (lease["lease_id"] in out) == (lease["pool_cidr"] != target)


def test_renew_racing_switch_is_equivalent_to_serial(settings: Settings) -> None:
    for _ in range(25):
        store = fresh_store(settings)
        start_pool = store.pool_info()["cidr"]
        lease, _ = store.acquire("client-a", ttl_seconds=3600)
        target = NEW if start_pool == OLD else OLD

        (renew_kind, renew_val), (switch_kind, _) = _run_pair(
            lambda: store.renew(lease["lease_id"], ttl_seconds=7200),
            lambda: store.switch_pool(target),
        )

        assert switch_kind == "ok"
        if renew_kind == "ok":
            # Renew committed before the switch: it saw the old pool.
            assert renew_val["status"] == "active"
            assert renew_val["seconds_remaining"] == 7200
            final = store.get_lease(lease["lease_id"])
            assert final["status"] == "active"
            assert final["ip"] == lease["ip"]
        else:
            assert renew_val == "address_out_of_pool"
            final = store.get_lease(lease["lease_id"])
            assert final["status"] == "active"
            assert final["lease_id"] == lease["lease_id"]
            assert final["expires_at"] == lease["expires_at"]


def test_release_racing_switch_never_breaks_invariants(settings: Settings) -> None:
    for _ in range(25):
        store = fresh_store(settings)
        lease, _ = store.acquire("client-a")
        start_pool = store.pool_info()["cidr"]
        target = NEW if start_pool == OLD else OLD

        (release_kind, _), (switch_kind, _) = _run_pair(
            lambda: store.release(lease["lease_id"]),
            lambda: store.switch_pool(target),
        )
        assert release_kind == "ok"
        assert switch_kind == "ok"
        final = store.get_lease(lease["lease_id"])
        assert final["status"] == "released"
        assert store.out_of_pool_leases() == []
        # The address is free again in the old pool's space.
        store.switch_pool(start_pool)
        fresh, _ = store.acquire("client-b")
        assert fresh["ip"] == lease["ip"]


def test_concurrent_acquires_never_share_an_address(settings: Settings) -> None:
    store = fresh_store(settings)

    def acquire(i: int) -> str | None:
        try:
            return store.acquire(f"client-{i}")[0]["ip"]
        except LeaseError as exc:
            assert exc.code == "pool_exhausted"
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        addresses = list(pool.map(acquire, range(12)))

    allocated = [a for a in addresses if a is not None]
    assert len(allocated) == len(set(allocated))
    assert len(allocated) == 6  # /29 capacity


# ------------------------------------------------------- guarded switch races


def _branch_table() -> list[RouteSpec]:
    return [RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH)]


def test_guarded_switch_racing_acquire_is_serializable(settings: Settings) -> None:
    """A lease acquired during the checked window must be validated too.

    With a table that only routes the *target* pool, a lease issued from the
    old pool before the guard runs makes the guard reject; a lease issued
    after the guard sees the new pool and succeeds.  Either way the final
    state equals one of the two serial orders.
    """
    for _ in range(25):
        store = fresh_store(settings)
        start_pool = store.pool_info()["cidr"]
        target = NEW if start_pool == OLD else OLD
        table = [RouteSpec(prefix=target, next_hop=BRANCH)]

        (acquire_kind, acquire_val), (switch_kind, switch_val) = _run_pair(
            lambda: store.acquire("client-a"),
            lambda: store.guarded_switch_pool(target, BRANCH, table),
        )

        assert acquire_kind == "ok"
        lease, _ = acquire_val
        if switch_kind == "ok":
            # Guard ran first (or found nothing), so the lease must be in the
            # target pool: the only range the table routes back to us.
            assert switch_val["changed"] is True
            assert lease["pool_cidr"] == target
            assert _in_pool(target, lease["ip"])
        else:
            # Guard ran after an old-pool lease existed: rejected, no switch.
            assert switch_val == "switch_blocked"
            assert lease["pool_cidr"] == start_pool
        assert store.pool_info()["cidr"] == (
            target if switch_kind == "ok" else start_pool
        )
        assert store.get_lease(lease["lease_id"])["status"] == "active"


def test_guarded_switch_racing_release_is_serializable(settings: Settings) -> None:
    for _ in range(25):
        store = fresh_store(settings)
        lease, _ = store.acquire("client-a")
        start_pool = store.pool_info()["cidr"]
        target = NEW if start_pool == OLD else OLD
        table = [RouteSpec(prefix=target, next_hop=BRANCH)]

        (release_kind, _), (switch_kind, switch_val) = _run_pair(
            lambda: store.release(lease["lease_id"]),
            lambda: store.guarded_switch_pool(target, BRANCH, table),
        )
        assert release_kind == "ok"
        if switch_kind == "ok":
            # Release committed first, so the old address no longer mattered.
            assert switch_val["changed"] is True
            assert store.pool_info()["cidr"] == target
        else:
            # Guard saw the lease still active and refused to move.
            assert switch_val == "switch_blocked"
            assert store.pool_info()["cidr"] == start_pool
        assert store.get_lease(lease["lease_id"])["status"] == "released"


def test_guarded_switch_racing_renew_reflects_serial_order(
    settings: Settings,
) -> None:
    for _ in range(25):
        store = fresh_store(settings)
        lease, _ = store.acquire("client-a", ttl_seconds=3600)
        start_pool = store.pool_info()["cidr"]
        target = NEW if start_pool == OLD else OLD
        table = [RouteSpec(prefix=target, next_hop=BRANCH)]

        (renew_kind, _), (switch_kind, switch_val) = _run_pair(
            lambda: store.renew(lease["lease_id"], ttl_seconds=7200),
            lambda: store.guarded_switch_pool(target, BRANCH, table),
        )
        if switch_kind == "ok":
            assert store.pool_info()["cidr"] == target
            # Renew either happened before (on the old lease) or after the
            # switch, in which case the address is out of pool and refused.
            assert renew_kind in {"ok", "err"}
        else:
            assert switch_val == "switch_blocked"
            assert store.pool_info()["cidr"] == start_pool
            assert renew_kind == "ok"
        assert store.get_lease(lease["lease_id"])["status"] == "active"


def test_two_guarded_switches_are_serializable(settings: Settings) -> None:
    """Two guards to different pools: the result equals one serial order."""
    for _ in range(25):
        store = fresh_store(settings)
        table_a = [RouteSpec(prefix=NEW, next_hop=BRANCH)]
        table_b = [RouteSpec(prefix=OLD, next_hop=BRANCH)]

        (a_kind, a_val), (b_kind, b_val) = _run_pair(
            lambda: store.guarded_switch_pool(NEW, BRANCH, table_a),
            lambda: store.guarded_switch_pool(OLD, BRANCH, table_b),
        )
        assert a_kind == "ok" and b_kind == "ok"
        final = store.pool_info()["cidr"]
        # Serial order A->B: A moves OLD->NEW, then B moves NEW->OLD.
        # Serial order B->A: B is a no-op (OLD already current), A moves.
        if final == NEW:
            assert a_val["changed"] is True
            assert b_val["changed"] is False
        else:
            assert final == OLD
            assert a_val["changed"] is True
            assert b_val["changed"] is True
        # A no-op response never claims a change time.
        for val in (a_val, b_val):
            assert (val["changed_at"] is None) is (val["changed"] is False)


def test_guarded_switch_never_issues_lease_from_unvalidated_pool(
    settings: Settings,
) -> None:
    """Under contention, every issued address is inside its recorded pool."""
    store = fresh_store(settings)
    table = [RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH)]
    errors: list[str] = []

    def guarded() -> None:
        for _ in range(10):
            try:
                store.guarded_switch_pool("10.40.0.0/24", BRANCH, table)
            except LeaseError as exc:  # pragma: no cover - should not happen
                errors.append(exc.code)

    def acquire_many() -> None:
        for i in range(10):
            lease, _ = store.acquire(f"load-{i}")
            if not _in_pool(lease["pool_cidr"], lease["ip"]):
                errors.append(f"bad allocation {lease}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(guarded), pool.submit(acquire_many)]
        for future in futures:
            future.result()
    assert errors == []
