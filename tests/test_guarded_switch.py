"""Guarded pool switch: routing-aware validation and its HTTP contract."""

from __future__ import annotations

import ipaddress

import pytest
from fastapi.testclient import TestClient

from app import routing
from app.config import Settings
from app.db import LeaseError, Store
from app.main import create_app
from app.routing import RouteSpec

BRANCH = "192.0.2.1"
OTHER = "198.51.100.9"


def default_to_branch(*overrides: RouteSpec) -> list[RouteSpec]:
    return [RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH), *overrides]


# ------------------------------------------------------------------ store


def test_guarded_switch_allows_fully_routed_target(store: Store) -> None:
    target = "10.40.0.0/28"
    result = store.guarded_switch_pool(target, BRANCH, default_to_branch())
    assert result["changed"] is True
    assert result["cidr"] == target
    assert result["previous_cidr"] == "10.20.0.0/29"
    assert result["branch_next_hop"] == BRANCH
    assert result["table_routes"] == 1
    assert result["validated"]["affected_segments"] == []
    assert result["validated"]["affected_lease_ids"] == []
    assert store.pool_info()["cidr"] == target
    fresh, _ = store.acquire("client-a")
    assert fresh["ip"] == "10.40.0.1"


def test_guarded_switch_rejects_discarded_target_segment(store: Store) -> None:
    target = "10.40.0.0/28"
    table = default_to_branch(
        RouteSpec(prefix="10.40.0.8/30", discard=True),
    )
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool(target, BRANCH, table)
    error = exc.value
    assert error.status_code == 409
    assert error.code == "switch_blocked"
    details = error.details or {}
    assert details["target_cidr"] == target
    assert details["affected_address_count"] == 4
    assert details["affected_segments"] == ["10.40.0.8/30"]
    assert details["affected_lease_ids"] == []
    # Old pool still serves and nothing was recorded.
    assert store.pool_info()["cidr"] == "10.20.0.0/29"
    lease, _ = store.acquire("client-a")
    assert lease["ip"] == "10.20.0.1"


def test_guarded_switch_rejects_no_route_for_target(store: Store) -> None:
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/30", BRANCH, [])
    details = exc.value.details or {}
    assert exc.value.code == "switch_blocked"
    assert details["affected_address_count"] == 2
    assert details["affected_segments"] == ["10.40.0.1/32", "10.40.0.2/32"]
    assert store.pool_info()["cidr"] == "10.20.0.0/29"


def test_guarded_switch_rejects_target_routed_to_other_branch(store: Store) -> None:
    table = [RouteSpec(prefix="10.40.0.0/28", next_hop=OTHER)]
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    details = exc.value.details or {}
    assert details["affected_address_count"] == 14
    assert store.pool_info()["cidr"] == "10.20.0.0/29"


def test_more_specific_branch_route_overrides_other_hop_default(store: Store) -> None:
    table = [
        RouteSpec(prefix="0.0.0.0/0", next_hop=OTHER),
        RouteSpec(prefix="10.40.0.0/28", next_hop=BRANCH),
    ]
    result = store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    assert result["changed"] is True


def test_more_specific_discard_beats_branch_default(store: Store) -> None:
    table = [
        RouteSpec(prefix="10.0.0.0/8", next_hop=BRANCH),
        RouteSpec(prefix="10.40.0.8/29", next_hop="discard"),
    ]
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    assert (exc.value.details or {})["affected_segments"] == [
        "10.40.0.8/30",
        "10.40.0.12/31",
        "10.40.0.14/32",
    ]


def test_guarded_switch_rejects_live_lease_not_routed_to_branch(store: Store) -> None:
    """A lease that stays valid must be returned here even outside the target."""
    lease, _ = store.acquire("client-a")  # 10.20.0.1, still active
    table = [
        RouteSpec(prefix="10.40.0.0/28", next_hop=BRANCH),
        RouteSpec(prefix="10.20.0.0/29", next_hop=OTHER),
    ]
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    details = exc.value.details or {}
    assert details["affected_lease_ids"] == [lease["lease_id"]]
    assert details["affected_segments"] == []  # target itself is fine
    assert store.pool_info()["cidr"] == "10.20.0.0/29"
    # The lease is untouched.
    assert store.get_lease(lease["lease_id"])["status"] == "active"


def test_guarded_switch_ignores_expired_lease(store: Store, clock) -> None:
    expired, _ = store.acquire("client-a", ttl_seconds=60)
    clock.advance(61)
    table = [RouteSpec(prefix="10.40.0.0/28", next_hop=BRANCH)]
    result = store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    assert result["changed"] is True
    assert result["validated"]["checked_leases"] == 0
    assert store.get_lease(expired["lease_id"])["status"] == "expired"


def test_guarded_switch_rejects_released_lease_address(store: Store) -> None:
    lease, _ = store.acquire("client-a")
    store.release(lease["lease_id"])
    table = [RouteSpec(prefix="10.40.0.0/28", next_hop=BRANCH)]
    result = store.guarded_switch_pool("10.40.0.0/28", BRANCH, table)
    assert result["changed"] is True
    assert result["validated"]["affected_lease_ids"] == []


def test_guarded_switch_same_pool_still_validates(store: Store) -> None:
    store.acquire("client-a")
    table = default_to_branch()
    result = store.guarded_switch_pool("10.20.0.0/29", BRANCH, table)
    assert result["changed"] is False
    assert result["changed_at"] is None

    blocked = default_to_branch(RouteSpec(prefix="10.20.0.0/29", discard=True))
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.20.0.0/29", BRANCH, blocked)
    assert exc.value.code == "switch_blocked"
    assert exc.value.details["affected_lease_ids"]


def test_target_pool_validation_is_not_enumeration(store: Store) -> None:
    """A huge target pool must validate using prefixes, not per-address work."""
    result = store.guarded_switch_pool("0.0.0.0/0", BRANCH, default_to_branch())
    assert result["changed"] is True
    assert result["validated"]["target_usable_addresses"] == 2**32 - 2
    assert result["usable_addresses"] == 2**32 - 2


def test_guarded_switch_invalid_pool_keeps_previous(store: Store) -> None:
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/33", BRANCH, default_to_branch())
    assert (exc.value.status_code, exc.value.code) == (422, "invalid_pool")
    assert store.pool_info()["cidr"] == "10.20.0.0/29"


@pytest.mark.parametrize(
    ("next_hop", "specs", "code"),
    [
        ("nope", [RouteSpec(prefix="0.0.0.0/0", next_hop=BRANCH)], "invalid_next_hop"),
        (BRANCH, [RouteSpec(prefix="0.0.0.0/0")], "invalid_routes"),
        (BRANCH, [RouteSpec(prefix="0.0.0.0/0", next_hop="999.1.1.1")], "invalid_routes"),
        (
            BRANCH,
            [RouteSpec(prefix="10.40.0.0/28", next_hop=BRANCH),
             RouteSpec(prefix="10.40.0.1/28", next_hop=BRANCH)],
            "invalid_routes",
        ),
    ],
)
def test_guarded_switch_invalid_inputs_are_422(
    store: Store, next_hop: str, specs: list[RouteSpec], code: str
) -> None:
    with pytest.raises(LeaseError) as exc:
        store.guarded_switch_pool("10.40.0.0/28", next_hop, specs)
    assert (exc.value.status_code, exc.value.code) == (422, code)
    assert store.pool_info()["cidr"] == "10.20.0.0/29"


def test_guarded_switch_is_atomic_on_failure(store: Store) -> None:
    import sqlite3

    conn = store._connect()
    try:
        conn.executescript(
            """
            CREATE TRIGGER fail_pool_change
            BEFORE INSERT ON pool_changes
            BEGIN
                SELECT RAISE(ABORT, 'simulated disk failure');
            END;
            """
        )
    finally:
        conn.close()
    with pytest.raises(sqlite3.IntegrityError):
        store.guarded_switch_pool("10.40.0.0/28", BRANCH, default_to_branch())
    assert store.pool_info()["cidr"] == "10.20.0.0/29"


def test_guarded_switch_migrates_old_pool_changes_schema(tmp_path) -> None:
    """A database created before the guarded switch still upgrades on start."""
    import sqlite3

    db = str(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    try:
        conn.executescript(
            """
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO settings(key, value) VALUES ('current_pool', '10.20.0.0/29');
            CREATE TABLE pool_changes (
                change_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                previous_cidr TEXT,
                new_cidr      TEXT NOT NULL,
                changed_at    REAL NOT NULL
            );
            """
        )
    finally:
        conn.close()

    store = Store(Settings(db_path=db, default_pool_cidr="10.20.0.0/29"))
    store.initialize()
    result = store.guarded_switch_pool("10.40.0.0/28", BRANCH, default_to_branch())
    assert result["changed"] is True
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT branch_next_hop, table_routes FROM pool_changes"
        ).fetchone()
    finally:
        conn.close()
    assert row == (BRANCH, 1)


# -------------------------------------------------------------------- API


def test_api_guarded_switch_allow(client: TestClient) -> None:
    lease = client.post("/v1/leases", json={"client_id": "a"}).json()
    response = client.put(
        "/v1/pool/guarded",
        json={
            "cidr": "10.40.0.0/28",
            "next_hop": BRANCH,
            "routes": [
                {"prefix": "10.0.0.0/8", "next_hop": BRANCH},
                {"prefix": "10.20.0.0/16", "discard": True},
            ],
        },
    )
    # The live lease 10.20.0.1 is discarded -> rejected.
    assert response.status_code == 409
    body = response.json()["error"]
    assert body["code"] == "switch_blocked"
    assert body["details"]["affected_lease_ids"] == [lease["lease_id"]]
    assert body["details"]["affected_segments"] == []

    allowed = client.put(
        "/v1/pool/guarded",
        json={
            "cidr": "10.40.0.0/28",
            "next_hop": BRANCH,
            "routes": [{"prefix": "10.0.0.0/8", "next_hop": BRANCH}],
        },
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload["changed"] is True
    assert payload["cidr"] == "10.40.0.0/28"
    assert payload["validated"]["checked_leases"] == 1
    assert client.get("/health").json()["pool"] == "10.40.0.0/28"


def test_api_guarded_switch_reject_reports_segments(client: TestClient) -> None:
    response = client.put(
        "/v1/pool/guarded",
        json={
            "cidr": "10.40.0.0/28",
            "next_hop": BRANCH,
            "routes": [
                {"prefix": "10.0.0.0/8", "next_hop": BRANCH},
                {"prefix": "10.40.0.4/30", "next_hop": OTHER},
            ],
        },
    )
    assert response.status_code == 409
    details = response.json()["error"]["details"]
    assert details["affected_segments"] == ["10.40.0.4/30"]
    assert details["affected_address_count"] == 4
    assert client.get("/v1/pool").json()["cidr"] == "10.20.0.0/29"


def test_api_guarded_switch_auth_and_validation(client: TestClient, tmp_path) -> None:
    settings = Settings(
        db_path=str(tmp_path / "guarded.db"),
        default_pool_cidr="10.20.0.0/29",
        operator_token="s3cret",
    )
    with TestClient(create_app(settings, store=Store(settings))) as locked:
        body = {
            "cidr": "10.40.0.0/28",
            "next_hop": BRANCH,
            "routes": [{"prefix": "0.0.0.0/0", "next_hop": BRANCH}],
        }
        assert locked.put("/v1/pool/guarded", json=body).status_code == 401
        assert (
            locked.put(
                "/v1/pool/guarded", json=body, headers={"X-Operator-Token": "bad"}
            ).status_code
            == 401
        )
        ok = locked.put(
            "/v1/pool/guarded", json=body, headers={"X-Operator-Token": "s3cret"}
        )
        assert ok.status_code == 200
        # Schema validation shares the uniform envelope.
        bad = locked.put(
            "/v1/pool/guarded",
            json={**body, "bogus": 1},
            headers={"X-Operator-Token": "s3cret"},
        )
        assert bad.status_code == 422
        assert bad.json()["error"]["code"] == "invalid_request"
        # An empty (omitted) table is structurally valid but routes nothing.
        empty = locked.put(
            "/v1/pool/guarded",
            json={"cidr": "10.40.0.0/28", "next_hop": BRANCH},
            headers={"X-Operator-Token": "s3cret"},
        )
        assert empty.status_code == 409
        assert empty.json()["error"]["details"]["affected_address_count"] == 14


def test_api_guarded_switch_rejects_more_than_128_routes(client: TestClient) -> None:
    routes_payload = [
        {"prefix": f"10.{i}.0.0/16", "next_hop": BRANCH} for i in range(129)
    ]
    response = client.put(
        "/v1/pool/guarded",
        json={"cidr": "10.40.0.0/28", "next_hop": BRANCH, "routes": routes_payload},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_route_lookup_matches_brute_force_for_random_tables() -> None:
    """Cross-check interval subtraction against address-by-address LPM."""
    import random

    rng = random.Random(20261121)
    for _ in range(40):
        specs: list[RouteSpec] = []
        used: set[ipaddress.IPv4Network] = set()
        for _ in range(rng.randint(1, 8)):
            prefixlen = rng.randint(24, 32)
            host = rng.getrandbits(32) & (0xFFFFFFFF << (32 - prefixlen))
            network = ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(host)}/{prefixlen}", strict=False
            )
            if network in used:
                continue
            used.add(network)
            hop = rng.choice([BRANCH, OTHER, None])
            specs.append(
                RouteSpec(prefix=str(network), next_hop=hop, discard=hop is None)
            )
        table = routing.parse_table(specs)
        branch_hop = ipaddress.IPv4Address(BRANCH)
        segments, count = table.uncovered_segments(
            int(ipaddress.IPv4Address("10.0.0.0")),
            int(ipaddress.IPv4Address("10.0.0.255")),
            branch_hop,
        )
        brute = sum(
            1
            for offset in range(256)
            if not table.points_to(ipaddress.IPv4Address(
                int(ipaddress.IPv4Address("10.0.0.0")) + offset), branch_hop)
        )
        assert count == brute
        # The summarised segments reproduce exactly the uncovered addresses.
        covered = sum(segment.num_addresses for segment in segments)
        assert covered == brute
