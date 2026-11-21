#!/usr/bin/env python3
"""Guarded pool switch demo, driven only through the public HTTP API.

Runs against a local uvicorn or inside the compose network:

    python3 scripts/demo_guarded.py
    BASE=http://lease-api:8000 OPERATOR_TOKEN=... python3 scripts/demo_guarded.py

It shows three refused switches (no route, explicit discard, live lease
pointing elsewhere) and then an accepted switch.  Safe to re-run: it uses a
unique client id and releases the lease it created.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("BASE", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("OPERATOR_TOKEN", "").strip()
BRANCH = "203.0.113.1"       # this branch's next hop (documentation range)
OTHER_HOP = "198.51.100.9"   # next hop of some other branch
RUN = str(os.getpid())
PREFERRED = os.environ.get("TARGET", "10.77.0.0/27")
FALLBACK = "10.66.0.0/27"

_leases: list[str] = []


def say(title: str) -> None:
    print(f"\n\033[1m== {title}\033[0m")


def api(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if TOKEN:
        request.add_header("X-Operator-Token", TOKEN)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = json.loads(exc.read() or b"{}")
    print(f"HTTP {status}")
    print(json.dumps(payload, indent=2))
    return status, payload


def guarded(target: str, routes: list[dict]) -> tuple[int, dict]:
    return api(
        "PUT",
        "/v1/pool/guarded",
        {"cidr": target, "next_hop": BRANCH, "routes": routes},
    )


def main() -> int:
    say("Health / current pool")
    _, health = api("GET", "/health")
    current = health.get("pool")
    target = PREFERRED if PREFERRED != current else FALLBACK
    print(f"current pool: {current}   target pool: {target}")

    say("A client holds a lease (this must never become unreachable)")
    _, lease = api(
        "POST",
        "/v1/leases",
        {"client_id": f"guard-demo-laptop-{RUN}", "ttl_seconds": 7200},
    )
    lease_id, lease_ip = lease["lease_id"], lease["ip"]
    _leases.append(lease_id)

    try:
        say(f"REFUSED 1: the table has no match for the target pool {target}")
        guarded(target, [])

        say("REFUSED 2: the first /28 inside the target pool is explicitly discarded")
        network = ipaddress.IPv4Network(target)
        discarded = network.subnets(new_prefix=min(28, network.prefixlen + 1))
        cut = str(next(iter(discarded)))
        guarded(
            target,
            [
                {"prefix": "0.0.0.0/0", "next_hop": BRANCH},
                {"prefix": cut, "discard": True},
            ],
        )

        say(f"REFUSED 3: target is routed here, but live lease {lease_ip} points elsewhere")
        guarded(
            target,
            [
                {"prefix": target, "next_hop": BRANCH},
                {"prefix": str(current), "next_hop": OTHER_HOP},
            ],
        )

        say("The old pool still serves after every refusal")
        api("GET", "/v1/pool")

        say("ALLOWED: headquarters routes everything back to this branch")
        status, _ = guarded(
            target, [{"prefix": "0.0.0.0/0", "next_hop": BRANCH}]
        )
        if status != 200:
            print("unexpected: switch was not accepted", file=sys.stderr)
            return 1

        say("New clients now come from the new pool")
        _, phone = api("POST", "/v1/leases", {"client_id": f"guard-demo-phone-{RUN}"})
        _leases.append(phone["lease_id"])

        say("The old lease is still valid and reported as out-of-pool (releasable)")
        api("GET", f"/v1/leases/{lease_id}")
        api("GET", "/v1/admin/out-of-pool")

        say("Second guarded switch to the same pool: validated, but a no-op")
        guarded(target, [{"prefix": "0.0.0.0/0", "next_hop": BRANCH}])

        say("The old pool's lease still keeps the branch honest: a table that "
            "drops it is refused even though the target pool is fully routed")
        guarded(
            target,
            [
                {"prefix": target, "next_hop": BRANCH},
                {"prefix": str(lease_ip) + "/32", "discard": True},
            ],
        )
    finally:
        say("Cleanup: release the demo leases")
        while _leases:
            try:
                api("POST", f"/v1/leases/{_leases.pop()}/release")
            except OSError:
                pass

    say("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
