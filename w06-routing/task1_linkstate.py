#!/usr/bin/env python3
"""Week 6 · Task 1 — Link state: build the forwarding table yourself.

Textbook §5.2 (link state and distance vector) and §5.3 (OSPF).

Every OSPF router ends up holding the same map of the network, and then each one
computes, alone, where to send a packet for every destination. The computation is
Dijkstra; the output is a forwarding table with **one next hop per destination**,
not a path.

That last part is what makes routing work without anybody carrying a route around
in the packet. Build it.

    python3 task1_linkstate.py --verify
"""
import argparse, heapq

# Undirected weighted graph: node -> {neighbour: cost}
TOPOLOGY = {
    "u": {"v": 2, "w": 5, "x": 1},
    "v": {"u": 2, "w": 3, "x": 2},
    "w": {"u": 5, "v": 3, "x": 3, "y": 1, "z": 5},
    "x": {"u": 1, "v": 2, "w": 3, "y": 1},
    "y": {"w": 1, "x": 1, "z": 2},
    "z": {"w": 5, "y": 2},
}


def dijkstra(graph, source):
    """Shortest path cost from `source` to every node.

    Return {node: cost}. Unreachable nodes must not appear.

    You write the loop. `heapq` is allowed; `networkx` is not.
    """
    return {n: c for n, (c, _) in _spf(graph, source).items() if n != source}


def _spf(graph, source):
    """Dijkstra that also remembers, for every node, the set of first hops
    that reach it at the shortest cost. {node: (cost, frozenset(first_hops))}

    Equal-cost paths are kept, not thrown away: when a second path arrives
    with the same cost, its first hops are added to the set. That set is the
    ECMP group a real router would install.
    """
    best = {source: (0, frozenset())}
    done = set()
    pq = [(0, source)]
    while pq:
        cost, node = heapq.heappop(pq)
        if node in done:
            continue
        done.add(node)
        hops = best[node][1]
        for nbr, w in graph.get(node, {}).items():
            if nbr in done:
                continue
            via = frozenset([nbr]) if node == source else hops
            new = cost + w
            old = best.get(nbr)
            if old is None or new < old[0]:
                best[nbr] = (new, via)
                heapq.heappush(pq, (new, nbr))
            elif new == old[0]:
                best[nbr] = (new, old[1] | via)     # a tie: keep both
    return best


def forwarding_table(graph, source):
    """What the router at `source` actually installs.

    Return {destination: first_hop}, where first_hop is a **direct neighbour**
    of `source` - the one interface a packet for that destination leaves by.

    The source itself is not in the table. Neither are unreachable nodes.

    The trap: it is easy to compute the full path and then take path[1]. That
    works, but think about what a router does when two shortest paths tie, and
    pick a rule. Say which in observation.md.
    """
    # Tie rule: of all first hops that lie on *some* shortest path, install
    # the one whose name sorts first. Deterministic, so every run and every
    # router builds the same table; a real router would install all of them
    # (ECMP) and hash flows across them.
    return {dest: min(hops) for dest, (_, hops) in _spf(graph, source).items()
            if dest != source and hops}


def link_down(graph, a, b):
    """A copy of `graph` with the link a-b removed, in both directions."""
    g = {n: dict(e) for n, e in graph.items()}
    g[a].pop(b, None)
    g[b].pop(a, None)
    return g


# ------------------------------------------------------------------- harness
# Costs from the textbook's worked example, §5.2.1
EXPECTED_COST_U = {"v": 2, "w": 3, "x": 1, "y": 2, "z": 4}
EXPECTED_TABLE_U = {"v": "v", "w": "x", "x": "x", "y": "x", "z": "x"}


def verify():
    fails = 0
    try:
        cost = dijkstra(TOPOLOGY, "u")
    except NotImplementedError:
        print("  dijkstra is still a stub"); return 1
    ok = cost == EXPECTED_COST_U
    print(f"  {'ok  ' if ok else 'FAIL'}  costs from u: {cost}")
    if not ok:
        print(f"        expected {EXPECTED_COST_U}")
    fails += not ok

    try:
        table = forwarding_table(TOPOLOGY, "u")
    except NotImplementedError:
        print("  forwarding_table is still a stub"); return 1
    ok = table == EXPECTED_TABLE_U
    print(f"  {'ok  ' if ok else 'FAIL'}  table at u:  {table}")
    if not ok:
        print(f"        expected {EXPECTED_TABLE_U}")
    fails += not ok

    # every node should be able to reach every other
    for n in TOPOLOGY:
        t = forwarding_table(TOPOLOGY, n)
        missing = set(TOPOLOGY) - {n} - set(t)
        bad = [d for d, h in t.items() if h not in TOPOLOGY[n]]
        ok = not missing and not bad
        print(f"  {'ok  ' if ok else 'FAIL'}  table at {n} covers all, hops are neighbours"
              + (f"  missing={missing} bad={bad}" if not ok else ""))
        fails += not ok

    # cutting a link must change somebody's mind
    cut = link_down(TOPOLOGY, "u", "x")
    after = forwarding_table(cut, "u")
    ok = after != table
    print(f"  {'ok  ' if ok else 'FAIL'}  u reroutes when u-x goes down: {after}")
    fails += not ok

    print(f"\n  {'all ok' if not fails else str(fails) + ' failed'}")
    return 1 if fails else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    raise SystemExit(verify() if a.verify else p.print_help())
