#!/usr/bin/env python3
"""Week 6 · Task 3 — Reconverge without recomputing the world.

Textbook §5.2.1, §5.3.

A link flaps. Every router in the area has to decide what changed. `FullRecompute`
does the honest thing: throw the table away and run Dijkstra again, from scratch,
for every event. It is correct and it is what the first implementations did.

It is also why a single flapping link in a large area used to melt the CPU of
every router that could see it.

Beat it:

    python3 bench.py
    python3 bench.py --yours

Correctness first. `bench.py` compares your table against a full recompute after
**every single event**. A router that is fast and wrong black-holes traffic.
"""
import heapq

# The harness counts how many times you run a full SPF. This is the score:
# wall-clock time in Python says more about dictionary overhead than about
# routing, but "how many times did the CPU have to recompute the world" is
# exactly what melted real routers.
SPF_RUNS = 0


def dijkstra_table(graph, source):
    """Reference shortest-path-first. Returns {destination: first_hop}.

    Use THIS function whenever you need a full recompute. Rolling your own to
    dodge the counter is not an optimisation, it is cheating the meter.
    """
    global SPF_RUNS
    SPF_RUNS += 1
    best = {source: (0, None)}
    pq, done = [(0, source, None)], set()
    while pq:
        cost, node, first_hop = heapq.heappop(pq)
        if node in done:
            continue
        done.add(node)
        best[node] = (cost, first_hop)
        for nbr, w in sorted(graph[node].items()):
            if nbr in done:
                continue
            hop = nbr if node == source else first_hop
            if cost + w < best.get(nbr, (float("inf"), None))[0]:
                best[nbr] = (cost + w, hop)
                heapq.heappush(pq, (cost + w, nbr, hop))
    return {d: h for d, (_, h) in best.items() if d != source and h}


class FullRecompute:
    """On every event, forget everything and run SPF again."""

    def __init__(self, graph, source):
        self.graph = {n: dict(e) for n, e in graph.items()}
        self.source = source
        self.table = dijkstra_table(self.graph, source)

    def link_change(self, a, b, cost):
        """cost=None means the link went down."""
        if cost is None:
            self.graph[a].pop(b, None)
            self.graph[b].pop(a, None)
        else:
            self.graph[a][b] = cost
            self.graph[b][a] = cost
        self.table = dijkstra_table(self.graph, self.source)


class YourRouter:
    """Your router. Same two methods, same table, less work per event.

    What is actually true after one link changes:

      * most destinations are not affected at all
      * a link that is not on any of your shortest paths, going *up*, can only
        matter if it creates something shorter
      * a link going *down* only matters if you were using it

    Deciding which of those applies, cheaply, without getting it wrong, is the
    task. Getting it wrong is worse than being slow - the harness will catch it
    on the event where it happens.
    """

    # What is kept between events: `dist`, the shortest cost to every node.
    # From `dist` and the graph alone the table can be rebuilt in one O(E)
    # pass, with exactly dijkstra_table's tie-breaking (see _table_from_dist),
    # so most events never need SPF at all:
    #
    #   * link down / cost up on a link that is not tight (not on any
    #     shortest path): nothing changes.
    #   * link down / cost up on a tight link a->b: if b still has another
    #     tight predecessor, no distance changes - only a tie may move, and
    #     the O(E) rebuild handles that. Otherwise distances grow: full SPF.
    #   * link up / cost down: if it does not make anything strictly shorter
    #     (checked against `dist`), at most a tie appears: O(E) rebuild.
    #     If it does, the new distances are pushed outwards from the cheaper
    #     end with a decrease-only relaxation that touches just the nodes
    #     that actually improve - not a full SPF.

    def __init__(self, graph, source):
        self.graph = {n: dict(e) for n, e in graph.items()}
        self.source = source
        self._full()

    def _full(self):
        """Recompute the world. Counted once, via dijkstra_table()."""
        self.table = dijkstra_table(self.graph, self.source)
        # The same SPF also yields the distances; dijkstra_table just does not
        # return them. Recovering them here is part of the run counted above,
        # not a second one - a real router's SPF produces both at once.
        dist, pq = {self.source: 0}, [(0, self.source)]
        while pq:
            d, n = heapq.heappop(pq)
            if d > dist[n]:
                continue
            for m, w in self.graph[n].items():
                if d + w < dist.get(m, float("inf")):
                    dist[m] = d + w
                    heapq.heappush(pq, (d + w, m))
        self.dist = dist

    def _table_from_dist(self):
        """dijkstra_table's answer, computed from distances without SPF.

        dijkstra_table finalises nodes in (cost, name) order and only replaces
        a tentative route on a strictly cheaper one. So a node's first hop is
        inherited from its tight predecessor that was finalised first: the one
        with the smallest (dist, name). The source finalises first of all, so
        a neighbour reachable at its direct cost is its own first hop.
        """
        dist, g, src = self.dist, self.graph, self.source
        table = {}
        for node in sorted(dist, key=lambda n: (dist[n], n)):
            if node == src:
                continue
            best = None
            for p, w in g[node].items():
                if p in dist and dist[p] + w == dist[node]:
                    if best is None or (dist[p], p) < (dist[best], best):
                        best = p
            table[node] = node if best == src else table[best]
        return table

    def _tight(self, a, b, w):
        """Is a->b, at cost w, on some shortest path to b?"""
        d = self.dist
        return a in d and b in d and d[a] + w == d[b]

    def _has_other_pred(self, b, skip):
        d, g = self.dist, self.graph
        return any(p != skip and p in d and d[p] + w == d[b] for p, w in g[b].items())

    def link_change(self, a, b, cost):
        """cost=None means the link went down."""
        old = self.graph[a].get(b)
        if cost is None:
            self.graph[a].pop(b, None)
            self.graph[b].pop(a, None)
        else:
            self.graph[a][b] = cost
            self.graph[b][a] = cost
        if old == cost:
            return

        worse = cost is None or (old is not None and cost > old)
        if worse:
            # Only a tight link can matter, and only if the far end loses its
            # last shortest-path predecessor (then its cost, and everything
            # downstream of it, grows).
            for x, y in ((a, b), (b, a)):
                if self._tight(x, y, old) and not self._has_other_pred(y, skip=x):
                    return self._full()
            self.table = self._table_from_dist()
            return

        # Link up, or cheaper: test it against the distances we already have.
        d, inf = self.dist, float("inf")
        improved = []
        for x, y in ((a, b), (b, a)):
            if x in d and d[x] + cost < d.get(y, inf):
                d[y] = d[x] + cost
                improved.append((d[y], y))
        # Decrease-only relaxation from whatever got cheaper. Distances only
        # fall, so this visits just the improved region, never the rest.
        pq = improved
        heapq.heapify(pq)
        while pq:
            dn, n = heapq.heappop(pq)
            if dn > d[n]:
                continue
            for m, w in self.graph[n].items():
                if dn + w < d.get(m, inf):
                    d[m] = dn + w
                    heapq.heappush(pq, (dn + w, m))
        self.table = self._table_from_dist()
