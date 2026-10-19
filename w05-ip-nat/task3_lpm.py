#!/usr/bin/env python3
"""Week 5 · Task 3 — Make longest-prefix match fast.

Textbook §4.3.3.

`LinearTable` is correct and it is what you probably wrote in Task 1: keep the
prefixes in a list, check every one, remember the longest that matched. On six
entries that is fine. A real router holds close to a million, and it has to
answer while the packet is still in the buffer.

Beat it:

    python3 bench.py
    python3 bench.py --yours

Correctness first: `bench.py` checks every one of your answers against the
linear table. A fast router that forwards to the wrong next hop is not a
router, it is an outage.
"""


class LinearTable:
    """Correct, and slow in the obvious way."""

    def __init__(self):
        self.entries = []                     # (prefix_len, network, next_hop)

    def add(self, network, prefix_len, next_hop):
        self.entries.append((prefix_len, network, next_hop))

    def lookup(self, address):
        best = None
        for plen, net, hop in self.entries:
            mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
            if address & mask == net and (best is None or plen > best[0]):
                best = (plen, hop)
        return best[1] if best else None


class YourTable:
    """Your table. Same three methods, same answers, fewer comparisons.

    Addresses and networks are plain 32-bit ints here - no strings, no parsing,
    so that the benchmark measures your lookup and nothing else.

    Two directions worth knowing about before you pick one:

      * group by prefix length. There are only 33 possible lengths, and you can
        ask them in an order that lets you stop early.
      * walk the address one bit at a time. Each bit takes you to at most one
        child, so the work is bounded by the address width, not by the table size.

    The second is what hardware does. The first is easier and often enough.
    Say which you chose and what it cost you in memory.
    """

    # Group by prefix length, then go one step further: controlled prefix
    # expansion. Every prefix of length 17-24 is rewritten as the /24s it
    # covers, and every prefix of length 1-16 as the /16s it covers. Then a
    # lookup is at most two dict probes - one for the /24 the address is in,
    # one for its /16 - plus the rare /25-/32 and the default route.
    #
    # Expansion must not let a shorter prefix overwrite a longer one, so
    # `_len24` / `_len16` remember the length that filled each slot. They are
    # only used while building; lookup touches the hop dicts alone.

    def __init__(self):
        self.t24, self._len24 = {}, {}     # addr >> 8  -> next hop, lengths 17-24
        self.t16, self._len16 = {}, {}     # addr >> 16 -> next hop, lengths 1-16
        self.long = {}          # prefix_len 25-32 -> {network: next_hop}
        self.default = None     # 0.0.0.0/0

    def add(self, network, prefix_len, next_hop):
        if prefix_len == 0:
            if self.default is None:
                self.default = next_hop
        elif prefix_len > 24:
            self.long.setdefault(prefix_len, {}).setdefault(network, next_hop)
        else:
            if prefix_len > 16:
                hops, lens, width = self.t24, self._len24, 24
            else:
                hops, lens, width = self.t16, self._len16, 16
            first = network >> (32 - width)
            for slot in range(first, first + (1 << (width - prefix_len))):
                # Strictly longer wins; on a tie the first add keeps the slot,
                # which is what LinearTable does with a duplicate prefix.
                if lens.get(slot, -1) < prefix_len:
                    lens[slot] = prefix_len
                    hops[slot] = next_hop

    def lookup(self, address):
        if self.long:           # empty in most tables, so this costs one test
            for plen in sorted(self.long, reverse=True):
                hop = self.long[plen].get(address & ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF))
                if hop is not None:
                    return hop
        hop = self.t24.get(address >> 8)
        if hop is None:
            hop = self.t16.get(address >> 16, self.default)
        return hop
