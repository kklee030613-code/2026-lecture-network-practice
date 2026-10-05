#!/usr/bin/env python3
"""Week 3 · Task 1 — Build your own iterative resolver.

Textbook §2.4.2 - §2.4.3.

`dig +trace` walks root -> TLD -> authoritative for you. In this task you do
that walk yourself: start at a root server, read the delegation it returns,
ask the next server, and keep going until somebody answers authoritatively.

You may shell out to `dig` for the transport, or use a DNS library
(`dnspython` is in the container). Either is fine - what matters is that
*you* follow the delegations rather than letting a tool do it.

    python3 task1_resolve.py www.korea.ac.kr
    python3 task1_resolve.py --verify        # check yourself against dig

Pass condition
--------------
`--verify` resolves five names with your resolver and with `dig`, and the
addresses must agree. A name behind a CDN may legitimately return a different
address each time; the harness compares the *set of authoritative nameservers*
you ended at for those, not the address.
"""
import argparse, subprocess, sys, shutil
import dns.name, dns.message, dns.query, dns.flags, dns.rdatatype, dns.rcode

# Root servers. Everything starts here; there is no earlier step.
ROOT_SERVERS = [
    "198.41.0.4",       # a.root-servers.net
    "199.9.14.201",     # b.root-servers.net
    "192.33.4.12",      # c.root-servers.net
]

# (name, kind).  "stable" names must match dig exactly.  "cdn" names are served
# from many replicas and may legitimately give you a different address than dig
# got a second earlier - for those we only require that you reached an answer.
VERIFY_NAMES = [
    ("www.korea.ac.kr", "stable"),
    ("dns.google", "stable"),
    ("en.wikipedia.org", "stable"),
    ("www.stanford.edu", "stable"),
    ("www.microsoft.com", "cdn"),
]


class Resolver:
    """IPv4 iterative resolver; RD is cleared on every transport query."""

    def __init__(self, timeout=1.5, max_depth=24, max_queries=150):
        self.timeout, self.max_depth, self.max_queries = timeout, max_depth, max_queries
        self.path, self.events, self.glueless = [], [], []
        self._ns_cache = {}

    def resolve(self, name):
        self.path, self.events, self.glueless = [], [], []
        self._ns_cache = {}
        result = self._walk(dns.name.from_text(name).canonicalize(), 0, frozenset())
        return result, list(self.path)

    def _ask(self, name, server):
        if len(self.path) >= self.max_queries:
            raise RuntimeError("global DNS query budget exceeded")
        self.path.append(server)
        q = dns.message.make_query(name, "A")
        q.flags &= ~dns.flags.RD
        event = {"name": name.to_text(), "server": server, "id": q.id, "rd": False}
        self.events.append(event)
        try:
            response = dns.query.udp(q, server, timeout=self.timeout)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(q, server, timeout=self.timeout)
                event["tcp_fallback"] = True
            event.update(rcode=dns.rcode.to_text(response.rcode()),
                         aa=bool(response.flags & dns.flags.AA),
                         answer=[r.to_text() for r in response.answer],
                         authority=[r.to_text() for r in response.authority],
                         additional=[r.to_text() for r in response.additional],
                         dns_bytes=len(response.to_wire()))
            return response
        except Exception as exc:
            event["error"] = f"{type(exc).__name__}: {exc}"
            raise

    def _walk(self, name, depth, active):
        if depth >= self.max_depth or name in active:
            raise RuntimeError("CNAME/NS cycle or recursion depth exceeded")
        active = active | {name}
        servers = list(ROOT_SERVERS)
        visited = set()
        zone = dns.name.root
        for _ in range(self.max_depth - depth):
            referral = None
            for server in servers:
                key = (name, server)
                if key in visited:
                    continue
                visited.add(key)
                try:
                    response = self._ask(name, server)
                except Exception:
                    if len(self.path) >= self.max_queries:
                        raise RuntimeError("global DNS query budget exceeded")
                    continue
                if response.rcode() == dns.rcode.NXDOMAIN and response.flags & dns.flags.AA:
                    raise LookupError(f"authoritative NXDOMAIN: {name}")
                if response.rcode() != dns.rcode.NOERROR:
                    continue
                # Follow an alias with a fresh root walk, even if target A is supplied.
                for rr in response.answer:
                    if rr.name == name and rr.rdtype == dns.rdatatype.CNAME:
                        return self._walk(rr[0].target.canonicalize(), depth + 1, active)
                if response.flags & dns.flags.AA:
                    for rr in response.answer:
                        if rr.name == name and rr.rdtype == dns.rdatatype.A:
                            return rr[0].address
                    if any(rr.rdtype == dns.rdatatype.SOA for rr in response.authority):
                        raise LookupError(f"authoritative NODATA (A): {name}")
                delegations = [rr for rr in response.authority
                               if rr.rdtype == dns.rdatatype.NS and name.is_subdomain(rr.name)
                               and rr.name != zone and rr.name.is_subdomain(zone)]
                if delegations:
                    referral = (response, max(delegations, key=lambda rr: len(rr.name.labels)))
                    break
            if referral is None:
                raise RuntimeError(f"no usable response for {name} at zone {zone}")
            response, ns_rr = referral
            zone = ns_rr.name
            ns_names = [r.target.canonicalize() for r in ns_rr]
            servers = []
            # Accept only addresses for the named NS, including root sibling glue.
            for rr in response.additional:
                if rr.rdtype == dns.rdatatype.A and rr.name in ns_names:
                    servers.extend(r.address for r in rr)
            if not servers:
                for ns in ns_names:
                    before = len(self.path)
                    try:
                        if ns not in self._ns_cache:
                            self._ns_cache[ns] = self._walk(ns, depth + 1, active)
                        servers.append(self._ns_cache[ns])
                    except (RuntimeError, LookupError):
                        continue
                    finally:
                        self.glueless.append({"zone": str(zone), "nameserver": str(ns),
                                              "extra_queries": len(self.path)-before})
                if not servers:
                    raise RuntimeError(f"no IPv4 nameserver address for {zone}")
            servers = list(dict.fromkeys(servers))
        raise RuntimeError("delegation depth exceeded")


# ------------------------------------------------------------------- harness
def dig_answer(name):
    """What the system resolver says, for comparison."""
    if not shutil.which("dig"):
        import dns.resolver
        return [r.address for r in dns.resolver.resolve(name, "A")]
    out = subprocess.run(["dig", "+short", name, "A"],
                         capture_output=True, text=True).stdout
    return [l for l in out.split() if l and l[0].isdigit()]


def verify():
    if not shutil.which("dig"):
        print("Reference: dnspython system recursive resolver (dig is not installed).")
        print("The iterative implementation itself never uses this recursive reference.")
    r, failures = Resolver(), 0
    for name, kind in VERIFY_NAMES:
        try:
            addr, path = r.resolve(name)
        except NotImplementedError:
            print("Nothing implemented yet - write Resolver.resolve first.")
            return 1
        except Exception as e:
            print(f"  FAIL  {name:<22} your resolver raised {e!r}")
            failures += 1
            continue
        expected = dig_answer(name)
        if addr in expected:
            note = ""
        elif kind == "cdn":
            note = "  <- differs, but this name is CDN-hosted. Explain it."
        else:
            note = "  <- should have matched"
            failures += 1
        print(f"  {'FAIL' if note.endswith('matched') else 'ok  '}  {name:<22} "
              f"you={addr:<16} reference={','.join(expected) or '-'}   "
              f"hops={len(path)}{note}")
    print(f"\n  {len(VERIFY_NAMES) - failures}/{len(VERIFY_NAMES)} ok")
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("name", nargs="?", default="www.korea.ac.kr")
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()

    if a.verify:
        sys.exit(verify())

    addr, path = Resolver().resolve(a.name)
    for i, server in enumerate(path, 1):
        print(f"  {i}. asked {server}")
    print(f"\n  {a.name} -> {addr}")


if __name__ == "__main__":
    main()


