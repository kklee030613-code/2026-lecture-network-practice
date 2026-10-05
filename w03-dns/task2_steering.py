#!/usr/bin/env python3
"""Week 3 · Task 2 — Does DNS actually steer you? Measure it.

Textbook §2.4.3 (records) and §2.5 (CDNs).

The lecture claims two things:

    (a) most large sites are served by a CDN, reached through a CNAME chain
    (b) DNS steers each user to a *nearby* replica

Both are testable from your laptop, and one of them is harder to prove than
the slide makes it look. Your job is to produce the evidence and a number.

    python3 task2_steering.py --collect        # gather the raw data
    python3 task2_steering.py --report         # your analysis

What you have to build
----------------------
1.  For each hostname in SITES, follow the CNAME chain to its end and record
    every hop. `--collect` should leave the raw data in out/chains.json.

2.  Decide, for each site, whether it is served by a **third party**.
    This is the hard part and there is no single right answer:

      - `www.microsoft.com` ends at `akamaiedge.net`     - clearly third party
      - `www.netflix.com`   stops inside `netflix.com`   - own CDN, not third party
      - some sites have no CNAME at all and still sit behind a CDN (anycast)
      - `foo.cloudfront.net` and `foo.s3.amazonaws.com` are both Amazon,
        but they are not the same service

    Write down the rule you used and **defend it in observation.md**. A rule
    that just compares the last two labels will be wrong on at least one of
    the sites below; find which, and say so.

3.  Ask **two different resolvers** for the same name and compare the
    addresses you get back. If DNS really steers by location, a CDN-hosted
    name should answer differently to resolvers sitting in different places.

        RESOLVERS below has your system resolver and two public ones.

    Report: of N CDN-hosted sites, how many returned a different address set
    from a different resolver? Claim (b) predicts most of them. Check it.

Pass condition
--------------
There is no fixed answer. You pass by producing, in out/report.md:

  - the table: site | chain length | final zone | third party? | your rule's verdict
  - the steering number: "X of N sites answered differently to a different resolver"
  - at least one site where your classification rule was wrong, and why
"""
import argparse, json, os, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

SITES = [
    "www.microsoft.com",     # Akamai, multi-hop
    "www.netflix.com",       # own CDN
    "www.adobe.com",
    "www.cnn.com",
    "www.apple.com",
    "www.korea.ac.kr",       # no CDN at all
    "www.stanford.edu",
    "www.bbc.co.uk",
    "www.spotify.com",
    "www.github.com",
    "www.wikipedia.org",
    "www.nytimes.com",
]

RESOLVERS = {
    "system": None,          # whatever is in your resolv.conf
    "google": "8.8.8.8",
    "quad9":  "9.9.9.9",
}


def query_chain(site, server, source_ip=None):
    import dns.resolver, dns.rdatatype
    import time
    resolver = dns.resolver.Resolver(configure=True)
    if server:
        resolver.nameservers = [server]
    resolver.timeout = 2
    resolver.lifetime = 5
    current = site.rstrip(".").lower()
    chain, records, seen = [], [], set()
    started = time.perf_counter()
    try:
        for _ in range(20):
            if current in seen:
                raise RuntimeError("CNAME cycle")
            seen.add(current)
            response = resolver.resolve(current, "CNAME", raise_on_no_answer=False, source=source_ip)
            records.append({"query": current, "type": "CNAME",
                            "response": response.response.to_text()})
            if response.rrset is None:
                break
            target = response.rrset[0].target.to_text().rstrip(".").lower()
            chain.append({"from": current, "to": target, "ttl": response.rrset.ttl})
            current = target
        else:
            raise RuntimeError("CNAME depth exceeded")
        answer = resolver.resolve(current, "A", source=source_ip)
        records.append({"query": current, "type": "A", "response": answer.response.to_text()})
        return {"status": "ok", "resolver_ips": resolver.nameservers, "source_ip": source_ip,
                "server_used": str(answer.nameserver), "chain": chain,
                "final_name": current, "addresses": sorted({r.address for r in answer}),
                "ttl": answer.rrset.ttl, "elapsed_ms": round((time.perf_counter()-started)*1000,2),
                "raw": records}
    except Exception as exc:
        return {"status": "error", "resolver_ips": resolver.nameservers, "chain": chain,
                "final_name": current, "addresses": [], "error": f"{type(exc).__name__}: {exc}",
                "raw": records}


def collect(label="network-1", source_ip=None, system_dns=None):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    path = os.path.join(OUT, "chains.json")
    data = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    timestamp = datetime.now(timezone.utc).isoformat()
    jobs = [(site, key, system_dns if key == "system" and system_dns else server)
            for site in SITES for key, server in RESOLVERS.items()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda job: query_chain(job[0], job[2], source_ip), jobs))
    for (site, key, _), result in zip(jobs, values):
        entry = data.setdefault(site, {"networks": {}})
        network = entry["networks"].setdefault(label, {"collected_at_utc": timestamp,"resolvers": {}})
        network["collected_at_utc"] = timestamp
        network["source_ip"] = source_ip
        network["resolvers"][key] = result
        print(label, site, key, result["status"], ",".join(result["addresses"]))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    return data


def report():
    from report_builder import build
    return build()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--collect", action="store_true")
    p.add_argument("--report", action="store_true")
    p.add_argument("--label", default="network-1", help="Actual network name; switch network before collecting again")
    p.add_argument("--source-ip", help="Bind queries to the measured interface IPv4 address")
    p.add_argument("--system-dns", help="DNS IPv4 configured on that interface, useful with multiple adapters")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.collect:
        collect(a.label, a.source_ip, a.system_dns)
    elif a.report:
        report()
    else:
        p.print_help()

