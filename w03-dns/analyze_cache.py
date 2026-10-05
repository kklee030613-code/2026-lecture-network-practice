"""Independently count necessary TTL coverage intervals in the supplied workload."""
import json
from collections import Counter
from pathlib import Path
import bench
from task3_cache import BaselineCache


def analyze():
    minimum, expires = Counter(), {}
    # At the first uncovered request, a fetch covers [time, time + TTL).
    # Moving an earlier fetch to this request cannot reduce future coverage.
    for time, name in bench.workload():
        if time >= expires.get(name, float('-inf')):
            minimum[name] += 1
            expires[name] = time + bench.FIXTURE[name][1]
    upstream = bench.Upstream()
    baseline = BaselineCache(upstream)
    calls, stale, expires = Counter(), Counter(), {}
    for time, name in bench.workload():
        upstream.now = time
        before = upstream.calls
        baseline.lookup(name, time)
        if upstream.calls > before:
            calls[name] += 1
            expires[name] = time + bench.FIXTURE[name][1]
        elif time >= expires[name]:
            stale[name] += 1
    result = {'floor': sum(minimum.values()), 'by_name': [
        {'name': n, 'ttl': ttl, 'minimum_fetches': minimum[n],
         'baseline_fetches': calls[n], 'baseline_stale': stale[n]}
        for n, (_, ttl) in bench.FIXTURE.items()]}
    path = Path(__file__).parent / 'out' / 'cache-analysis.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    print(json.dumps(analyze(), indent=2))
