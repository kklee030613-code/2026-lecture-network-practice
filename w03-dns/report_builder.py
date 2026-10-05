"""Rebuild the report from saved measurements; never invent missing measurements."""
import json
from pathlib import Path
from analyze_cache import analyze

HERE = Path(__file__).parent
OUT = HERE / 'out'
NETWORKS = ('home-wifi', 'phone-hotspot')
PROVIDERS = {
    'www.microsoft.com': ('예', 'Akamai'),
    'www.netflix.com': ('아니오', '자체 CDN (서비스 수준 분류)'),
    'www.adobe.com': ('예', 'Akamai'),
    'www.cnn.com': ('예', 'Fastly'),
    'www.apple.com': ('예', 'Akamai'),
    'www.korea.ac.kr': ('확인되지 않음', 'CDN 증거 없음'),
    'www.stanford.edu': ('예', 'Netlify'),
    'www.bbc.co.uk': ('예', 'Fastly'),
    'www.spotify.com': ('예', 'Fastly'),
    'www.github.com': ('확인되지 않음', '동일 운영 도메인; CDN 미확정'),
    'www.wikipedia.org': ('아니오', 'Wikimedia 자체 CDN'),
    'www.nytimes.com': ('예', 'Fastly'),
}


def last2(name):
    return '.'.join(name.rstrip('.').split('.')[-2:])


def build():
    data = json.loads((OUT / 'chains.json').read_text(encoding='utf-8'))
    cdn = [s for s, (_, provider) in PROVIDERS.items() if '증거 없음' not in provider and '미확정' not in provider]
    sets, rows = {}, []
    for site, entry in data.items():
        sets[site] = {}
        for network in NETWORKS:
            record = entry['networks'][network]
            for resolver in ('system', 'google', 'quad9'):
                r = record['resolvers'][resolver]
                if r['status'] != 'ok':
                    raise ValueError(f'Incomplete measurement: {site}/{network}/{resolver}')
                sets[site][network, resolver] = frozenset(r['addresses'])
                rows.append(f"| {network} | {site} | {resolver} | {len(r['chain'])} | {r['final_name']} | {', '.join(r['addresses'])} |")
    different = [s for s in cdn if len(set(sets[s].values())) > 1]
    resolver_diff = {n: [s for s in cdn if len({sets[s][n, r] for r in ('system', 'google', 'quad9')}) > 1] for n in NETWORKS}
    network_diff = [s for s in cdn if any(sets[s][NETWORKS[0], r] != sets[s][NETWORKS[1], r] for r in ('system', 'google', 'quad9'))]
    summary = {'cdn_sites': cdn, 'different_either': different, 'different_resolver': resolver_diff, 'different_network_same_resolver': network_diff}
    (OUT / 'steering-summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    lines = ['# Week 3 — DNS 계층 구조 및 CDN 실험 보고서', '',
             '## 측정 범위와 방법', '',
             '12개 사이트 × 3개 resolver × 2개 네트워크 = 72개 실측 레코드이다. 집 연결은 사용자 명칭 `home-wifi`, 휴대폰 핫스팟은 `phone-hotspot`으로 보존했다. 수집은 CNAME을 끝까지 따라간 후 최종 A 주소를 집합으로 비교했다. 반환 순서는 차이로 세지 않았다. 각 단계 원문 응답과 TTL은 `chains.json`, 모든 결과는 `measurement-table.md`에 있다.', '',
             '| 네트워크 | 수집 시작 UTC | system DNS 설정 |', '| --- | --- | --- |']
    first = next(iter(data.values()))
    for n in NETWORKS:
        e = first['networks'][n]
        lines.append(f"| {n} | {e['collected_at_utc']} | {', '.join(e['resolvers']['system']['resolver_ips'])} |")
    lines += ['', 'Google은 8.8.8.8, Quad9는 9.9.9.9이다. 최초 집 측정의 system은 dnspython이 읽은 Windows DNS 후보 목록이며 실제 응답한 서버 IP는 별도로 기록하지 못했다. 핫스팟에서는 다중 어댑터의 DNS가 섞이지 않도록 소스 172.20.10.2와 해당 어댑터 DNS 172.20.10.1을 지정했다. OS 확인 시 집 연결은 유선 어댑터 192.168.0.29도 연결되어 있었으며, Wi-Fi 핫스팟의 기본 경로 우선순위가 더 높았다. 네트워크의 이름은 사용자가 알려 준 연결 명칭이지 무선 매체를 입증하는 필드는 아니다.', '',
              '## Part B — Third-party 분류', '',
              '먼저 **원래 이름과 최종 이름의 마지막 두 label이 다르면 third party**라는 단순 규칙을 적용했다. 그 뒤 실제 운영 주체와 CDN 공급자의 공식 문서로 교정했다. 표의 final zone은 비교용 도메인 접미사이며 SOA로 검증한 DNS zone apex라는 뜻은 아니다. 체인 길이와 최종 이름은 집/system 기준이고 다른 측정은 전체 결과표에서 확인할 수 있다.', '',
              '| Site | CNAME chain length | Final zone | Third party? (교정) | 단순 규칙 verdict | 근거 / 서비스 |',
              '| --- | ---: | --- | --- | --- | --- |']
    for s, e in data.items():
        r = e['networks'][NETWORKS[0]]['resolvers']['system']
        zone = last2(r['final_name'])
        if r['final_name'].endswith('korea.ac.kr'):
            zone = 'korea.ac.kr'
        verdict, provider = PROVIDERS[s]
        lines.append(f"| {s} | {len(r['chain'])} | {zone} | {verdict} | {'예' if last2(s) != last2(r['final_name']) else '아니오'} | {provider} |")
    lines += ['', '**틀린 사례는 Wikipedia**다. `wikipedia.org → dyna.wikimedia.org`는 마지막 두 label이 달라 단순 규칙은 외부 업체라고 판정하지만, Wikimedia가 운영하는 자체 CDN이다. 또한 `co.uk`나 `ac.kr`는 등록 가능한 개별 조직의 도메인이 아니라 공용 접미사이므로 마지막 두 label만으로 소유권을 구별할 수 없다. CNAME이 없다는 것 역시 CDN이 없다는 증명이 아니다.', '',
              '공식 근거: [Akamai edge hostname](https://techdocs.akamai.com/property-mgr/reference/modify-property-hostnames), [Fastly DNS 라우팅](https://www.fastly.com/documentation/guides/concepts/routing-traffic-to-fastly/), [Netlify의 netlifyglobalcdn.com 지원 답변](https://answers.netlify.com/t/how-can-i-change-which-netlify-site-my-hostname-is-pointing-to/3259), [Wikimedia CDN 운영 문서](https://wikitech.wikimedia.org/wiki/CDN), [Netflix Open Connect 설명](https://openconnect.netflix.com/Open-Connect-Overview.pdf). 공급자 문서와 실제 관측한 CNAME suffix를 연결해 분류했으며 IP의 소유자만으로 CDN이라고 추정하지 않았다.', '',
              'Netflix의 Open Connect는 영상 전송망이다. `www.prod.ftl.netflix.com`이라는 홈페이지 종단이 영상 캐시 노드임을 이 DNS 결과만으로 증명하지는 못했다. 아래 N=10은 과제 예시처럼 Netflix를 자체 CDN 서비스로 포함한 사이트 수준 분모이다. 홈페이지 종단 증거에 한정하면 Netflix를 제외한 N=9도 함께 제시하는 것이 타당하다. GitHub의 단순 동일 도메인 alias와 고려대의 직접 A는 CDN 여부가 확정되지 않아 분모에서 제외했다.', '',
              '## Resolver / network steering', '',
              f"**{len(different)} of {len(cdn)} CDN-hosted sites answered differently to a different resolver or network.** 집 `home-wifi`와 휴대폰 `phone-hotspot`의 여섯 주소 집합 중 하나라도 다르면 1개 사이트로 셌다.", '',
              '| 비교 조건 | 다른 주소 집합을 보인 CDN 사이트 |', '| --- | ---: |',
              *[f'| {n} 내부 resolver 비교 | {len(resolver_diff[n])}/{len(cdn)} |' for n in NETWORKS],
              f'| 같은 resolver 이름으로 두 네트워크 비교 | {len(network_diff)}/{len(cdn)} |',
              f'| resolver 또는 network 어느 쪽이든 차이 | {len(different)}/{len(cdn)} |', '',
              '차이가 있었던 사이트: ' + ', '.join(different) + '.',
              '네트워크를 바꾼 비교에서 차이가 있었던 사이트: ' + (', '.join(network_diff) or '없음') + '.', '',
              f"Netflix를 제외한 종단 증거 기준으로는 {len([s for s in different if s != 'www.netflix.com'])}/9이다. 두 네트워크에서 system은 각 접속망의 DNS이므로 ‘system끼리’ 비교에는 resolver 변경도 포함된다. 네트워크 효과만 분리하려면 같은 공개 resolver 주소의 결과를 우선 비교해야 한다.", '',
              '주소 선택이 resolver나 관측 시점에 따라 달라진다는 증거는 있지만 **가까운 복제본으로 보냈다는 주장 (b)은 입증하지 못했다.** Anycast 공용 DNS 주소가 같아도 처리 지점은 다를 수 있으며, 8.8.8.8이나 9.9.9.9를 미국의 고정 서버라고 부를 수 없다. 순차 측정이므로 TTL·캐시·부하분산·시간에 따른 변경도 교란 요인이다. 서버 위치와 실제 연결 RTT를 함께 측정하고 여러 번 교차 반복해야 근접성 주장을 강화할 수 있다. `elapsed_ms`는 여러 DNS 질의의 합계이지 CDN 서버까지의 RTT가 아니다.', '',
              (OUT / 'capture-notes.md').read_text(encoding='utf-8'), '',
              '## Task 1 — 반복형 조회와 검증', '',
              '루트부터 시작하고 매번 RD=0으로 직접 UDP 질의를 보낸다. 응답이 잘리면 TCP로 다시 받는다. authority의 더 구체적인 NS 위임을 따라가고, NS의 A glue가 없으면 그 NS 이름을 루트부터 별도로 해결한다. CNAME은 대상 이름으로 루트 조회를 다시 시작한다. 서버별 timeout 후 다음 서버, 이름 cycle 검사, 최대 깊이 24와 전역 질의 예산 150으로 무한 탐색을 막았다. glue는 응답의 NS 이름에 해당하는 A만 사용하되 루트의 sibling glue도 허용한다. 교육용 구현이며 DNSSEC 검증이나 완전한 캐시 오염 방어 구현은 아니다.', '',
              '| 이름 | 반환 주소 | 질의 횟수 | 재귀 참조 주소 집합과 일치 |', '| --- | --- | ---: | --- |']
    for r in json.loads((OUT / 'resolver-live.json').read_text(encoding='utf-8')):
        lines.append(f"| {r['name']} | {r.get('address', '실패')} | {len(r['events'])} | {r.get('match', False)} |")
    lines += ['', '이 실측 다섯 건에는 glue 없는 위임이 나오지 않았다. 별도 제어 테스트에서 첫 루트 timeout 후 다음 루트로 이동하고, glue 없는 NS를 1회 추가 조회하여 최종 A에 도달함을 확인했다(전체 4회=실패 1+위임 1+NS 주소 1+최종 답 1). 이는 실제 인터넷에서 1회가 항상 충분하다는 주장이 아니다. 참조 대조에는 dig 미설치로 dnspython의 시스템 재귀 resolver를 사용했으며 반복형 구현 자체는 이 재귀 참조를 호출하지 않는다.', '',
              '## Task 3 — TTL cache와 최소 조회 수', '',
              'Baseline의 공통 원인은 실제 TTL을 버리고 60초로 고정하는 것이다. 짧은 TTL을 너무 오래 써서 정답성이 깨지고, 긴 TTL은 너무 일찍 버려 불필요한 외부 조회가 늘어난다. 리스트 전체 검색도 추가적인 CPU 비용이다. 개선안은 이름별 딕셔너리에 (주소, 만료시각)을 저장해 평균 O(1) 검색, O(고유 이름 수) 메모리를 사용한다. now가 만료시각과 같으면 갱신하고 TTL=0은 재사용하지 않는다.', '',
              '| 이름 | TTL(s) | Baseline upstream | 최소 upstream | Baseline stale |', '| --- | ---: | ---: | ---: | ---: |']
    cache = analyze()
    for r in cache['by_name']:
        lines.append(f"| {r['name']} | {r['ttl']} | {r['baseline_fetches']} | {r['minimum_fetches']} | {r['baseline_stale']} |")
    lines += ['', f"**하한은 {cache['floor']}회**다. 빈 캐시에서 각 이름의 최초 미충족 요청 시각 t에 받아 온 응답은 [t, t+TTL)만 덮는다. 다음 미충족 요청에는 새 조회가 필요하다. 최초 요청보다 먼저 조회해도 만료가 더 일러질 뿐이고, 최초 요청 시점보다 늦추면 그 요청을 올바르게 답할 수 없다. 이 교환 논증을 이름마다 반복하면 최초 미충족 요청에서만 갱신하는 방식이 최적이다. 위 표의 합 118+76+37+23+11+6+1+1+1+1=275를 더 낮출 수 없다. 전제는 TTL을 준수하고, 미리 채워진 캐시나 답을 하드코딩한 지식이 없으며, 주어진 인터페이스처럼 한 조회가 한 이름의 응답만 얻는다는 것이다. 단순 ceil(3600/TTL)의 합은 요청이 없는 구간까지 세므로 이 workload의 하한이 아니다.", '',
              '수정하지 않은 bench.py 결과: baseline 325 upstream / 67.5% hit / 266 stale / 6.5s, 개선안 275 / 72.5% / 0 / 5.5s. upstream은 약 15.4% 감소했다. 정답성 기준 최악은 microsoft.com(20초 TTL)으로 stale 189건이며 cnn.com의 77건과 합쳐 266건이다. 불필요한 조회의 절대 증가량 기준으로는 stanford.edu가 27회 대 최소 1회로 26회 낭비되어 ‘최악’의 의미를 구분해야 한다.', '',
              '재현: `python analyze_cache.py`, `python bench.py --yours`, `python verify_extra.py`, `python test_tasks.py`, `python ../check.py w03`. 테스트 결과와 실행 환경의 도구 부족 여부는 `validation.txt`를 확인한다.']
    (OUT / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    table = ['# 모든 DNS 측정', '', '| Network | Site | Resolver | CNAME hops | Final name | A set |', '| --- | --- | --- | ---: | --- | --- |', *rows]
    (OUT / 'measurement-table.md').write_text('\n'.join(table) + '\n', encoding='utf-8')
    print(f'Report rebuilt: {len(rows)} records; steering {len(different)}/{len(cdn)}; cache floor {cache["floor"]}.')


if __name__ == '__main__':
    build()
