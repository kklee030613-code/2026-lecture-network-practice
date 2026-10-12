# Week 4 · Observation

## Task 1 · Reliable delivery over a bad channel

- **프로토콜: Selective Repeat (window 16, 패킷별 타이머 6 step).** ACK는 `(누적 ACK, 받은 seq)` 쌍으로 보내 Go-Back-N의 누적 ACK와 SR의 개별 ACK를 같이 쓴다. 선택을 강제한 경우는 **손실된 ACK**: stop-and-wait(window 1)도 통과하지만 659 step이 걸렸고, SR은 99 step으로 같은 2,000 B를 보냈다. 또 데이터 1개만 유실돼도 GBN처럼 뒤의 15개를 전부 재전송하지 않으려면 수신 측 버퍼(재정렬 대비)와 개별 ACK가 필요했다.
- **비용:** 최소 250개(2000/8) 대비 seed 246에서 데이터 304개(1.22배)와 ACK 274개를 보냈다. 500개 seed에서 데이터 패킷은 중앙값 288개(269–317개)였고, 실패한 seed는 0개였다. 초과분은 손실 10%에 대한 재전송과, ACK 손실(역방향 10%) 때문에 이미 도착한 패킷을 다시 보낸 경우다.
- **처음 깨진 것: 재정렬 + 중복.** 도착 순서대로 붙이는 naive 수신기는 1,816 B만 조립했고 결과는 CORRUPTED였다. 해결책은 seq를 키로 한 버퍼에 `seq >= expected and seq not in buffer`일 때만 넣고, `expected`부터 연속 구간만 출력하는 것이다. 중복 데이터는 무시하되 **ACK는 항상 다시 보낸다**(중복 데이터는 대개 내 ACK가 유실됐다는 뜻이다). 중복 ACK는 집합에 추가만 하므로 멱등이다.

## Task 2 · Measure your own link, twice

### Part A · Handshake — **경로 (B): 공식 trace 사용**

이 PC에는 Wireshark/Npcap이 없고 관리자 권한도 없어 직접 캡처할 수 없었다. 그래서 공식 trace `traces/tcp-wireshark-trace1-1.pcapng`(9판)를 사용했다. 값은 직접 작성한 pcapng 파서 `analyze_capture.py`로 뽑았고 Wireshark 화면으로도 확인할 수 있다.

- **A2:** **SYN #1**, **SYN-ACK #2**, **ACK #3** (`192.168.86.68:55639 → 128.119.245.12:80`). SYN→SYN-ACK 간격은 22.4 ms(= 클라이언트에서 본 RTT 1회)였다.
- **A3 ISN (raw):** client **4,236,649,187**, server **1,068,969,752**. 둘 다 0이 아니고 서로 다르다. SYN-ACK의 ack = 4,236,649,188(client ISN+1), 마지막 ACK의 ack = 1,068,969,753(server ISN+1)이므로 SYN이 1바이트 seq를 소비한다는 것도 확인된다. 0에서 시작하지 않는 이유는 두 가지다. (1) 같은 4-tuple을 재사용한 이전 연결의 지연 세그먼트가 새 연결의 유효 seq 범위에 들어오는 것을 막기 위해서이고, (2) off-path 공격자가 seq를 맞혀 RST나 데이터를 주입하지 못하게 하기 위해서다(RFC 6528: 시계 + 4-tuple 해시). 양쪽이 각자 독립적으로 고르기 때문에 서로 다르다. Wireshark의 "relative seq 0"은 표시용이다.
- **A4 SYN 옵션:** client SYN은 **MSS 1460**(이더넷 MTU 1500 − IP 20 − TCP 20), **window scale shift 6 (×64)**, **SACK permitted**였다. server SYN-ACK은 MSS 1460, **shift 7 (×128)**, SACK permitted였다. 양쪽 모두 옵션을 냈으므로 스케일링이 적용된다.
- **A5:** 데이터는 client→server 방향(업로드 153,425 B)이므로 수신자는 서버다. 서버가 광고한 윈도우는 raw 값 × 128로, 272 × 128 = **34,816 B**에서 시작해 최대 1,522 × 128 = **194,816 B**까지 커졌다. 그런데 클라이언트의 bytes in flight는 최대 **75,296 B**(frame #145, 이때 rwnd 173,824 B)로, rwnd의 절반도 채우지 못했다. in-flight는 4,344 → 13,032 → 26,064 → 44,888 → 75,296 B로 RTT마다 거의 두 배가 됐다. 이는 **slow start 중인 cwnd**이고, 153 KB 파일이 그 단계에서 다 끝났다(0.19 s). 즉 한계는 rwnd가 아니라 **cwnd와 RTT(약 22 ms)**였다.
- **누구의 전송인가 (경로 B 추가 질문):** 출발지 192.168.86.68은 사설 주소(Google Wifi 기본 대역)로 NAT 뒤의 가정망이다. frame #4의 HTTP 헤더는 `POST /wireshark-labs/lab3-1-reply.htm`, `Host: gaia.cs.umass.edu`, `User-Agent: … Macintosh; Intel Mac OS X 10.15 … Firefox/85.0`이고, 본문은 *Alice in Wonderland*(alice.txt)이다. 캡처 시각은 2021-02-03 02:43 UTC다. 즉 2021년 2월 교재 저자 측이 Mac Firefox로 랩 페이지에 alice.txt를 업로드한 기록이다. Windows를 쓰는 내 PC, 내 IP, 2026년과는 하나도 맞지 않으므로 캡처만 보고도 내 트래픽이 아님을 알 수 있다.

> Wireshark lab trace files from J.F. Kurose and K.W. Ross, *Computer Networking: A Top-Down Approach*, 9th ed. <https://gaia.cs.umass.edu/kurose_ross/> Copyright 1996-2025 J.F. Kurose, K.W. Ross. All Rights Reserved.

### Part B · Throughput (`out/throughput.json`, target = speed.cloudflare.com 5 MB)

| network | median | min – max (spread) | median handshake |
|---|---|---|---|
| campus wifi (KUWIFI, 802.11ac 866 Mbps link) | **160.9 Mbps** | 99.4 – 168.8 (43%) | **13.6 ms** |
| tethering (iPhone hotspot → cellular) | **81.9 Mbps** | 61.5 – 94.7 (40%) | **37.8 ms** (25.7 – 53.1) |

측정 시각: campus 2026-10-12 17:55, tethering 18:05. 같은 노트북에서 10분 간격으로, 같은 Cloudflare 대상에 측정했다.

- **B4 spread:** 두 네트워크 모두 1회차가 가장 느렸다(campus 99 Mbps, TTFB 208 ms / tethering 61.5 Mbps, DNS 115 ms). 첫 연결은 DNS 캐시 미스, TLS 세션 재사용 불가, 무선 절전 상태에서의 복귀가 겹친다. 1회차를 빼면 campus는 150–169 Mbps(±6%)로 모였다. tethering은 82–95 Mbps로 여전히 흔들렸고 handshake도 25.7–53.1 ms로 2배 차이가 났다. 셀룰러 구간은 기지국 스케줄러가 매 순간 다른 사용자들과 무선 자원을 나누기 때문에 RTT 자체가 흔들린다. campus의 변동은 공유 Wi-Fi 경쟁과 CDN 엣지 부하에서 온다.
- **B5 (mechanism = slow start, 처리율 ≈ cwnd / RTT):** tethering의 handshake(≈1 RTT)는 campus의 **2.8배**(37.8 vs 13.6 ms)이고, 처리율은 **절반**(81.9 vs 160.9 Mbps)이다. TCP는 작은 cwnd(IW10 ≈ 14.6 KB)로 시작해 **RTT마다 두 배**로 늘린다. 5 MB를 다 보내려면 약 log₂(5 MB / 14.6 KB) ≈ 8.4번의 RTT가 slow start에만 쓰인다. 이 구간은 campus에서 약 115 ms, tethering에서 약 320 ms다. 전체 전송 시간(0.24 s vs 0.47 s)의 대부분이 이 구간이므로, 링크 용량과 무관하게 RTT가 긴 쪽이 처리율에서 진다. 감소폭(2.0배)이 RTT 비율(2.8배)보다 작은 것은 cwnd가 커진 뒤 셀룰러 링크 자체의 용량 한계에 닿는 구간도 섞여 있기 때문이다. 손실 후 AIMD 회복(+1 MSS/RTT)도 RTT에 비례해 느려진다. 그래서 handshake 시간과 처리율은 독립이 아니다.

## Task 3 · Beat the fixed window

```
baseline   goodput  986.8/1000 slots   loss  37.4%   retx  2340   avg queue   8.8
yours      goodput  953.8/1000 slots   loss   2.9%   retx   113   avg queue   4.6   -> 97%, strong
```

- **R5:** baseline이 goodput 1위인 이유는 큐를 항상 가득(8.8/10) 채워 두기 때문이다. 그 대가로 보낸 것의 37%를 버리고(재전송 2,340회), 링크를 같이 쓰는 모든 흐름에 약 9 slot의 큐잉 지연을 떠넘긴다. 이 링크에 나 혼자일 때만 1등이다. 같은 송신자가 둘만 있어도 서로의 패킷을 버리면서 재전송이 링크를 채운다. 1986년 congestion collapse가 정확히 이 모습이었다. 좋은 송신자는 "내 처리량"이 아니라 공유 자원에 대한 비용까지 포함해서 평가해야 한다.
- **수렴점:** slow start(첫 손실까지 ACK마다 +1) 후 AIMD(+1/RTT, 손실 시 ×0.7)로 동작하며, 후반부 window는 16.6–32 사이를 톱니 모양으로 오가고 평균은 **24.7**이다. 이는 BDP 20(1 pkt/slot × RTT 20) + 큐 약 4.6 = pipe + 큐 절반 정도다. 큐 30(=20+10)에 닿아 드롭이 나면 21로 내려가는데, 21은 여전히 BDP 이상이라 링크가 비지 않는다. 또 tail drop 한 번이 연속 타임아웃 여러 개로 보이므로 **window 하나 분량의 ACK마다 최대 한 번만 감소**시켰다(Reno의 fast recovery와 같은 아이디어). 이게 없으면 버스트 한 번에 window가 1까지 떨어진다.
- **backoff를 완화했을 때:** β를 바꿔 측정한 결과는 다음과 같다(같은 하네스).

  | β | goodput | loss | avg queue |
  |---|---|---|---|
  | 0.5 (Reno) | 851.5 | 2.1% | 3.0 |
  | 0.6 | 908.3 | 2.4% | 3.9 |
  | **0.7 (선택)** | **953.8** | **2.9%** | **4.6** |
  | 0.8 | 977.8 | 3.9% | 6.1 ✗ |
  | 0.9 | 977.8 | 7.6% ✗ | 8.2 ✗ |

  β=0.5는 window가 15까지 떨어져 BDP 20보다 작아지므로 링크가 놀고 goodput을 잃는다. β를 키울수록 goodput은 baseline에 가까워지지만 window가 큐 위에 머물러 큐 길이와 손실이 그대로 늘어난다. β=0.8부터 avg queue 5를 넘는다. 즉 완화된 backoff의 비용은 **다른 사용자에게 지연을 떠넘기는 것**이다. 최적점은 감소 후 window가 BDP 바로 위(0.7×30 ≈ 21 ≥ 20)에 떨어지는 지점이다.
