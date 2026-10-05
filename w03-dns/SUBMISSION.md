# 제출 파일 안내

이 폴더 전체를 본인 저장소의 `w03-dns/`에 넣고 커밋하면 됩니다. LMS 업로드와 GitHub push는 수행하지 않았습니다. 제출 대상은 커밋된 본인 저장소 URL입니다.

필수 결과는 `out/observation.md`, `out/report.md`, `out/chains.json`, `out/bench.txt`, `out/dns.pcapng`입니다. 코드는 세 task 파일에 있으며 `bench.py`와 `test_tasks.py`는 제공본을 수정하지 않았습니다.

## 실행

Python 3 환경에서:

```text
python -m pip install -r requirements.txt
python task1_resolve.py --verify
python task2_steering.py --report
python bench.py --yours
python verify_extra.py
python test_tasks.py
python ../check.py w03
```

Windows의 `python`을 macOS/Linux에서는 `python3`로 바꿀 수 있습니다. 원래 강의 저장소의 checker를 사용할 때는 `check.py`가 w03-dns의 상위 폴더에 있어야 합니다.

재측정할 때는 실제 네트워크를 바꾼 후 `python task2_steering.py --collect --label home-wifi` 또는 `--label phone-hotspot`을 실행합니다. 다중 연결에서는 `--source-ip`와 `--system-dns`로 해당 인터페이스의 실제 IPv4/DNS를 지정합니다. 기존 같은 label은 갱신되므로 제출 결과를 보존하려면 먼저 복사하세요.

## 검증과 남은 제한

`out/validation.txt`에 공식 테스트·형식 검사·보충 검사의 실제 출력이 있습니다. dig/tshark 미설치로 공식 검사 일부가 SKIP이며, 별도로 dnspython 실측 대조 및 Scapy 캡처 판독을 수행했습니다. SKIP을 PASS로 바꾸지 않았습니다.

Part A는 공식 trace 경로 (B)입니다. 제공 공식 trace에는 NS 위임 응답이 없으므로 **A3의 위임 패킷 번호는 미충족**이고, 대신 실제 반복형 조회 로그를 근거로 비교했습니다. 완전히 충족하려면 Wireshark가 설치된 환경에서 직접 `port 53` 캡처 중 Task 1을 실행해 위임 응답과 A 응답을 확보하고 캡처 설명을 갱신해야 합니다. 그 외 두 네트워크의 72개 측정과 코드·보고서는 포함되어 있습니다.

저장소의 ignore 규칙이 캡처를 제외하면 `git add -f w03-dns/out/dns.pcapng`로 포함 여부를 확인하세요. `out/observation.md`는 실제 측정 근거를 요약한 초안이므로 내용을 읽고 자신의 이해와 일치하는지 확인한 뒤 제출하세요.
