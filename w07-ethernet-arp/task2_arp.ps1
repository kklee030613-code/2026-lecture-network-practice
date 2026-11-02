# Week 7 Task 2 on Windows, no Wireshark needed. Run as Administrator.
#
#   powershell -ExecutionPolicy Bypass -File task2_arp.ps1
#
# Captures ARP with the built-in pktmon, empties the ARP cache, refills it,
# keeps capturing for one more minute (B4), then writes out/arp.pcapng.
$ErrorActionPreference = "Continue"
$out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force $out | Out-Null
$log = Join-Path $out "task2-run.log"
function Log($m) { "$(Get-Date -Format 'HH:mm:ss.fff')  $m" | Tee-Object -FilePath $log -Append }

$gw = (Get-NetIPConfiguration | Where-Object IPv4DefaultGateway | Select-Object -First 1).IPv4DefaultGateway.NextHop
Log "gateway $gw"

arp -a | Out-File -Encoding utf8 (Join-Path $out "arp-before.txt")
Log "A1 saved arp-before.txt"

pktmon filter remove | Out-Null
pktmon filter add ARP -d ARP | Out-Null
$etl = Join-Path $out "arp.etl"
pktmon start --capture --comp nics --pkt-size 0 --file-name $etl | Out-Null
Log "pktmon capture started (ARP only, NICs only)"

netsh interface ip delete arpcache | Out-Null
Log "ARP cache cleared"
arp -a | Out-File -Encoding utf8 (Join-Path $out "arp-cleared.txt")

Log "ping gateway"
ping -n 3 $gw | Out-Null
arp -a | Out-File -Encoding utf8 (Join-Path $out "arp-after-ping.txt")
Log "curl https://www.korea.ac.kr"
curl.exe -s -o NUL https://www.korea.ac.kr
arp -a | Out-File -Encoding utf8 (Join-Path $out "arp-after.txt")
Log "A1 saved arp-after.txt"

Log "capturing background ARP for 60 s (B4)"
Start-Sleep -Seconds 60

pktmon stop | Out-Null
pktmon etl2pcap $etl --out (Join-Path $out "arp.pcapng") | Out-Null
pktmon filter remove | Out-Null
Remove-Item $etl -ErrorAction SilentlyContinue
Log "done -> out/arp.pcapng"
