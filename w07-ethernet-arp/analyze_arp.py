#!/usr/bin/env python3
"""Task 2 Part B helper: list every ARP frame in a pcapng (no tshark needed).

    python3 analyze_arp.py [file.pcapng]

For each ARP frame: frame number, time, Ethernet src/dst MAC, opcode
(1 request, 2 reply), and the sender/target MAC and IP inside the ARP body.
Ends with the count per minute, for B4.
"""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def frames(path):
    """Yield (frame_no, seconds, link_bytes) for each packet in a pcapng."""
    data = open(path, "rb").read()
    off, n, endian = 0, 0, "<"
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if btype == 6:
            _, hi, lo, cap = struct.unpack_from(endian + "IIII", data, off + 8)
            n += 1
            yield n, ((hi << 32) | lo) / 1e6, data[off + 28:off + 28 + cap]
        off += blen


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def ip(b):
    return ".".join(str(x) for x in b)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out", "arp.pcapng")
    rows, total, t0, t_last = [], 0, None, None
    for n, ts, f in frames(path):
        total += 1
        t0 = ts if t0 is None else t0
        t_last = ts
        if f[12:14] != b"\x08\x06":
            continue
        a = f[14:]
        op = struct.unpack("!H", a[6:8])[0]
        rows.append((n, ts))
        print(f"#{n:<4} t={ts - t0:8.3f}s  eth {mac(f[6:12])} -> {mac(f[0:6])}  "
              f"{'REQUEST' if op == 1 else 'REPLY  ' if op == 2 else op}  "
              f"sender {ip(a[14:18])} ({mac(a[8:14])})  target {ip(a[24:28])} ({mac(a[18:24])})")
    span = (t_last - t0) if t0 is not None else 0
    print(f"\n{len(rows)} ARP frames of {total} total over {span:.1f} s"
          + (f"  = {len(rows) / span * 60:.1f} ARP frames/minute" if span else ""))


if __name__ == "__main__":
    main()
