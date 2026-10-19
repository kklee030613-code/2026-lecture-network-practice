#!/usr/bin/env python3
"""Task 2 Part C helper: list every DHCP message in a pcapng (no tshark needed).

    python3 analyze_dhcp.py [file.pcapng]

For each message: frame number, IP/UDP source and destination, the DHCP type,
transaction id, the broadcast flag, ciaddr/yiaddr, and the options that C2-C4
ask about (server id, requested address, lease time, T1/T2, mask, router).
"""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK",
         6: "NAK", 7: "Release", 8: "Inform"}


def frames(path):
    """Yield (frame_no, seconds, link_bytes) for each packet in a pcapng."""
    data = open(path, "rb").read()
    off, n, endian, tsres = 0, 0, "<", {}
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if btype == 6:
            iface, hi, lo, cap = struct.unpack_from(endian + "IIII", data, off + 8)
            n += 1
            yield n, ((hi << 32) | lo) / tsres.get(iface, 1e6), data[off + 28:off + 28 + cap]
        elif btype == 1:
            tsres[len(tsres)] = 1e6
        off += blen


def ip(b):
    return ".".join(str(x) for x in b)


def dhcp_messages(path):
    for n, ts, pkt in frames(path):
        if pkt[12:14] != b"\x08\x00":
            continue
        iph = pkt[14:]
        ihl = (iph[0] & 15) * 4
        if iph[9] != 17:
            continue
        udp = iph[ihl:]
        sport, dport = struct.unpack("!HH", udp[:4])
        if {sport, dport} - {67, 68}:
            continue
        b = udp[8:]
        flags = struct.unpack("!H", b[10:12])[0]
        msg = dict(n=n, ts=ts, src=ip(iph[12:16]), dst=ip(iph[16:20]), sport=sport, dport=dport,
                   xid=struct.unpack("!I", b[4:8])[0], broadcast=bool(flags & 0x8000),
                   ciaddr=ip(b[12:16]), yiaddr=ip(b[16:20]),
                   chaddr=":".join(f"{x:02x}" for x in b[28:34]), opts={})
        o = 240                                   # after the magic cookie
        while o < len(b) and b[o] != 255:
            if b[o] == 0:
                o += 1
                continue
            code, ln = b[o], b[o + 1]
            val = b[o + 2:o + 2 + ln]
            if code == 53:
                msg["type"] = TYPES.get(val[0], val[0])
            elif code in (51, 58, 59):
                msg["opts"][{51: "lease", 58: "T1", 59: "T2"}[code]] = struct.unpack("!I", val)[0]
            elif code in (1, 3, 50, 54):
                msg["opts"][{1: "mask", 3: "router", 50: "requested", 54: "server_id"}[code]] = ip(val[:4])
            o += 2 + ln
        yield msg


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out", "dhcp.pcapng")
    msgs = list(dhcp_messages(path))
    t0 = msgs[0]["ts"] if msgs else 0
    for m in msgs:
        print(f"#{m['n']:<4} t={m['ts'] - t0:8.3f}s  {m.get('type', '?'):<9} "
              f"{m['src']}:{m['sport']} -> {m['dst']}:{m['dport']}  xid=0x{m['xid']:08x}  "
              f"bcast_flag={int(m['broadcast'])}  ciaddr={m['ciaddr']} yiaddr={m['yiaddr']}  "
              f"chaddr={m['chaddr']}  {m['opts']}")


if __name__ == "__main__":
    main()
