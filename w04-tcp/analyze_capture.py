#!/usr/bin/env python3
"""Task 2 Part A helper: read the first TCP handshake out of a pcapng.

    python3 analyze_capture.py [file.pcapng]

Pure Python (no tshark needed). Prints A2-A5: the three handshake packets by
frame number, both raw initial sequence numbers, the SYN options, the scaled
receive window, and the bytes the sender actually had in flight.
"""
import os, socket, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def frames(path):
    """Yield (frame_no, seconds, link_bytes) for each packet in a pcapng."""
    data = open(path, "rb").read()
    off, n, endian, tsres = 0, 0, "<", {}
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:                       # section header
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if btype == 6:                                # enhanced packet block
            iface, hi, lo, cap = struct.unpack_from(endian + "IIII", data, off + 8)
            n += 1
            ts = ((hi << 32) | lo) / tsres.get(iface, 1e6)
            yield n, ts, data[off + 28:off + 28 + cap]
        elif btype == 1:                              # interface description
            idx = len(tsres)
            tsres[idx] = 1e6
            o = off + 16
            while o < off + blen - 4:
                code, ln = struct.unpack_from(endian + "HH", data, o)
                if code == 0:
                    break
                if code == 9:                         # if_tsresol
                    v = data[o + 4]
                    tsres[idx] = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                o += 4 + (ln + 3) // 4 * 4
        off += blen


def tcp_packets(path):
    for n, ts, pkt in frames(path):
        if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
            continue                                   # IPv4 over Ethernet only
        ip = pkt[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6:
            continue
        total = struct.unpack("!H", ip[2:4])[0]
        t = ip[ihl:]
        sport, dport, seq, ack, offflags, win = struct.unpack("!HHIIHH", t[:16])
        doff = (offflags >> 12) * 4
        flags = offflags & 0x1FF
        opts, o = {}, 20
        while o < doff:
            kind = t[o]
            if kind == 0:
                break
            if kind == 1:
                o += 1
                continue
            ln = t[o + 1]
            if kind == 2:
                opts["mss"] = struct.unpack("!H", t[o + 2:o + 4])[0]
            elif kind == 3:
                opts["wscale"] = t[o + 2]
            elif kind == 4:
                opts["sack_perm"] = True
            o += ln
        yield dict(n=n, ts=ts, src=socket.inet_ntoa(ip[12:16]), dst=socket.inet_ntoa(ip[16:20]),
                   sport=sport, dport=dport, seq=seq, ack=ack, win=win, opts=opts,
                   syn=bool(flags & 2), is_ack=bool(flags & 16), fin=bool(flags & 1),
                   length=total - ihl - doff)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out", "tcp.pcapng")
    pkts = list(tcp_packets(path))
    syn = next(p for p in pkts if p["syn"] and not p["is_ack"])
    c, s = (syn["src"], syn["sport"]), (syn["dst"], syn["dport"])
    conn = [p for p in pkts if {(p["src"], p["sport"]), (p["dst"], p["dport"])} == {c, s}]
    sa = next(p for p in conn if p["syn"] and p["is_ack"])
    ack = next(p for p in conn if (p["src"], p["sport"]) == c and not p["syn"] and p["is_ack"])

    print(f"connection {c[0]}:{c[1]} -> {s[0]}:{s[1]}   ({len(conn)} packets)\n")
    for name, p in [("SYN", syn), ("SYN-ACK", sa), ("ACK", ack)]:
        print(f"  {name:8} frame #{p['n']:<4} t={p['ts'] - syn['ts']:.6f}s  "
              f"seq(raw)={p['seq']:<10} ack(raw)={p['ack'] if p['is_ack'] else '-'}")
    for name, p in [("SYN", syn), ("SYN-ACK", sa)]:
        o = p["opts"]
        print(f"  {name:8} options  MSS={o.get('mss')}  window scale shift={o.get('wscale')} "
              f"(x{2 ** o['wscale'] if 'wscale' in o else 1})  SACK_PERM={'yes' if o.get('sack_perm') else 'no'}  "
              f"raw window={p['win']}")

    # Scaling is in force only if both SYNs carried the option.
    both = "wscale" in syn["opts"] and "wscale" in sa["opts"]
    sh = {c: syn["opts"].get("wscale", 0) if both else 0, s: sa["opts"].get("wscale", 0) if both else 0}

    # Who carried the data? That side is the sender, the other the receiver.
    up = sum(p["length"] for p in conn if (p["src"], p["sport"]) == c)
    down = sum(p["length"] for p in conn if (p["src"], p["sport"]) == s)
    snd, rcv = (c, s) if up >= down else (s, c)
    rcv_wins = [p["win"] << sh[rcv] for p in conn
                if (p["src"], p["sport"]) == rcv and not p["syn"]]

    # Bytes in flight at each data segment = highest byte sent - highest byte acked.
    high_sent = high_ack = None
    flight = []
    for p in conn:
        if (p["src"], p["sport"]) == snd and p["length"] > 0:
            end = p["seq"] + p["length"]
            high_sent = end if high_sent is None else max(high_sent, end)
            if high_ack is not None:
                flight.append((p["n"], (high_sent - high_ack) % 2 ** 32))
        elif (p["src"], p["sport"]) == rcv and p["is_ack"]:
            high_ack = p["ack"] if high_ack is None else max(high_ack, p["ack"])
    hs = [p for p in conn if p is syn or p is sa]
    rtt = (sa["ts"] - syn["ts"]) * 1000
    data = [p for p in conn if (p["src"], p["sport"]) == snd and p["length"] > 0]
    dur = data[-1]["ts"] - data[0]["ts"] if len(data) > 1 else 0
    print(f"\n  data direction  {snd[0]} -> {rcv[0]}   {max(up, down):,} bytes "
          f"in {dur:.3f}s = {max(up, down) * 8 / dur / 1e6 if dur else 0:.2f} Mbps")
    print(f"  receiver advertised window (scaled x{2 ** sh[rcv]}): "
          f"min {min(rcv_wins):,} B, max {max(rcv_wins):,} B")
    print(f"  sender bytes in flight: max {max(f for _, f in flight):,} B "
          f"(frame #{max(flight, key=lambda x: x[1])[0]})")
    print(f"  SYN -> SYN-ACK at the client: {rtt:.1f} ms")


if __name__ == "__main__":
    main()
