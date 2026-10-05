"""Supplementary real DNS socket-PDU recording, NOT an interface capture.

Stores exact UDP payload bytes in Wireshark exported-PDU pcapng (linktype 252).
No Ethernet/IP/UDP headers are synthesized. Does not replace Part A's interface
capture requirement; useful to inspect real delegation packets when blocked.
Format: https://wiki.wireshark.org/Protocols/exported_pdu
"""
import json
import socket
import struct
import time
from pathlib import Path
from unittest.mock import patch
import dns.query, dns.message, dns.flags
from task1_resolve import Resolver


def main():
    out = Path(__file__).parent / 'out'
    records, payloads = [], []

    def record(data, source, destination, direction):
        when = time.time_ns() // 1000
        message = dns.message.from_wire(data)
        payloads.append((when, bytes(data)))
        records.append({'packet': len(records) + 1, 'timestamp_us': when,
                        'direction': direction, 'source': source, 'destination': destination,
                        'id': message.id, 'dns_bytes': len(data),
                        'response': bool(message.flags & dns.flags.QR),
                        'answer': [r.to_text() for r in message.answer],
                        'authority': [r.to_text() for r in message.authority],
                        'additional': [r.to_text() for r in message.additional]})

    class RecordingSocket(socket.socket):
        def sendto(self, data, *args):
            count = super().sendto(data, *args)
            record(data[:count], self.getsockname(), args[-1], 'sent')
            return count

        def recvfrom(self, *args):
            data, peer = super().recvfrom(*args)
            record(data, peer, self.getsockname(), 'received')
            return data, peer

    with patch.object(dns.query, 'socket_factory', RecordingSocket):
        address, path = Resolver().resolve('www.korea.ac.kr')

    def block(kind, body):
        body += b'\0' * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack('<II', kind, length) + body + struct.pack('<I', length)

    output = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    output += block(1, struct.pack('<HHI', 252, 0, 65535))
    for timestamp, data in payloads:
        # Dissector-name TLV (12, "dns\0"), end-of-options TLV, exact DNS bytes.
        pdu = struct.pack('!HH', 12, 4) + b'dns\0' + struct.pack('!HH', 0, 0) + data
        output += block(6, struct.pack('<IIIII', 0, timestamp >> 32,
                                     timestamp & 0xffffffff, len(pdu), len(pdu)) + pdu)
    (out / 'dns-socket.pcapng').write_bytes(output)
    (out / 'socket-capture.json').write_text(json.dumps({
        'method': 'Real socket sendto/recvfrom DNS payload recording; NOT interface capture; no synthetic link/network headers.',
        'address': address, 'path': path, 'packets': records}, indent=2) + '\n', encoding='utf-8')
    print(f'{len(records)} real DNS socket PDUs recorded; address={address}')
    for r in records:
        print(r['packet'], r['direction'], r['id'], r['dns_bytes'], r['answer'], r['authority'])


if __name__ == '__main__':
    main()
