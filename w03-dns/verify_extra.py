"""Offline edge cases, independent of the unmodified course harness."""
import unittest
from unittest.mock import patch
import dns.message, dns.flags, dns.rrset, dns.exception
from task1_resolve import Resolver, ROOT_SERVERS
from task3_cache import YourCache


def reply(q, answer=(), authority=(), additional=(), aa=False):
    r = dns.message.make_response(q)
    if aa:
        r.flags |= dns.flags.AA
    for section, records in ((r.answer, answer), (r.authority, authority), (r.additional, additional)):
        for name, kind, value in records:
            section.append(dns.rrset.from_text(name, 60, 'IN', kind, value))
    return r


class EdgeCases(unittest.TestCase):
    def test_glueless_and_timeout(self):
        seen = []
        def transport(q, server, timeout):
            name = str(q.question[0].name)
            self.assertFalse(q.flags & dns.flags.RD)
            seen.append((name, server))
            if server == ROOT_SERVERS[0] and name == 'www.example.':
                raise dns.exception.Timeout
            if server in ROOT_SERVERS:
                if name == 'ns.other.':
                    return reply(q, answer=[(name, 'A', '192.0.2.53')], aa=True)
                return reply(q, authority=[('example.', 'NS', 'ns.other.')])
            return reply(q, answer=[(name, 'A', '192.0.2.80')], aa=True)
        with patch('dns.query.udp', side_effect=transport):
            r = Resolver()
            address, path = r.resolve('www.example')
        self.assertEqual(address, '192.0.2.80')
        self.assertEqual(path, [ROOT_SERVERS[0], ROOT_SERVERS[1], ROOT_SERVERS[0], '192.0.2.53'])
        self.assertEqual(r.glueless[0]['extra_queries'], 1)

    def test_cname_restarts_at_root(self):
        def transport(q, server, timeout):
            name = str(q.question[0].name)
            self.assertEqual(server, ROOT_SERVERS[0])
            return reply(q, answer=[(name, 'CNAME', 'target.')], aa=True) if name == 'alias.' else reply(q, answer=[(name, 'A', '192.0.2.1')], aa=True)
        with patch('dns.query.udp', side_effect=transport):
            self.assertEqual(Resolver().resolve('alias'), ('192.0.2.1', [ROOT_SERVERS[0]] * 2))

    def test_cycle_is_bounded(self):
        def transport(q, server, timeout):
            name = str(q.question[0].name)
            return reply(q, answer=[(name, 'CNAME', 'b.' if name == 'a.' else 'a.')], aa=True)
        with patch('dns.query.udp', side_effect=transport):
            with self.assertRaises(RuntimeError):
                Resolver().resolve('a')

    def test_tcp_fallback(self):
        def truncated(q, server, timeout):
            r = reply(q); r.flags |= dns.flags.TC; return r
        def tcp(q, server, timeout):
            return reply(q, answer=[('a.', 'A', '192.0.2.9')], aa=True)
        with patch('dns.query.udp', side_effect=truncated), patch('dns.query.tcp', side_effect=tcp):
            self.assertEqual(Resolver().resolve('a')[0], '192.0.2.9')

    def test_ttl_boundary_and_changed_address(self):
        values = iter([('192.0.2.1', 10), ('192.0.2.2', 10)])
        c = YourCache(lambda _: next(values))
        self.assertEqual(c.lookup('a', 0), '192.0.2.1')
        self.assertEqual(c.lookup('a', 9.999), '192.0.2.1')
        self.assertEqual(c.lookup('a', 10), '192.0.2.2')
        self.assertEqual(c.stats()['misses'], 2)

    def test_zero_ttl(self):
        values = iter([('first', 0), ('second', 0)])
        c = YourCache(lambda _: next(values))
        self.assertEqual(c.lookup('a', 0), 'first')
        self.assertEqual(c.lookup('a', 0), 'second')
        self.assertEqual(c.stats()['entries'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
