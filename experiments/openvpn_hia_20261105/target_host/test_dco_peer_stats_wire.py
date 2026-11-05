#!/usr/bin/env python3
"""Offline OVPN_CMD_PEER_GET protocol regression, exercising the real helper.

Run: python -m unittest -v test_dco_peer_stats_wire.py
This is a simulated netlink server, NOT a true kernel TUN/DCO acceptance test.
"""
import errno
import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'dco_peer_stats.py'
spec = importlib.util.spec_from_file_location('dco_peer_stats_under_test', SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FakeKernelNetlink:
    """Emulate the relevant ctrl/family + peer-dump framing only."""
    def __init__(self):
        self.sent = []
        self.pending = []
        self.reject_all = False

    def __enter__(self): return self
    def __exit__(self, *_): return False
    def bind(self, _address): pass
    def getsockname(self): return (100, 0)
    def settimeout(self, _seconds): pass

    @staticmethod
    def packet(family, seq, body, flags=0):
        return mod.NLHDR.pack(16 + len(body), family, flags, seq, 0) + body

    def send(self, packet):
        self.sent.append(packet)
        n, fam, flags, seq, pid = mod.NLHDR.unpack_from(packet)
        assert n == len(packet)
        if seq == 1:
            assert fam == mod.GENL_ID_CTRL
            body = mod.GENLHDR.pack(1, 2, 0) + mod.attr(1, struct.pack('=H', 44))
            self.pending.append(self.packet(mod.GENL_ID_CTRL, seq, body))
            return
        assert seq == 2 and fam == 44 and flags & mod.NLM_F_DUMP
        request_attrs = mod.attrs(packet[20:])
        self.request_attrs = request_attrs
        if self.reject_all or set(request_attrs) != {1}:
            # Mirrors the observed EINVAL for an extra zero-length OVPN_A_PEER.
            self.pending.append(self.packet(mod.NLMSG_ERROR, seq, struct.pack('=i', -errno.EINVAL)))
            return
        peer = mod.attr(1, struct.pack('=I', 19))
        for key in range(16, 24):
            peer += mod.attr(key, struct.pack('=Q', 1000 + key))
        body = mod.GENLHDR.pack(3, 1, 0) + mod.attr(1, struct.pack('=I', 7)) + mod.attr(2 | 0x8000, peer)
        message = self.packet(44, seq, body, mod.NLM_F_MULTI)
        done = self.packet(mod.NLMSG_DONE, seq, struct.pack('=i', 0))
        self.pending.append(message + done)

    def recvmsg(self, _max_size):
        if not self.pending:
            raise AssertionError('unexpected netlink receive')
        return self.pending.pop(0), [], 0, (0, 0)


class PeerGetDumpTests(unittest.TestCase):
    def kernel(self, sock):
        return patch.object(mod.socket, 'socket', return_value=sock), patch.object(mod.socket, 'if_nametoindex', return_value=7)

    def test_dump_carries_ifindex_but_no_empty_nested_peer_attribute(self):
        sock = FakeKernelNetlink()
        sm, im = self.kernel(sock)
        with sm, im:
            result = mod.query('tunbench-s')
        self.assertEqual(set(sock.request_attrs), {1})
        self.assertEqual(sock.request_attrs[1], struct.pack('=I', 7))
        self.assertEqual(result['peers'][0]['peer_id'], 19)
        self.assertEqual(result['peers'][0]['vpn_rx_bytes'], 1016)
        self.assertEqual(result['peers'][0]['link_tx_packets'], 1023)
        self.assertEqual(len(sock.sent), 2)

    def test_real_kernel_errno_not_silenced(self):
        sock = FakeKernelNetlink()
        sock.reject_all = True
        sm, im = self.kernel(sock)
        with sm, im, self.assertRaises(OSError) as ctx:
            mod.query('tunbench-s')
        self.assertEqual(ctx.exception.errno, errno.EINVAL)


    def test_rejects_cumulative_multipart_wire_bytes(self):
        # Every individual datagram is below recvmsg(1 << 20), but the
        # stream exceeds 4 MiB. A missing DONE must not permit unbounded
        # journal hex strings or retained peer rows.
        class OversizedKernel(FakeKernelNetlink):
            def send(self, packet):
                super().send(packet)
                if mod.NLHDR.unpack_from(packet)[3] == 2:
                    reply = self.packet(
                        44, 2,
                        mod.GENLHDR.pack(3, 1, 0) + mod.attr(99, b'Z' * 16300),
                        mod.NLM_F_MULTI)
                    self.pending = [reply * 40] * 8

        sock = OversizedKernel()
        sm, im = self.kernel(sock)
        with sm, im, self.assertRaisesRegex(ValueError, 'netlink reply wire budget exceeded'):
            mod.query('tunbench-s')

    def test_rejects_cumulative_multipart_message_count(self):
        # A single small datagram can hold thousands of distinct messages.
        # Count frames before appending parsed objects to the reply list.
        class ExcessiveMessagesKernel(FakeKernelNetlink):
            def send(self, packet):
                super().send(packet)
                if mod.NLHDR.unpack_from(packet)[3] == 2:
                    reply = self.packet(
                        44, 2,
                        mod.GENLHDR.pack(3, 1, 0) + mod.attr(99, b'Z'),
                        mod.NLM_F_MULTI)
                    done = self.packet(mod.NLMSG_DONE, 2, struct.pack('=i', 0))
                    self.pending = [reply * 4097 + done]

        sock = ExcessiveMessagesKernel()
        sm, im = self.kernel(sock)
        with sm, im, self.assertRaisesRegex(ValueError, 'netlink message budget exceeded'):
            mod.query('tunbench-s')

if __name__ == '__main__': unittest.main(verbosity=2)
