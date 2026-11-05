#!/usr/bin/env python3
"""Probe implementation checks only: real loopback UDP + offline frame algebra.

These tests never qualify TUN, authentication, kernel replay or DCO execution.
"""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


payload = load('payload_probe')
capture = load('encrypted_capture')
TOKEN = '12015e6d8ff641719f5743a7cd439e40'


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class PayloadProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
            proc.communicate(timeout=3)
        self.temp.cleanup()

    def receiver(self, count=12, size=96, deadline=0.8):
        out = self.root / 'receiver'; chosen = port()
        argv = [sys.executable, str(HERE / 'payload_probe.py'), 'receiver', '--bind', '127.0.0.1',
                '--port', str(chosen), '--run-id', TOKEN, '--count', str(count), '--size', str(size),
                '--deadline', str(deadline), '--out', str(out)]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(proc)
        until = time.monotonic() + 3
        while not (out / 'ready.json').exists() and proc.poll() is None and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue((out / 'ready.json').is_file(), 'receiver failed to become ready')
        return proc, out, chosen

    def test_finite_real_udp_echo(self):
        receiver, out, chosen = self.receiver()
        client = subprocess.run([sys.executable, str(HERE / 'payload_probe.py'), 'sender',
            '--bind', '127.0.0.1', '--peer', '127.0.0.1', '--port', str(chosen),
            '--run-id', TOKEN, '--count', '12', '--size', '96', '--interval', '0.002',
            '--drain', '0.1', '--out', str(self.root / 'sender')], capture_output=True, timeout=3)
        self.assertEqual(client.returncode, 0, client.stderr.decode())
        receiver.communicate(timeout=3)
        self.assertEqual(receiver.returncode, 0)
        a = json.loads((out / 'summary.json').read_text())
        b = json.loads((self.root / 'sender' / 'summary.json').read_text())
        self.assertEqual((a['unique_packets'], a['duplicate_packets'], a['missing_count']), (12, 0, 0))
        self.assertEqual((b['unique_echoes'], b['sent_packets']), (12, 12))
        self.assertEqual(a['unique_payload_bytes'], 12 * 96)
        self.assertFalse(a['claims']['tunnel_path_verified'])

    def test_duplicate_corruption_foreign_run_and_order_observed(self):
        receiver, out, chosen = self.receiver(count=3, deadline=0.5)
        token = bytes.fromhex(TOKEN)
        frames = [payload.packet(token, seq, 1, 3, 96) for seq in (1, 0, 1, 2)]
        corrupt = bytearray(payload.packet(token, 2, 1, 3, 96)); corrupt[-1] ^= 1
        frames += [bytes(corrupt), payload.packet(bytes(16), 0, 1, 3, 96)]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            for frame in frames:
                sock.sendto(frame, ('127.0.0.1', chosen))
        receiver.communicate(timeout=3)
        self.assertEqual(receiver.returncode, 1)
        row = json.loads((out / 'summary.json').read_text())
        self.assertEqual(row['unique_packets'], 3)
        self.assertEqual(row['duplicate_packets'], 1)
        self.assertEqual(row['reordered_packets'], 1)
        self.assertEqual(row['invalid_reasons'], {'content': 1, 'foreign_run': 1})
        self.assertEqual(row['missing_count'], 0)
        self.assertFalse(row['passed'])

    def test_deadline_with_no_payload_is_failure(self):
        receiver, out, _ = self.receiver(count=3, deadline=0.15)
        receiver.communicate(timeout=3)
        row = json.loads((out / 'summary.json').read_text())
        self.assertEqual(receiver.returncode, 1)
        self.assertEqual(row['received_packets'], 0)
        self.assertEqual(row['missing_ranges_inclusive'], [[0, 2]])
        self.assertFalse(row['passed'])

    def test_sender_no_echo_and_output_preservation(self):
        out = self.root / 'no-peer'
        args = [sys.executable, str(HERE / 'payload_probe.py'), 'sender', '--bind', '127.0.0.1',
                '--peer', '127.0.0.1', '--port', str(port()), '--run-id', TOKEN, '--count', '3',
                '--size', '96', '--interval', '0.001', '--drain', '0.05', '--out', str(out)]
        first = subprocess.run(args, capture_output=True, timeout=3)
        self.assertEqual(first.returncode, 1)
        before = (out / 'summary.json').read_bytes()
        row = json.loads(before)
        self.assertEqual(row['send_attempts'], 3)
        self.assertEqual(row['unique_echoes'], 0)
        second = subprocess.run(args, capture_output=True, timeout=3)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((out / 'summary.json').read_bytes(), before)


class CapturedFrameChecks(unittest.TestCase):
    def frame(self, size=120):
        body = bytes([9 << 3 | 2]) + bytes(range(size - 1))
        udp = struct.pack('!HHHH', 35173, 1194, 8 + len(body), 0x1234) + body
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0x4000, 64, 17, 0xabcd,
                         socket.inet_aton('192.0.2.2'), socket.inet_aton('192.0.2.1'))
        return bytes.fromhex('0200000000010200000000020800') + ip + udp

    def check_sums(self, frame):
        p = capture.parse_frame(frame)
        self.assertEqual(capture.checksum(frame[14:14+p['ip_header_bytes']]), 0)
        pseudo = frame[26:34] + struct.pack('!BBH', 0, 17, p['udp_bytes'])
        self.assertEqual(capture.checksum(pseudo + frame[p['udp_offset']:]), 0)

    def test_capture_command_timeout_retains_real_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            command = [sys.executable, '-u', '-c',
                       'import sys,time; print("partial capture command"); print("partial failure",file=sys.stderr); time.sleep(3)']
            with self.assertRaises(RuntimeError):
                capture.run_json(command, out, 'timeout-child', timeout=0.15)
            self.assertEqual((out / 'timeout-child.stdout').read_text(), 'partial capture command\n')
            self.assertEqual((out / 'timeout-child.stderr').read_text(), 'partial failure\n')
            row = json.loads((out / 'timeout-child.command.json').read_text())
            self.assertEqual(row['exit_code'], 124)
            self.assertTrue(row['timed_out'])

    def test_exact_datagram_replay_and_partial_checksum_repair(self):
        original = self.frame()
        replay = capture.submitted_frame(original, 'replay')
        self.assertEqual(capture.parse_frame(original)['payload'], capture.parse_frame(replay)['payload'])
        self.check_sums(replay)
        self.assertTrue(capture.matching(capture.parse_frame(replay), '192.0.2.2', '192.0.2.1', 1194, 80))

    def test_incoming_witness_requires_real_outer_checksums(self):
        partial = self.frame()
        self.assertFalse(all(capture.checksum_observation(partial).values()))
        normalized = capture.submitted_frame(partial, "replay")
        self.assertTrue(all(capture.checksum_observation(normalized).values()))
        bad = bytearray(normalized); bad[-1] ^= 1
        self.assertFalse(capture.checksum_observation(bytes(bad))["udp_valid"])
        zero = bytearray(normalized); struct.pack_into("!H", zero, 40, 0)
        self.assertFalse(capture.checksum_observation(bytes(zero))["udp_present"])
        flipped = capture.submitted_frame(partial, "flip")
        self.assertTrue(all(capture.checksum_observation(flipped).values()))
        self.assertNotEqual(capture.sha(capture.parse_frame(normalized)["payload"]),
                            capture.sha(capture.parse_frame(flipped)["payload"]))

    def test_tag_or_ciphertext_flip_changes_one_datagram_byte(self):
        original = self.frame()
        flipped = capture.submitted_frame(original, 'flip')
        before = capture.parse_frame(original)['payload']; after = capture.parse_frame(flipped)['payload']
        self.assertEqual(sum(x != y for x, y in zip(before, after)), 1)
        self.assertEqual(before[-1] ^ after[-1], 1)
        self.check_sums(flipped)

    def test_truncation_fragmentation_control_keepalive_and_direction_filters(self):
        frame = self.frame()
        for end in (0, 13, 14, 20, 33, 41, len(frame)-1):
            self.assertIsNone(capture.parse_frame(frame[:end]))
        fragmented = bytearray(frame); struct.pack_into('!H', fragmented, 20, 0x2000)
        self.assertIsNone(capture.parse_frame(fragmented))
        p = capture.parse_frame(frame)
        self.assertFalse(capture.matching(p, '192.0.2.1', '192.0.2.2', 1194, 80))
        self.assertFalse(capture.matching(capture.parse_frame(self.frame(30)), '192.0.2.2', '192.0.2.1', 1194, 80))
        control = bytearray(frame); control[42] = 4 << 3
        self.assertFalse(capture.matching(capture.parse_frame(control), '192.0.2.2', '192.0.2.1', 1194, 80))
        self.assertEqual(capture.parse_frame(frame)['key_id'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
