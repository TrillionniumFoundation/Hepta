#!/usr/bin/env python3
"""Unit checks for evidence parsing and real child timeout preservation only.

No mocked OpenVPN or device is run; these checks cannot qualify any tunnel/DCO.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'tunnel_trial.py'
spec = importlib.util.spec_from_file_location('trial', PATH)
trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)


def peer_group(peer=7, values=(1, 2, 3, 4)):
    lines = [f'2026 test ovpn_handle_peer: parsing message for peer {peer}...']
    lines.extend(f'2026 test dco_update_peer_stat / {name}: {value}'
                 for name, value in zip(trial.PEER_FIELDS, values))
    return '\n'.join(lines) + '\n'


class TunnelObserverTests(unittest.TestCase):
    def test_complete_peer_groups_and_partial_do_not_merge(self):
        good = trial.peer_snapshots(peer_group())
        self.assertEqual(len(good), 1)
        self.assertEqual(good[0]['peer_id'], 7)
        self.assertEqual(good[0]['counters']['tun_write_bytes'], 4)
        # A new peer header resets a partial record; no cross-peer assembly.
        partial = '\n'.join(peer_group().splitlines()[:3]) + '\n'
        tail = '\n'.join(peer_group(8).splitlines()[3:]) + '\n'
        self.assertEqual(trial.peer_snapshots(partial + 'ovpn_handle_peer: parsing message for peer 8...\n' + tail), [])
        self.assertEqual(trial.peer_snapshots(tail), [])
        duplicate = peer_group().replace('tun_read_bytes: 3', 'dco_read_bytes: 3')
        self.assertEqual(trial.peer_snapshots(duplicate), [])

    def test_missing_field_warning_invalidates_group(self):
        text = peer_group().replace('dco_update_peer_stat / tun_read_bytes: 3',
                                   'dco_update_peer_stat: no VPN RX bytes provided in reply for peer 7')
        self.assertEqual(trial.peer_snapshots(text), [])

    def test_positive_byte_and_packet_delta_requires_all_fields(self):
        self.assertEqual(trial.positive_delta({'x': 1}, {'x': 8}, ('x',)), {'x': 7})
        for after in ({}, {'x': 1}, {'x': 0}, {'x': '8'}, {'x': True}):
            with self.assertRaises(RuntimeError):
                trial.positive_delta({'x': 1}, after, ('x',))
        link = {'stats64': {'rx': {'bytes': 10, 'packets': 2}, 'tx': {'bytes': 20, 'packets': 3}}}
        self.assertEqual(trial.link_bytes(link), {'rx_bytes': 10, 'tx_bytes': 20, 'rx_packets': 2, 'tx_packets': 3})
        with self.assertRaises(RuntimeError):
            trial.link_bytes({})

    def test_counter_growth_cannot_hide_peer_reuse_or_reset(self):
        first = trial.peer_snapshots(peer_group(values=(10, 20, 30, 40)))[0]
        last = trial.peer_snapshots(peer_group(values=(100, 200, 300, 400)))[0]
        good = trial.peer_interval(first, last, peer_group(values=(50, 60, 70, 80)))
        self.assertEqual(good['dco_read_bytes'], 90)
        for text in ('dco_new_peer: peer-id 7, fd 2', 'dco_del_peer: peer-id 7',
                     'ovpn-dco: received CMD_PEER_DEL_NTF, ifindex: 8, peer-id 7',
                     peer_group(values=(1, 2, 3, 4)), peer_group(peer=8),
                     'dco_update_peer_stat: no link RX bytes provided in reply for peer 7'):
            with self.assertRaises(RuntimeError):
                trial.peer_interval(first, last, text)

    def test_real_short_process_exit_is_benign_during_cleanup(self):
        proc = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(proc.wait(timeout=3), 0)
        self.assertFalse(trial.signal_group(proc, __import__('signal').SIGTERM))
        row = trial.cleanup_process(proc, timeout=0.1)
        self.assertEqual(row['exit_code'], 0)
        self.assertFalse(row['forced_kill'])
        self.assertNotIn('cleanup_error', row)

    def test_real_timeout_preserves_partial_stdout_stderr_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory); commands = []
            # A real Python process, not a fake VPN, emits output then exceeds its budget.
            command = [sys.executable, '-u', '-c',
                       'import sys,time; print("partial stdout"); print("partial stderr",file=sys.stderr); time.sleep(3)']
            row = trial.run_record(command, out, 'timeout-child', commands, timeout=0.15)
            self.assertTrue(row['timed_out'])
            self.assertNotEqual(row['exit_code'], 0)
            self.assertEqual((out / row['stdout']).read_text(), 'partial stdout\n')
            self.assertEqual((out / row['stderr']).read_text(), 'partial stderr\n')
            self.assertEqual(row['stdout_sha256'], trial.sha(out / row['stdout']))
            self.assertEqual(len(commands), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
