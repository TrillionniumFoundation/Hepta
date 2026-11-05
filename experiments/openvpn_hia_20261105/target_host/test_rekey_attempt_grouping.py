#!/usr/bin/env python3
"""Bounded offline rekey log tests, not tunnel or protocol qualification."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('matrix', Path(__file__).with_name('run_matrix.py'))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)

EXPLICIT = 'TLS: soft reset sec=10/10\n'
TLS = 'Control Channel: TLSv1.3\n'
OUT = "Outgoing Epoch Data key 1: Cipher 'AES-256-GCM' initialized\n"
IN = "Incoming Epoch Data key 1: Cipher 'AES-256-GCM' initialized\n"
KEYS = TLS + OUT + IN
BOUNDARIES = ('TLS: Initial packet from peer', 'initial untrusted session promoted to trusted',
              'Initialization Sequence Completed', 'SIGUSR1[hard,] received')


def received(kid=1, ipv=4):
    return f'UDPv{ipv} READ [54] from [AF_INET]192.0.2.1:1194: P_CONTROL_SOFT_RESET_V1 kid={kid} pid=[ #1 ]\n'


class PassiveRekeyTests(unittest.TestCase):
    def test_archived_passive_reset_projection(self):
        # Verbatim selected lines, with source provenance below. The complete
        # original receipt remains failed; this projection tests parsing only.
        observation = matrix.observe(ARCHIVED_PROJECTION)
        self.assertEqual(observation['soft_resets'], 0)
        self.assertEqual(observation['peer_soft_resets'], 3)
        self.assertEqual(observation['completed_rekeys'], 3)
        self.assertEqual([row['reset_line'] for row in observation['rekey_cycles']], [1, 5, 9])
        self.assertEqual([row['incoming_key_line'] for row in observation['rekey_cycles']], [4, 8, 12])

    def test_incoming_reset_starts_attempt_but_never_proves_completion(self):
        for ipv in (4, 6):
            observation = matrix.observe(received(ipv=ipv))
            self.assertEqual(observation['soft_resets'], 0)
            self.assertEqual(observation['peer_soft_resets'], 1)
            self.assertEqual(observation['completed_rekeys'], 0)
            self.assertEqual(matrix.observe(received(ipv=ipv) + KEYS)['completed_rekeys'], 1)

    def test_outgoing_and_non_packet_mentions_do_not_start_rekey(self):
        for line in (received().replace(' READ ', ' WRITE ').replace(' from ', ' to '),
                     'P_CONTROL_SOFT_RESET_V1 kid=1\n',
                     'UDPv4 READ failed P_CONTROL_SOFT_RESET_V1 kid=1\n',
                     received(kid=12), received().replace('kid=1 ', 'kid=1x ')):
            observation = matrix.observe(line + KEYS)
            self.assertEqual(observation['soft_resets'], 0)
            self.assertEqual(observation['completed_rekeys'], 0)

    def test_explicit_reset_and_received_response_are_one_attempt(self):
        text = EXPLICIT + received() + KEYS
        observation = matrix.observe(text)
        self.assertEqual(observation['soft_resets'], 1)
        self.assertEqual(observation['completed_rekeys'], 1)
        self.assertEqual(observation['rekey_cycles'][0]['reset_line'], 1)

    def test_retransmits_do_not_split_handshake_or_inflate_completed_count(self):
        partial = received() + TLS + received() + OUT + received() + IN
        grouped = matrix.observe(partial)
        self.assertEqual(grouped['soft_resets'], 0)
        self.assertEqual(grouped['peer_soft_resets'], 3)
        self.assertEqual(grouped['completed_rekeys'], 1)
        text = received() + TLS + received() + OUT + received() + IN + received() + KEYS
        observation = matrix.observe(text)
        self.assertEqual(observation['soft_resets'], 0)
        self.assertEqual(observation['peer_soft_resets'], 4)
        self.assertEqual(observation['completed_rekeys'], 1)
        self.assertEqual(observation['rekey_cycles'][0]['reset_line'], 1)

    def test_error_before_received_response_is_not_discarded(self):
        for text in (EXPLICIT + 'TLS Error: failed\n' + received() + KEYS,
                     received() + TLS + 'TLS Error: failed\n' + received() + OUT + IN):
            observation = matrix.observe(text)
            self.assertEqual(observation['completed_rekeys'], 0)
            self.assertEqual(observation['peer_soft_resets'], 1 if text.startswith(EXPLICIT) else 2)
            self.assertEqual(observation['soft_resets'], 1 if text.startswith(EXPLICIT) else 0)

    def test_new_key_id_does_not_complete_previous_partial_handshake(self):
        text = received(1) + TLS + OUT + received(2) + IN
        observation = matrix.observe(text)
        self.assertEqual(observation['soft_resets'], 0)
        self.assertEqual(observation['peer_soft_resets'], 2)
        self.assertEqual(observation['completed_rekeys'], 0)

    def test_explicit_resets_still_separate_incomplete_attempts(self):
        self.assertEqual(matrix.observe(EXPLICIT + TLS + OUT + EXPLICIT + IN)['completed_rekeys'], 0)
        self.assertEqual(matrix.observe(EXPLICIT + received() + KEYS + EXPLICIT + received() + KEYS)['completed_rekeys'], 2)

    def test_key_id_wrap_and_reuse_are_not_global_duplicates(self):
        text = ''.join(received(kid) + KEYS for kid in (1, 2, 3, 4, 5, 6, 7, 0, 1))
        self.assertEqual(matrix.observe(text)['completed_rekeys'], 9)

    def test_session_boundaries_block_cross_session_key_assembly(self):
        for boundary in BOUNDARIES:
            with self.subTest(boundary=boundary):
                self.assertEqual(matrix.observe(received() + boundary + '\n' + KEYS)['completed_rekeys'], 0)
                text = received() + KEYS + boundary + '\n' + KEYS + received() + KEYS
                self.assertEqual(matrix.observe(text)['completed_rekeys'], 2)

    def test_userspace_completion_still_requires_ordered_tls_and_both_keys(self):
        for keys in (TLS + OUT, TLS + IN, OUT + TLS + IN, IN + TLS + OUT):
            self.assertEqual(matrix.observe(received() + keys)['completed_rekeys'], 0)
        self.assertEqual(matrix.observe(received() + TLS + "Outgoing Data Channel: Cipher 'AES-256-GCM' initialized\nIncoming Data Channel: Cipher 'AES-256-GCM' initialized\n")['completed_rekeys'], 1)

    def test_offload_completion_still_requires_ordered_install_swap_and_no_error(self):
        install = 'dco_new_key: slot 1, key-id 1, peer-id 0\n'
        swap = 'dco_swap_keys: peer-id 0\n'
        self.assertEqual(matrix.observe(received() + TLS + install + swap)['completed_rekeys'], 1)
        for tail in (TLS + install, TLS + swap, install + TLS + swap,
                     TLS + install + 'Cannot swap keys\n' + swap,
                     TLS + install + 'Impossible to install key material\n' + swap,
                     TLS + install + 'DCO key state mismatch\n' + swap):
            self.assertEqual(matrix.observe(received() + tail)['completed_rekeys'], 0)


# Run 42014583779, artifact 13440824546; archive SHA-256:
# 3ae660728a3b537b23b315a23a0e3f11ec346cb6d3f8202169478f70422b37d6
# Member tunnel/cases/epoch-hia-c/client-openvpn.stdout SHA-256:
# 73043a3479d4ef9aa03291c4208a7fcd979cdd1c0e9ca5bee57799aa4e05be47
# Source line numbers: 1258,1282,1283,1284,2302,2326,2327,2328,3349,3373,3374,3375.
ARCHIVED_PROJECTION = """2026-11-05 18:22:16 us=664 UDPv4 READ [54] from [AF_INET]192.0.2.1:1194: P_CONTROL_SOFT_RESET_V1 kid=1 pid=[ #3921615390 ] [ 2972581975 ]
2026-11-05 18:22:16 us=4239 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256, peer temporary key: 253 bits X25519, peer signing digest/type: SHA256 RSASSA-PSS, key agreement: x25519
2026-11-05 18:22:16 us=4279 Outgoing Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
2026-11-05 18:22:16 us=4292 Incoming Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
2026-11-05 18:22:26 us=554 UDPv4 READ [54] from [AF_INET]192.0.2.1:1194: P_CONTROL_SOFT_RESET_V1 kid=2 pid=[ #1064154443 ] [ 2737945407 ]
2026-11-05 18:22:26 us=4099 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256, peer temporary key: 253 bits X25519, peer signing digest/type: SHA256 RSASSA-PSS, key agreement: x25519
2026-11-05 18:22:26 us=4139 Outgoing Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
2026-11-05 18:22:26 us=4153 Incoming Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
2026-11-05 18:22:36 us=714 UDPv4 READ [54] from [AF_INET]192.0.2.1:1194: P_CONTROL_SOFT_RESET_V1 kid=3 pid=[ #2888905496 ] [ 221598442 ]
2026-11-05 18:22:36 us=4358 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA, signature: RSA-SHA256, peer temporary key: 253 bits X25519, peer signing digest/type: SHA256 RSASSA-PSS, key agreement: x25519
2026-11-05 18:22:36 us=4398 Outgoing Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
2026-11-05 18:22:36 us=4412 Incoming Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key
"""


if __name__ == "__main__":
    unittest.main(verbosity=2)
