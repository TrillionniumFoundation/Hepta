#!/usr/bin/env python3
"""Offline regression for peer-initiated OpenVPN TLS/key rekey observation.

The frozen real-host guarded artifact #13440824546 (SHA 2f0646b) recorded
three completed server rekeys but zero on the responding C client. Its
client stdout actually contains three received P_CONTROL_SOFT_RESET_V1 records
followed by TLS 1.3 completion and fresh incoming/outgoing epoch key installs.
This synthetic log fixture reproduces that parser failure; it is NOT a
TUN/DCO qualification or proof of old-ciphertext rejection.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('run_matrix', HERE / 'run_matrix.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def rekey_lines(index, *, local=False, received=True, keys=True, bad=False):
    lines = []
    if local:
        lines.append(f"TLS: soft reset sec=10/10 bytes=100/100 pkts=1/1 kid={index}")
    if received:
        lines.append(
            f"UDPv4 READ [54] from [AF_INET]192.0.2.1:1194: "
            f"P_CONTROL_SOFT_RESET_V1 kid={index} pid=[ 123 ]"
        )
    lines.append(
        "Control Channel: TLSv1.3, cipher TLS_AES_256_GCM_SHA384, "
        "peer temporary key: X25519"
    )
    if keys:
        lines.extend((
            "Outgoing Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key",
            "Incoming Epoch Data key 1: Cipher 'AES-256-GCM' initialized with 256 bit key",
        ))
    if bad:
        lines.append("TLS Error: failed to negotiate")
    return lines


class AcceptedPeerRekeyTests(unittest.TestCase):
    def test_three_peer_initiated_rekeys_have_full_key_install_receipts(self):
        lines = ["Initialization Sequence Completed"]
        for index in (1, 2, 3):
            lines.extend(rekey_lines(index))
        observation = matrix.observe('\n'.join(lines))
        self.assertEqual(observation['soft_resets'], 0)
        self.assertEqual(observation['peer_soft_resets'], 3)
        self.assertEqual(observation['completed_rekeys'], 3)
        self.assertEqual(len(observation['rekey_cycles']), 3)
        for receipt in observation['rekey_cycles']:
            self.assertLess(receipt['reset_line'], receipt['tls_line'])
            self.assertLess(receipt['tls_line'], receipt['outgoing_key_line'])
            self.assertLessEqual(receipt['outgoing_key_line'], receipt['incoming_key_line'])

    def test_local_reset_and_inbound_reply_do_not_count_twice(self):
        lines = ["Initialization Sequence Completed"]
        lines.extend(rekey_lines(1, local=True, received=True))
        observation = matrix.observe('\n'.join(lines))
        self.assertEqual(observation['soft_resets'], 1)
        self.assertEqual(observation['peer_soft_resets'], 1)
        self.assertEqual(observation['completed_rekeys'], 1)

    def test_retransmitted_remote_reset_is_not_an_extra_completed_rekey(self):
        lines = ["Initialization Sequence Completed"]
        lines.extend(rekey_lines(1, keys=False))
        lines.extend(rekey_lines(1, keys=True))
        self.assertEqual(matrix.observe('\n'.join(lines))['completed_rekeys'], 1)

    def test_received_reset_without_fresh_keys_stays_incomplete(self):
        lines = ["Initialization Sequence Completed"]
        lines.extend(rekey_lines(1, keys=False))
        observation = matrix.observe('\n'.join(lines))
        self.assertEqual(observation['peer_soft_resets'], 1)
        self.assertEqual(observation['completed_rekeys'], 0)

    def test_tls_error_fails_closed_even_if_keys_are_logged(self):
        lines = ["Initialization Sequence Completed"]
        lines.extend(rekey_lines(1, keys=True, bad=True))
        self.assertEqual(matrix.observe('\n'.join(lines))['completed_rekeys'], 0)

    def test_outbound_only_control_packet_is_not_remote_authorization(self):
        lines = ["Initialization Sequence Completed"]
        lines.append(
            "UDPv4 WRITE [54] to [AF_INET]192.0.2.1:1194: "
            "P_CONTROL_SOFT_RESET_V1 kid=1"
        )
        lines.extend(rekey_lines(1, local=False, received=False))
        observation = matrix.observe('\n'.join(lines))
        self.assertEqual(observation['peer_soft_resets'], 0)
        self.assertEqual(observation['completed_rekeys'], 0)


class TargetMatrixControlTests(unittest.TestCase):
    def test_sysfs_topology_reader_records_package_and_core(self):
        with tempfile.TemporaryDirectory() as root:
            for cpu, package, core in ((0, 0, 0), (1, 0, 0), (2, 0, 1), (3, 0, 1)):
                topology = Path(root) / f"cpu{cpu}" / "topology"
                topology.mkdir(parents=True)
                (topology / "physical_package_id").write_text(f"{package}\n")
                (topology / "core_id").write_text(f"{core}\n")
            self.assertEqual(
                matrix.read_cpu_topology([0, 1, 2, 3], Path(root)),
                {0: (0, 0), 1: (0, 0), 2: (0, 1), 3: (0, 1)},
            )

    def test_physical_cpu_selection_skips_smt_siblings(self):
        topology = {0: (0, 0), 1: (0, 0), 2: (0, 1), 3: (0, 1)}
        self.assertEqual(matrix.select_distinct_physical_cpus([0, 1, 2, 3], topology), [0, 2])

    def test_physical_cpu_selection_fails_closed_on_one_core(self):
        with self.assertRaisesRegex(RuntimeError, "two distinct physical CPU cores"):
            matrix.select_distinct_physical_cpus([0, 1], {0: (0, 0), 1: (0, 0)})

    def test_client_initiates_and_server_responds_to_rekey(self):
        self.assertEqual(
            matrix.resolve_reneg_seconds(10, {"client": 10, "server": 3600}),
            {"server": 3600, "client": 10},
        )

    def test_role_schedule_must_cover_both_roles_and_be_positive(self):
        with self.assertRaisesRegex(ValueError, "cover server and client"):
            matrix.resolve_reneg_seconds(10, {"client": 10})
        with self.assertRaisesRegex(ValueError, "server renegotiation seconds"):
            matrix.resolve_reneg_seconds(10, {"client": 10, "server": 0})
        with self.assertRaisesRegex(ValueError, "client renegotiation seconds"):
            matrix.resolve_reneg_seconds(10, {"client": True, "server": 3600})


if __name__ == '__main__':
    unittest.main(verbosity=2)
