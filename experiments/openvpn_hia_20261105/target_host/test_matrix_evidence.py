#!/usr/bin/env python3
"""Offline evidence counterexamples and real bounded child-process checks.

These tests do not create a namespace, use TUN, load a module or qualify DCO.
Constructed log/JSON/netlink vectors only test rejection by the evidence parser.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import socket
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


matrix=load('run_matrix')
netlink=load('dco_peer_stats')
verifier=load('verify_result')
encrypted=load('encrypted_capture')


class SessionEvidenceTests(unittest.TestCase):
    def test_old_epoch_profile_does_not_cover_reconnected_profile(self):
        first="Initialization Sequence Completed\nData Channel: cipher 'AES-256-GCM'\nProtocol options: protocol-flags aead-epoch\n"
        matrix.negotiated_profile(matrix.observe(first),True)
        absent=first+'SIGUSR1[hard,] received\nInitialization Sequence Completed\n'
        with self.assertRaises(ValueError):matrix.negotiated_profile(matrix.observe(absent),True)
        second=absent+"Data Channel: cipher 'AES-256-GCM'\nProtocol options: protocol-flags tls-ekm\n"
        with self.assertRaises(ValueError):matrix.negotiated_profile(matrix.observe(second),True)
        latest=matrix.negotiated_profile(matrix.observe(second),False)
        self.assertEqual(latest['initialization_line'],5)
        self.assertEqual(len(latest['protocol_lines']),1)

    def test_new_session_key_install_is_not_a_completed_rekey(self):
        keys='Control Channel: TLSv1.3\nOutgoing Epoch Data key 1: initialized\nIncoming Epoch Data key 1: initialized\n'
        good='TLS: soft reset sec=10/10\n'+keys
        self.assertEqual(matrix.observe(good)['completed_rekeys'],1)
        for boundary in ('TLS: Initial packet from peer','initial untrusted session promoted to trusted',
                         'Initialization Sequence Completed','SIGUSR1[hard,] received'):
            self.assertEqual(matrix.observe('TLS: soft reset sec=10/10\n'+boundary+'\n'+keys)['completed_rekeys'],0)
        self.assertEqual(matrix.observe('TLS: soft reset sec=10/10\nTLS Error: handshake failed\n'+keys)['completed_rekeys'],0)

    def test_dco_rekey_requires_control_install_and_swap_in_order(self):
        reset='TLS: soft reset sec=10/10\n'
        tls='Control Channel: TLSv1.3\n'
        install='dco_new_key: slot 1, key-id 2, peer-id 0\n'
        swap='dco_swap_keys: peer-id 0\n'
        self.assertEqual(matrix.observe(reset+tls+install+swap)['completed_rekeys'],1)
        for text in (reset+tls+install,reset+tls+swap,reset+install+tls+swap,
                     reset+tls+install+'Cannot swap keys\n'+swap):
            self.assertEqual(matrix.observe(text)['completed_rekeys'],0)

    def test_session_marker_detects_peer_replacement_without_process_restart(self):
        first=matrix.observe('Initialization Sequence Completed\nPeer Connection Initiated\n')
        later=matrix.observe('Initialization Sequence Completed\nPeer Connection Initiated\nPeer Connection Initiated\n')
        self.assertNotEqual(matrix.session_marker(first),matrix.session_marker(later))


class ThroughputEvidenceTests(unittest.TestCase):
    def fixture(self):
        return {'start':{'test_start':{'bidir':1}},'end':{
            'sum_received':{'bytes':100,'seconds':5,'bits_per_second':160,'sender':False},
            'sum_received_bidir_reverse':{'bytes':200,'seconds':5,'bits_per_second':320,'sender':False}}}

    def test_each_direction_uses_its_local_receiving_endpoint(self):
        document=self.fixture()
        self.assertEqual(matrix.local_bidir_receiver(document,'server')['bytes'],100)
        self.assertEqual(matrix.local_bidir_receiver(document,'client')['bytes'],200)
        for role,key in (('server','sum_received'),('client','sum_received_bidir_reverse')):
            missing=copy.deepcopy(document);del missing['end'][key]
            with self.assertRaises(ValueError):matrix.local_bidir_receiver(missing,role)
            for value in (0,-1,float('nan'),float('inf'),True,'200'):
                wrong=copy.deepcopy(document);wrong['end'][key]['bytes']=value
                with self.assertRaises(ValueError):matrix.local_bidir_receiver(wrong,role)
            wrong=copy.deepcopy(document);wrong['end'][key]['sender']=True
            with self.assertRaises(ValueError):matrix.local_bidir_receiver(wrong,role)
        document['start']['test_start']['bidir']=0
        with self.assertRaises(ValueError):matrix.local_bidir_receiver(document,'client')

    def udp_client_document(self, client_to_server_bps, server_to_client_bps):
        return {"end": {
            "sum_sent": {"bits_per_second": client_to_server_bps, "sender": True},
            "sum_sent_bidir_reverse": {"bits_per_second": server_to_client_bps, "sender": True},
        }}

    def udp_receiver(self, bits_per_second, lost_percent):
        return {"bits_per_second": bits_per_second, "lost_percent": lost_percent,
                "sender": False}

    def udp_policy(self):
        return {"minimum_offered_rate_fraction": 0.95,
                "maximum_receiver_loss_percent": 1.0}

    def test_exact_dco_udp64_under_offer_is_not_a_pass(self):
        # Exact values retained from target run 42174797170, profile-c-dco,
        # workload-0-udp-64. Both senders were CPU-limited below the declared
        # 100 Mbit/s in each direction, despite zero packet loss.
        document = self.udp_client_document(59_806_802.81, 16_570_974.66)
        result = matrix.udp_delivery_evidence(
            {"transport": "udp", "offered_rate_each_direction": "100M"},
            document,
            self.udp_receiver(16_523_656.37, 0.0),
            self.udp_receiver(59_779_815.18, 0.0),
            self.udp_policy(),
        )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["offered_rate_met"])
        self.assertFalse(result["checks"]["receiver_rate_met"])
        self.assertTrue(result["checks"]["loss_within_limit"])

    def test_exact_userspace_udp512_loss_is_not_a_pass(self):
        # Exact target-run case perf-r0-o0-p0-c-user: the server received
        # 90.55 Mbit/s with 9.1296% loss; the opposite direction stayed healthy.
        document = self.udp_client_document(99_979_099.0045469, 100_315_767.5804186)
        result = matrix.udp_delivery_evidence(
            {"transport": "udp", "offered_rate_each_direction": "100M"},
            document,
            self.udp_receiver(99_622_849.58243865, 0.0),
            self.udp_receiver(90_547_672.19435424, 9.12964040212039),
            self.udp_policy(),
        )
        self.assertFalse(result["passed"])
        self.assertTrue(result["checks"]["offered_rate_met"])
        self.assertFalse(result["checks"]["receiver_rate_met"])
        self.assertFalse(result["checks"]["loss_within_limit"])

    def test_udp_workload_passes_only_when_both_directions_meet_policy(self):
        document = self.udp_client_document(100_000_000.0, 100_000_000.0)
        result = matrix.udp_delivery_evidence(
            {"transport": "udp", "offered_rate_each_direction": "100M"},
            document,
            self.udp_receiver(99_500_000.0, 0.1),
            self.udp_receiver(99_700_000.0, 0.0),
            self.udp_policy(),
        )
        self.assertTrue(result["passed"])
        self.assertTrue(all(result["checks"].values()))

    def test_udp_sender_receipt_must_be_explicit_and_finite(self):
        document = self.udp_client_document(100_000_000.0, 100_000_000.0)
        document["end"]["sum_sent"]["sender"] = False
        with self.assertRaises(ValueError):
            matrix.udp_delivery_evidence(
                {"transport": "udp", "offered_rate_each_direction": "100M"},
                document,
                self.udp_receiver(99_500_000.0, 0.1),
                self.udp_receiver(99_700_000.0, 0.0),
                self.udp_policy(),
            )

    def test_failure_before_traffic_still_writes_failed_measurement(self):
        def broken_spawn(*args,**kwargs):raise OSError('deliberate pre-traffic spawn failure')
        with tempfile.TemporaryDirectory() as directory:
            pair=SimpleNamespace(folder=Path(directory),result={},processes={},spawn=broken_spawn)
            row=matrix.throughput(pair,{'name':'failure-vector','transport':'tcp'},5,[0,1],'failure-vector')
            receipt=json.loads((Path(directory)/'failure-vector-measurement.json').read_text())
            self.assertFalse(row['passed']);self.assertEqual(receipt,row)
            self.assertEqual(len(pair.result['measurements']),1)
            self.assertTrue(any('pre-traffic spawn failure' in f['failure'] for f in row['failures']))
            self.assertEqual(row['status'],'failed')
            self.assertEqual(row['process_cpu_seconds'],{})

    def test_counter_identity_change_and_reset_fail(self):
        first={'ifindex':7,'netns_inode':100,'family_id':32,
               'peers':[{'peer_id':1,**{key:10 for key in matrix.PEER_COUNTERS}}]}
        last=copy.deepcopy(first)
        last['peers'][0].update({key:20 for key in matrix.PEER_COUNTERS})
        self.assertEqual(matrix.peer_delta(first,last)['1']['vpn_rx_bytes'],10)
        for field in ('ifindex','netns_inode','family_id'):
            changed=copy.deepcopy(last);changed[field]+=1
            with self.assertRaises(ValueError):matrix.peer_delta(first,changed)
        changed=copy.deepcopy(last);changed['peers'][0]['peer_id']=2
        with self.assertRaises(ValueError):matrix.peer_delta(first,changed)
        changed=copy.deepcopy(last);changed['peers'][0]['vpn_tx_bytes']=0
        with self.assertRaises(ValueError):matrix.peer_delta(first,changed)


class NetlinkWireTests(unittest.TestCase):
    def test_attributes_reject_duplicate_truncated_and_wrong_width(self):
        valid=netlink.attr(1,struct.pack('=I',7))
        self.assertEqual(netlink.uint(netlink.attrs(valid)[1],(4,)),7)
        for raw in (valid+valid,valid[:-1],struct.pack('=HH',3,1),valid+b'\0'):
            with self.assertRaises(ValueError):netlink.attrs(raw)
        with self.assertRaises(ValueError):netlink.uint(b'\0\0')
        with self.assertRaises(ValueError):netlink.uint(bytes(8),(4,))

    def test_error_and_invalid_reply_keep_wire_journal(self):
        class WireVector:
            def __init__(self,raw,port=0,flags=0):self.raw=raw;self.port=port;self.flags=flags
            def getsockname(self):return (1234,0)
            def send(self,raw):return len(raw)
            def settimeout(self,timeout):pass
            def recvmsg(self,maximum):return self.raw,[],self.flags,(self.port,0)
        error=netlink.NLHDR.pack(20,netlink.NLMSG_ERROR,0,1,0)+struct.pack('=i',-2)
        for sock in (WireVector(error),WireVector(error,port=2),WireVector(error,flags=socket.MSG_TRUNC)):
            journal=[]
            with self.assertRaises((OSError,ValueError)):
                netlink.request(sock,netlink.GENL_ID_CTRL,3,netlink.attr(2,b'ovpn\0'),1,journal=journal)
            self.assertEqual([x['direction'] for x in journal],['request','reply'])
            self.assertEqual(journal[1]['hex'],error.hex())

    def test_wrong_generic_command_or_version_rejected(self):
        class OneReply:
            def __init__(self,cmd,version):
                body=netlink.GENLHDR.pack(cmd,version,0)+netlink.attr(1,struct.pack('=H',32))
                self.raw=netlink.NLHDR.pack(16+len(body),netlink.GENL_ID_CTRL,0,1,0)+body
            def getsockname(self):return (1234,0)
            def send(self,raw):return len(raw)
            def settimeout(self,timeout):pass
            def recvmsg(self,maximum):return self.raw,[],0,(0,0)
        for cmd,version in ((3,2),(1,1)):
            with self.assertRaises(ValueError):netlink.request(OneReply(cmd,version),netlink.GENL_ID_CTRL,3,b'',1)
        rows=netlink.request(OneReply(1,2),netlink.GENL_ID_CTRL,3,b'',1)
        self.assertEqual(netlink.uint(rows[0][1],(2,)),32)


class ProcessEvidenceTests(unittest.TestCase):
    def test_real_child_timeout_keeps_partial_output_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);private=out/'private';private.mkdir()
            ledger=matrix.Ledger(out,private,5)
            try:
                child=matrix.Job(ledger,'timeout-child',[sys.executable,'-u','-c',
                    'import sys,time; print("partial stdout"); print("partial stderr",file=sys.stderr); time.sleep(3)'],out/'commands')
                row=child.wait(.12,required=False)
                self.assertTrue(row['timed_out']);self.assertNotEqual(row['exit_code'],0)
                self.assertEqual(child.stdout.read_text(),'partial stdout\n')
                self.assertEqual(child.stderr.read_text(),'partial stderr\n')
                child.signal(signal.SIGTERM)
                self.assertEqual(row['stdout_sha256'],matrix.digest(child.stdout))
            finally:ledger.close()



class UdpVerifierTests(unittest.TestCase):
    def valid_receipt(self):
        workload={"transport":"udp","offered_rate_each_direction":"100M"}
        policy={"minimum_offered_rate_fraction":0.95,"maximum_receiver_loss_percent":1.0}
        client_document={"end":{
            "sum_sent":{"bits_per_second":100_000_000.0,"sender":True},
            "sum_sent_bidir_reverse":{"bits_per_second":100_000_000.0,"sender":True},
        }}
        server_receiver={"bits_per_second":99_600_000.0,"lost_percent":0.2,"sender":False}
        client_receiver={"bits_per_second":99_700_000.0,"lost_percent":0.1,"sender":False}
        evidence=matrix.udp_delivery_evidence(
            workload,client_document,client_receiver,server_receiver,policy)
        value={
            "client_iperf":client_document,
            "server_local_receiver":server_receiver,
            "client_local_receiver":client_receiver,
            "udp_delivery":evidence,
            "checks":{
                "udp_offered_rate_met":True,
                "udp_receiver_rate_met":True,
                "udp_loss_within_limit":True,
            },
        }
        return value,workload,policy

    def test_independent_verifier_accepts_complete_bidirectional_udp_receipt(self):
        value,workload,policy=self.valid_receipt()
        verifier.verify_udp_delivery(value,workload,policy)

    def test_independent_verifier_rejects_raw_receiver_loss_changed_after_summary(self):
        value,workload,policy=self.valid_receipt()
        value["server_local_receiver"]["lost_percent"]=2.0
        with self.assertRaises(ValueError):
            verifier.verify_udp_delivery(value,workload,policy)

    def test_independent_verifier_rejects_forged_direction_summary(self):
        value,workload,policy=self.valid_receipt()
        value["udp_delivery"]["directions"]["client_to_server"]["receiver_bps"]+=1.0
        with self.assertRaises(ValueError):
            verifier.verify_udp_delivery(value,workload,policy)

    def test_independent_verifier_rejects_missing_reverse_receiver(self):
        value,workload,policy=self.valid_receipt()
        del value["client_local_receiver"]
        with self.assertRaises(ValueError):
            verifier.verify_udp_delivery(value,workload,policy)



class DcoReplayEvidenceTests(unittest.TestCase):
    def peer(self):
        return {
            "ifindex": 7, "netns_inode": 200, "family_id": 32,
            "peers": [{
                "peer_id": 0,
                "vpn_rx_bytes": 100, "vpn_tx_bytes": 100,
                "vpn_rx_packets": 10, "vpn_tx_packets": 10,
                "link_rx_bytes": 100, "link_tx_bytes": 100,
                "link_rx_packets": 10, "link_tx_packets": 10,
            }],
        }

    def test_dco_replay_delta_requires_link_rx_without_vpn_rx(self):
        before = self.peer()
        after = copy.deepcopy(before)
        after["peers"][0]["link_rx_bytes"] += 354
        after["peers"][0]["link_rx_packets"] += 1
        expected = {"0": {
            "vpn_rx_bytes": 0, "vpn_tx_bytes": 0,
            "vpn_rx_packets": 0, "vpn_tx_packets": 0,
            "link_rx_bytes": 354, "link_tx_bytes": 0,
            "link_rx_packets": 1, "link_tx_packets": 0,
        }}
        self.assertEqual(matrix.dco_rejection_delta(before, after), expected)
        self.assertEqual(verifier.verify_dco_rejection_delta(before, after), expected)

    def test_dco_replay_delta_rejects_vpn_delivery(self):
        before = self.peer()
        after = copy.deepcopy(before)
        after["peers"][0]["link_rx_bytes"] += 354
        after["peers"][0]["link_rx_packets"] += 1
        after["peers"][0]["vpn_rx_bytes"] += 312
        after["peers"][0]["vpn_rx_packets"] += 1
        for function in (matrix.dco_rejection_delta, verifier.verify_dco_rejection_delta):
            with self.assertRaises(ValueError):
                function(before, after)

    def test_dco_replay_delta_rejects_missing_link_ingress(self):
        before = self.peer()
        after = copy.deepcopy(before)
        after["peers"][0]["vpn_tx_bytes"] += 1
        for function in (matrix.dco_rejection_delta, verifier.verify_dco_rejection_delta):
            with self.assertRaises(ValueError):
                function(before, after)

    def test_frame_scan_count_accepts_bounded_multi_frame_and_rejects_invalid(self):
        # The real target run inspected 3–7 AF_PACKET frames before finding the exact hash.
        self.assertEqual(verifier.verify_frame_inspection_count({"frames_inspected": 7}), 7)
        self.assertEqual(verifier.verify_frame_inspection_count({"frames_inspected": 1_000_000}), 1_000_000)
        for value in (0, True, False, 1_000_001, None, "7"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    verifier.verify_frame_inspection_count({"frames_inspected": value})

    def test_exact_ingress_verifier_accepts_byte_identical_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            case_dir = Path(directory)
            capture_dir = case_dir / "capture-old"
            submit_dir = case_dir / "same-epoch-replay"
            witness_dir = case_dir / "same-epoch-replay-witness"
            for path in (capture_dir, submit_dir, witness_dir):
                path.mkdir()
            payload = bytes([0x30]) + bytes((i % 256 for i in range(1, 312)))
            source = self.frame(payload)
            submitted = encrypted.submitted_frame(source, "replay")
            capture_result = {
                "status": "captured",
                "frame_sha256": hashlib.sha256(source).hexdigest(),
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
            }
            (capture_dir / "frame.bin").write_bytes(source)
            capture_path = capture_dir / "result.json"
            capture_path.write_text(json.dumps(capture_result, indent=2, sort_keys=True) + "\n")
            helper_sha = hashlib.sha256((HERE / "encrypted_capture.py").read_bytes()).hexdigest()
            submission = {
                "status": "injection_submitted", "mode": "replay",
                "capture_metadata_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                "captured_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "helper_sha256": helper_sha,
                "submissions": [{"monotonic_ns": 1000}],
            }
            (submit_dir / "submitted-frame.bin").write_bytes(submitted)
            (submit_dir / "result.json").write_text(json.dumps(submission, indent=2, sort_keys=True) + "\n")
            witness = {
                "status": "captured", "direction": "incoming", "exact_ciphertext_match": True,
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "frame": "frame.bin", "frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "frames_inspected": 7, "monotonic_ns": 1100,
                "helper_sha256": helper_sha,
                "capture_state": {
                    "interface": "ovpn-us", "network_namespace_inode": 200,
                    "pid1_network_namespace_inode": 100,
                },
                "outer_checksums": encrypted.checksum_observation(submitted),
                "datagram": {"src": "192.0.2.2", "dst": "192.0.2.1", "dport": 1194},
            }
            (witness_dir / "frame.bin").write_bytes(submitted)
            (witness_dir / "result.json").write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n")
            injection = {
                "submission": submission, "peer_exact_witness": witness,
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "observation_finished_monotonic_ns": 1200,
                "old_receiver_alive_before_and_after_observation": True,
                "injection_command": {"label": "same-epoch-replay-submit", "exit_code": 0},
                "witness_command": {"label": "same-epoch-replay-witness", "exit_code": 0},
            }
            observed = verifier.verify_exact_ciphertext_ingress(
                case_dir, "same-epoch-replay", injection, capture_result, capture_path, payload,
                helper_sha)
            self.assertEqual(observed["mode"], "replay")
            self.assertEqual(observed["submit_monotonic_ns"], 1000)
            self.assertEqual(observed["observation_finished_monotonic_ns"], 1200)

    def test_exact_ingress_verifier_rejects_peer_frame_payload_change(self):
        with tempfile.TemporaryDirectory() as directory:
            case_dir = Path(directory)
            capture_dir = case_dir / "capture-old"
            submit_dir = case_dir / "same-epoch-replay"
            witness_dir = case_dir / "same-epoch-replay-witness"
            for path in (capture_dir, submit_dir, witness_dir):
                path.mkdir()
            payload = bytes([0x30]) + bytes((i % 256 for i in range(1, 312)))
            source = self.frame(payload)
            submitted = encrypted.submitted_frame(source, "replay")
            capture_result = {"status": "captured", "frame_sha256": hashlib.sha256(source).hexdigest(),
                              "ciphertext_sha256": hashlib.sha256(payload).hexdigest()}
            (capture_dir / "frame.bin").write_bytes(source)
            capture_path = capture_dir / "result.json"
            capture_path.write_text(json.dumps(capture_result, indent=2, sort_keys=True) + "\n")
            helper_sha = hashlib.sha256((HERE / "encrypted_capture.py").read_bytes()).hexdigest()
            submission = {"status": "injection_submitted", "mode": "replay",
                "capture_metadata_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                "captured_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "helper_sha256": helper_sha, "submissions": [{"monotonic_ns": 1000}]}
            (submit_dir / "submitted-frame.bin").write_bytes(submitted)
            (submit_dir / "result.json").write_text(json.dumps(submission, indent=2, sort_keys=True) + "\n")
            witness = {"status": "captured", "direction": "incoming", "exact_ciphertext_match": True,
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "frame": "frame.bin", "frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "frames_inspected": 1, "monotonic_ns": 1100, "helper_sha256": helper_sha,
                "capture_state": {"interface": "ovpn-us", "network_namespace_inode": 200,
                                  "pid1_network_namespace_inode": 100},
                "outer_checksums": encrypted.checksum_observation(submitted),
                "datagram": {"src": "192.0.2.2", "dst": "192.0.2.1", "dport": 1194}}
            damaged = bytearray(submitted);damaged[-1] ^= 1
            (witness_dir / "frame.bin").write_bytes(damaged)
            (witness_dir / "result.json").write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n")
            injection = {"submission": submission, "peer_exact_witness": witness,
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "observation_finished_monotonic_ns": 1200,
                "old_receiver_alive_before_and_after_observation": True,
                "injection_command": {"label": "same-epoch-replay-submit", "exit_code": 0},
                "witness_command": {"label": "same-epoch-replay-witness", "exit_code": 0}}
            with self.assertRaises(ValueError):
                verifier.verify_exact_ciphertext_ingress(
                    case_dir, "same-epoch-replay", injection, capture_result, capture_path, payload,
                    helper_sha)

    def frame(self, payload):
        src = socket.inet_aton("192.0.2.2")
        dst = socket.inet_aton("192.0.2.1")
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        total = 20 + 8 + len(payload)
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, src, dst))
        struct.pack_into("!H", ip, 10, encrypted.checksum(bytes(ip)))
        udp = bytearray(struct.pack("!HHHH", 1194, 1194, 8 + len(payload), 0) + payload)
        pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
        struct.pack_into("!H", udp, 6, encrypted.checksum(pseudo + bytes(udp)) or 0xffff)
        return ethernet + bytes(ip) + bytes(udp)



class ProfileInventoryTests(unittest.TestCase):
    def test_hia_hotspot_and_dco_profiles_keep_fixed_65_case_216_workload_inventory(self):
        plan = json.loads((HERE / "plan.json").read_text())
        cases = verifier.expected_cases(plan)
        profiles = [row["id"] for row in cases if row["kind"] == "profile"]
        self.assertEqual(profiles, ["profile-hia-user", "profile-c-dco"])
        self.assertEqual(len(cases), 65)
        self.assertEqual(sum(row["kind"] == "performance" for row in cases), 54)
        workloads = (plan["performance"]["rounds"]
                     * len(plan["performance"]["orders"])
                     * len(plan["performance"]["client_arms"])
                     * len(plan["performance"]["workloads"]))
        self.assertEqual(workloads, 216)

    def test_independent_verifier_requires_hia_process_sample(self):
        with self.assertRaises(ValueError):
            verifier.verify_profile_process_samples(
                {"openvpn_sample_headers_by_role": {"client": 0}}, "hia-user")
        verifier.verify_profile_process_samples(
            {"openvpn_sample_headers_by_role": {"client": 1}}, "hia-user")
        report = "\\n".join((
            "  1.25% openvpn [.] ovpn_hia_packet_id_read",
            "  0.75% openvpn [.] ovpn_hia_packet_id_write",
        ))
        verifier.verify_hia_profile_hotspot(
            {"hia_profile_symbol_lines": 2}, report, "hia-user")
        with self.assertRaises(ValueError):
            verifier.verify_hia_profile_hotspot(
                {"hia_profile_symbol_lines": 2},
                "  1.25% openvpn [.] ovpn_hia_packet_id_read_epoch", "hia-user")


class ContinuityLossEvidenceTests(unittest.TestCase):
    def fixture(self, root, missing=(5,6), receiver_stop=None):
        root=Path(root);sender_dir=root/"continuity-sender";receiver_dir=root/"continuity-receiver"
        sender_dir.mkdir();receiver_dir.mkdir()
        expected=8;size=256;run_id="continuity-fixture"
        missing=set(missing);sent=[i for i in range(expected) if i not in missing]
        errors=sorted(missing);echoes=sent;payloads=sent
        sender_events=[{"kind":"ready","run_id":run_id,"expected_count":expected}]
        sender_events += [{"kind":"sent","run_id":run_id,"sequence":i,"bytes":size} for i in sent]
        sender_events += [{"kind":"send_error","run_id":run_id,"sequence":i,"error":"[Errno 101] Network is unreachable"} for i in errors]
        sender_events += [{"kind":"echo","run_id":run_id,"sequence":i,"duplicate":False,"reordered":False,"bytes":size} for i in echoes]
        receiver_events=[{"kind":"ready","run_id":run_id,"expected_count":expected}]
        receiver_events += [{"kind":"payload","run_id":run_id,"sequence":i,"duplicate":False,"reordered":False,"bytes":size} for i in payloads]
        sender_path=sender_dir/"events.jsonl";receiver_path=receiver_dir/"events.jsonl"
        sender_path.write_text("".join(json.dumps(row,sort_keys=True)+"\n" for row in sender_events))
        receiver_path.write_text("".join(json.dumps(row,sort_keys=True)+"\n" for row in receiver_events))
        sender_sha=hashlib.sha256(sender_path.read_bytes()).hexdigest()
        receiver_sha=hashlib.sha256(receiver_path.read_bytes()).hexdigest()
        sender={"role":"sender","run_id":run_id,"expected_count":expected,"payload_size":size,
                "expected_payload_bytes":expected*size,"all_sends_attempted":True,"send_attempts":expected,
                "sent_packets":len(sent),"send_errors":len(errors),"received_packets":len(echoes),
                "unique_echoes":len(echoes),"missing_echo_count":len(errors),
                "missing_echo_ranges_inclusive":matrix.inclusive_ranges(errors),
                "duplicate_echoes":0,"invalid_echoes":0,"reordered_echoes":0,"unexpected_peer_packets":0,
                "deadline_reached":False,"stop_signal":None,"passed":False,"event_count":len(sender_events),
                "events":"events.jsonl","events_sha256":sender_sha}
        receiver={"role":"receiver","run_id":run_id,"expected_count":expected,"payload_size":size,
                  "expected_payload_bytes":expected*size,"received_packets":len(payloads),
                  "unique_packets":len(payloads),"valid_packets":len(payloads),"echoed_packets":len(payloads),
                  "missing_count":len(errors),"missing_ranges_inclusive":matrix.inclusive_ranges(errors),
                  "duplicate_packets":0,"invalid_packets":0,"reordered_packets":0,"foreign_run_packets":0,
                  "unexpected_peer_packets":0,"echo_errors":0,"deadline_reached":True,
                  "stop_signal":receiver_stop,"passed":False,"event_count":len(receiver_events),
                  "events":"events.jsonl","events_sha256":receiver_sha}
        continuity={"run_id":run_id,"sender":sender,"receiver":receiver,"sender_exit":1,
                    "receiver_exit":1,"passed":False}
        case={"continuity":continuity,"checks":{"continuity_all_losses_retained":True}}
        probe={"run_id":run_id,"count":expected,"size":size,
               "sender_dir":sender_dir,"receiver_dir":receiver_dir}
        plan={"behavior":{"continuous_count":expected,"strict_probe_size":size}}
        return probe,continuity,case,plan

    def test_completed_degraded_sender_is_accepted_only_when_every_loss_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe,continuity,case,plan=self.fixture(tmp)
            self.assertTrue(matrix.continuity_loss_receipt(probe,continuity))
            receipt=verifier.verify_continuity_loss_evidence(Path(tmp),case,plan)
            self.assertEqual(receipt["missing_echo_count"],2)
            self.assertEqual(receipt["missing_payload_count"],2)
            self.assertEqual(receipt["sender_exit"],1)

    def test_early_stopped_receiver_is_not_a_complete_continuity_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe,continuity,case,plan=self.fixture(tmp,receiver_stop=15)
            continuity["receiver"]["deadline_reached"]=False
            with self.assertRaises(ValueError):matrix.continuity_loss_receipt(probe,continuity)
            with self.assertRaises(ValueError):verifier.verify_continuity_loss_evidence(Path(tmp),case,plan)

    def test_missing_range_tampering_is_rejected_by_both_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe,continuity,case,plan=self.fixture(tmp)
            continuity["sender"]["missing_echo_ranges_inclusive"]=[[6,6]]
            with self.assertRaises(ValueError):matrix.continuity_loss_receipt(probe,continuity)
            with self.assertRaises(ValueError):verifier.verify_continuity_loss_evidence(Path(tmp),case,plan)

    def test_sender_completion_allows_exit_one_but_rejects_timeout_or_unbalanced_signal(self):
        self.assertEqual(matrix.continuity_sender_completion({"exit_code":1,"signals":[]})["sender_exit_code"],1)
        paired={"exit_code":1,"signals":[{"signal":signal.SIGSTOP},{"signal":signal.SIGCONT}]}
        self.assertEqual(matrix.continuity_sender_completion(paired)["sender_signals"],paired["signals"])
        for row in ({"exit_code":1,"timed_out":True,"signals":[]},
                    {"exit_code":2,"signals":[]},
                    {"exit_code":1,"signals":[{"signal":signal.SIGSTOP}]}):
            with self.assertRaises(ValueError):matrix.continuity_sender_completion(row)

    def test_security_subset_is_exactly_seven_behavior_and_two_authentication_cases(self):
        plan=json.loads((HERE/"plan.json").read_text())
        tasks=matrix.select_tasks(matrix.build_tasks(plan),"security")
        self.assertEqual(len(tasks),9)
        self.assertEqual(sum(row["kind"]=="behavior" for row in tasks),7)
        self.assertEqual(sum(row["kind"]=="authentication" for row in tasks),2)
        self.assertEqual(sum(row["kind"] in ("profile","performance") for row in tasks),0)
        expected=verifier.expected_cases_for_security(plan)
        self.assertEqual(len(expected),9)
        self.assertIn("not performance qualification",matrix.security_claim_limit(True))




class ReconnectReplayEndpointTests(unittest.TestCase):
    def status(self, port=46689, peer_id=1, extra=""):
        return (
            "TITLE\tOpenVPN 2.7.8\n"
            "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tPeer ID\n"
            f"CLIENT_LIST\tOpenVPN-HIA-client\tudp4:192.0.2.2:{port}\t10.77.0.2\t{peer_id}\n"
            + extra + "END\n"
        )

    def log(self, port=46689):
        return (
            "2026-11-07 06:12:09 us=283502 udp4:192.0.2.2:"
            f"{port} [OpenVPN-HIA-client] Peer Connection Initiated with [AF_INET]192.0.2.2:{port}"
        )

    def test_current_peer_endpoint_requires_status_and_latest_authenticated_log_to_agree(self):
        expected = {
            "remote_address": "udp4:192.0.2.2:46689",
            "source_ip": "192.0.2.2",
            "source_port": 46689,
            "peer_id": 1,
            "peer_init_line": self.log(),
        }
        self.assertEqual(matrix.active_peer_endpoint(self.status(), self.log()), expected)
        self.assertEqual(verifier.verify_active_peer_endpoint(self.status(), self.log()), expected)

    def test_stale_status_or_duplicate_client_rows_are_rejected(self):
        duplicate = self.status().replace(
            "END\n",
            "CLIENT_LIST\tOpenVPN-HIA-client\tudp4:192.0.2.2:46689\t10.77.0.2\t1\nEND\n",
        )
        for function in (matrix.active_peer_endpoint, verifier.verify_active_peer_endpoint):
            with self.subTest(function=function.__name__):
                with self.assertRaises(ValueError):
                    function(self.status(57102), self.log(46689))
                with self.assertRaises(ValueError):
                    function(duplicate, self.log())

    def test_reconnect_replay_rewrites_only_outer_udp_source_port(self):
        payload = bytes([0x30]) + bytes((index % 256 for index in range(1, 312)))
        original = DcoReplayEvidenceTests().frame(payload)
        rewritten = encrypted.submitted_frame(original, "replay", source_port=46689)
        before = encrypted.parse_frame(original)
        after = encrypted.parse_frame(rewritten)
        self.assertEqual(after["sport"], 46689)
        self.assertEqual(after["dport"], before["dport"])
        self.assertEqual(after["src"], before["src"])
        self.assertEqual(after["dst"], before["dst"])
        self.assertEqual(after["payload"], payload)
        self.assertTrue(all(encrypted.checksum_observation(rewritten).values()))

    def test_reconnect_replay_rejects_invalid_source_ports(self):
        payload = bytes([0x30]) + bytes((index % 256 for index in range(1, 312)))
        original = DcoReplayEvidenceTests().frame(payload)
        for value in (0, 65536, True, "46689"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    encrypted.submitted_frame(original, "replay", source_port=value)

    def test_independent_ingress_verifier_accepts_exact_ciphertext_on_current_port(self):
        with tempfile.TemporaryDirectory() as directory:
            case_dir = Path(directory)
            capture_dir = case_dir / "capture-old"
            submit_dir = case_dir / "after-reconnect-replay"
            witness_dir = case_dir / "after-reconnect-replay-witness"
            for path in (capture_dir, submit_dir, witness_dir):
                path.mkdir()
            payload = bytes([0x30]) + bytes((index % 256 for index in range(1, 312)))
            source = DcoReplayEvidenceTests().frame(payload)
            submitted = encrypted.submitted_frame(source, "replay", source_port=46689)
            capture_result = {
                "status": "captured",
                "frame_sha256": hashlib.sha256(source).hexdigest(),
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
            }
            (capture_dir / "frame.bin").write_bytes(source)
            capture_path = capture_dir / "result.json"
            capture_path.write_text(json.dumps(capture_result, indent=2, sort_keys=True) + "\n")
            helper_sha = hashlib.sha256((HERE / "encrypted_capture.py").read_bytes()).hexdigest()
            submission = {
                "status": "injection_submitted",
                "mode": "replay",
                "source_port_override": 46689,
                "capture_metadata_sha256": hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                "captured_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "submitted_frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "helper_sha256": helper_sha,
                "submissions": [{"monotonic_ns": 1000}],
            }
            (submit_dir / "submitted-frame.bin").write_bytes(submitted)
            (submit_dir / "result.json").write_text(json.dumps(submission, indent=2, sort_keys=True) + "\n")
            witness = {
                "status": "captured",
                "direction": "incoming",
                "exact_ciphertext_match": True,
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "frame": "frame.bin",
                "frame_sha256": hashlib.sha256(submitted).hexdigest(),
                "frames_inspected": 7,
                "monotonic_ns": 1100,
                "helper_sha256": helper_sha,
                "capture_state": {
                    "interface": "ovpn-us",
                    "network_namespace_inode": 200,
                    "pid1_network_namespace_inode": 100,
                },
                "outer_checksums": encrypted.checksum_observation(submitted),
                "datagram": {
                    "src": "192.0.2.2",
                    "dst": "192.0.2.1",
                    "sport": 46689,
                    "dport": 1194,
                },
            }
            (witness_dir / "frame.bin").write_bytes(submitted)
            (witness_dir / "result.json").write_text(json.dumps(witness, indent=2, sort_keys=True) + "\n")
            injection = {
                "submission": submission,
                "peer_exact_witness": witness,
                "expected_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "observation_finished_monotonic_ns": 1200,
                "old_receiver_alive_before_and_after_observation": True,
                "injection_command": {
                    "label": "after-reconnect-replay-submit",
                    "exit_code": 0,
                },
                "witness_command": {
                    "label": "after-reconnect-replay-witness",
                    "exit_code": 0,
                },
            }
            observed = verifier.verify_exact_ciphertext_ingress(
                case_dir, "after-reconnect-replay", injection, capture_result, capture_path,
                payload, helper_sha)
            self.assertEqual(observed["source_port"], 46689)
            self.assertEqual(observed["arrival_source_port"], 46689)




if __name__=='__main__':unittest.main(verbosity=2)
