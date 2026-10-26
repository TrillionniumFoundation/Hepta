"""Byte values and memory tokens are finite external test instructions."""
from copy import deepcopy
import unittest

from test_hia_resource_trace import fixture
from hepta.hia_byte_trace import HIAByteTraceRejected, replay_byte_memory_path


def program():
    graph, receipt = fixture(borrow=True)
    ops=graph["functions"][0]["blocks"][0]["ops"]
    # Borrow is read-only, so one value read after a newly allocated zeroed buffer.
    assert [op["op"] for op in ops] == ["acquire","borrow","use","end_borrow"]
    return graph, receipt

class HIAByteTraceTests(unittest.TestCase):
    def test_read_zero_through_shared_loan_and_drop(self):
        graph, receipt = program()
        for value in (True, False):
            result=replay_byte_memory_path(graph,receipt,"f",inputs={"p0":value},actions=(
                {"kind":"alloc","bytes":16},{"kind":"read","index":5}))
            self.assertEqual(result["allocation_count"],1)
            self.assertEqual(result["free_count"],1)
            self.assertEqual(result["memory_token_final"],2)
            self.assertEqual(result["peak_live_bytes"],16)
            self.assertTrue(any(ev["kind"]=="read" and ev["value"]==0 for ev in result["memory_observations"]))
            self.assertFalse(result["claims"]["full_memory_ssa_proved"])

    def test_owned_move_and_memory_release(self):
        graph, receipt = fixture()
        ops=graph["functions"][0]["blocks"][0]["ops"]
        ops.insert(1,{"op":"move","src":"v0","dest":"v1"})
        graph["functions"][0]["locals"].append({"id":"v1","type":"Buffer<u8>","mutable":False})
        for block in graph["functions"][0]["blocks"][1:]:
            for operation in block["ops"]:
                if operation["op"] == "drop":
                    operation["src"] = "v1"
        # Our stripped Resource IR verifier fixture accepts this valid transfer.
        from hepta.resource_ir import verify_resource_ir
        receipt=verify_resource_ir(graph)
        self.assertTrue(receipt["ok"],receipt)
        report=replay_byte_memory_path(graph,receipt,"f",inputs={"p0":False},actions=({"kind":"alloc","bytes":4},))
        self.assertEqual(report["allocation_count"],1)
        self.assertEqual(report["free_count"],1)
        self.assertEqual(report["memory_token_final"],2)
        self.assertTrue(any(ev["kind"]=="move" for ev in report["memory_observations"]))

    def test_out_of_bounds_and_type_confusion_fail_closed(self):
        graph, receipt=program()
        for extra in (({"kind":"alloc","bytes":8},{"kind":"read","index":8}),
                      ({"kind":"alloc","bytes":8},{"kind":"read","index":True}),
                      ({"kind":"alloc","bytes":-1},{"kind":"read","index":0}),
                      ({"kind":"alloc","bytes":False},{"kind":"read","index":0}),
                      ({"kind":"alloc","bytes":8},{"kind":"read","index":0},{"kind":"read","index":0}),
                      ({"kind":"alloc","bytes":8},),
                      ({"kind":"alloc","bytes":8},{"kind":"write","index":0,"value":42}),):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(HIAByteTraceRejected,"E_HIA_BYTE_TRACE"):
                    replay_byte_memory_path(graph,receipt,"f",inputs={"p0":True},actions=extra)

    def test_mutable_borrow_write_then_read_tracks_memory_token(self):
        graph, receipt=program()
        for op in graph["functions"][0]["blocks"][0]["ops"]:
            if op["op"] == "borrow": op["mode"] = "mut"
            if op["op"] == "use": op["mode"] = "write"
        from hepta.resource_ir import verify_resource_ir
        receipt = verify_resource_ir(graph)
        self.assertTrue(receipt["ok"])
        report=replay_byte_memory_path(graph, receipt, "f", inputs={"p0":True}, actions=(
            {"kind":"alloc","bytes":4},{"kind":"write","index":0,"value":255}))
        self.assertEqual(report["memory_token_final"], 3)
        self.assertEqual(report["memory_observations"][2]["value"], 255)
        self.assertEqual(report["free_count"], 1)

    def test_unhashable_resource_access_shape_rejects(self):
        graph, receipt=program()
        for malicious in (["read"], ["write"], {"mode":"read"}):
            changed=deepcopy(graph)
            changed["functions"][0]["blocks"][0]["ops"][2]["mode"] = malicious
            with self.subTest(malicious=malicious):
                with self.assertRaisesRegex(HIAByteTraceRejected,"E_HIA_BYTE_TRACE"):
                    replay_byte_memory_path(changed,receipt,"f",inputs={"p0":True},actions=(
                        {"kind":"alloc","bytes":4},{"kind":"read","index":0}))

    def test_forged_external_memory_receipt_rejects(self):
        graph, receipt=program()
        other=deepcopy(receipt);other["ir_sha256"]="f"*64
        with self.assertRaisesRegex(HIAByteTraceRejected,"E_HIA_BYTE_TRACE"):
            replay_byte_memory_path(graph,other,"f",inputs={"p0":True},actions=(
                {"kind":"alloc","bytes":4},{"kind":"read","index":0}))

    def test_indexed_buffer_projection_uses_checked_resource_place(self):
        # * is the Resource IR index projection, not a value-level SSA fact.
        from hepta.resource_ir import verify_resource_ir
        for cond in (False, True):
            graph, _ = fixture()
            fn = graph["functions"][0]
            fn["locals"][0]["mutable"] = True
            ops = fn["blocks"][0]["ops"]
            ops.insert(1, {"op": "use", "place": {"root": "v0", "path": ["*"]},
                           "mode": "write"})
            ops.insert(2, {"op": "use", "place": {"root": "v0", "path": ["*"]},
                           "mode": "read"})
            verified = verify_resource_ir(graph)
            self.assertTrue(verified["ok"], verified)
            report = replay_byte_memory_path(
                graph, verified, "f", inputs={"p0": cond},
                actions=({"kind": "alloc", "bytes": 4},
                         {"kind": "write", "index": 1, "value": 72},
                         {"kind": "read", "index": 1}))
            self.assertEqual(report["allocation_count"], 1)
            self.assertEqual(report["free_count"], 1)
            self.assertEqual(report["memory_token_final"], 3)
            self.assertEqual(
                [event["value"] for event in report["memory_observations"]
                 if event["kind"] == "read"], [72])
            self.assertFalse(report["claims"]["memory_bytes_match_original_source_proved"])
            with self.assertRaisesRegex(HIAByteTraceRejected, "E_HIA_BYTE_TRACE"):
                replay_byte_memory_path(
                    graph, verified, "f", inputs={"p0": cond},
                    actions=({"kind": "alloc", "bytes": 4},
                             {"kind": "write", "index": 4, "value": 72},
                             {"kind": "read", "index": 1}))

if __name__ == "__main__": unittest.main()
