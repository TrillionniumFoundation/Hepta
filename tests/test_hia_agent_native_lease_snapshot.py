"""Actual native invocations retain the admitted lease identity."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta.hia_agent_runner import run_native_batch
from tests.test_hia_agent_buffer_lifecycle import NATIVE, workload
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.test_hia_native_byte_abi import byte_program


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld are required")
class LeaseSnapshotTests(AgentToolCase):
    def test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers(self):
        _, _, base, built, receipts = self.build_pair(document=byte_program(),
            candidate=byte_program(), workload=workload())
        evaluation = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(evaluation["outcome"], "unchanged")
        self.client.result("hia_adopt", self.session.arguments(target_slot="lease-snapshot",
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=built["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
        caller_lease = self.service.acquire_slot("lease-snapshot")
        admitted = deepcopy(caller_lease)

        def mutate_caller_then_execute(*args, **kwargs):
            # Emulate the caller changing its shared dictionary while the
            # synchronous invocation is in its disposable native runner.
            caller_lease["id"] = "lease-relabelled"
            caller_lease["slot"] = "other-slot"
            caller_lease["generation"] = "999"
            caller_lease["artifact"]["sha256"] = "0" * 64
            return run_native_batch(*args, **kwargs)

        with patch("hepta.hia_agent_runner.run_native_batch", side_effect=mutate_caller_then_execute):
            result = self.service.invoke_lease(caller_lease, "copy_bytes",
                [{"bytes_hex": "0102fe"}, {"byte_length": 4, "fill_byte": 3}])
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["generation"], admitted["generation"])
        self.assertEqual(result["artifact"], admitted["artifact"])
        self.assertEqual(len(result["buffers"]), 2)
        for buffer in result["buffers"]:
            data, metadata = self.service.store.get(buffer["artifact"], kind="invocation-buffer")
            self.assertEqual(metadata["lease"], admitted["id"])
            self.assertEqual(metadata["generation"], admitted["generation"])
            self.assertEqual(metadata["artifact"], admitted["artifact"])
            if buffer["argument"] == 1:
                self.assertEqual(data, b"\x01\x02\xfe\x03")
        self.service.release_slot(admitted)


if __name__ == "__main__":
    unittest.main()
