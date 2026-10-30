"""Failure-accounting and fixed-runtime regressions; zero model loading."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.hia_agent_toolstudy_v11_20261030 import accounting, runtime, support
from tools import qualify_hia_agent_tool_capacity_v11 as capacity
from tools import qualify_hia_agent_toolstudy_v11 as study
from tools.provider_adapter.llama_cpp_engine import file_identity


class FakeEngine:
    """No subprocess, model, tokenizer or compiler is invoked by this stub."""
    def __init__(self, *, output_dir, identity="ok", close_error=False, complete_receipt=False,
                 timeout=False, delete_on_close=None, **_):
        self.output = Path(output_dir); self.output.mkdir(parents=True, exist_ok=False)
        self.process = SimpleNamespace(pid=31337, poll=lambda: 0)
        self.generation_count = self.response_count = self.preparation_count = 0
        self.service_calls = [{"endpoint": "/health", "wall_ns": 7, "success": True}]
        self.last_usage_receipt = None
        self.identity_mode = identity; self.close_error = close_error
        self.complete_receipt = complete_receipt; self.timeout = timeout
        self.delete_on_close = delete_on_close

    def verify_final_identity(self):
        if self.identity_mode == "raise":
            raise RuntimeError("injected final identity failure")
        return {"model_unchanged": self.identity_mode != "false", "runtime_unchanged": True}

    def close(self):
        if self.delete_on_close is not None:
            self.delete_on_close.unlink()
        if self.close_error:
            raise RuntimeError("injected close failure")

    def generate(self, *_, **__):
        self.generation_count += 1; self.preparation_count += 1
        self.response_count += int(self.complete_receipt)
        self.last_usage_receipt = {
            "complete": self.complete_receipt, "input_tokens": 7,
            "output_tokens": 3 if self.complete_receipt else None,
            "total_tokens": 10 if self.complete_receipt else None,
            "observed_output_token_lower_bound": 3,
        }
        if self.timeout:
            raise TimeoutError("injected partial stream")
        raise OSError("injected response persistence failure")


class RuntimeBindingTests(unittest.TestCase):
    def test_archive_member_manifest_and_arbitrary_helper_rejection(self):
        data = runtime.manifest()
        self.assertEqual(data["archive_bytes"], 17851611)
        self.assertEqual(data["archive_sha256"], runtime.ARCHIVE_SHA256)
        self.assertEqual(len(data["members"]), 40)
        self.assertEqual(sum(row["kind"] == "symlink" for row in data["members"]), 10)
        with self.assertRaisesRegex(ValueError, "PINNED_RUNTIME_ROLES"):
            support.tool_identities(sys.executable, sys.executable, sys.executable, sys.executable)

    def test_exact_companion_set_payload_and_link_topology(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = {"llama-server": b"server", "llama-tokenize": b"tokens", "libtest.so.1": b"library"}
            members = []
            for name, payload in payloads.items():
                (root / name).write_bytes(payload)
                members.append({"name": name, "kind": "regular", "linkname": None,
                                "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest()})
            alias = root / "libtest.so"; alias.symlink_to("libtest.so.1")
            members.append({**members[-1], "name": alias.name, "kind": "symlink", "linkname": "libtest.so.1"})
            with patch.object(runtime, "manifest", return_value={"members": members}):
                args = (root / "llama-server", root / "llama-tokenize")
                self.assertEqual(len(runtime.verify_runtime(*args)), 4)
                extra = root / "unexpected.so"; extra.write_bytes(b"extra")
                with self.assertRaisesRegex(ValueError, "COMPANION_SET"):
                    runtime.verify_runtime(*args)
                extra.unlink()
                (root / "libtest.so.1").write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "RUNTIME_BYTES"):
                    runtime.verify_runtime(*args)
                (root / "libtest.so.1").write_bytes(payloads["libtest.so.1"])
                alias.unlink()
                with self.assertRaisesRegex(ValueError, "COMPANION_SET"):
                    runtime.verify_runtime(*args)
                alias.symlink_to("llama-server")
                with self.assertRaisesRegex(ValueError, "RUNTIME_SYMLINK"):
                    runtime.verify_runtime(*args)


class FailureAccountingTests(unittest.TestCase):
    def _capacity(self, root, *, identity="ok", close_error=False, final_checks_fail=False):
        model = root / "model"; model.write_bytes(b"test-data-not-a-model")
        chosen = {"sha256": "test", "file": file_identity(model)}
        output = root / "capacity"
        def engine(**kwargs):
            return FakeEngine(**kwargs, identity=identity, close_error=close_error,
                              delete_on_close=model if final_checks_fail else None)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"LLAMA_ARG_REPACK": "0"}))
            for name, value in (("clean_committed_source", ("test-source", {})), ("check_model", chosen),
                                ("prompt_bindings", {}), ("cells", [])):
                stack.enter_context(patch.object(support, name, return_value=value))
            stack.enter_context(patch.object(support, "snapshot"))
            stack.enter_context(patch.object(capacity, "runtime_preflight", return_value={"test_only": True}))
            stack.enter_context(patch.object(capacity, "ToolStudyEngine", side_effect=engine))
            if final_checks_fail:
                stack.enter_context(patch.object(support, "bindings", side_effect=FileNotFoundError("source deleted")))
                stack.enter_context(patch.object(support, "tool_identities", side_effect=[{}, OSError("tool deleted")]))
            else:
                stack.enter_context(patch.object(support, "bindings", return_value={}))
                stack.enter_context(patch.object(support, "tool_identities", return_value={}))
            result = capacity.run(output=output, binary="unused", tokenizer="unused", model=str(model), clang="unused", rustc="unused")
        self.assertEqual(result, json.loads((output / "CAPACITY.json").read_text()))
        self.assertTrue((output / "TOKENIZER_SERVICE_CALLS.json").is_file())
        self.assertGreater(result["experiment_wall_ns"], 0)
        self.assertFalse(result["complete"])
        self.assertEqual(result["model_requests"], 0)
        return result

    def test_capacity_saves_report_after_identity_exception(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self._capacity(Path(folder), identity="raise")
            self.assertIsNone(result["engine_identity_after"])
            self.assertTrue(result["engine_finalization"]["finalization_errors"])

    def test_returned_false_identity_cannot_complete_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = FakeEngine(output_dir=Path(folder)/"engine", identity="false")
            record = accounting.finish_engine(engine, {}, capacity.evaluator.save, Path(folder)/"service.json")
            self.assertFalse(record["complete"])
            self.assertIn("model_identity_unconfirmed", record["failure_reasons"])

    def test_capacity_saves_costs_after_close_error_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self._capacity(Path(folder), close_error=True, final_checks_fail=True)
            self.assertFalse(result["engine_finalization"]["complete"])
            self.assertEqual({e["operation"] for e in result["finalization_errors"]},
                             {"source_unchanged", "tools_unchanged", "model_unchanged"})
            self.assertTrue(result["engine_exited"])

    def test_cli_cost_survives_receipt_persistence_failure(self):
        records = []
        with tempfile.TemporaryDirectory() as folder, patch.object(capacity.subprocess, "run", return_value=
                subprocess.CompletedProcess([], 0, stdout=b"[1, 2]", stderr=b"")), patch.object(
                capacity.evaluator, "save", side_effect=OSError("receipt write failed")):
            with self.assertRaises(OSError):
                capacity.verify_cli_tokens("unused", "unused", "text", [1, 2], special=False,
                                           receipt=Path(folder)/"receipt.json", records=records)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["matched"])
        self.assertGreater(records[0]["wall_ns"], 0)

    def _study(self, root, *, stage="calibration", complete_receipt=False, close_error=False, final_checks_fail=False):
        cfg = support.protocol()
        model = root / "model"; model.write_bytes(b"test-data-not-a-model")
        chosen = {"sha256": "test", "file": file_identity(model)}
        cap = root / "capacity.json"; cap.write_text("{}")
        calibration = root / "calibration.json"; calibration.write_text("{}")
        output = root / "study"
        task = {"id": "test_task", "category": "test"}
        arm = "calibration" if stage == "calibration" else "rust_node"
        query = {"query_sha256": "query", "source_revision": "rev"}
        bindings = {stage + "/test_task/" + arm: {"prompt_sha256": hashlib.sha256(b"fixed").hexdigest(),
                                                  "query_sha256": "query", "source_revision": "rev"}}
        original_read = Path.read_bytes
        def read(path):
            return b"LLAMA_ARG_REPACK=0\0" if str(path) == "/proc/31337/environ" else original_read(path)
        def engine(**kwargs):
            return FakeEngine(**kwargs, complete_receipt=complete_receipt, close_error=close_error,
                              timeout=close_error, delete_on_close=model if final_checks_fail else None)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"LLAMA_ARG_REPACK": "0"}))
            for name, value in (("clean_committed_source", ("test-source", {})), ("check_model", chosen),
                                ("prompt_bindings", bindings), ("cells", [(task, arm)]),
                                ("session_for", SimpleNamespace(query=lambda: query)),
                                ("validate_capacity", None), ("validate_qualification", {"eligible": True})):
                stack.enter_context(patch.object(support, name, return_value=value))
            stack.enter_context(patch.object(support, "snapshot"))
            stack.enter_context(patch.object(support, "protocol", side_effect=[cfg, FileNotFoundError("protocol deleted")]))
            stack.enter_context(patch.object(study, "runtime_preflight", return_value={"test_only": True}))
            stack.enter_context(patch.object(study, "ToolStudyEngine", side_effect=engine))
            stack.enter_context(patch.object(study.prompts, "prompt", return_value="fixed"))
            stack.enter_context(patch.object(Path, "read_bytes", read))
            if final_checks_fail:
                stack.enter_context(patch.object(support, "bindings", side_effect=[{}, FileNotFoundError("source deleted")]))
                stack.enter_context(patch.object(support, "tool_identities", side_effect=[{}, OSError("tool deleted")]))
            else:
                stack.enter_context(patch.object(support, "bindings", return_value={}))
                stack.enter_context(patch.object(support, "tool_identities", return_value={}))
            result = study.run(stage=stage, output=output, model=str(model), binary="unused", tokenizer="unused",
                               clang="unused", rustc="unused", capacity=str(cap),
                               calibration_result=str(calibration) if stage == "main" else None)
        self.assertEqual(result, json.loads((output / "RESULT.json").read_text()))
        self.assertFalse(result["valid_observation"])
        self.assertFalse(result["calibration_eligible"])
        self.assertEqual(result["requests"], 1)
        self.assertGreater(result["experiment_wall_ns"], 0)
        self.assertGreater(result["cells"][0]["cell_wall_ns"], 0)
        return result

    def test_study_close_error_retains_request_and_unknown_cost(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self._study(Path(folder), close_error=True)
            self.assertEqual(result["responses"], 0)
            self.assertEqual(result["known_input_tokens"], 7)
            self.assertEqual(result["partial_output_token_lower_bound"], 3)
            self.assertEqual(result["unknown_usage_requests"], 1)
            self.assertIsNone(result["total_tokens"])
            self.assertFalse(result["engines"][0]["complete"])

    def test_main_final_file_failures_preserve_result_without_reloading_protocol(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self._study(Path(folder), stage="main", final_checks_fail=True)
            self.assertEqual(len(result["finalization_errors"]), 3)
            self.assertIsNone(result["total_tokens"])
            self.assertFalse(result["summary"]["descriptive_advantage_gate"])

    def test_complete_terminal_receipt_retains_cost_but_not_eligibility(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self._study(Path(folder), complete_receipt=True)
            self.assertEqual(result["responses"], 1)
            self.assertEqual(result["total_tokens"], 10)
            self.assertEqual(result["recovered_terminal_usage_receipts"], 1)
            self.assertIsNone(result["cells"][0]["attempts"][0]["usage"])

    def test_usage_never_double_counts_a_receipt_or_invents_missing_usage(self):
        usage = {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
        result = accounting.usage_summary([{"actual_generation_requested": True, "usage": usage,
                                            "partial_usage": {**usage, "complete": True}}], 1)
        self.assertEqual(result["total_tokens"], 10)
        unknown = accounting.usage_summary([{"actual_generation_requested": True, "usage": None}], 1)
        self.assertEqual(unknown["unknown_usage_requests"], 1)
        self.assertIsNone(unknown["total_tokens"])
        self.assertIsNone(accounting.counter_sum([{"requests": None}], "requests"))


if __name__ == "__main__":
    unittest.main()
