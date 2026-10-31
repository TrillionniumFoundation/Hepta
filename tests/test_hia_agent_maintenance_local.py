"""Controlled local transport/state-machine checks, never model successes."""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import qualify_hia_agent_maintenance as maintenance
from tools import qualify_hia_agent_maintenance_local as study
from tools import hia_agent_llama_transport as transport
from tools.hia_agent_codex_transport import canonical, identity, save
from tools.provider_adapter import hia_maintenance_llama_worker as worker


def process(status="exited"):
    return {"pid": 999, "pgid": 999, "status": status, "cleanup_confirmed": True,
            "leader_reaped": True, "wall_ns": 10}


def usage():
    return {"input_tokens": 100, "output_tokens": 5, "returned_token_ids": 4, "total_tokens": 105}


def answer(action, *, qualified=True, used=True):
    u = usage() if used else None
    return {"process": process(), "usage": u, "qualified": qualified,
            "observed_prefix": {"worker": None, "usage": u, "generation_endpoint_attempted": True,
                                "completion_received": used, "generation_count": 1,
                                "response_count": 1 if used else None, "observability": "synthetic_bound_fixture",
                                "validation_errors": []},
            "worker": {"text": json.dumps(action), "generation_endpoint_attempted": True,
                       "completion_received": used, "usage": u}}


def write_bound_completion(request, *, terminal, tamper=None):
    """Synthetic native records for accounting controls; no model is invoked."""
    out = Path(request["evidence_dir"]); out.mkdir(parents=True)
    ids = [1] * 100
    text = '{"action":"catalog"}'
    payload = {"prompt": ids, "n_predict": 1536, "temperature": 0, "seed": 0, "cache_prompt": False}
    raw = {"content": text, "tokens": [4, 5, 6, 7], "truncated": False, "stop_type": "eos",
           "tokens_evaluated": 100, "generation_settings": {"params": {"temperature": 0, "seed": 0}},
           "timings": {"predicted_n": 5}}
    native_request = {"messages": [{"role": "user", "content": request["text"]}],
                      "rendered_prompt": "controlled rendered prompt", "payload": payload}
    generation = {"schema": "hepta.gguf-generation.v1", "status": "completed", "text": text,
                  "rendered_prompt": native_request["rendered_prompt"], "input_token_ids": ids,
                  "output_token_ids": raw["tokens"], "request": payload, "response": raw, "usage": usage()}
    save(out / "GENERATION.json", generation)
    save(out / "engine/transport-001.request.json", native_request)
    save(out / "engine/transport-001.response.raw", raw)
    save(out / "engine/identity.json", {"model": {"sha256": request["runtime"]["model_sha256"]},
         "runtime_files": request["runtime"]["runtime_files"], "context": 8192, "threads": 4,
         "decoder": {"mode": "unconstrained"}})
    if tamper == "messages":
        native_request["messages"][0]["content"] = "a different request"
        save(out / "engine/transport-001.request.json", native_request)
    elif tamper == "tokens":
        native_request["payload"]["prompt"] = [2] * 100
        save(out / "engine/transport-001.request.json", native_request)
    reply = {"schema": worker.RECEIPT_SCHEMA, "mode": request["mode"],
             "status": "completed" if terminal else "starting",
             "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
             "text_sha256": hashlib.sha256(request["text"].encode()).hexdigest(),
             "protocol_sha256": request["protocol_sha256"], "usage": usage() if terminal else None,
             "generation_endpoint_attempted": terminal, "completion_received": terminal,
             "worker_pid": 999, "worker_pgid": 999, "server_pgid": 999,
             "inner_cleanup_confirmed": terminal, "socket_removed": terminal,
             "final_identity": {"model_unchanged": True, "runtime_unchanged": True},
             "generation_count": 1 if terminal else 0, "response_count": 1 if terminal else 0,
             "unknown_usage": not terminal, "text": text, "generation": identity(out / "GENERATION.json")}
    save(out / "RECEIPT.json", reply)


class LocalUsageTests(unittest.TestCase):
    def test_actual_four_field_usage_and_eos_delta_are_preserved(self):
        actual = usage()
        checked = transport.checked_usage(actual)
        self.assertEqual(checked, actual)
        actual["input_tokens"] = 0
        self.assertEqual(checked["input_tokens"], 100)
        self.assertNotIn("cached_input_tokens", checked)
        self.assertNotIn("reasoning_output_tokens", checked)

    def test_false_counters_boolean_overflow_and_inconsistent_totals_are_refused(self):
        cases = []
        for key, value in [("cached_input_tokens", 0), ("reasoning_output_tokens", 0),
                           ("input_tokens", True), ("input_tokens", 6657),
                           ("output_tokens", 1537), ("output_tokens", 0),
                           ("returned_token_ids", 2), ("total_tokens", 106)]:
            item = usage(); item[key] = value; cases.append(item)
        for item in cases:
            with self.subTest(usage=item), self.assertRaises(transport.LocalTransportFailure):
                transport.checked_usage(item)


class ConfigAndBudgetTests(unittest.TestCase):
    def test_oversized_text_is_refused_before_persisting_model_request_or_owner(self):
        with tempfile.TemporaryDirectory() as td, patch.object(maintenance, "run_owned") as owner:
            path = Path(td) / "request"
            caught = None
            try:
                transport.invoke("x" * (1024**2 + 1), path, study.protocol(), deadline=time.monotonic() + 20)
            except Exception as error:
                caught = error
            self.assertIsInstance(caught, transport.LocalTransportFailure)
            owner.assert_not_called(); self.assertFalse(path.exists())

    def test_worker_default_remains_original_protocol_and_override_is_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            candidate = base / "candidate.json"
            save(candidate, "fn target(x:u32,y:u32)->u32 { 0 }")
            recorded = []
            def compile_only(argv, **kwargs):
                recorded.append(argv)
                return SimpleNamespace(returncode=1, stdout="", stderr="controlled compiler refusal")
            for index, override in enumerate([None, {"rustc": "/explicit/rustc"}]):
                args = argparse.Namespace(task="quota_reserve", language="rust", mode="public",
                                          candidate=str(candidate), build=None, output=str(base / str(index)))
                with patch.object(maintenance, "protocol", return_value={"rustc": "/default/rustc"}) as default, \
                        patch.object(maintenance.subprocess, "run", side_effect=compile_only):
                    maintenance.evaluate_worker(args, tool_config=override)
                    self.assertEqual(default.call_count, int(override is None))
            self.assertEqual([row[0] for row in recorded], ["/default/rustc", "/explicit/rustc"])

    def test_protocol_preserves_task_and_wall_limits_and_declares_local_token_difference(self):
        cfg = study.protocol(); inherited = maintenance.protocol()
        for key in ["tasks", "max_requests_per_cell", "max_public_checks_per_cell", "max_cell_wall_seconds",
                    "max_request_wall_seconds", "max_experiment_wall_seconds", "cleanup_reserve_seconds", "transport"]:
            self.assertEqual(cfg[key], inherited[key])
        self.assertEqual((cfg["context_tokens"], cfg["output_reserve_tokens"]), (8192, 1536))
        self.assertNotEqual(cfg["models"], inherited["models"])

    def test_request_preparation_expiry_refuses_owner_without_cleanup_poison(self):
        clock = [10.0]
        real_save = transport.save
        def persist(path, value):
            real_save(path, value)
            clock[0] = 12.0
        with tempfile.TemporaryDirectory() as td, patch.object(transport.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(transport, "save", side_effect=persist), patch.object(maintenance, "run_owned") as owner:
            with self.assertRaises(maintenance.WallBudgetExhausted) as raised:
                transport.invoke("public only", Path(td) / "request", study.protocol(), deadline=11.0)
            self.assertFalse(raised.exception.record["owner_call_attempted"])
            owner.assert_not_called()

    def test_request_persistence_error_cannot_launch_owner(self):
        with tempfile.TemporaryDirectory() as td, patch.object(transport, "save", side_effect=OSError("controlled disk failure")), \
                patch.object(maintenance, "run_owned") as owner:
            with self.assertRaises(OSError):
                transport.invoke("public only", Path(td) / "request", study.protocol(), deadline=time.monotonic() + 20)
            owner.assert_not_called()

    def test_missing_formal_freeze_refuses_before_runtime_or_git(self):
        cfg = study.protocol()
        with tempfile.TemporaryDirectory() as td, patch.object(study, "HERE", Path(td)), \
                patch.object(study, "protocol", return_value=cfg), \
                patch.object(transport, "invoke") as model, patch.object(study.subprocess, "check_output") as git:
            with self.assertRaises(FileNotFoundError):
                study.run(Path(td) / "out", Path(td) / "no-review", "unregistered")
            model.assert_not_called(); git.assert_not_called()


class WorkerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "fixture-runtime"
        self.binary.write_bytes(b"synthetic runtime identity; never executed")
        self.endpoints = []
        self.clock = [10.0]
        self.request = {"schema": worker.REQUEST_SCHEMA, "mode": "capacity_probe", "text": "public task only",
                        "runtime": {"binary": str(self.binary), "model": str(self.root / "not-a-real-model"),
                                    "model_sha256": worker.MODEL_SHA256,
                                    "engine_source_sha256": identity(worker.ROOT / "tools/provider_adapter/llama_cpp_engine.py")["sha256"],
                                    "runtime_files": [identity(self.binary)]},
                        "context": 8192, "output_limit": 1536, "threads": 4,
                        "deadline_monotonic": 20.0, "evidence_dir": str(self.root / "evidence"),
                        "protocol_sha256": "1" * 64}
        endpoints = self.endpoints
        runtime_files = self.request["runtime"]["runtime_files"]
        class FakeEngine:
            def __init__(self, *, output_dir, **kwargs):
                self.output = Path(output_dir); self.output.mkdir()
                save(self.output / "identity.json", {"controlled_engine": True})
                self.runtime_identity = runtime_files
                self.process = SimpleNamespace(pid=os.getpid(), poll=lambda: 0, returncode=0)
                self.socket_path = str(self.output / "never-created.sock")
                self.generation_count = 0; self.response_count = 0
            def request(self, endpoint, payload=None, timeout=10):
                endpoints.append(endpoint)
                return {"prompt": "rendered public input", "tokens": [1, 2, 3]}
            def tokenize(self, text, special=False):
                return self.request("/tokenize", {"text": text})["tokens"]
            def generate(self, messages, **kwargs):
                self.generation_count += 1
                self.request("/completion", {"controlled": True})
                self.response_count += 1
                return {"text": '{"action":"catalog"}', "usage": usage()}
            def verify_final_identity(self):
                return {"model_unchanged": True, "runtime_unchanged": True}
            def close(self):
                pass
        self.engine = FakeEngine

    def test_capacity_probe_has_no_completion_or_synthetic_usage(self):
        with patch.object(worker.time, "monotonic", side_effect=lambda: self.clock[0]):
            row = worker.execute(self.request, engine_class=self.engine)
        self.assertEqual(row["status"], "capacity_probe_complete")
        self.assertEqual(row["generation_count"], 0)
        self.assertIsNone(row["usage"])
        self.assertNotIn("/completion", self.endpoints)

    def test_completion_is_refused_if_receipt_cost_exhausts_deadline(self):
        self.request["mode"] = "generate"
        real_save = worker.save
        def persist(path, value):
            real_save(path, value)
            if value.get("requests") and value["requests"][-1]["endpoint"] == "/completion":
                self.clock[0] = 21.0
        with patch.object(worker.time, "monotonic", side_effect=lambda: self.clock[0]), patch.object(worker, "save", side_effect=persist):
            row = worker.execute(self.request, engine_class=self.engine)
        self.assertEqual(row["status"], "worker_failed")
        self.assertFalse(row["generation_endpoint_attempted"])
        self.assertNotIn("/completion", self.endpoints)

    def test_runtime_drift_is_rejected_before_engine_start(self):
        self.binary.write_bytes(b"changed")
        with patch.object(worker, "LlamaCppEngine") as constructor, self.assertRaises(ValueError):
            worker.execute(self.request, engine_class=constructor)
        constructor.assert_not_called()


class ReceiptTests(unittest.TestCase):
    def test_bounded_json_reads_limit_plus_one_and_refuses_growth_after_small_metadata(self):
        reads = []
        raw = b"{}" + b" " * 64
        class Reader(io.BytesIO):
            def read(self, size=-1):
                reads.append(size); return super().read(size)
        class GrowingFile:
            def stat(self): return SimpleNamespace(st_size=2)
            def read_bytes(self): reads.append(-1); return raw
            def open(self, mode): return Reader(raw)
        caught = None
        try:
            transport._bounded_json(GrowingFile(), 64)
        except Exception as error:
            caught = error
        self.assertIsInstance(caught, transport.LocalTransportFailure)
        self.assertEqual(reads, [65])

    def test_receipt_path_cannot_use_small_stat_to_read_more_than_one_mib(self):
        reads = []
        request = {"mode": "generate", "text": "public", "protocol_sha256": "1" * 64}
        record = {"schema": worker.RECEIPT_SCHEMA, "mode": "generate", "status": "starting",
                  "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
                  "text_sha256": hashlib.sha256(b"public").hexdigest(), "protocol_sha256": "1" * 64,
                  "usage": None}
        small = canonical(record); raw = small + b" " * (1024**2 + 2 - len(small))
        class Reader(io.BytesIO):
            def read(self, size=-1):
                reads.append(size); return super().read(size)
        class GrowingPath:
            def __truediv__(self, value): return self
            def is_file(self): return True
            def stat(self): return SimpleNamespace(st_size=len(small))
            def read_bytes(self): reads.append(-1); return raw
            def open(self, mode): return Reader(raw)
        caught = None
        with patch.object(transport, "Path", return_value=GrowingPath()):
            try:
                transport.read_receipt("fixture", request)
            except Exception as error:
                caught = error
        self.assertIsInstance(caught, transport.LocalTransportFailure)
        self.assertEqual(reads, [1024**2 + 1])

    def test_persisted_generation_usage_survives_interrupted_final_worker_metadata(self):
        def owner(phase, argv, cwd, output, **kwargs):
            write_bound_completion(json.loads(kwargs["input_bytes"]), terminal=False)
            return process("wall_timeout")
        with tempfile.TemporaryDirectory() as td:
            result = transport.invoke("public", Path(td) / "request", study.protocol(), deadline=time.monotonic() + 20, owned=owner)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["usage"], usage())
        self.assertTrue(result["observed_prefix"]["completion_received"])

    def test_full_bound_completion_retains_actual_usage_and_qualifies(self):
        def owner(phase, argv, cwd, output, **kwargs):
            write_bound_completion(json.loads(kwargs["input_bytes"]), terminal=True)
            return process()
        with tempfile.TemporaryDirectory() as td:
            result = transport.invoke("public", Path(td) / "request", study.protocol(), deadline=time.monotonic() + 20, owned=owner)
        self.assertTrue(result["qualified"]); self.assertEqual(result["usage"], usage())

    def test_changed_native_prompt_or_token_ids_cannot_qualify_completed_worker_metadata(self):
        for tamper in ["messages", "tokens"]:
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as td:
                def owner(phase, argv, cwd, output, **kwargs):
                    write_bound_completion(json.loads(kwargs["input_bytes"]), terminal=True, tamper=tamper)
                    return process()
                result = transport.invoke("public", Path(td) / "request", study.protocol(), deadline=time.monotonic() + 20, owned=owner)
                self.assertFalse(result["qualified"])
                self.assertTrue(result["process"]["cleanup_confirmed"])

    def test_failed_owner_keeps_valid_observed_usage_without_qualification(self):
        cfg = study.protocol()
        def owner(phase, argv, cwd, output, **kwargs):
            req = json.loads(kwargs["input_bytes"])
            payload = Path(req["evidence_dir"]); payload.mkdir()
            import hashlib
            save(payload / "RECEIPT.json", {"schema": worker.RECEIPT_SCHEMA, "mode": req["mode"],
                 "status": "worker_failed", "request_sha256": hashlib.sha256(canonical(req)).hexdigest(),
                 "text_sha256": hashlib.sha256(req["text"].encode()).hexdigest(),
                 "protocol_sha256": req["protocol_sha256"], "usage": usage()})
            return process("process_failure")
        with tempfile.TemporaryDirectory() as td:
            result = transport.invoke("public", Path(td) / "request", cfg, deadline=time.monotonic() + 20, owned=owner)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["usage"], usage())

    def test_unconfirmed_outer_cleanup_poison_precedes_receipt_qualification(self):
        def owner(*args, **kwargs):
            value = process(); value["cleanup_confirmed"] = False; return value
        with tempfile.TemporaryDirectory() as td, self.assertRaises(maintenance.CleanupUncertain):
            transport.invoke("public", Path(td) / "request", study.protocol(), deadline=time.monotonic() + 20, owned=owner)


class CellStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.cfg = study.protocol(); self.task = maintenance.TASKS[0]

    def cell(self):
        return study.run_cell(self.task, "rust", self.root / "cell", time.monotonic() + 1000, self.cfg, verify=lambda: None)

    def test_unknown_usage_ends_cell_without_evaluation(self):
        with patch.object(transport, "invoke", return_value=answer({"action": "catalog"}, qualified=False, used=False)) as model, \
                patch.object(study, "evaluate") as evaluator:
            row = self.cell()
        self.assertEqual(model.call_count, 1); evaluator.assert_not_called()
        self.assertFalse(row["complete_usage"]); self.assertIsNone(row["requests"][0]["observed_usage"])

    def test_later_unknown_recovery_cannot_erase_known_usage_or_endpoint_flags(self):
        unknown = {"worker": None, "usage": None, "generation_endpoint_attempted": None,
                   "completion_received": None, "generation_count": None, "response_count": None,
                   "observability": "unknown", "validation_errors": [{"type": "OSError", "message": "controlled later read failure"}]}
        with patch.object(transport, "invoke", return_value=answer({"action": "final", "candidate": "wrong"})), \
                patch.object(study, "evaluate", side_effect=ValueError("controlled later public failure")), \
                patch.object(study, "recover_prefix", return_value=unknown):
            row = self.cell()
        receipt = row["requests"][0]
        self.assertEqual(receipt["observed_usage"], usage())
        self.assertTrue(receipt["generation_endpoint_attempted"])
        self.assertTrue(receipt["completion_received"])
        self.assertEqual(receipt["generation_count"], 1)
        self.assertEqual(row["charged_tokens"], 105)

    def test_cleanup_uncertainty_without_terminal_receipt_keeps_endpoint_status_unknown(self):
        error = maintenance.CleanupUncertain("model", None, self.root / "transport", 20)
        with patch.object(transport, "invoke", side_effect=error):
            row = self.cell()
        self.assertTrue(row["experiment_poisoned"])
        self.assertIsNone(row["requests"][0]["generation_endpoint_attempted"])
        self.assertIsNone(row["requests"][0]["completion_received"])

    def test_confirmed_owner_with_malformed_usage_keeps_process_and_only_fails_cell(self):
        def owner(phase, argv, cwd, output, **kwargs):
            request = json.loads(kwargs["input_bytes"])
            write_bound_completion(request, terminal=False)
            # Remove completion artifacts: only this malformed worker usage
            # remains, so it cannot supply known output cost.
            Path(request["evidence_dir"], "GENERATION.json").unlink()
            path = Path(request["evidence_dir"], "RECEIPT.json")
            value = json.loads(path.read_text()); value["usage"] = {**usage(), "cached_input_tokens": 0}
            save(path, value)
            return process()
        with patch.object(maintenance, "checked_owned", side_effect=owner), patch.object(study, "evaluate") as evaluator:
            row = self.cell()
        self.assertEqual(row["status"], "terminal_runtime_or_protocol_failure")
        self.assertFalse(row["experiment_poisoned"]); evaluator.assert_not_called()
        self.assertTrue(maintenance.cleanup_confirmed(row["requests"][0].get("process")))
        self.assertIsNone(row["requests"][0]["observed_usage"])

    def test_hidden_result_is_terminal_and_never_added_to_a_model_conversation(self):
        with patch.object(transport, "invoke", return_value=answer({"action": "final", "candidate": "fn target(x:u32,y:u32)->u32 {0}"})) as model, \
                patch.object(study, "evaluate", side_effect=[{"accepted": True, "correct": True, "status": "accepted", "hidden_evaluated": False},
                                                            {"accepted": True, "correct": True, "status": "accepted", "hidden_evaluated": True, "hidden_marker": "NEVER_MODEL_INPUT"}]) as evaluator:
            row = self.cell()
        self.assertTrue(row["correct"]); self.assertTrue(row["hidden_evaluated"])
        self.assertEqual(model.call_count, 1); self.assertEqual(evaluator.call_count, 2)
        self.assertNotIn("NEVER_MODEL_INPUT", model.call_args.args[0])

    def test_public_check_limit_is_three_with_six_model_responses(self):
        with patch.object(transport, "invoke", return_value=answer({"action": "check", "candidate": "wrong"})) as model, \
                patch.object(study, "evaluate", return_value={"accepted": False, "correct": False, "status": "cases_failed", "hidden_evaluated": False}) as evaluator:
            row = self.cell()
        self.assertEqual(model.call_count, 6); self.assertEqual(evaluator.call_count, 3)
        self.assertFalse(row["hidden_evaluated"]); self.assertEqual(row["charged_tokens"], 6 * 105)

    def test_cleanup_uncertainty_after_paid_usage_poison_is_retained(self):
        error = maintenance.CleanupUncertain("hidden", process(), self.root / "transport", 20)
        error.observation = {"accepted": False, "correct": False, "status": "evaluation_cleanup_uncertain", "hidden_evaluated": True}
        with patch.object(transport, "invoke", return_value=answer({"action": "final", "candidate": "wrong"})) as model, \
                patch.object(study, "evaluate", side_effect=[{"accepted": True, "correct": True, "status": "accepted", "hidden_evaluated": False}, error]):
            row = self.cell()
        self.assertTrue(row["experiment_poisoned"]); self.assertEqual(row["status"], "terminal_cleanup_uncertain")
        self.assertEqual(row["charged_tokens"], 105); self.assertEqual(model.call_count, 1)

    def test_budget_exhausted_by_model_cannot_launch_public_evaluator(self):
        clock = [10.0]
        def model(*args, **kwargs):
            clock[0] = 1000.0
            return answer({"action": "final", "candidate": "wrong"})
        with patch.object(study.time, "monotonic", side_effect=lambda: clock[0]), patch.object(transport, "invoke", side_effect=model), \
                patch.object(maintenance, "run_owned") as owner:
            row = study.run_cell(self.task, "rust", self.root / "cell", 100.0, self.cfg, verify=lambda: None)
        self.assertEqual(row["status"], "wall_budget"); self.assertFalse(row["experiment_poisoned"])
        self.assertEqual(row["charged_tokens"], 105); owner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
