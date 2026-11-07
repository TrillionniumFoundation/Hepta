"""Contract tests use explicit authored transport fixtures, never live model evidence."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from tools.hia_macro_codex_provider import (INSTRUCTION, REQUEST_SCHEMA, SCHEMA,
    canonical, charged_tokens, parse_stream, prompt_bytes, request_document,
    store_raw, verify_receipt)
from tools.qualify_hia_macro_campaign import Evidence


USAGE = {"input_tokens": 17, "cached_input_tokens": 3, "cache_write_input_tokens": 0,
         "output_tokens": 9, "reasoning_output_tokens": 2}


def stream(answer=None, usage=None, extra=()):
    answer = answer or {"candidate": {"test_fixture_only": True}, "selected_id": "abstain"}
    events = [{"type": "thread.started", "thread_id": "authored-test-fixture"},
        {"type": "turn.started"}, *extra,
        {"type": "item.completed", "item": {"id": "answer", "type": "agent_message", "text": json.dumps(answer)}},
        {"type": "turn.completed", "usage": USAGE if usage is None else usage}]
    return b"".join(canonical(item) + b"\n" for item in events)


class MacroProviderParsingTests(unittest.TestCase):
    def test_original_complete_usage_and_conservative_overlap_charge(self):
        row = parse_stream(stream())
        self.assertTrue(row["stream_valid"])
        self.assertEqual(row["usage"], USAGE)
        self.assertEqual(row["charged_model_tokens"], 28)
        self.assertEqual(charged_tokens(None), None)

    def test_partial_usage_remains_unknown(self):
        row = parse_stream(stream(usage={"input_tokens": 1, "output_tokens": 2}))
        self.assertFalse(row["stream_valid"])
        self.assertIsNone(row["usage"])
        self.assertIsNone(row["charged_model_tokens"])

    def test_tool_violation_does_not_discard_later_original_cost(self):
        row = parse_stream(stream(extra=[{"type": "item.completed", "item": {
            "id": "bad", "type": "command_execution", "command": "test fixture"}}]))
        self.assertFalse(row["stream_valid"])
        self.assertEqual(row["usage"], USAGE)
        self.assertEqual(row["charged_model_tokens"], 28)
        self.assertIsNone(row["answer"])

    def test_quota_cannot_become_zero_tokens_or_answer(self):
        raw = canonical({"type": "turn.failed", "error": {"message": "You've hit your usage limit. fixture"}}) + b"\n"
        row = parse_stream(raw)
        self.assertTrue(row["account_block_observed"])
        self.assertIsNone(row["charged_model_tokens"])
        self.assertIsNone(row["answer"])

    def test_multiple_completions_do_not_pick_favorable_usage(self):
        raw = stream() + canonical({"type": "turn.completed", "usage": USAGE}) + b"\n"
        row = parse_stream(raw)
        self.assertFalse(row["stream_valid"])
        self.assertIsNone(row["usage"])

    def test_reasoning_allowed_but_out_of_turn_reasoning_rejected(self):
        reasoning = {"type": "item.completed", "item": {"id": "r", "type": "reasoning", "text": "test fixture"}}
        self.assertTrue(parse_stream(stream(extra=[reasoning]))["stream_valid"])
        self.assertFalse(parse_stream(canonical(reasoning) + b"\n" + stream())["stream_valid"])

    def test_prompt_has_no_reference_candidate_or_later_observations(self):
        task = {"id": "fixture", "specification": {"test": True}, "baseline": {"source": "public"},
                "candidate": {"secret": "reference answer"}, "workload": {"later": "not in prompt"}}
        request = request_document(task, {"ledger": [], "budget": {"wall_ns": 10, "model_tokens": 5}})
        prompt = prompt_bytes(request)
        self.assertNotIn(b'reference answer', prompt)
        self.assertNotIn(b'not in prompt', prompt)
        self.assertEqual(request["task_input_sha256"], sha256(canonical(task)).hexdigest())


class ProviderOriginalReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Evidence(Path(self.temp.name) / "bundle")
        self.provider = {"cli_identity": {"path": "/authored-fixture", "sha256": "a" * 64, "bytes": 1},
            "requested_model": "authored-test-model", "reasoning_effort": "low", "registered_startup_warnings": [],
            "invocation_path": "/authored-fixture"}
        request = {"schema": REQUEST_SCHEMA, "task_id": "fixture", "task_input_sha256": "b" * 64,
            "task": {}, "state": {}, "instruction": INSTRUCTION, "information_boundary": "test only"}
        raw = {"stdin.raw": prompt_bytes(request), "stdout.raw": stream(), "stderr.raw": b""}
        process = {"cwd": "/authored/cwd", "argv": ["/authored-fixture", "exec", "--json", "--ephemeral",
            "--sandbox", "read-only", "--skip-git-repo-check", "-c", 'sqlite_home="/authored/state"',
            "-c", 'log_dir="/authored/logs"', "-c", 'model_reasoning_effort="low"',
            "-m", "authored-test-model", "-"], "status": "exited", "returncode": 0, "cleanup_confirmed": True, "leader_reaped": True,
            "streams_complete": True, "wall_ns": 50, "files": {name: {
                "sha256": sha256(data).hexdigest(), "bytes": len(data)} for name, data in raw.items()}}
        self.receipt = {"schema": SCHEMA, "provider": "codex_cli", **self.provider,
            "request_sha256": self.evidence.put(request), "remaining_wall_ns": 100, "remaining_tokens": 50,
            "status": "completed", "process": process, "cli_identity_after": self.provider["cli_identity"],
            "raw": {name: store_raw(self.evidence, data) for name, data in raw.items()},
            "monetary_cost": None, "original_receipts_authenticated": False,
            "strong_ordinary_advice_observed": True, **parse_stream(raw["stdout.raw"])}
        self.originals = {item: (self.evidence.root / "objects" / item).read_bytes() for item in self.evidence.inventory}

    def test_authored_fixture_only_checks_byte_consistency_never_authentication(self):
        self.assertEqual(verify_receipt(self.receipt, self.originals, self.provider)["task_id"], "fixture")
        self.assertFalse(self.receipt["original_receipts_authenticated"])
        self.assertIsNone(self.receipt["monetary_cost"])

    def test_retyped_usage_cannot_replace_original_stream(self):
        self.receipt["usage"]["input_tokens"] += 1
        with self.assertRaisesRegex(ValueError, "original stream"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_actual_invoked_model_cannot_differ_from_claimed_model(self):
        self.receipt["process"]["argv"][-2] = "another-model"
        with self.assertRaisesRegex(ValueError, "actual provider"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_provider_time_overrun_stays_unqualified(self):
        self.receipt["remaining_wall_ns"] = 49
        with self.assertRaisesRegex(ValueError, "bounded originals"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_token_overrun_stays_unqualified(self):
        self.receipt["remaining_tokens"] = 27
        with self.assertRaisesRegex(ValueError, "bounded originals"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_uncertain_cleanup_stays_unqualified(self):
        self.receipt["process"]["cleanup_confirmed"] = False
        with self.assertRaisesRegex(ValueError, "bounded originals"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_unknown_monetary_cost_cannot_be_assigned_zero(self):
        self.receipt["monetary_cost"] = 0
        with self.assertRaisesRegex(ValueError, "monetary"):
            verify_receipt(self.receipt, self.originals, self.provider)

    def test_changed_raw_prompt_rejected_even_when_its_hash_is_recomputed(self):
        original = deepcopy(self.receipt["raw"]["stdin.raw"])
        changed = b"Different actual instruction\n"
        identity = sha256(changed).hexdigest()
        self.originals[identity] = changed
        self.receipt["raw"]["stdin.raw"] = {"sha256": identity, "bytes": len(changed), "chunks": [identity]}
        self.receipt["process"]["files"]["stdin.raw"] = {"sha256": identity, "bytes": len(changed)}
        self.assertNotEqual(original["sha256"], identity)
        with self.assertRaisesRegex(ValueError, "request bytes"):
            verify_receipt(self.receipt, self.originals, self.provider)


if __name__ == "__main__":
    unittest.main()
