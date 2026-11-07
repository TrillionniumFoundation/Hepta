"""Local fakes test ownership and uncertainty rules; no native or remote run."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import http_lifecycle as life
import http_qualification as h
import http_replay as replay


class FakeOwner:
    def __init__(self, *, first_status="accepted", change_replay_job=False, unrelated=False, incomplete=False):
        self.first_status, self.change_replay_job = first_status, change_replay_job
        self.unrelated, self.incomplete = unrelated, incomplete
        self.submitted, self.cancelled, self.inventory_reads = False, False, 0
        self.clients, self.calls = [], []
        self.operation = {"host": "x230", "job_id": "original-evaluate", "request_sha256": "a" * 64,
                          "report_artifact": None}

    def open(self):
        if self.clients:
            assert self.clients[-1].closed, "original client was not discarded before reconnect"
        client = FakeClient(self, len(self.clients) + 1)
        self.clients.append(client)
        return client

    def dispatch(self, connection, name, args):
        self.calls.append((connection, name, deepcopy(args)))
        if name == "hia_evaluate":
            status = "unknown" if self.cancelled else "accepted"
            if not self.submitted:
                status = self.first_status
            self.submitted = True
            operation = deepcopy(self.operation)
            if connection == 2 and self.change_replay_job:
                operation["job_id"] = "replacement-job"
            response = {"contract_version": "hepta.hia.agent-native.v1", "status": status,
                        "request_id": "hia_" + "a" * 64, "operation": operation}
            if self.cancelled:
                response["error"] = {"code": "HIA_WORKER_TERMINATED", "retry_action": "observe_original"}
            return response
        if name == "process_list_page":
            self.inventory_reads += 1
            jobs = [{"id": "unrelated-existing"}]
            if self.submitted:
                jobs.append({"id": "original-evaluate"})
                if self.unrelated:
                    jobs.append({"id": "unrelated-concurrent"})
            return {"jobs": jobs, "next_cursor": None, "inventory_complete": not self.incomplete}
        assert args["host"] == "x230" and args["job_id"] == "original-evaluate"
        if name == "process_status":
            return {"job_id": "original-evaluate", "state": "cancelled" if self.cancelled else "running",
                    "launch_nonce": "b" * 32, "cancelled": self.cancelled,
                    "audit_recorded": True, "backend": "systemd", "automatic_retry": False,
                    "timed_out": False, "exit_code": 143 if self.cancelled else None,
                    "terminal_publication_protocol": 1,
                    "log_bytes": {n: {"seen": 0, "stored": 0} for n in ("stdout", "stderr")},
                    "log_synced": {n: True for n in ("stdout", "stderr")},
                    "log_errors": {n: None for n in ("stdout", "stderr")},
                    "log_truncated": {n: False for n in ("stdout", "stderr")},
                    "systemd": {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                        "ExecMainPID": "123", "InvocationID": "a" * 32,
                        "Description": "Hepta Runtime job original-evaluate " + "b" * 32},
                    "output_complete": self.cancelled, "output_durable": self.cancelled,
                    "terminal_publication_confirmed": self.cancelled}
        if name == "process_cancel":
            self.cancelled = True
            return {"job_id": "original-evaluate", "cancel_requested": True}
        if name == "process_read":
            part = {"offset": 0, "next_offset": 0, "size": 0, "eof": True, "bytes_hex": "", "text": ""}
            return {"audit_recorded": True, "job_id": "original-evaluate", "stdout": deepcopy(part), "stderr": deepcopy(part)}
        raise AssertionError("unexpected owner action: " + name)


class FakeClient:
    _domain_result = staticmethod(h.MCPHTTP._domain_result)
    def __init__(self, owner, number): self.owner, self.number, self.closed = owner, number, False
    def rpc(self, method, params):
        assert method == "tools/call"
        return {"structuredContent": self.owner.dispatch(self.number, params["name"], params["arguments"])}
    def connection_receipt(self): return {"url": h.ENDPOINTS[0], "initialize_observed": True, "client": self.number}
    def close(self): self.closed = True


class PagedOutputOwner(FakeOwner):
    """A cancelled worker with output crossing UTF-8 and pagination boundaries."""
    def __init__(self, *, changed_second_nonce=False, unaudited_second_page=False):
        super().__init__()
        self.changed_second_nonce, self.unaudited_second_page = changed_second_nonce, unaudited_second_page
        self.streams = {"stdout": b"x" * 16383 + "中".encode() + b"\xffretained\n",
                        "stderr": b"cancelled after partial evaluation\xff\n"}
        self.output_pages = 0

    def dispatch(self, connection, name, args):
        result = super().dispatch(connection, name, args)
        if name == "process_status" and self.cancelled:
            result["log_bytes"] = {name: {"seen": len(raw), "stored": len(raw)}
                                   for name, raw in self.streams.items()}
        if name == "process_read":
            self.output_pages += 1
            result["launch_nonce"] = "b" * 32
            if self.output_pages == 2 and self.changed_second_nonce:
                result["launch_nonce"] = "c" * 32
            if self.output_pages == 2 and self.unaudited_second_page:
                result["audit_recorded"] = False
            for stream, raw in self.streams.items():
                offset = args[stream + "_offset"]
                chunk = raw[offset:offset + args["limit"]]
                end = offset + len(chunk)
                result[stream] = {"offset": offset, "next_offset": end, "size": len(raw),
                    "eof": end == len(raw), "bytes_hex": chunk.hex(), "text": chunk.decode("utf-8", "replace")}
        return result


class LifecycleTests(unittest.TestCase):
    def run_case(self, owner, output):
        binding = h.selected_campaign("faa85-v4-c81-shadow-test")
        arguments = {"catalog_sha256": h.PINS["catalog_sha256"],
                     "request_key": binding["request_prefix"] + "/cancel/11/call", "context": {"id": "original"}}
        def prepare(connection, scenario, given, path):
            self.assertEqual(given, binding)
            h.dump(path / "LIFECYCLE-REQUEST.json", {"tool": "hia_evaluate", "arguments": arguments})
            return arguments
        with patch.object(life, "prepare_evaluation", prepare):
            return life.run_lifecycle({}, binding, output, owner.open), arguments

    def test_original_evaluate_survives_client_reinitialization_and_is_only_cancel_target(self):
        with tempfile.TemporaryDirectory() as path:
            owner = FakeOwner()
            result, arguments = self.run_case(owner, Path(path))
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["same_job_after_reconnect"] and result["no_duplicate_native_job_proved"])
            self.assertFalse(result["server_restarted"])
            self.assertEqual(len(owner.clients), 2)
            evaluations = [args for _, name, args in owner.calls if name == "hia_evaluate"]
            self.assertEqual(evaluations, [arguments] * 4)
            cancellations = [args for _, name, args in owner.calls if name == "process_cancel"]
            self.assertEqual(cancellations, [{"host": "x230", "job_id": "original-evaluate", "grace_seconds": 1}])
            self.assertFalse(any(name == "process_start" for _, name, _ in owner.calls))

    def test_initial_unknown_is_retained_without_second_client_or_cancel(self):
        with tempfile.TemporaryDirectory() as path:
            owner = FakeOwner(first_status="unknown")
            with self.assertRaises(h.QualificationFailure): self.run_case(owner, Path(path))
            self.assertEqual(len(owner.clients), 1)
            self.assertFalse(owner.cancelled)
            self.assertEqual(sum(name == "hia_evaluate" for _, name, _ in owner.calls), 1)
            self.assertTrue((Path(path) / "LIFECYCLE-REQUEST.json").is_file())
            self.assertEqual(json.loads((Path(path) / "evaluate-first.json").read_text())["status"], "unknown")

    def test_changed_reconnect_job_fails_before_any_cancellation(self):
        with tempfile.TemporaryDirectory() as path:
            owner = FakeOwner(change_replay_job=True)
            with self.assertRaises(h.QualificationFailure): self.run_case(owner, Path(path))
            self.assertFalse(owner.cancelled)
            self.assertTrue((Path(path) / "evaluate-after-reconnect.json").is_file())

    def test_unrelated_concurrent_job_marks_incomplete_without_cancelling_it(self):
        with tempfile.TemporaryDirectory() as path:
            owner = FakeOwner(unrelated=True)
            result, _ = self.run_case(owner, Path(path))
            self.assertEqual(result["status"], "incomplete")
            self.assertFalse(result["no_duplicate_native_job_proved"])
            self.assertEqual(result["inventory_added"], ["original-evaluate", "unrelated-concurrent"])
            self.assertEqual([args["job_id"] for _, name, args in owner.calls if name == "process_cancel"],
                             ["original-evaluate"])

    def test_incomplete_inventory_cannot_prove_no_duplicate(self):
        with tempfile.TemporaryDirectory() as path:
            owner = FakeOwner(incomplete=True)
            with self.assertRaises(h.QualificationFailure):
                self.run_case(owner, Path(path))
            self.assertFalse(owner.submitted)
            self.assertFalse(owner.cancelled)

    def test_arbitrary_process_start_and_other_hosts_are_rejected(self):
        for tool, args in [("process_start", {"host": "x230"}), ("process_cancel", {"host": "main"})]:
            with self.subTest(tool=tool, args=args), self.assertRaises(h.QualificationFailure):
                life.owner_call(None, tool, args)

    def test_review_changed_terminal_nonce_is_rejected_and_retained(self):
        class ChangedTerminalNonce(FakeOwner):
            def dispatch(self, connection, name, args):
                value = super().dispatch(connection, name, args)
                if name == "process_status" and self.cancelled:
                    value["launch_nonce"] = "changed-after-cancel"
                return value
        with tempfile.TemporaryDirectory() as path:
            owner = ChangedTerminalNonce()
            with self.assertRaisesRegex(h.QualificationFailure, "launch nonce"):
                self.run_case(owner, Path(path))
            terminal = json.loads((Path(path) / "cancel-status-observations.jsonl").read_text().splitlines()[0])
            self.assertEqual(terminal["launch_nonce"], "changed-after-cancel")
            self.assertEqual(sum(name == "hia_evaluate" for _, name, _ in owner.calls), 2)
            self.assertFalse((Path(path) / "LIFECYCLE.json").exists())

    def test_changed_nonterminal_cancel_status_nonce_is_also_rejected(self):
        class ChangedLiveNonce(FakeOwner):
            def dispatch(self, connection, name, args):
                value = super().dispatch(connection, name, args)
                if name == "process_status" and self.cancelled:
                    value.update(launch_nonce="changed-after-cancel", state="running", cancelled=False)
                return value
        with tempfile.TemporaryDirectory() as path:
            with self.assertRaises(ValueError):
                self.run_case(ChangedLiveNonce(), Path(path))

    def test_cancelled_output_reassembles_all_pages_and_reconciles_exact_bytes(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            owner = PagedOutputOwner()
            result, _ = self.run_case(owner, directory)
            self.assertEqual(result["status"], "passed")
            retained = json.loads((directory / "cancelled-job-output.json").read_bytes())
            reconciliation = json.loads((directory / "cancelled-original-reconciliation.json").read_bytes())
            self.assertEqual(len(retained["pages"]), 2)
            self.assertEqual(retained["native_output"]["launch_nonce"], "b" * 32)
            for name, raw in owner.streams.items():
                self.assertEqual(bytes.fromhex(retained["native_output"][name]["bytes_hex"]), raw)
                self.assertEqual(retained["native_output"][name]["text"], raw.decode("utf-8", "replace"))
                self.assertEqual(reconciliation["output"][name],
                                 {"bytes": len(raw), "sha256": h.sha256(raw).hexdigest()})
            self.assertFalse(reconciliation["automatic_retry_authorized"])

    def test_second_output_page_nonce_cannot_be_erased_during_reassembly(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            owner = PagedOutputOwner(changed_second_nonce=True)
            with self.assertRaises(h.QualificationFailure):
                self.run_case(owner, directory)
            self.assertEqual(owner.output_pages, 2)
            self.assertTrue(owner.cancelled)
            self.assertEqual(sum(name == "hia_evaluate" for _, name, _ in owner.calls), 2)
            self.assertFalse((directory / "LIFECYCLE.json").exists())

    def test_one_unaudited_output_page_prevents_authoritative_cancelled_result(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            owner = PagedOutputOwner(unaudited_second_page=True)
            with self.assertRaises(ValueError):
                self.run_case(owner, directory)
            self.assertEqual(owner.output_pages, 2)
            self.assertFalse((directory / "cancelled-original-reconciliation.json").exists())
            self.assertFalse((directory / "LIFECYCLE.json").exists())


class ReplayTests(unittest.TestCase):
    def fixture(self, directory):
        binding = h.selected_campaign("faa85-v4-c81-shadow-test")
        registration = {"hepta_commit": h.HEPTA_COMMIT, "runtime_commit": h.RUNTIME_COMMIT,
                        "url": h.ENDPOINTS[0], "pins": h.PINS, "source": h.verify_source(), "campaign": binding,
                        "adapter_sha256": h.sha256((h.ROOT / "http_qualification.py").read_bytes()).hexdigest()}
        intent = {"tool": "hia_artifact", "arguments": {
            "catalog_sha256": h.PINS["catalog_sha256"], "request_key": binding["request_prefix"] + "/5/call",
            "artifact_profile": {"id": "review-profile", "sha256": "1" * 64},
            "source": {"kind": "utf8", "text": "original"}}}
        pending = {"contract_version": "hepta.hia.agent-native.v1", "status": "unknown",
                   "request_id": "hia_" + "a" * 64,
                   "operation": {"host": "x230", "job_id": "original", "request_sha256": "a" * 64,
                                 "report_artifact": None}}
        h.dump(directory / "registration.json", registration)
        h.write_new(directory / "application-events.jsonl", h.json_bytes({"phase": "intent", "sequence": 5, **intent}) + b"\n")
        h.write_new(directory / "http-events.jsonl", h.json_bytes({"stage": "intent", "wire_id": 1,
            "request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": intent["tool"], "arguments": intent["arguments"]}}}) + b"\n"
            + h.json_bytes({"stage": "pending_operation", **intent, "response": pending}) + b"\n")
        return intent, pending

    def test_replay_loads_only_the_exact_retained_intent_and_pending_job(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            intent, pending = self.fixture(directory)
            attempt = replay.load_attempt(directory, 5)
            self.assertEqual(attempt["intent"], intent)
            self.assertEqual(attempt["original_pending"], pending)
            self.assertFalse(attempt["wire_endpoint_fields_present"])
            with self.assertRaises(h.QualificationFailure): replay.load_attempt(directory, 33)

    def test_changed_journal_body_cannot_become_a_replacement_request(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            intent, _ = self.fixture(directory)
            changed = {**intent, "arguments": {"request_key": "fresh-replacement"}}
            h.append_event(directory / "application-events.jsonl", {"phase": "error", "sequence": 5, **changed})
            with self.assertRaises(h.QualificationFailure): replay.load_attempt(directory, 5)

    def test_conflicting_pending_job_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            intent, pending = self.fixture(directory)
            pending["operation"]["job_id"] = "replacement"
            h.append_event(directory / "http-events.jsonl", {"stage": "pending_operation", **intent, "response": pending})
            with self.assertRaises(h.QualificationFailure): replay.load_attempt(directory, 5)

    def test_review_schema_valid_application_only_change_cannot_dispatch_fresh_key(self):
        from jsonschema import Draft202012Validator
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            original, pending = self.fixture(directory)
            control = replay.load_attempt(directory, 5)
            self.assertEqual(control["original_pending"], pending)
            changed = deepcopy(original)
            changed["arguments"]["request_key"] = h.selected_campaign("faa85-v4-c81-shadow-test")["request_prefix"] + "/fresh-call"
            changed["arguments"]["source"]["text"] = "changed"
            catalog = json.loads((h.ROOT / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json").read_bytes())
            schema = next(t for t in catalog["tools"] if t["name"] == "hia_artifact")["inputSchema"]
            Draft202012Validator(schema).validate(changed["arguments"])
            (directory / "application-events.jsonl").write_bytes(
                h.json_bytes({"phase": "intent", "sequence": 5, **changed}) + b"\n")
            with patch.object(h, "token_bytes") as token:
                with self.assertRaisesRegex(h.QualificationFailure, "contradicts"):
                    replay.main(["--from", str(directory), "--sequence", "5", "--token-file", "/unused",
                                 "--output", str(directory / "must-not-be-created")])
                token.assert_not_called()
            self.assertFalse((directory / "must-not-be-created").exists())

    def test_wire_pending_replay_is_grouped_before_the_next_application_sequence(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            original, pending = self.fixture(directory)
            h.append_event(directory / "http-events.jsonl", {"stage": "intent", "wire_id": 2,
                "request": {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": original["tool"], "arguments": original["arguments"]}}})
            following = {"tool": "hia_describe", "arguments": {"section": "manifest"}}
            h.append_event(directory / "application-events.jsonl", {"phase": "intent", "sequence": 6, **following})
            h.append_event(directory / "http-events.jsonl", {"stage": "intent", "wire_id": 3,
                "request": {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": following["tool"], "arguments": following["arguments"]}}})
            first, second = replay.load_attempt(directory, 5), replay.load_attempt(directory, 6)
            self.assertEqual(first["original_pending"], pending)
            self.assertEqual(first["wire_attempt"]["replay_wire_id"], 2)
            self.assertEqual(second["intent"], following)
            self.assertEqual(second["wire_attempt"]["first_wire_id"], 3)

    def test_missing_original_outbound_intent_cannot_fall_back_to_dispatch(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            self.fixture(directory)
            (directory / "http-events.jsonl").write_bytes(b"")
            with self.assertRaisesRegex(h.QualificationFailure, "no corresponding"):
                replay.load_attempt(directory, 5)

    def test_optional_external_original_intent_hash_must_match(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            original, _ = self.fixture(directory)
            expected = h.sha256(h.json_bytes(original)).hexdigest()
            self.assertEqual(replay.load_attempt(directory, 5, expected)["original_outbound_intent_sha256"], expected)
            with self.assertRaisesRegex(h.QualificationFailure, "externally fixed"):
                replay.load_attempt(directory, 5, "f" * 64)


class PredecessorBindingTests(unittest.TestCase):
    """Reconciliation permits a distinct trial only for its exact predecessor.

    Request arguments and the independently recorded request/profile hashes are
    from the retained faa85-v4-c81-live-r1 attempt. The surrounding local files
    are fixtures; these tests neither authenticate nor dispatch that request.
    """
    PROFILE_SHA = "9aa23fc9d98a7ebf8db12cb8825d5d9ef5cba0233f4f71fa19a1d8c51907239b"
    REQUEST_SHA = "c752a30e7565b3bf10bd210354088605d2c529923e2802dd646ac72ce89c2a0c"
    WORKFLOW_SHA = "3b7a1f783df58e36a0cde1073cff6761b323f598a424ee21a4d4a954e9fffe39"

    def fixture(self, directory, *, separate_campaign=False):
        old = h.selected_campaign("faa85-v4-c81-live-r1")
        new = h.selected_campaign("faa85-v4-c81-successor-test")
        artifact = {"id": "a-c061e4e795c1442fb652b5c79f59ecae",
            "sha256": "c1a53a5700f018193a3d6c59bdb6c179c310c8c38b7c54a10a51ca0ad51bc68d",
            "uri": "hia://artifacts/2efdb6f4518542cd8f00f651ca7308c4"}
        arguments = {"baseline_artifact": deepcopy(artifact), "candidate_artifact": deepcopy(artifact),
            "build_receipt": {"id": "a-e61d7ee98ff94c0d8f613c404c43a4fe",
                "sha256": "935032877e162daa60ebbfc50cb44be67d0b72d05a30ecf723937cbe73b4ac3b",
                "uri": "hia://artifacts/038077dcbb6b49518f30290b7eaeac60"},
            "catalog_sha256": h.PINS["catalog_sha256"],
            "context": {"id": "ctx-91d802fd6e244d2b90934ff2b609ea45",
                "sha256": "82c50cc088ee324232963307e7e09affcc8cb1088c9d9b23ecdaec71886b9733"},
            "request_key": old["request_prefix"] + "/cancel/8/call",
            "verification_receipts": [
                {"id": "a-f85d473def944f589f56d693d97b2884",
                 "sha256": "40c3414d9877dabfce5f608898ca614b00d7643bfab222845ca779f00503ae8d",
                 "uri": "hia://artifacts/1c707b9570ac4741abcee33e340580d9"},
                {"id": "a-e35b06a9a7cb45558ccf5920ccf19ba6",
                 "sha256": "1ae716ea6f7228add25f23a1726662011879877b7148fb54ceb3cb947881e578",
                 "uri": "hia://artifacts/f5bdd98b63c7486e8ed0541985c8af7d"}]}
        body = {"schema": "hia-agent-worker-request-v1", "tool": "hia_evaluate",
                "arguments": arguments, "profile_sha256": self.PROFILE_SHA,
                "catalog_sha256": h.PINS["catalog_sha256"]}
        self.assertEqual(h.sha256(h.json_bytes(body)).hexdigest(), self.REQUEST_SHA)
        registration = {"schema": "hia-http-v4-lifecycle-registration.v1", "url": h.ENDPOINTS[1],
            "campaign": old, "worker_host": "x230", "pins": deepcopy(h.PINS),
            "hepta_commit": h.HEPTA_COMMIT, "runtime_commit": h.RUNTIME_COMMIT,
            "workflow_sha256": self.WORKFLOW_SHA, "automatic_retry": False}
        if separate_campaign:
            registration["campaign"] = h.selected_campaign("faa85-v4-c81-core-test")
            registration["lifecycle_campaign"] = old
        job, nonce = "1a1b59f7d31-12894-7d", "3edba7a89e2aaad2f912f109318dc327"
        accepted = {"contract_version": "hepta.hia.agent-native.v1", "status": "accepted",
            "request_id": "hia_" + self.REQUEST_SHA, "operation": {"host": "x230", "job_id": job,
                "request_sha256": self.REQUEST_SHA, "report_artifact": None}}
        active = {"job_id": job, "state": "running", "audit_recorded": True, "backend": "systemd",
            "systemd": {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                "Description": "Hepta Runtime job " + job + " " + nonce,
                "ExecMainPID": "680168", "InvocationID": "d9f8f339b41c4fa590e04a8e81cba61b"}}
        reconciliation = {"schema": "hepta.hia.original-reconciliation.v1", "terminal_reconciled": True,
            "state": "succeeded", "automatic_retry_authorized": False, "tool": "hia_evaluate",
            "original": {"host": "x230", "job_id": job, "launch_nonce": nonce, "kind": "hia_worker"},
            "request_sha256": self.REQUEST_SHA, "profile_sha256": self.PROFILE_SHA,
            "installation": deepcopy(h.PINS)}
        records = {"registration.json": registration, "evaluate-first.json": accepted,
            "status-before-disconnect.json": active, "LIFECYCLE-REQUEST.json": {
                "tool": "hia_evaluate", "arguments": arguments, "request_key": arguments["request_key"]}}
        for name, value in records.items():
            h.dump(directory / name, value)
        prior = {"schema": "hia-http-v4-lifecycle-result.v1", "status": "failed",
                 "registration": registration, "files": {name: self.file_pin(directory / name) for name in records}}
        h.dump(directory / "result.json", prior)
        return prior, reconciliation, new

    def file_pin(self, path):
        raw = path.read_bytes()
        return {"bytes": len(raw), "sha256": h.sha256(raw).hexdigest()}

    def repin(self, directory, prior, *, name=None, value=None):
        if name is not None:
            (directory / name).write_bytes(h.json_bytes(value) + b"\n")
            prior["files"][name] = self.file_pin(directory / name)
        (directory / "result.json").write_bytes(h.json_bytes(prior) + b"\n")
        return self.file_pin(directory / "result.json")["sha256"]

    def check(self, directory, prior, reconciliation, new, **changes):
        digest = self.repin(directory, prior)
        return life.check_predecessor(directory, changes.get("digest", digest), reconciliation,
                                      changes.get("workflow_sha", self.WORKFLOW_SHA), new)

    def test_legacy_and_separate_lifecycle_campaign_bind_the_recorded_request(self):
        for separate in (False, True):
            with self.subTest(separate=separate), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory, separate_campaign=separate)
                result = self.check(directory, prior, reconciliation, new)
                self.assertEqual(result["original"], reconciliation["original"])
                self.assertEqual(result["request_sha256"], self.REQUEST_SHA)
                self.assertEqual(result["old_campaign"], h.selected_campaign("faa85-v4-c81-live-r1"))
                self.assertEqual(result["url"], h.ENDPOINTS[1])
                self.assertFalse(reconciliation["automatic_retry_authorized"])

    def test_changed_external_attempt_pin_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            prior, reconciliation, new = self.fixture(directory)
            with self.assertRaisesRegex(h.QualificationFailure, "result pin"):
                self.check(directory, prior, reconciliation, new, digest="f" * 64)

    def test_every_manifest_file_is_verified_even_if_not_parsed(self):
        for name in ("registration.json", "evaluate-first.json", "status-before-disconnect.json",
                     "LIFECYCLE-REQUEST.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                target = directory / name
                target.write_bytes(target.read_bytes() + b"\n")
                with self.assertRaisesRegex(h.QualificationFailure, "evidence differs"):
                    self.check(directory, prior, reconciliation, new)

    def test_unpinned_consumed_files_cannot_be_borrowed_from_the_directory(self):
        for name in ("evaluate-first.json", "status-before-disconnect.json", "LIFECYCLE-REQUEST.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                del prior["files"][name]
                with self.assertRaisesRegex(h.QualificationFailure, "manifest omits"):
                    self.check(directory, prior, reconciliation, new)

    def test_manifest_cannot_escape_the_preceding_attempt(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            prior, reconciliation, new = self.fixture(directory)
            prior["files"]["../outside.json"] = {"bytes": 0, "sha256": "0" * 64}
            with self.assertRaisesRegex(h.QualificationFailure, "unsafe original evidence path"):
                self.check(directory, prior, reconciliation, new)

    def test_reconciled_original_host_job_nonce_kind_and_installation_must_all_match(self):
        for field in ("host", "job_id", "launch_nonce", "kind", "request_sha256",
                      "worker_sha256", "backend_sha256", "catalog_sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                if field in reconciliation["original"]:
                    reconciliation["original"][field] = "unrelated"
                elif field in reconciliation["installation"]:
                    reconciliation["installation"][field] = "f" * 64
                else:
                    reconciliation[field] = "f" * 64
                with self.assertRaisesRegex(h.QualificationFailure, "unrelated reconciliation"):
                    self.check(directory, prior, reconciliation, new)

    def test_success_of_another_release_or_workflow_does_not_discharge_the_original(self):
        for field in ("hepta_commit", "runtime_commit", "workflow_sha256", "pins", "status"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                if field == "status":
                    prior[field] = "passed"
                elif field == "pins":
                    prior["registration"][field]["worker_sha256"] = "f" * 64
                else:
                    prior["registration"][field] = "f" * 64
                with self.assertRaisesRegex(h.QualificationFailure, "another release/workflow"):
                    self.check(directory, prior, reconciliation, new)

    def test_active_evidence_must_bind_the_original_unit_incarnation(self):
        for field in ("job_id", "launch_nonce", "InvocationID", "state", "status_authoritative"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                active = json.loads((directory / "status-before-disconnect.json").read_bytes())
                if field == "InvocationID": active["systemd"][field] = ""
                elif field == "status_authoritative": active[field] = False
                elif field == "state": active[field] = "owner_unknown"
                else: active[field] = "unrelated"
                self.repin(directory, prior, name="status-before-disconnect.json", value=active)
                with self.assertRaises(ValueError):
                    self.check(directory, prior, reconciliation, new)

    def test_request_tool_catalog_and_both_request_keys_are_bound_to_old_namespace(self):
        for field in ("tool", "catalog", "top_key", "both_keys", "reconciled_tool"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                request = json.loads((directory / "LIFECYCLE-REQUEST.json").read_bytes())
                if field == "tool": request["tool"] = "hia_emit"
                elif field == "catalog": request["arguments"]["catalog_sha256"] = "f" * 64
                elif field == "top_key": request["request_key"] += "/changed"
                elif field == "reconciled_tool": reconciliation["tool"] = "hia_emit"
                else:
                    request["request_key"] = request["arguments"]["request_key"] = new["request_prefix"] + "/cancel/8/call"
                self.repin(directory, prior, name="LIFECYCLE-REQUEST.json", value=request)
                with self.assertRaisesRegex(h.QualificationFailure, "another namespace or tool"):
                    self.check(directory, prior, reconciliation, new)

    def test_rehashed_manifest_does_not_bind_altered_worker_arguments(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            prior, reconciliation, new = self.fixture(directory)
            request = json.loads((directory / "LIFECYCLE-REQUEST.json").read_bytes())
            request["arguments"]["candidate_artifact"]["sha256"] = "f" * 64
            self.repin(directory, prior, name="LIFECYCLE-REQUEST.json", value=request)
            with self.assertRaisesRegex(h.QualificationFailure, "request bytes"):
                self.check(directory, prior, reconciliation, new)

    def test_changed_or_missing_profile_cannot_reconstruct_original_worker_request(self):
        for profile in (None, "f" * 64):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory)
                if profile is None: del reconciliation["profile_sha256"]
                else: reconciliation["profile_sha256"] = profile
                with self.assertRaisesRegex(h.QualificationFailure, "request bytes"):
                    self.check(directory, prior, reconciliation, new)

    def test_a_new_trial_must_change_both_request_prefix_and_slot(self):
        for field in ("request_prefix", "target_slot"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as path:
                directory = Path(path)
                prior, reconciliation, new = self.fixture(directory, separate_campaign=True)
                new[field] = prior["registration"]["lifecycle_campaign"][field]
                with self.assertRaisesRegex(h.QualificationFailure, "cannot reuse"):
                    self.check(directory, prior, reconciliation, new)

    def test_unrelated_reconciliation_is_rejected_before_credentials_or_output(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            prior, reconciliation, new = self.fixture(directory)
            reconciliation["original"]["job_id"] = "another-job"
            h.dump(directory / "reconciled.json", reconciliation)
            digest = self.repin(directory, prior)
            with patch.object(life, "load_workflow", return_value=({}, self.WORKFLOW_SHA)), \
                    patch.object(h, "token_bytes") as token, \
                    patch.object(h.MCPHTTP, "__init__", return_value=None) as transport:
                with self.assertRaises(h.QualificationFailure):
                    life.main(["--url", h.ENDPOINTS[1], "--token-file", "/unused",
                        "--workflow-result", str(directory / "workflow.json"),
                        "--campaign-id", "faa85-v4-c81-core-test", "--lifecycle-id", new["id"],
                        "--predecessor-reconciliation", str(directory / "reconciled.json"),
                        "--predecessor-attempt", str(directory), "--predecessor-attempt-sha256", digest,
                        "--output", str(directory / "must-not-be-created")])
                token.assert_not_called()
                transport.assert_not_called()
            self.assertFalse((directory / "must-not-be-created").exists())


class WorkflowBindingTests(unittest.TestCase):
    def fixture(self):
        binding = h.selected_campaign("faa85-v4-c81-shadow-test")
        candidate, baseline = {"artifact": "candidate"}, {"artifact": "baseline"}
        adoption = {"target_slot": binding["target_slot"], "previous": {"generation": "0", "epoch": "0"},
                    "current": {"generation": "1", "epoch": "1"}, "active_artifact": candidate}
        scenario = {"adoption": adoption, "stale_adoption": {"status": "rejected", "error": {"code": "E_HIA_GENERATION_STALE"}},
                    "rollback": {"target_slot": binding["target_slot"], "previous": adoption["current"],
                                 "current": {"generation": "0", "epoch": "2"}, "active_artifact": baseline,
                                 "future_calls_only": True, "past_effects_reversed": False},
                    "candidate_build": {"native_artifact": candidate}, "baseline_build": {"native_artifact": baseline}}
        return scenario, binding

    def test_unrelated_rejection_is_not_stale_generation_evidence(self):
        scenario, binding = self.fixture()
        life.verify_workflow_scenario(scenario, binding)
        scenario["stale_adoption"]["error"]["code"] = "E_HIA_RECEIPT_BINDING"
        with self.assertRaises(h.QualificationFailure): life.verify_workflow_scenario(scenario, binding)

    def test_epoch_restoration_without_exact_baseline_is_not_rollback_evidence(self):
        scenario, binding = self.fixture()
        scenario["rollback"]["active_artifact"] = scenario["candidate_build"]["native_artifact"]
        with self.assertRaises(h.QualificationFailure): life.verify_workflow_scenario(scenario, binding)

if __name__ == "__main__":
    unittest.main(verbosity=2)
