"""Ordinary artifact-read calls through an actual selected HIA page owner.

The issued-byte store, request journal and worker envelope retain their current
owners.  These controls replace only _reference_hia_read, exercise actual native
receipts, and distinguish explicit development from matching-source cold builds.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected, wire

ROOT = Path(__file__).resolve().parents[1]
COLD = "HEPTA_HIA_AGENT_READ_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_AGENT_READ_DEVELOPMENT_COMPILER"
EVIDENCE = "HEPTA_HIA_AGENT_READ_EVIDENCE"
SELECTOR = "HEPTA_HIA_AGENT_READ_MANIFEST"
REFERENCE_READ = HIAAgentService._reference_hia_read


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                    encoding="utf-8")


def identity(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "sha256": sha256(raw).hexdigest(), "bytes": len(raw)}


def source_map():
    from tools.hia_selfhost_contract import SOURCE_FILES, CONTRACT_PATH
    paths = set(SOURCE_FILES) | {CONTRACT_PATH, str(Path(__file__).relative_to(ROOT)),
        "hepta/hia_agent_read_native.py", "tools/generate_hia_agent_read.py",
        "tools/build_hia_agent_read.py", "examples/hia_bootstrap/agent_read.hepta"}
    paths.update(path.relative_to(ROOT).as_posix() for path in (ROOT / "hepta").rglob("*.py"))
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}


def cursor_rows(service):
    return [list(row) for row in service.store.db.execute("SELECT * FROM cursors ORDER BY id")]


def denied_page(*args, **kwargs):
    raise AssertionError("selected native read entered the retained Python pagination owner")


# The child executes the original worker main, with only the retained page
# owner poisoned and a transparent recorder around the real native transition.
# Its request, stdout envelope, error and return code remain those of main().
WORKER_CHILD = r"""
import importlib.abc, json, os, sys
from hashlib import sha256
from pathlib import Path
site, trace_path, installed = sys.argv[1:4]
sys.path.insert(0, site)
initial_selectors = sorted(name for name in os.environ if name.startswith("HEPTA_HIA_") and
    name.endswith(("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_DEVELOPMENT_MANIFEST", "_EVIDENCE")))
assert not initial_selectors, initial_selectors
if installed == "yes":
    class NoAuthoring(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in {"tools", "tests"} or fullname.startswith(("tools.", "tests.")):
                raise AssertionError("installed read worker imported authoring or tests")
    sys.meta_path.insert(0, NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_read_native import NativeAgentRead, SOURCE
from hepta.hia_agent_worker import main
def forbidden(*args, **kwargs):
    raise AssertionError("ordinary selected worker entered hosted pagination")
HIAAgentService._reference_hia_read = forbidden
trace = Path(trace_path)
trace.mkdir(mode=0o700)
frames = []
original = NativeAgentRead.transition
def observed(image, request, data):
    index = len(frames)
    request_path = trace / (str(index) + ".request.bin")
    artifact_path = trace / (sha256(data).hexdigest() + ".artifact.bin")
    output_path = trace / (str(index) + ".output.bin")
    request_path.write_bytes(request)
    if not artifact_path.exists():
        artifact_path.write_bytes(data)
    assert artifact_path.read_bytes() == data
    record = {"request_path": str(request_path), "request_sha256": sha256(request).hexdigest(),
              "artifact_path": str(artifact_path), "artifact_sha256": sha256(data).hexdigest(),
              "artifact_bytes": len(data), "image_sha256": sha256(bytes(image._mapping)).hexdigest()}
    frames.append(record)
    try:
        receipt = original(image, request, data)
    except BaseException as error:
        record["raised"] = {"type": type(error).__name__, "message": str(error)}
        raise
    output_path.write_bytes(receipt.raw)
    record.update(status=receipt.status, output_path=str(output_path),
                  output_sha256=sha256(receipt.raw).hexdigest(),
                  offset=receipt.offset, consumed=receipt.consumed,
                  next_offset=receipt.next_offset, wire_budget=receipt.wire_budget,
                  fields_hex=[value.hex() for value in receipt.fields[:4]])
    return receipt
NativeAgentRead.transition = observed
before = dict(os.environ)
status = None
try:
    status = main(sys.argv[4:])
finally:
    after = dict(os.environ)
    report = {"frames": frames, "returncode": status, "environment_restored": after == before,
              "initial_hia_test_or_manifest_selectors": initial_selectors,
              "source": str(SOURCE), "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
              "module": sys.modules["hepta.hia_agent_read_native"].__file__,
              "authoring_imported": any(name in {"tools", "tests"} or
                  name.startswith(("tools.", "tests.")) for name in sys.modules)}
    (trace / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    assert after == before, "worker scope leaked selectors"
    if installed == "yes":
        assert Path(site).resolve() in Path(SOURCE).resolve().parents
        assert Path(site).resolve() in Path(report["module"]).resolve().parents
        assert not report["authoring_imported"]
raise SystemExit(status)
"""


class AgentReadIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta import hia_agent_read_native as native
        from tools.build_hia_json_preflight import admit_cold_build

        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        for name, value in ((COLD, cold), (DEVELOPMENT, development)):
            if name in os.environ and not value:
                raise AssertionError("explicit read selection is empty: " + name)
        if bool(cold) == bool(development):
            raise AssertionError("read integration requires exactly one explicit cold report or development compiler")
        cls.bindings = {}
        cls.cold = Path(cold).resolve(strict=True) if cold else None
        if cls.cold:
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            nested_path = Path(report["nested_report"]).resolve(strict=True)
            nested_bytes = nested_path.read_bytes()
            cls.compiler = Path(json.loads(nested_bytes)["generations"][-1]["produced_image"]).resolve(strict=True)
            admit_cold_build(cls.compiler.read_bytes(), cold_bytes)
            helper_cold = os.environ.get("HEPTA_HIA_WORKER_HELPERS_COLD_REPORT")
            if helper_cold is not None and (
                    not helper_cold or Path(helper_cold).read_bytes() != cold_bytes):
                raise AssertionError("read and worker cold selections must bind the same original report")
            cls.bindings.update({cls.cold: cold_bytes, nested_path: nested_bytes})
        else:
            if os.environ.get("HEPTA_HIA_WORKER_HELPERS_COLD_REPORT"):
                raise AssertionError("read development cannot borrow a worker cold qualification")
            cls.compiler = Path(development).resolve(strict=True)
        cls.bindings[cls.compiler] = cls.compiler.read_bytes()
        if os.environ.get(EVIDENCE):
            cls.folder = Path(os.environ[EVIDENCE]) / "integration"
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-agent-read-integration-")
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        cls.before = source_map()
        write_json(cls.folder / "source-before.json", cls.before)
        cls.addClassCleanup(cls.finish_custody)
        output = cls.folder / ("qualified-read" if cls.cold else "development-read")
        if cls.cold:
            from tools.build_hia_agent_read import build
            cls.manifest = Path(build(output, cls.compiler, cls.cold)).resolve(strict=True)
        else:
            from tools.qualify_hia_selfhost import compile_stage
            output.mkdir(mode=0o700)
            image, receipt = compile_stage(output, "agent-read", cls.compiler, native.SOURCE.read_bytes())
            cls.manifest = output / "manifest.json"
            write_json(cls.manifest, {"schema": native.SCHEMA,
                "source_sha256": sha256(native.SOURCE.read_bytes()).hexdigest(),
                "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                "compiler_sha256": sha256(cls.compiler.read_bytes()).hexdigest()})
            write_json(output / "development-observation.json", {
                "matching_current_source_cold_qualified": False,
                "native_compile_receipt": receipt, "compiler": identity(cls.compiler),
                "source": identity(native.SOURCE)})
        manifest = json.loads(cls.manifest.read_bytes())
        cls.image_path = (cls.manifest.parent / manifest["image_path"]).resolve(strict=True)
        cls.image_sha256 = manifest["image_sha256"]
        for path in (cls.manifest, cls.image_path, native.SOURCE):
            cls.bindings[path] = path.read_bytes()
        if sha256(cls.bindings[cls.image_path]).hexdigest() != cls.image_sha256:
            raise AssertionError("actual read image differs from its manifest")
        write_json(cls.folder / "fixture.json", {
            "scope": "MATCHING_CURRENT_SOURCE_COLD_BUILD" if cls.cold else "EXPLICIT_DEVELOPMENT_ONLY",
            "matching_current_source_cold_qualified": bool(cls.cold),
            "compiler": identity(cls.compiler), "cold_report": identity(cls.cold) if cls.cold else None,
            "manifest": identity(cls.manifest), "image": identity(cls.image_path),
            "source": identity(native.SOURCE), "hosted_owner_poisoned": "_reference_hia_read",
            "artifact_get_metadata_request_journal_and_worker_envelope_remain_current_owners": True,
            "source_or_wheel_without_bundle_is_not_claimed_fully_native": True,
            "implicit_bootstrap": False,
            "budget_sources": {"packaging_each_90_seconds": "tests/test_hia_slot_ledger_native_integration.py",
                "worker_and_installed_each_60_seconds": "tests/test_hia_worker_native_helpers.py"},
        })

    @classmethod
    def finish_custody(cls):
        after = source_map()
        write_json(cls.folder / "source-after.json", after)
        changed = [str(path) for path, raw in cls.bindings.items() if path.read_bytes() != raw]
        write_json(cls.folder / "final-custody.json", {
            "sources_preserved": cls.before == after, "changed_bound_files": changed,
            "bound_files": [identity(path) for path in sorted(cls.bindings, key=str)],
            "matching_current_source_cold_qualified": bool(cls.cold)})
        if cls.before != after or changed:
            raise AssertionError("read integration changed bound source, compiler, cold report or image")

    def setUp(self):
        from hepta.hia_agent_read_native import NativeAgentRead
        self.root = self.folder / self._testMethodName
        self.root.mkdir(mode=0o700)
        (self.root / "native").mkdir(mode=0o700)
        self.environment_before = dict(os.environ)
        self.clean_environment = {name: value for name, value in os.environ.items()
            if not (name.startswith("HEPTA_HIA_") and name.endswith("_MANIFEST"))}
        self.runtime_environment = {name: value for name, value in self.clean_environment.items()
            if not (name.startswith("HEPTA_HIA_") and name.endswith(("_COLD_REPORT",
                "_DEVELOPMENT_COMPILER", "_DEVELOPMENT_MANIFEST", "_EVIDENCE")))}
        self.stack = ExitStack()
        self.services, self.transitions, self.receipts, self.observations = [], [], [], []
        self.addCleanup(self.finish_case)
        self.stack.enter_context(patch.dict(os.environ, {
            **self.clean_environment, SELECTOR: str(self.manifest)}, clear=True))
        self.stack.enter_context(patch.object(HIAAgentService, "_reference_hia_read", denied_page))
        original = NativeAgentRead.transition

        def observed(image, request, data):
            self.assertIs(type(request), bytes)
            self.assertIs(type(data), bytes)
            index = len(self.transitions)
            request_path = self.root / "native" / (str(index) + ".request.bin")
            data_path = self.root / "native" / (sha256(data).hexdigest() + ".artifact.bin")
            output_path = self.root / "native" / (str(index) + ".output.bin")
            request_path.write_bytes(request)
            if not data_path.exists():
                data_path.write_bytes(data)
            self.assertEqual(data_path.read_bytes(), data)
            mapped = sha256(bytes(image._mapping)).hexdigest()
            self.assertEqual(mapped, self.image_sha256)
            record = {"request": identity(request_path), "artifact": identity(data_path),
                      "image_sha256": mapped, "request_words": list(struct.unpack_from("<16Q", request))}
            self.transitions.append(record)
            try:
                receipt = original(image, request, data)
            except BaseException as error:
                record["raised"] = {"type": type(error).__name__, "message": str(error)}
                raise
            output_path.write_bytes(receipt.raw)
            record.update({"output": identity(output_path), "status": receipt.status,
                "encoding": receipt.encoding, "offset": receipt.offset, "consumed": receipt.consumed,
                "next_offset": receipt.next_offset, "artifact_size": receipt.artifact_size,
                "wire_budget": receipt.wire_budget, "more": receipt.more,
                "identity_and_cursor_fields_hex": [value.hex() for value in receipt.fields[:4]]})
            self.receipts.append(receipt)
            return receipt

        self.stack.enter_context(patch.object(NativeAgentRead, "transition", observed))

    def finish_case(self):
        errors = []
        for service in reversed(self.services):
            try:
                service.close()
            except BaseException as error:
                errors.append(type(error).__name__ + ": " + str(error))
        try:
            self.stack.close()
        finally:
            write_json(self.root / "native-transitions.json", self.transitions)
            write_json(self.root / "observations.json", self.observations)
        if dict(os.environ) != self.environment_before:
            raise AssertionError("read fixture leaked environment selection")
        if errors:
            raise AssertionError("read fixture cleanup failed: " + repr(errors))

    def service(self, name="state", *, reopen=False):
        root = self.root / name
        files = self.root / (name + "-files")
        files.mkdir(mode=0o700, exist_ok=reopen)
        service = HIAAgentService(root, artifact_roots=(files,))
        self.assertIsNotNone(service._agent_read)
        self.assertIs(service._agent_read.db, service.store.db)
        self.services.append(service)
        return service

    def close_service(self, service):
        service.close()
        self.services.remove(service)

    def arguments(self, service, ref, **extra):
        return {"catalog_sha256": service.catalog_sha256, "artifact": deepcopy(ref), **extra}

    def completed(self, service, tool, arguments):
        response = service.call(tool, arguments)
        self.assertEqual(response["status"], "completed", response)
        return response["result"]

    def native_page(self, service, arguments):
        before = len(self.transitions)
        result = self.completed(service, "hia_read", arguments)
        self.assertEqual(len(self.transitions), before + 1)
        self.assertEqual(self.receipts[-1].status, 0)
        return result

    def reference_page(self, service, arguments):
        """Actual retained owner, explicitly outside the selected call path.

        Restore only this fixture's cursor rows after observing its original
        SQLite INSERT OR IGNORE.  The subsequent ordinary selected call must
        independently reproduce the complete result and rows.
        """
        before = cursor_rows(service)
        result = REFERENCE_READ(service, deepcopy(arguments))
        after = cursor_rows(service)
        with service.store.transaction():
            service.store.db.execute("DELETE FROM cursors")
            service.store.db.executemany("INSERT INTO cursors VALUES (?,?,?,?)", before)
        self.assertEqual(cursor_rows(service), before)
        return result, after

    def bundle(self, name="read-bundle.json", manifest=None):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        selected = self.manifest if manifest is None else Path(manifest)
        path = self.root / name
        write_json(path, {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
            "selector": SELECTOR, "manifest_path": str(selected),
            "manifest_sha256": sha256(selected.read_bytes()).hexdigest()}]})
        return path, sha256(path.read_bytes()).hexdigest()

    def run_recorded(self, name, command, *, cwd=None, environment=None, raw_input=None, timeout=60):
        prefix = self.root / name
        write_json(prefix.with_suffix(".command.json"), {"command": [str(value) for value in command],
            "timeout_seconds": timeout, "cwd": str(cwd or self.root)})
        if raw_input is not None:
            prefix.with_suffix(".stdin").write_bytes(raw_input)
        try:
            result = subprocess.run(command, cwd=cwd or self.root, env=environment,
                input=raw_input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            write_json(prefix.with_suffix(".process.json"), {
                "timed_out": True, "timeout_seconds": timeout, "complete_output": False})
            raise
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        write_json(prefix.with_suffix(".process.json"), {
            "returncode": result.returncode, "timed_out": False, "complete_output": True})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def worker(self, name, site, installed, state, roots, bundle, bundle_sha, pins,
               profile_sha, tool, arguments):
        envelope = {"schema": "hia-agent-worker-request-v1", "tool": tool,
            "arguments": arguments, "profile_sha256": profile_sha,
            "catalog_sha256": pins["catalog_sha256"]}
        envelope["request_sha256"] = sha256(wire(envelope)).hexdigest()
        trace = self.root / (name + "-trace")
        command = [sys.executable, "-I", "-S", "-B", "-c", WORKER_CHILD,
            str(site), str(trace), "yes" if installed else "no",
            "--state-root", str(state), "--request-json-stdin",
            *[argument for root in roots for argument in ("--artifact-root", str(root))],
            "--native-helpers-manifest", str(bundle), "--expected-native-helpers-sha256", bundle_sha,
            "--expected-worker-sha256", pins["worker_sha256"],
            "--expected-backend-sha256", pins["backend_sha256"],
            "--expected-catalog-sha256", pins["catalog_sha256"]]
        result = self.run_recorded(name, command, environment={**self.runtime_environment, "PATH": ""},
                                   raw_input=wire(envelope), timeout=60)
        report = json.loads(result.stdout)
        trace_report = json.loads((trace / "report.json").read_bytes())
        self.assertEqual(trace_report["initial_hia_test_or_manifest_selectors"], [])
        self.assertIs(report["complete"], True)
        self.assertEqual(report["request_sha256"], envelope["request_sha256"])
        self.assertEqual(report["profile_sha256"], profile_sha)
        self.assertEqual(report["native_helpers_sha256"], bundle_sha)
        self.assertEqual(report["response"]["status"], "completed", report)
        self.assertEqual(len(trace_report["frames"]), 1)
        self.assertEqual(trace_report["frames"][0]["image_sha256"], self.image_sha256)
        self.assertTrue(trace_report["environment_restored"])
        self.assertFalse(trace_report["authoring_imported"])
        self.observations.append({"worker_report": report, "trace_report": trace_report})
        return report["response"]["result"], trace_report

    def test_ordinary_read_resource_alias_and_cursor_restart_use_the_real_owner(self):
        service = self.service()
        data = ("page-é-🙂/" * 400).encode("utf-8")
        ref = service.store.put(data, "input")
        args = self.arguments(service, ref, max_bytes=512.0)
        expected, expected_rows = self.reference_page(service, args)
        actual = self.native_page(service, args)
        self.assertEqual(actual, expected)
        self.assertEqual(cursor_rows(service), expected_rows)
        self.assertEqual(actual["artifact"], ref)
        self.assertEqual(self.receipts[-1].fields[:3],
                         tuple(ref[name].encode() for name in ("id", "sha256", "uri")))
        count = len(self.transitions)
        alias = self.completed(service, "hia_resource_read", {"uri": ref["uri"], "max_bytes": 512.0})
        self.assertEqual(alias, actual)
        self.assertEqual(len(self.transitions), count + 1)
        first_cursor = actual["next_cursor"]
        self.assertIsInstance(first_cursor, str)
        rows_before = cursor_rows(service)
        identities, roots = service.identities, service.artifact_roots
        self.close_service(service)
        service = self.service(reopen=True)
        self.assertEqual(service.identities, identities)
        self.assertEqual(service.artifact_roots, roots)
        self.assertEqual(cursor_rows(service), rows_before)
        args = self.arguments(service, ref, max_bytes=512.0, cursor=first_cursor)
        expected, expected_rows = self.reference_page(service, args)
        resumed = self.native_page(service, args)
        self.assertEqual(resumed, expected)
        self.assertEqual(cursor_rows(service), expected_rows)
        self.assertEqual(resumed["artifact"], ref)
        self.assertEqual(self.receipts[-1].offset, rows_before[0][3])
        before = len(self.transitions)
        unknown = service.call("hia_resource_read", {"uri": "hia://artifacts/not-issued"})
        self.assertEqual(unknown["error"]["code"], "E_HIA_ARTIFACT_IDENTITY")
        self.assertEqual(len(self.transitions), before)
        self.observations.append({"reference": ref, "first": actual, "alias": alias,
            "resumed": resumed, "cursor_rows": expected_rows,
            "original_resource_alias_retains_store_uri_authority": unknown})

    def test_store_get_refusals_precede_cursor_and_do_not_enter_hosted_pagination(self):
        cases = ("extra-ref-key", "unissued-id", "different-uri", "missing-file",
                 "corrupt-file", "invalid-metadata", "cursor-only")
        for index, label in enumerate(cases):
            with self.subTest(label=label):
                service = self.service("case-" + str(index))
                data = b"issued byte authority before cursor admission"
                ref = service.store.put(data, "input", {"fixture": label})
                args = self.arguments(service, ref, cursor="missing-cursor", max_bytes=512)
                if label == "extra-ref-key":
                    args["artifact"]["extra"] = "not part of the issued reference"
                elif label == "unissued-id":
                    args["artifact"]["id"] = "a-" + "0" * 32
                elif label == "different-uri":
                    args["artifact"]["uri"] = "hia://artifacts/" + "0" * 32
                elif label == "missing-file":
                    (service.store.artifacts / ref["sha256"]).unlink()
                elif label == "corrupt-file":
                    path = service.store.artifacts / ref["sha256"]
                    path.chmod(0o600)
                    path.write_bytes(b"changed issued bytes")
                elif label == "invalid-metadata":
                    service.store.db.execute("UPDATE artifacts SET metadata=? WHERE id=?", ("{", ref["id"]))

                def rejected(call):
                    try:
                        call()
                    except (ValueError, TypeError, OSError, OverflowError) as error:
                        return {"type": type(error).__name__, "code": getattr(error, "code", None),
                                "message": str(error), "phase": getattr(error, "phase", None)}
                    raise AssertionError("expected the original Store.get/cursor refusal")

                expected = rejected(lambda: REFERENCE_READ(service, deepcopy(args)))
                before_rows, count = cursor_rows(service), len(self.transitions)
                actual = rejected(lambda: service._hia_read(deepcopy(args)))
                self.assertEqual(actual, expected)
                self.assertEqual(cursor_rows(service), before_rows)
                self.assertEqual(len(self.transitions), count + int(label == "cursor-only"))
                if label == "cursor-only":
                    self.assertEqual(actual["code"], "E_HIA_CURSOR")
                    self.assertEqual(self.receipts[-1].status, 1)
                self.observations.append({"case": label, "original": expected,
                    "selected": actual, "cursor_rows_unchanged": before_rows})
                self.close_service(service)

    def test_complete_artifact_utf8_and_exact_double_wire_halving_are_preserved(self):
        service = self.service()
        exact = b"\x00" * 17690 + b"a" * 11
        cases = (
            ("full-invalid-tail", b"A" * 2048 + b"\xff", 512.0, "base64", 512),
            ("utf8-page-boundary", b"A" * 511 + "🙂tail".encode(), 512.0, "utf8", 511),
            ("exact-230000", exact, 65536, "utf8", len(exact)),
            ("first-over-230000", exact + b"a", 65536, "utf8", (len(exact) + 1) // 2),
            ("two-original-halvings", b"\x00" * 65536, 65536, "utf8", 16384),
            ("quotes-backslashes", b'"\x5c' * 32768, 65536, "utf8", 32768),
        )
        for label, data, limit, encoding, consumed in cases:
            with self.subTest(label=label):
                ref = service.store.put(data, "input", {"fixture": label})
                args = self.arguments(service, ref, max_bytes=limit)
                expected, rows = self.reference_page(service, args)
                actual = self.native_page(service, args)
                self.assertEqual(actual, expected)
                self.assertEqual(cursor_rows(service), rows)
                receipt = self.receipts[-1]
                self.assertEqual(receipt.consumed, consumed)
                self.assertEqual(receipt.artifact_size, len(data))
                self.assertEqual(actual["encoding"], encoding)
                first_wire = wire(actual["content"])
                second_wire = wire(first_wire.decode("utf-8"))
                cost = len(first_wire) + len(second_wire)
                self.assertEqual(receipt.wire_budget, cost)
                self.assertLessEqual(cost, 230000)
                if label == "exact-230000":
                    self.assertEqual(cost, 230000)
                    self.assertIsNone(actual["next_cursor"])
                if label == "first-over-230000":
                    self.assertEqual(len(wire(data.decode())) +
                        len(wire(wire(data.decode()).decode())), 230002)
                observed = (base64.b64decode(actual["content"]) if encoding == "base64"
                            else actual["content"].encode())
                self.assertEqual(observed, data[:consumed])
                self.observations.append({"case": label, "reference": ref,
                    "maximum_json_number": limit, "consumed": consumed,
                    "first_wire_bytes": len(first_wire), "second_wire_bytes": len(second_wire),
                    "actual_wire_budget": cost, "cursor": actual["next_cursor"]})

    def test_negative_cursor_offsets_and_insert_or_ignore_keep_original_sql_semantics(self):
        service = self.service()
        data = b"0123456789abcdef" * 80
        ref = service.store.put(data, "input")
        for index, offset in enumerate((-1, -513, -1280, -2048, -(1 << 63), 0, 511, (1 << 63) - 1)):
            with self.subTest(offset=offset):
                key = "retained-negative-" + str(index)
                service.store.db.execute("INSERT INTO cursors VALUES (?,?,?,?)",
                                        (key, ref["id"], ref["sha256"], offset))
                args = self.arguments(service, ref, max_bytes=512.0, cursor=key)
                expected, rows = self.reference_page(service, args)
                actual = self.native_page(service, args)
                self.assertEqual(actual, expected)
                self.assertEqual(cursor_rows(service), rows)
                self.assertEqual(self.receipts[-1].offset, offset)
                self.assertIs(service._agent_read.db, service.store.db)
                self.assertFalse(service.store.db.in_transaction)
                self.observations.append({"offset": offset, "result": actual, "cursor_rows": rows})

        key = "collision-input"
        service.store.db.execute("INSERT INTO cursors VALUES (?,?,?,?)",
                                (key, ref["id"], ref["sha256"], 111))
        args = self.arguments(service, ref, max_bytes=512, cursor=key)
        expected, _ = self.reference_page(service, args)
        next_key = expected["next_cursor"]
        self.assertIsNotNone(next_key)
        service.store.db.execute("DELETE FROM cursors WHERE id=?", (next_key,))
        collision = [next_key, "already-retained-artifact", "f" * 64, -777]
        service.store.db.execute("INSERT INTO cursors VALUES (?,?,?,?)", collision)
        expected, rows = self.reference_page(service, args)
        actual = self.native_page(service, args)
        self.assertEqual(actual, expected)
        self.assertEqual(cursor_rows(service), rows)
        self.assertEqual(list(service.store.db.execute("SELECT * FROM cursors WHERE id=?",
                                                       (next_key,)).fetchone()), collision)
        self.observations.append({"insert_or_ignore_original_collision": collision,
                                  "result": actual, "cursor_rows": rows})

    def test_stable_read_mutation_cannot_relabel_captured_full_arguments_or_reference(self):
        from hepta import hia_agent_store as store_module
        real_stable_read = store_module.stable_read
        for route in ("ordinary-tool", "selected-adapter-boundary"):
            with self.subTest(route=route):
                service = self.service(route)
                data = b"frozen-input/" * 300
                ref = service.store.put(data, "input")
                cursor = "frozen-cursor"
                service.store.db.execute("INSERT INTO cursors VALUES (?,?,?,?)",
                                        (cursor, ref["id"], ref["sha256"], 123))
                arguments = self.arguments(service, ref, max_bytes=512.0, cursor=cursor)
                captured = deepcopy(arguments)
                original_reference = arguments["artifact"]
                expected, rows = self.reference_page(service, captured)
                target = service.store.artifacts / ref["sha256"]
                calls = []

                def changed_during_io(path, limit, **kwargs):
                    if Path(path) == target:
                        calls.append({"path": str(path), "limit": limit, "dir_fd": kwargs.get("dir_fd")})
                        original_reference.clear()
                        original_reference.update({"id": "changed-id", "sha256": "0" * 64,
                            "uri": "hia://artifacts/changed", "unexpected": True})
                        arguments["artifact"] = {"another": "mutable producer"}
                        arguments["cursor"] = "different-cursor"
                        arguments["max_bytes"] = 65536
                        arguments["catalog_sha256"] = "0" * 64
                        arguments["extra"] = "must not enter a captured request"
                    return real_stable_read(path, limit, **kwargs)

                before = len(self.transitions)
                with patch.object(store_module, "stable_read", changed_during_io):
                    if route == "ordinary-tool":
                        actual = self.completed(service, "hia_read", arguments)
                    else:
                        actual = service._hia_read(arguments)
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(self.transitions), before + 1)
                self.assertNotEqual(arguments, captured)
                self.assertEqual(actual, expected)
                self.assertEqual(actual["artifact"], captured["artifact"])
                self.assertEqual(cursor_rows(service), rows)
                receipt = self.receipts[-1]
                self.assertEqual(receipt.fields[:3], tuple(captured["artifact"][name].encode()
                    for name in ("id", "sha256", "uri")))
                self.assertEqual(receipt.offset, 123)
                self.assertEqual(receipt.consumed, 512)
                self.assertEqual(self.transitions[-1]["request_words"][3], 512)
                self.assertEqual(self.transitions[-1]["artifact"]["sha256"], ref["sha256"])
                self.observations.append({"route": route, "frozen_arguments": captured,
                    "producer_after_real_io": arguments, "native_result": actual,
                    "real_stable_read_calls": calls})

    def test_selected_read_and_bundle_admission_refuse_before_store_without_fallback(self):
        from hepta.hia_agent_read_native import NativeAgentRead, SOURCE, SCHEMA
        from hepta.hia_json_preflight_native import _installed_json_image
        from hepta.hia_native_helpers import native_helpers_scope
        original = json.loads(self.manifest.read_bytes())
        attempts = [("empty", None), ("schema", {"schema": "unknown.agent.read"}),
                    ("source", {"source_sha256": "0" * 64}),
                    ("image", {"image_sha256": "0" * 64})]
        for name, change in attempts:
            with self.subTest(name=name):
                root = self.root / ("refused-" + name)
                if change is None:
                    selected = ""
                else:
                    path = self.root / (name + ".manifest.json")
                    write_json(path, {**original, "image_path": str(self.image_path), **change})
                    selected = str(path)
                before = len(self.transitions)
                with patch.dict(os.environ, {**self.clean_environment, SELECTOR: selected}, clear=True):
                    with self.assertRaises(AgentRejected) as error:
                        HIAAgentService(root)
                self.assertEqual(error.exception.code, "E_HIA_READ_NATIVE_CUSTODY")
                self.assertFalse(root.exists())
                self.assertEqual(len(self.transitions), before)
                self.observations.append({"refusal": name, "code": error.exception.code,
                                          "message": str(error.exception)})
        bundle, digest = self.bundle()
        class UnregisteredReadView(NativeAgentRead):
            pass
        with patch.dict(os.environ, self.clean_environment, clear=True), \
                native_helpers_scope(str(bundle), digest):
            with self.assertRaises(ValueError):
                _installed_json_image(str(self.manifest), SOURCE, SCHEMA, UnregisteredReadView)
        target = self.root / "wrong-bundle-pin-state"
        with patch.dict(os.environ, self.clean_environment, clear=True):
            with self.assertRaises(ValueError):
                with native_helpers_scope(str(bundle), "0" * 64):
                    HIAAgentService(target)
        self.assertFalse(target.exists())

    def test_original_worker_pinned_bundle_reads_and_resumes_without_per_call_selectors(self):
        from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
        bundle, digest = self.bundle()
        with patch.dict(os.environ, self.clean_environment, clear=True), \
                native_helpers_scope(str(bundle), digest):
            service = self.service()
            data = ("worker-π-🙂/" * 200).encode()
            ref = service.store.put(data, "input")
            first_args = self.arguments(service, ref, max_bytes=512)
            first = self.native_page(service, first_args)
            cursor = first["next_cursor"]
            self.assertIsNotNone(cursor)
            next_args = self.arguments(service, ref, max_bytes=512, cursor=cursor)
            expected, expected_rows = self.reference_page(service, next_args)
            pins, profile = dict(service.identities), service.profiles["compiler"]["sha256"]
            roots, state = service.artifact_roots, service.store.root
            self.assertEqual(native_helpers_identity()["native_helpers_sha256"], digest)
            self.close_service(service)
        self.assertFalse(any(name.endswith("_MANIFEST") and name.startswith("HEPTA_HIA_")
                             for name in self.clean_environment))
        resumed, resumed_trace = self.worker("worker-resume", ROOT, False, state, roots,
            bundle, digest, pins, profile, "hia_read", next_args)
        self.assertEqual(resumed, expected)
        alias, alias_trace = self.worker("worker-resource-alias", ROOT, False, state, roots,
            bundle, digest, pins, profile, "hia_resource_read", {"uri": ref["uri"], "max_bytes": 512})
        self.assertEqual(alias, first)
        with patch.dict(os.environ, self.clean_environment, clear=True), \
                native_helpers_scope(str(bundle), digest):
            service = self.service(reopen=True)
            self.assertEqual(service.identities, pins)
            self.assertEqual(cursor_rows(service), expected_rows)
            data_after, _ = service.store.get(ref)
            self.assertEqual(data_after, data)
        self.observations.append({"first": first, "resumed": resumed, "alias": alias,
            "same_administrator_artifact_roots": [str(root) for root in roots],
            "worker_selection_source": "fixed bundle argv and whole-bundle sha256 pin",
            "per_call_manifest_environment": False,
            "native_worker_transitions": [resumed_trace["frames"], alias_trace["frames"]]})

    def test_real_installed_wheel_worker_uses_packaged_read_and_rejects_resource_drift(self):
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES)
        bundle, digest = self.bundle()
        source = self.root / "source"
        source.mkdir()
        shutil.copytree(ROOT / "hepta", source / "hepta",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        resources = tuple("docs/" + name for name in DISCOVERY_FILES) + \
            NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        self.assertIn("examples/hia_bootstrap/agent_read.hepta", resources)
        historical_fixture = "tests/fixtures/hia_compiler_rename_reference.json.gz"
        historical_bytes = (ROOT / historical_fixture).read_bytes()
        self.assertEqual(len(historical_bytes), 182803)
        self.assertEqual(sha256(historical_bytes).hexdigest(),
                         "0bfb03e219dc31352ae92e22288139e66e1c00ab4a4861648b54712c8e213069")
        self.assertNotIn(historical_fixture, resources)
        for name in (*resources, historical_fixture, "setup.py", "pyproject.toml", "MANIFEST.in"):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get("HEPTA_HIA_TEST_PACKAGING_PYTHON", sys.executable)
        self.run_recorded("sdist", [packaging, "-B", "setup.py", "sdist",
            "--dist-dir", str(self.root / "sdist")], cwd=source, timeout=90)
        archive, = (self.root / "sdist").glob("*.tar.gz")
        with tarfile.open(archive) as tar:
            prefix = tar.getnames()[0].split("/")[0] + "/"
            for name in resources:
                self.assertEqual(tar.extractfile(prefix + name).read(), (ROOT / name).read_bytes(), name)
            self.assertEqual(tar.extractfile(prefix + historical_fixture).read(), historical_bytes)
        self.run_recorded("wheel", [packaging, "-B", "-m", "pip", "wheel", "--no-deps", "--no-index",
            "--no-build-isolation", "--wheel-dir", str(self.root / "wheels"), str(archive)], timeout=90)
        wheel, = (self.root / "wheels").glob("*.whl")
        with zipfile.ZipFile(wheel) as archive_file:
            self.assertFalse(any(name.endswith("/hia_compiler_rename_reference.json.gz")
                                 for name in archive_file.namelist()))
        installed = self.root / "installed"
        self.run_recorded("install", [packaging, "-B", "-m", "pip", "install", "--no-deps", "--no-index",
            "--target", str(installed), str(wheel)], timeout=90)
        self.assertFalse(list(installed.rglob("hia_compiler_rename_reference.json.gz")))
        prepare = r"""
import importlib.abc, json, os, sys
from hashlib import sha256
from pathlib import Path
site, bundle, bundle_hash, state, evidence = sys.argv[1:]
sys.path.insert(0, site)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"tools", "tests"} or fullname.startswith(("tools.", "tests.")):
            raise AssertionError("installed read fixture imported authoring/test code")
sys.meta_path.insert(0, NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_read_native import NativeAgentRead, SOURCE
from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
assert Path(site).resolve() in Path(SOURCE).resolve().parents
assert Path(site).resolve() in Path(sys.modules["hepta.hia_agent_read_native"].__file__).resolve().parents
initial_selectors = sorted(name for name in os.environ if name.startswith("HEPTA_HIA_") and
    name.endswith(("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_DEVELOPMENT_MANIFEST", "_EVIDENCE")))
assert not initial_selectors, initial_selectors
roots = (Path(state + "-files"),)
roots[0].mkdir(mode=0o700)
data = ("installed-é-🙂/" * 200).encode()
plain = HIAAgentService(state + "-without-bundle", artifact_roots=roots)
assert plain._agent_read is None, "unselected wheel must keep its explicit hosted boundary"
plain_ref = plain.store.put(b"unselected ordinary read", "input")
plain_response = plain.call("hia_read", {"catalog_sha256": plain.catalog_sha256,
    "artifact": plain_ref, "max_bytes": 512})
assert plain_response["status"] == "completed", plain_response
plain.close()
def forbidden(*args, **kwargs):
    raise AssertionError("installed selected ordinary read used hosted pagination")
HIAAgentService._reference_hia_read = forbidden
frames = []
original = NativeAgentRead.transition
evidence = Path(evidence)
evidence.mkdir(mode=0o700)
def observed(image, request, artifact):
    index = len(frames)
    before = bytes(request), bytes(artifact)
    (evidence / (str(index) + ".request.bin")).write_bytes(before[0])
    (evidence / (str(index) + ".artifact.bin")).write_bytes(before[1])
    receipt = original(image, request, artifact)
    (evidence / (str(index) + ".output.bin")).write_bytes(receipt.raw)
    frames.append({"request_sha256": sha256(before[0]).hexdigest(),
        "artifact_sha256": sha256(before[1]).hexdigest(), "artifact_bytes": len(before[1]),
        "output_sha256": sha256(receipt.raw).hexdigest(), "offset": receipt.offset,
        "consumed": receipt.consumed, "next_offset": receipt.next_offset,
        "fields_hex": [value.hex() for value in receipt.fields[:4]],
        "image_sha256": sha256(bytes(image._mapping)).hexdigest()})
    return receipt
NativeAgentRead.transition = observed
before_env = dict(os.environ)
with native_helpers_scope(bundle, bundle_hash):
    service = HIAAgentService(state, artifact_roots=roots)
    assert service._agent_read is not None
    assert service._agent_read.db is service.store.db
    ref = service.store.put(data, "input")
    args = {"catalog_sha256": service.catalog_sha256, "artifact": ref, "max_bytes": 512.0}
    response = service.call("hia_read", args)
    assert response["status"] == "completed", response
    assert len(frames) == 1, frames
    first = response["result"]
    assert first["artifact"] == ref and first["next_cursor"]
    assert native_helpers_identity()["native_helpers_sha256"] == bundle_hash
    pins, profile = service.identities, service.profiles["compiler"]["sha256"]
    rows = [list(row) for row in service.store.db.execute("SELECT * FROM cursors ORDER BY id")]
    service.close()
assert dict(os.environ) == before_env
assert not any(name in {"tools", "tests"} or name.startswith(("tools.", "tests.")) for name in sys.modules)
payload = {"reference": ref, "first": first, "data_hex": data.hex(),
    "next_arguments": {"catalog_sha256": pins["catalog_sha256"], "artifact": ref,
                       "max_bytes": 512.0, "cursor": first["next_cursor"]},
    "identities": pins, "profile_sha256": profile, "artifact_roots": [str(root) for root in roots],
    "frames": frames, "cursor_rows": rows, "source": str(SOURCE),
    "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
    "unselected_wheel_read": plain_response, "unselected_wheel_read_owner": "retained hosted owner",
    "selected_wheel_pagination_owner": "actual NativeAgentRead",
    "authoring_imported": False, "initial_hia_test_or_manifest_selectors": initial_selectors}
print(json.dumps(payload, sort_keys=True))
"""
        (self.root / "installed-prepare.py").write_text(prepare)
        state = self.root / "installed-state"
        prepared = self.run_recorded("installed-prepare", [sys.executable, "-I", "-S", "-B", "-c", prepare,
            str(installed), str(bundle), digest, str(state), str(self.root / "installed-native")],
            environment={**self.runtime_environment, "PATH": ""}, timeout=60)
        payload = json.loads(prepared.stdout)
        self.assertFalse(payload["authoring_imported"])
        self.assertEqual(payload["initial_hia_test_or_manifest_selectors"], [])
        self.assertEqual(len(payload["frames"]), 1)
        self.assertEqual(payload["frames"][0]["image_sha256"], self.image_sha256)
        roots, pins = payload["artifact_roots"], payload["identities"]
        resumed, _ = self.worker("installed-worker-resume", installed, True, state, roots,
            bundle, digest, pins, payload["profile_sha256"], "hia_read", payload["next_arguments"])
        alias, _ = self.worker("installed-worker-alias", installed, True, state, roots,
            bundle, digest, pins, payload["profile_sha256"], "hia_resource_read",
            {"uri": payload["reference"]["uri"], "max_bytes": 512.0})
        self.assertEqual(alias, payload["first"])
        self.assertEqual(resumed["artifact"], payload["reference"])
        complete = bytes.fromhex(payload["data_hex"])
        offset = payload["frames"][0]["next_offset"]
        expected_chunk = complete[offset:offset + 512]
        while True:
            try:
                expected_text = expected_chunk.decode("utf-8")
                break
            except UnicodeDecodeError:
                expected_chunk = expected_chunk[:-1]
        self.assertEqual(resumed["encoding"], "utf8")
        self.assertEqual(resumed["content"], expected_text)
        self.assertNotEqual(resumed["next_cursor"], payload["first"]["next_cursor"])

        refusal = r"""
import importlib.abc, json, os, sys
from pathlib import Path
from hashlib import sha256
site, bundle, bundle_hash, state = sys.argv[1:]
sys.path.insert(0, site)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"tools", "tests"} or fullname.startswith(("tools.", "tests.")):
            raise AssertionError("installed refusal searched authoring/tests")
sys.meta_path.insert(0, NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_read_native import SOURCE
from hepta.hia_native_helpers import native_helpers_scope
initial_selectors = sorted(name for name in os.environ if name.startswith("HEPTA_HIA_") and
    name.endswith(("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_DEVELOPMENT_MANIFEST", "_EVIDENCE")))
assert not initial_selectors, initial_selectors
def forbidden(*args, **kwargs):
    raise AssertionError("installed source refusal fell back to hosted pagination")
HIAAgentService._reference_hia_read = forbidden
original = SOURCE.read_bytes()
before = dict(os.environ)
controls = []
for index, replacement in enumerate((None, b"changed packaged read source")):
    target = Path(state + "-refused-" + str(index))
    try:
        if replacement is None:
            SOURCE.unlink()
        else:
            SOURCE.write_bytes(replacement)
        try:
            with native_helpers_scope(bundle, bundle_hash):
                HIAAgentService(target)
        except (ValueError, OSError) as error:
            controls.append({"type": type(error).__name__, "message": str(error)})
        else:
            raise AssertionError("packaged source drift admitted a new service")
        assert not target.exists(), target
    finally:
        SOURCE.write_bytes(original)
assert SOURCE.read_bytes() == original
assert dict(os.environ) == before
assert not any(name in {"tools", "tests"} or name.startswith(("tools.", "tests.")) for name in sys.modules)
print(json.dumps({"controls": controls, "source": str(SOURCE),
    "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(), "source_restored": True,
    "environment_restored": True, "authoring_imported": False,
    "initial_hia_test_or_manifest_selectors": initial_selectors}, sort_keys=True))
"""
        (self.root / "installed-refusal.py").write_text(refusal)
        rejected = self.run_recorded("installed-refusal", [sys.executable, "-I", "-S", "-B", "-c", refusal,
            str(installed), str(bundle), digest, str(state)],
            environment={**self.runtime_environment, "PATH": ""}, timeout=60)
        refusal_report = json.loads(rejected.stdout)
        self.assertEqual(len(refusal_report["controls"]), 2)
        self.assertEqual(refusal_report["initial_hia_test_or_manifest_selectors"], [])
        self.assertEqual(refusal_report["source_sha256"], payload["source_sha256"])
        self.assertTrue(refusal_report["source_restored"])
        self.assertTrue(refusal_report["environment_restored"])
        self.observations.append({"installed_payload": payload, "resumed": resumed,
            "alias": alias, "refusal_report": refusal_report,
            "source_checkout_not_used_by_installed_runtime": True})


if __name__ == "__main__":
    unittest.main()
