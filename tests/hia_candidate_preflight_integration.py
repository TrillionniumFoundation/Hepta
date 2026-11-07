"""Cross-repository preflight tests against the exact runtime contract helpers.

The runtime checkout is a required explicit input. Worker subprocesses and MCP
servers below are small committed protocol fixtures, not production deployments
or evidence that the HIA native backend is self-hosted. No network or SSH is used.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import marshal
from pathlib import Path
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import hia_candidate_preflight as preflight

RUNTIME_REVISION = "9f60a30530f47925f4f6ae495660a1d68bb6947d"
RUNTIME_CHECKOUT = None

WORKER = '''from hashlib import sha256
import json
from pathlib import Path
from .hia_agent_contract import DISCOVERY_FILES
root = Path(__file__).resolve().parents[1]
entries = {str(p.relative_to(root)): sha256(p.read_bytes()).hexdigest()
           for p in sorted((root / "hepta").rglob("*.py"))}
for name in DISCOVERY_FILES:
    p = root / "docs" / name
    entries[str(p.relative_to(root))] = sha256(p.read_bytes()).hexdigest()
wire = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
print(json.dumps({"worker_sha256": sha256(wire).hexdigest(),
    "backend_sha256": sha256((root / "hepta/hia_program_native.py").read_bytes()).hexdigest(),
    "catalog_sha256": entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"]}))
'''


class CandidateIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if RUNTIME_CHECKOUT is None:
            raise RuntimeError("--runtime-checkout at the pinned revision is required")
        preflight.configure_runtime(RUNTIME_CHECKOUT, RUNTIME_REVISION)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-preflight-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        docs = (*sorted(preflight.REQUIRED_WORKER_DOCS), "HIA_EXTRA_DISCOVERY.md")
        catalog = (RUNTIME_CHECKOUT / "src/mcp/hia_tool_catalog.json").read_bytes()
        files = {
            ".gitignore": b"__pycache__/\nignored_*.py\n",
            "hepta/__init__.py": b"",
            "hepta/hia_agent_worker.py": WORKER.encode(),
            "hepta/hia_agent_store.py": b"FIXED_STORE = True\n",
            "hepta/hia_program_native.py": b"NATIVE_FIXTURE = True\n",
            "hepta/hia_agent_contract.py": ("DISCOVERY_FILES = " + repr(docs) + "\n").encode(),
            "tools/hia_agent_native_transport.py": (ROOT / preflight.TRANSPORT).read_bytes(),
            **{"docs/" + name: (catalog if name.endswith(".json") else b"Fixture guidance\n") for name in docs},
        }
        for path, raw in files.items():
            self.write(self.source / path, raw)
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Protocol fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "committed source fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.secret = "CONFIGURATION_SECRET_MUST_NOT_APPEAR_IN_REPORT"
        self.configuration = {
            "state_dir": str(self.root / "controller"),
            "hosts": {"fixture": {
                "ssh_target": "explicit-fixture-host", "platform": "linux", "allow_execute": True,
                "allow_write": True, "allowed_read_path_prefixes": ["/"],
                "allowed_write_path_prefixes": [str(self.root / "state")],
            }},
            "hia_worker": {
                "host": "fixture", "python_executable": sys.executable,
                "working_directory": str(self.source), "state_root": str(self.root / "state"),
                "artifact_roots": [str(self.root / "inputs")],
                "worker_sha256": "placeholder", "backend_sha256": "placeholder", "catalog_sha256": "placeholder",
            },
            "unrelated_existing_policy": {"secret": self.secret, "grant": False},
        }
        self.config_file = self.write(self.root / "input-config.json", preflight.json_bytes(self.configuration))
        self.tools = preflight.hia_mcp_catalog.registered_tools() + [
            {"name": name, "description": "Existing owner fixture " + name,
             "inputSchema": {"type": "object", "additionalProperties": False},
             "annotations": {"readOnlyHint": True, "destructiveHint": False,
                             "idempotentHint": True, "openWorldHint": False}}
            for name in sorted(preflight.OWNER_TOOLS)
        ]
        self.contract_value = preflight.hia_mcp_catalog.make_contract(self.tools)
        self.contract = preflight.ToolContract(self.contract_value)
        self.contract_file = self.write(self.root / "full-contract.json", preflight.json_bytes(self.contract_value))

    @staticmethod
    def write(path, raw, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args], text=True)

    def prepare(self, **kwargs):
        return preflight.prepare(self.source, self.revision, RUNTIME_REVISION,
                                 self.config_file, Path(sys.executable), **kwargs)

    def retained_candidate(self):
        candidate, raw_config = self.prepare()
        directory = self.root / "candidate"
        raw_candidate = preflight.json_bytes(candidate)
        preflight.publish(directory, {"candidate.json": raw_candidate, "runtime-config.json": raw_config})
        return candidate, directory, preflight.sha256(raw_candidate)

    def verify_args(self, directory, digest, output):
        return ["verify", "--runtime-checkout", str(RUNTIME_CHECKOUT),
                "--candidate", str(directory / "candidate.json"), "--candidate-sha256", digest,
                "--config", str(directory / "runtime-config.json"),
                "--full-contract", str(self.contract_file),
                "--full-contract-sha256", preflight.sha256(self.contract_file.read_bytes()),
                "--native-tools", str(self.root / "native-tools.json"),
                "--worker-manifest", str(self.root / "worker-manifest.json"),
                "--output-directory", str(output)]

    def test_real_manifest_subprocess_matches_independent_inventory(self):
        candidate, raw_config = self.prepare()
        self.assertTrue(candidate["source_qualified"])
        self.assertEqual(candidate["source_pair"]["hepta_commit"], self.revision)
        self.assertEqual(candidate["source_pair"]["runtime_commit"], RUNTIME_REVISION)
        self.assertIn("docs/HIA_EXTRA_DISCOVERY.md", candidate["worker_source_files"])
        installed = preflight.installed_pins(self.source, Path(sys.executable))
        self.assertEqual(candidate["source_pair"]["installation"], installed)
        config = preflight.decode(raw_config)
        self.assertEqual(config["unrelated_existing_policy"], self.configuration["unrelated_existing_policy"])
        self.assertEqual(preflight.decode(self.config_file.read_bytes()), self.configuration)
        self.assertNotIn(self.secret, preflight.json_bytes(candidate).decode())

    def test_valid_ignored_worker_cache_is_rejected_without_execution(self):
        source = self.source / "hepta/hia_agent_worker.py"
        original = source.read_bytes()
        cached = Path(py_compile.compile(str(source), doraise=True))
        marker = self.root / "cached-worker-executed"
        forged = compile("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n", str(source), "exec")
        cached.write_bytes(cached.read_bytes()[:16] + marshal.dumps(forged))
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(ValueError, "cache or binary shadow"):
            self.prepare()
        with self.assertRaisesRegex(ValueError, "cache or binary shadow"):
            preflight.installed_pins(self.source, Path(sys.executable))
        self.assertFalse(marker.exists())

    def test_published_configuration_and_manifest_are_private_and_reloadable(self):
        candidate, directory, digest = self.retained_candidate()
        loaded, _, _ = preflight.load_candidate(directory / "candidate.json", digest,
                                                directory / "runtime-config.json")
        self.assertEqual(loaded, candidate)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_destination_is_not_repaired_or_overwritten(self):
        directory = self.root / "existing"
        directory.mkdir(mode=0o777)
        directory.chmod(0o777)
        marker = self.write(directory / "marker", b"untouched")
        with self.assertRaises(FileExistsError):
            preflight.publish(directory, {"candidate.json": b"{}"})
        self.assertEqual(marker.read_bytes(), b"untouched")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)

    def test_output_cannot_follow_a_symlink_ancestor(self):
        actual = self.root / "actual"
        actual.mkdir()
        link = self.root / "link"
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            preflight.publish(link / "candidate", {"candidate.json": b"{}"})
        self.assertEqual(list(actual.iterdir()), [])

    def test_security_source_fix_changes_worker_pin_without_guessing_other_pins(self):
        original, _ = self.prepare()
        self.write(self.source / "hepta/hia_agent_store.py", b"FIXED_STORE = True\nCHECK_ARTIFACT_DIRECTORY = True\n")
        changed, _ = self.prepare(allow_dirty=True)
        old = original["source_pair"]["installation"]
        new = changed["source_pair"]["installation"]
        self.assertNotEqual(new["worker_sha256"], old["worker_sha256"])
        self.assertEqual(new["backend_sha256"], old["backend_sha256"])
        self.assertEqual(new["catalog_sha256"], old["catalog_sha256"])
        self.assertFalse(changed["source_qualified"])
        with self.assertRaisesRegex(ValueError, "observed worker"):
            preflight.verify_captures(changed, {"tools": self.tools}, old, self.contract)

    def test_development_candidate_never_qualifies_an_installation(self):
        self.write(self.source / "uncommitted.txt", b"development")
        candidate, configuration = self.prepare(allow_dirty=True)
        raw = preflight.json_bytes(candidate)
        directory = self.root / "development"
        preflight.publish(directory, {"candidate.json": raw, "runtime-config.json": configuration})
        with self.assertRaisesRegex(ValueError, "development candidate"):
            preflight.load_candidate(directory / "candidate.json", preflight.sha256(raw),
                                     directory / "runtime-config.json")

    def test_assume_unchanged_cannot_hide_modified_source(self):
        self.git("update-index", "--assume-unchanged", "hepta/hia_agent_store.py")
        self.write(self.source / "hepta/hia_agent_store.py", b"FIXED_STORE = False\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(ValueError, "actual worker files"):
            self.prepare()

    def test_ignored_importable_python_is_still_measured_and_rejected(self):
        self.write(self.source / "hepta/ignored_new.py", b"UNCOMMITTED = True\n")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(ValueError, "actual worker files"):
            self.prepare()

    def test_changed_source_pair_cannot_reuse_a_prepared_candidate(self):
        _, directory, digest = self.retained_candidate()
        self.write(self.source / "hepta/hia_agent_store.py", b"CHANGED = True\n")
        with self.assertRaises(ValueError):
            preflight.load_candidate(directory / "candidate.json", digest, directory / "runtime-config.json")

    def test_configuration_edit_requires_a_new_candidate(self):
        _, directory, digest = self.retained_candidate()
        path = directory / "runtime-config.json"
        config = preflight.decode(path.read_bytes())
        config["hia_worker"]["state_root"] = str(self.root / "another-state")
        path.write_bytes(preflight.json_bytes(config))
        with self.assertRaisesRegex(ValueError, "SHA256"):
            preflight.load_candidate(directory / "candidate.json", digest, path)

    def test_actual_catalog_and_worker_pins_verify_together(self):
        candidate, _ = self.prepare()
        checks = preflight.verify_captures(candidate, {"jsonrpc": "2.0", "id": 7, "result": {"tools": self.tools}},
                                           candidate["source_pair"]["installation"], self.contract)
        self.assertEqual(checks["hia_tool_count"], 11)
        self.assertEqual(checks["tool_count"], len(self.tools))
        self.assertEqual(checks["whole_server_catalog_sha256"], self.contract.catalog_sha256)

    def test_hia_family_contract_cannot_replace_full_operator_contract(self):
        candidate, _ = self.prepare()
        family = preflight.hia_mcp_catalog.registered_tools()
        contract = preflight.ToolContract(preflight.hia_mcp_catalog.make_contract(family))
        with self.assertRaisesRegex(ValueError, "HIA-only"):
            preflight.verify_captures(candidate, {"tools": family}, candidate["source_pair"]["installation"], contract)

    def test_non_hia_tool_drift_is_detected_by_whole_server_pin(self):
        candidate, _ = self.prepare()
        tools = copy.deepcopy(self.tools)
        tools[-1]["description"] += " unauthorized change"
        with self.assertRaisesRegex(ValueError, "upstream tool contract drift"):
            preflight.verify_captures(candidate, {"tools": tools}, candidate["source_pair"]["installation"], self.contract)

    def test_hia_schema_drift_fails_even_if_a_new_full_contract_was_supplied(self):
        candidate, _ = self.prepare()
        tools = copy.deepcopy(self.tools)
        tools[0]["outputSchema"] = {"type": "object"}
        altered = preflight.ToolContract(preflight.hia_mcp_catalog.make_contract(tools))
        with self.assertRaisesRegex(ValueError, "outputSchema differs"):
            preflight.verify_captures(candidate, {"tools": tools}, candidate["source_pair"]["installation"], altered)

    def test_duplicate_tool_names_are_not_collapsed(self):
        candidate, _ = self.prepare()
        with self.assertRaisesRegex(ValueError, "duplicate tool name"):
            preflight.verify_captures(candidate, {"tools": [*self.tools, self.tools[0]]},
                                      candidate["source_pair"]["installation"], self.contract)

    def test_cli_capture_verification_cannot_claim_a_live_deployment(self):
        candidate, directory, digest = self.retained_candidate()
        self.write(self.root / "native-tools.json", preflight.json_bytes({"tools": self.tools}))
        self.write(self.root / "worker-manifest.json", preflight.json_bytes(candidate["source_pair"]["installation"]))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = preflight.main(self.verify_args(directory, digest, self.root / "verified"))
        self.assertEqual(status, 0)
        report = json.loads(stdout.getvalue())
        self.assertFalse(report["entrypoint_observed"])
        self.assertFalse(report["production_deployed"])
        self.assertFalse(report["binary_build_provenance_attested"])
        self.assertEqual(report["evidence"]["origin"], "operator_supplied_captures")
        self.assertNotIn(self.secret, stdout.getvalue())

    def stdio_fixture(self, pins, *, pending=False, corrupt=False):
        manifest = preflight.canonical({"schema": "hepta.hia.agent.manifest.v1", "installation": pins})
        ref = {"id": "fixture-manifest", "sha256": preflight.sha256(manifest),
               "uri": "hia://artifacts/fixture-manifest"}
        if corrupt:
            ref["sha256"] = "0" * 64
        source = f'''#!{sys.executable}
import json,sys
from pathlib import Path
Path({str(self.root / "probe-started")!r}).write_text("started")
tools = {self.tools!r}
ref = {ref!r}
pins = {pins!r}
manifest = {manifest.decode()!r}
for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request: continue
    method = request["method"]
    if method == "initialize":
        result = {{"protocolVersion":"2025-03-26","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"protocol-fixture","version":"1"}}}}
    elif method == "tools/list": result = {{"tools":tools}}
    else:
        name = request["params"]["name"]
        payload = ({{"catalog_sha256":pins["catalog_sha256"],"manifest":ref}}
            if name == "hia_describe" else {{"artifact":ref,"encoding":"utf8","content":manifest,"next_cursor":None}})
        domain = {{"contract_version":"hepta.hia.agent-native.v1","request_id":"fixture",
                   "status":"completed","result":payload}}
        if {pending!r}:
            domain = {{"contract_version":"hepta.hia.agent-native.v1","status":"accepted",
                      "operation":{{"host":"fixture","job_id":"original-job"}}}}
        result = {{"structuredContent":domain,"content":[]}}
    print(json.dumps({{"jsonrpc":"2.0","id":request["id"],"result":result}}),flush=True)
'''
        return self.write(self.root / "mcp-fixture", source.encode(), 0o700)

    def test_stdio_probe_checks_real_protocol_discovery_and_retained_manifest(self):
        candidate, directory, _ = self.retained_candidate()
        binary = self.stdio_fixture(candidate["source_pair"]["installation"])
        checks, files, _ = preflight.probe(candidate, directory / "runtime-config.json", binary,
            preflight.sha256(binary.read_bytes()), self.contract, timeout=3)
        self.assertTrue((self.root / "probe-started").exists())
        self.assertEqual(checks["hia_tool_count"], 11)
        self.assertEqual(preflight.decode(files["worker-manifest.json"]), candidate["source_pair"]["installation"])
        calls = [item["request"]["params"]["name"] for item in preflight.decode(files["stdio-transcript.json"])
                 if item["request"]["method"] == "tools/call"]
        self.assertEqual(calls, ["hia_describe", "hia_read"])

    def test_wrong_binary_pin_is_rejected_before_start(self):
        candidate, directory, _ = self.retained_candidate()
        binary = self.stdio_fixture(candidate["source_pair"]["installation"])
        with self.assertRaisesRegex(ValueError, "SHA256"):
            preflight.probe(candidate, directory / "runtime-config.json", binary, "0" * 64, self.contract)
        self.assertFalse((self.root / "probe-started").exists())

    def test_corrupt_live_manifest_is_rejected(self):
        candidate, directory, _ = self.retained_candidate()
        binary = self.stdio_fixture(candidate["source_pair"]["installation"], corrupt=True)
        with self.assertRaisesRegex(ValueError, "manifest bytes"):
            preflight.probe(candidate, directory / "runtime-config.json", binary,
                            preflight.sha256(binary.read_bytes()), self.contract, timeout=3)

    def test_pending_live_job_remains_pending_with_same_operation_identity(self):
        candidate, directory, _ = self.retained_candidate()
        binary = self.stdio_fixture(candidate["source_pair"]["installation"], pending=True)
        with self.assertRaises(preflight.IncompleteProbe) as raised:
            preflight.probe(candidate, directory / "runtime-config.json", binary,
                            preflight.sha256(binary.read_bytes()), self.contract, timeout=1)
        self.assertEqual(raised.exception.recovery["response"]["operation"]["job_id"], "original-job")
        self.assertEqual(raised.exception.recovery["arguments"], {"section": "manifest"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-checkout", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    RUNTIME_CHECKOUT = args.runtime_checkout
    unittest.main(argv=[sys.argv[0], *remaining])
