"""Self-contained rejection tests for the unified candidate's new boundaries.

The pinned runtime's real catalog/snapshot helpers are exercised separately by
hia_candidate_preflight_integration.py. These tests do not require a runtime
checkout, native binary, network endpoint or SSH account.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import hia_candidate_preflight as preflight


PINS = {"worker_sha256": "1" * 64, "backend_sha256": "2" * 64, "catalog_sha256": "3" * 64}


class UncachedWorkerBoundary(unittest.TestCase):
    def test_manifest_admission_refuses_cache_and_native_shadow_before_execution(self):
        for name in ("__pycache__", "worker.pyc", "worker.pyo", "worker.cpython-312-x86_64-linux-gnu.so", "worker.pyd"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hepta").mkdir()
                shadow = root / "hepta" / name
                if name == "__pycache__":
                    shadow.mkdir()
                else:
                    shadow.write_bytes(b"untracked executable bytes")
                with mock.patch.object(preflight.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "cache or binary shadow"):
                        preflight.installed_pins(root, Path("/usr/bin/python3"))
                run.assert_not_called()


def config():
    return {
        "hosts": {"worker": {
            "ssh_target": "existing-worker", "platform": "linux", "allow_execute": True,
            "allow_write": True, "remote_state_dir": "/srv/runtime-state",
            "allowed_read_path_prefixes": ["/usr/bin", "/srv"],
            "allowed_write_path_prefixes": ["/srv/state"],
            "allowed_cwd_prefixes": ["/srv/source"],
            "protected_path_prefixes": ["/srv/private"],
        }},
        "hia_worker": {
            **PINS, "host": "worker", "python_executable": "/usr/bin/python3",
            "working_directory": "/srv/source", "state_root": "/srv/state/hia",
            "artifact_roots": ["/srv/inputs"],
        },
        "unrelated_policy": {"must_survive": True},
    }


class ProfileBoundary(unittest.TestCase):
    def test_defaults_are_explicit_without_mutating_existing_policy(self):
        original = config()
        before = copy.deepcopy(original)
        result = preflight.validate_config(original, PINS)
        self.assertEqual(original, before)
        self.assertEqual(result["timeout_seconds"], 120)
        self.assertEqual(result["memory_max_bytes"], 1024**3)
        self.assertEqual(result["host"], "worker")

    def test_all_three_pins_must_match(self):
        for key in PINS:
            with self.subTest(key=key):
                value = config()
                value["hia_worker"][key] = "f" * 64
                with self.assertRaisesRegex(ValueError, "configured source pin"):
                    preflight.validate_config(value, PINS)

    def test_unknown_profile_field_cannot_add_command_authority(self):
        value = config()
        value["hia_worker"]["command"] = ["arbitrary-shell"]
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            preflight.validate_config(value, PINS)

    def test_missing_worker_configuration_is_not_created_implicitly(self):
        with self.assertRaisesRegex(ValueError, "existing runtime configuration"):
            preflight.validate_config({"hosts": {}}, PINS)

    def test_unknown_host_is_not_provisioned(self):
        value = config()
        value["hia_worker"]["host"] = "another-host"
        with self.assertRaisesRegex(ValueError, "already configured"):
            preflight.validate_config(value, PINS)

    def test_non_linux_host_is_rejected(self):
        value = config()
        value["hosts"]["worker"]["platform"] = "macos"
        with self.assertRaisesRegex(ValueError, "Linux"):
            preflight.validate_config(value, PINS)

    def test_execute_and_write_authority_are_required(self):
        for flag in ("allow_execute", "allow_write"):
            with self.subTest(flag=flag):
                value = config()
                value["hosts"]["worker"][flag] = False
                with self.assertRaisesRegex(ValueError, "already configured"):
                    preflight.validate_config(value, PINS)

    def test_all_capture_roots_require_existing_read_authority(self):
        value = config()
        value["hia_worker"]["artifact_roots"].append("/ungranted")
        with self.assertRaisesRegex(ValueError, "read policy"):
            preflight.validate_config(value, PINS)

    def test_path_prefix_is_component_aware(self):
        value = config()
        value["hia_worker"]["working_directory"] = "/srv/source-escape"
        with self.assertRaisesRegex(ValueError, "execution roots"):
            preflight.validate_config(value, PINS)

    def test_protected_root_denies_capture(self):
        value = config()
        value["hia_worker"]["artifact_roots"] = ["/srv/private/data"]
        with self.assertRaisesRegex(ValueError, "read policy"):
            preflight.validate_config(value, PINS)

    def test_state_cannot_overlap_source_in_either_direction(self):
        for state in ("/srv/source", "/srv/source/state", "/srv"):
            with self.subTest(state=state):
                value = config()
                value["hosts"]["worker"]["allowed_write_path_prefixes"] = ["/srv"]
                value["hia_worker"]["state_root"] = state
                with self.assertRaisesRegex(ValueError, "disjoint"):
                    preflight.validate_config(value, PINS)

    def test_write_policy_is_not_expanded(self):
        value = config()
        value["hia_worker"]["state_root"] = "/srv/ungranted-state"
        with self.assertRaisesRegex(ValueError, "writable private root"):
            preflight.validate_config(value, PINS)

    def test_path_traversal_relative_paths_and_controls_are_rejected(self):
        for path in ("../inputs", "/srv/../private", "/srv/./inputs", "/srv/in\nputs", "/srv/\0x"):
            with self.subTest(path=path):
                value = config()
                value["hia_worker"]["artifact_roots"] = [path]
                with self.assertRaises(ValueError):
                    preflight.validate_config(value, PINS)

    def test_resource_booleans_and_out_of_range_values_are_rejected(self):
        for key, value in (("timeout_seconds", True), ("timeout_seconds", 0),
                           ("timeout_seconds", 3601), ("memory_max_bytes", True),
                           ("memory_max_bytes", 1024), ("memory_max_bytes", 17 * 1024**3)):
            with self.subTest(key=key, value=value):
                candidate = config()
                candidate["hia_worker"][key] = value
                with self.assertRaisesRegex(ValueError, "resource limits"):
                    preflight.validate_config(candidate, PINS)

    def test_bad_pin_shapes_are_rejected(self):
        for invalid in ({}, {**PINS, "extra": "0" * 64}, {**PINS, "worker_sha256": "A" * 64},
                        {**PINS, "worker_sha256": 0}, {**PINS, "worker_sha256": "0" * 63}):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "SHA256"):
                    preflight.validate_pins(invalid)


class InputBoundary(unittest.TestCase):
    def test_discovery_inventory_includes_new_pinned_guidance(self):
        names = (*sorted(preflight.REQUIRED_WORKER_DOCS), "HIA_AGENT_MACRO_POLICY.md")
        source = ("DISCOVERY_FILES = " + repr(names)).encode()
        self.assertEqual(preflight.discovery_documents(source), names)

    def test_discovery_inventory_does_not_execute_expressions(self):
        with self.assertRaises(ValueError):
            preflight.discovery_documents(b"DISCOVERY_FILES = compute_inventory()")

    def test_discovery_inventory_refuses_duplicates_traversal_and_missing_contracts(self):
        base = sorted(preflight.REQUIRED_WORKER_DOCS)
        for names in (base + [base[0]], base + ["../other.md"], base[:-1]):
            with self.subTest(names=names):
                with self.assertRaises(ValueError):
                    preflight.discovery_documents(("DISCOVERY_FILES = " + repr(names)).encode())

    def test_discovery_inventory_refuses_redefinitions(self):
        source = ("DISCOVERY_FILES = " + repr(tuple(preflight.REQUIRED_WORKER_DOCS)) + "\n") * 2
        with self.assertRaises(ValueError):
            preflight.discovery_documents(source.encode())

    def test_strict_json_preserves_unicode_and_integer_identity(self):
        value = {"测试": "上下文", "generation": "18446744073709551615", "counter": 17}
        self.assertEqual(preflight.decode(preflight.json_bytes(value)), value)

    def test_duplicate_members_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            preflight.decode(b'{"nested":{"pin":"a","pin":"b"}}')

    def test_nonfinite_numbers_cannot_enter_pin_documents(self):
        for value in (b'NaN', b'Infinity', b'-Infinity', b'1e400'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    preflight.decode(value)

    def test_oversized_capture_is_rejected(self):
        with mock.patch.object(preflight, "MAX_JSON_BYTES", 32):
            with self.assertRaisesRegex(ValueError, "bound"):
                preflight.decode(b'"' + b"x" * 40 + b'"')

    def test_failed_and_partial_tools_list_are_rejected_before_contract_loading(self):
        cases = [[], {"error": {"message": "failed"}},
                 {"jsonrpc": "2.0", "result": {"tools": [], "nextCursor": "later"}},
                 {"result": {"tools": []}}, {"tools": [], "nextCursor": ""}]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    preflight.complete_tools(value)

    def test_pending_probe_retains_an_immutable_original_operation(self):
        args = {"section": "manifest"}
        response = {"status": "accepted", "operation": {"host": "worker", "job_id": "original"}}
        error = preflight.IncompleteProbe("hia_describe", args, response)
        args["section"] = "changed"
        response["operation"]["job_id"] = "replacement"
        self.assertEqual(error.recovery["arguments"], {"section": "manifest"})
        self.assertEqual(error.recovery["response"]["operation"]["job_id"], "original")
        self.assertEqual(error.recovery["retry_action"], "observe_original")


class SourceBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-candidate-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.git("init", "--quiet")
        (self.root / "source.py").write_text("VERSION = 1\n")
        self.git("add", "source.py")
        self.git("-c", "user.name=Test fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "test source")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True)

    def test_clean_source_binds_full_commit(self):
        identity = preflight.source_identity(self.root, self.revision)
        self.assertTrue(identity["clean"])
        self.assertEqual(identity["commit"], self.revision)

    def test_revision_mismatch_does_not_choose_another_branch(self):
        with self.assertRaisesRegex(ValueError, "HEAD differs"):
            preflight.source_identity(self.root, "0" * 40)

    def test_moving_branch_names_are_not_source_pins(self):
        with self.assertRaisesRegex(ValueError, "40-character"):
            preflight.source_identity(self.root, "HEAD")

    def test_dirty_source_requires_explicit_development_mode(self):
        (self.root / "source.py").write_text("VERSION = 2\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            preflight.source_identity(self.root, self.revision)
        identity = preflight.source_identity(self.root, self.revision, allow_dirty=True)
        self.assertFalse(identity["clean"])
        self.assertTrue(identity["changes"])

    def test_untracked_source_cannot_receive_clean_identity(self):
        (self.root / "extra.py").write_text("CHANGED = True\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            preflight.source_identity(self.root, self.revision)

    def test_bootstrap_read_refuses_symbolic_links_and_fifos(self):
        link = self.root / "source-link.py"
        link.symlink_to(self.root / "source.py")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path):
                with self.assertRaises((ValueError, OSError)):
                    preflight.bootstrap_read(path)

    def test_bootstrap_read_refuses_other_user_writes(self):
        path = self.root / "source.py"
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "trusted"):
            preflight.bootstrap_read(path)

    def test_git_blob_identity_matches_actual_git_hash(self):
        raw = (self.root / "source.py").read_bytes()
        expected = self.git("rev-parse", self.revision + ":source.py").strip()
        self.assertEqual(preflight.blob_sha(raw), expected)


if __name__ == "__main__":
    unittest.main()
