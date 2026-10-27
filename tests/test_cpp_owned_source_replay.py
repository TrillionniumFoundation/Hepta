"""Fresh source replay, including internally valid but unrelated resource graphs.

These tests run the real frontend only. They do not execute native programs or
turn a rewritten historical receipt into a new execution result.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.pipeline import analyze, analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
import tools.validate_cpp_owned as qualifier


def unrelated_safe_graph(document):
    """Replace the operation with a different legal abstract resource program."""
    graph = copy.deepcopy(document)
    operation = next(fn for fn in graph["functions"] if fn["name"].endswith("run_owned"))
    value = next(local["id"] for local in operation["locals"] if local["type"] == "u64")
    operation["blocks"] = [{"id": operation["entry"], "ops": [],
                            "term": {"op": "return", "value": value, "loan": None}}]
    return graph


def reseal_source_binding(binding):
    seal = {key: value for key, value in binding.items() if key != "sha256"}
    encoded = json.dumps(seal, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    binding["sha256"] = hashlib.sha256(encoded).hexdigest()


def forge_unrelated_safe_projection(row):
    """Keep every graph verdict/hash/self-seal consistent with the wrong graph."""
    row["resource_ir"] = unrelated_safe_graph(row["resource_ir"])
    verdict = verify_resource_ir(row["resource_ir"])
    if verdict["ok"] is not True:
        raise AssertionError(verdict)
    row["resource_verification"] = verdict
    binding = row["source_binding"]
    binding["resource_verification"] = copy.deepcopy(verdict)
    binding["source_binding"]["resource_ir_sha256"] = verdict["ir_sha256"]
    reseal_source_binding(binding)


class CppOwnedSourceReplayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-owned-source-replay-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.migrated = self.root / "migrated.hepta"
        self.migrated.write_bytes((qualifier.EXAMPLE / "expected.hepta").read_bytes())
        self.entry = self.root / "consumer.hepta"
        self.entry.write_bytes((qualifier.EXAMPLE / "consumer.hepta").read_bytes())
        standalone = analyze(self.migrated.read_text(), str(self.migrated), backend="rust", native=False, crate_type="obj")
        self.assertTrue(standalone.report["ok"], standalone.report)
        self.report = {"hepta_compiler_sha256": compiler_hash(),
                       "migrated_source": qualifier._identity(self.migrated),
                       "inputs": qualifier._inputs(),
                       "migration": {"output_sha256": standalone.report["source_sha256"],
                                     "hepta_checks": {"rust": standalone.report},
                                     "resource_ir": lower_resource_ir(standalone.program, standalone.checked)}}

    def row(self, backend):
        fresh = analyze_project(self.entry, backend=backend, native=False, crate_type="obj")
        self.assertTrue(fresh.report["ok"], fresh.report)
        graph = lower_resource_ir(fresh.program, fresh.checked, project_sha256=fresh.project.identity)
        binding = verify_resource_source(self.entry, graph, native=False)
        self.assertTrue(binding["ok"], binding)
        emitted = fresh.c if backend == "c" else fresh.rust
        return {"frontend": fresh.report, "emitted_source": emitted,
                "emitted_sha256": hashlib.sha256(emitted.encode()).hexdigest(),
                "resource_ir": graph, "resource_verification": verify_resource_ir(graph), "source_binding": binding}

    def test_current_source_replays_all_graphs_codegen_and_semantics_without_native(self):
        with (patch("hepta.pipeline.compile_rust", side_effect=AssertionError("replay must be frontend only")),
              patch("hepta.c_backend.compile_c", side_effect=AssertionError("replay must be frontend only"))):
            qualifier._replay_migrated_source(self.report)
            for backend in ("rust", "c"):
                with self.subTest(backend=backend):
                    qualifier._replay_backend_source(self.row(backend), backend, self.report)

    def test_internally_valid_resealed_replacement_graph_is_not_source_evidence(self):
        for backend in ("rust", "c"):
            with self.subTest(backend=backend):
                row = self.row(backend)
                forge_unrelated_safe_projection(row)
                self.assertTrue(verify_resource_ir(row["resource_ir"])["ok"])
                source_check = verify_resource_source(self.entry, row["resource_ir"], native=False)
                self.assertFalse(source_check["ok"])
                self.assertEqual(source_check["diagnostics"][0]["code"], "E_RIR_SOURCE_GRAPH")
                with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_GRAPH"):
                    qualifier._replay_backend_source(row, backend, self.report)

    def test_standalone_migration_graph_is_rebuilt_from_published_source(self):
        self.report["migration"]["resource_ir"] = unrelated_safe_graph(self.report["migration"]["resource_ir"])
        self.assertTrue(verify_resource_ir(self.report["migration"]["resource_ir"])["ok"])
        with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_GRAPH"):
            qualifier._replay_migrated_source(self.report)

    def test_consistently_rehashed_changed_codegen_is_rejected(self):
        for backend in ("rust", "c"):
            with self.subTest(backend=backend):
                row = self.row(backend)
                old = row["emitted_source"]
                row["emitted_source"] = old.replace("2002", "2004")
                self.assertNotEqual(old, row["emitted_source"])
                row["emitted_sha256"] = hashlib.sha256(row["emitted_source"].encode()).hexdigest()
                row["frontend"]["c_sha256" if backend == "c" else "rust_sha256"] = row["emitted_sha256"]
                with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_CODEGEN"):
                    qualifier._replay_backend_source(row, backend, self.report)

    def test_resealed_semantics_claim_is_compared_with_fresh_checked_ast(self):
        row = self.row("c")
        row["source_binding"]["source_binding"]["canonical_semantic_sha256"] = "0" * 64
        reseal_source_binding(row["source_binding"])
        with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_SEMANTICS"):
            qualifier._replay_backend_source(row, "c", self.report)

    def test_actual_source_mutation_and_missing_file_cannot_reuse_old_receipt(self):
        row = self.row("c")
        self.entry.write_text(self.entry.read_text() + "\n// changed after the receipt\n")
        with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_CHANGED"):
            qualifier._replay_backend_source(row, "c", self.report)
        self.migrated.unlink()
        with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_REPLAY"):
            qualifier._replay_migrated_source(self.report)

    def test_replay_cannot_be_disabled_with_nonboolean_values(self):
        for value in (None, 0, 1, "false"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "explicit boolean"):
                qualifier.validate_report({}, current_inputs=value)


if __name__ == "__main__":
    unittest.main()
