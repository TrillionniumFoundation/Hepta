"""Adversarial source identity and clean export checks for Selfhost-Core."""
from __future__ import annotations

from hashlib import sha256
import ast
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from tools.hia_selfhost_contract import (CONTRACT_PATH, PROFILE, ROOT,
                                       validate_contract)
from tools.replay_hia_selfhost_cold import cold_replay


# Retained complete registry counter before the flat literal fast path.
def _retained_native_worker_helper_count(root):
    path = Path(root) / 'hepta/hia_native_helpers.py'
    declarations = [
        node for node in ast.parse(path.read_bytes(), filename=str(path)).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'HELPERS'
                for target in node.targets)
    ]
    if (len(declarations) != 1 or len(declarations[0].targets) != 1
            or not isinstance(declarations[0].value, ast.Dict)):
        raise ValueError('native helper registry must have one literal HELPERS declaration')
    table = declarations[0].value
    helpers = ast.literal_eval(table)
    if (type(helpers) is not dict or len(helpers) != len(table.keys)
            or any(type(selector) is not str
                   or not selector.startswith('HEPTA_HIA_')
                   or not selector.endswith('_MANIFEST')
                   or type(contract) is not tuple or len(contract) != 2
                   or any(type(name) is not str or not name.isidentifier()
                          for name in contract)
                   for selector, contract in helpers.items())):
        raise ValueError('native helper registry has duplicate or invalid literal contracts')
    return len(helpers)


class SelfhostContractTests(unittest.TestCase):
    def test_hosted_agent_discovery_resources_are_in_actual_source_identity(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES
        declared = validate_contract()["source_identity"]["files"]
        self.assertNotIn(CONTRACT_PATH, declared)  # generated identity cannot hash itself
        for filename in DISCOVERY_FILES:
            if "docs/" + filename == CONTRACT_PATH:
                continue  # validate_contract checks the generated complete content above
            path = ROOT / "docs" / filename
            self.assertEqual(declared[path.relative_to(ROOT).as_posix()],
                             sha256(path.read_bytes()).hexdigest())


    def test_release_freeze_inventory_covers_the_complete_selfhost_closure(self):
        from tools.hia_release import BOOTSTRAP_FILES
        declared = validate_contract()["source_identity"]["files"]
        # The public freeze reads its own explicit inventory. A newly declared
        # selfhost helper must be present there before a release can be locked.
        automatic_python_sources = {
            path.relative_to(ROOT).as_posix() for path in (ROOT / "hepta").rglob("*.py")
        }
        self.assertEqual(set(BOOTSTRAP_FILES) - {CONTRACT_PATH},
                         set(declared) - automatic_python_sources)

    def test_contract_binds_support_and_complete_seed_source_closure(self):
        contract = validate_contract()
        self.assertEqual(contract["profile"], PROFILE)
        self.assertEqual(contract["target"]["triple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(contract["abi"]["entry"], "f0")
        files = contract["source_identity"]["files"]
        self.assertIn("tools/generate_hia_catalog.py", files)
        for path in (ROOT / "hepta").rglob("*.py"):
            self.assertEqual(files[path.relative_to(ROOT).as_posix()], sha256(path.read_bytes()).hexdigest())
        self.assertFalse(contract["claims"]["whole_HIA_language_self_hosted"])
        status = {row["area"]: row["status"] for row in contract["support"]}
        self.assertEqual(status["recursion"], "bounded_subset")
        recursion = next(row for row in contract["support"] if row["area"] == "recursion")
        self.assertEqual(recursion["limits"]["additional_frames_per_self_tail_call"], 0)
        self.assertFalse(recursion["limits"]["runtime_termination_proved"])
        self.assertIn("tools/hia_selfhost_tailcalls.py", files)
        resources = next(row for row in contract["support"] if row["area"] == "resources")
        self.assertIn("buffer.swap with both bounds before access", resources["items"])
        self.assertIn("tools/hia_selfhost_resources.py", files)
        self.assertIn("tools/hia_selfhost_select.py", files)
        self.assertIn("tools/hia_selfhost_loans.py", files)
        self.assertIn("exact capability graph joins and closed loop/edge transfers", resources["items"])
        operations = next(row for row in contract["support"] if row["area"] == "integer_operations")
        self.assertIn("select (bool condition, matching scalars including unit)", operations["items"])
        self.assertEqual(status["successor_object_output"], "bounded_subset")
        self.assertEqual(status["general_object_linking"], "not_implemented")
        self.assertEqual(status["owned_resources"], "bounded_subset")
        owned = next(row for row in contract["support"] if row["area"] == "owned_resources")
        self.assertEqual(owned["output_format"], "selfhost_elf or explicit scalar-export ELF only")
        self.assertEqual(owned["items"][:4], ["buffer.new", "buffer.try_new", "owner.move", "owner.drop"])
        self.assertFalse(owned["allocation"]["workspace_is_heap"])
        self.assertEqual(owned["allocation"]["imports"], ["calloc", "free"])
        self.assertEqual(owned["excluded"], ["more than three results"])
        self.assertEqual(contract["limits"]["internal_result_area_bytes"], 64)
        self.assertEqual(contract["limits"]["internal_result_stride_bytes"], 16)
        self.assertEqual(contract["limits"]["internal_result_descriptor_words"], 2)
        self.assertEqual(contract["limits"]["function_results"], 3)
        self.assertEqual(contract["abi"]["core_return"], "u32")
        for path in ("tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
                     "tools/qualify_hia_selfhost_owned_elf.py"):
            self.assertIn(path, files)

    def test_matching_cold_builder_inputs_are_in_actual_source_identity(self):
        import ast
        import importlib

        declared = validate_contract()["source_identity"]["files"]
        covered = set()
        for path in sorted((ROOT / "tools").glob("build_hia*.py")):
            raw = path.read_bytes()
            tree = ast.parse(raw, filename=str(path))
            admission_names = {
                alias.asname or alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                and node.module == "tools.build_hia_json_preflight"
                for alias in node.names if alias.name == "admit_cold_build"
            }
            calls_cold_admission = any(
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in admission_names for node in ast.walk(tree))
            declares_inputs = any(
                (isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "INPUTS"
                    for target in node.targets))
                or (isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name) and node.target.id == "INPUTS")
                for node in tree.body)
            if not calls_cold_admission or not declares_inputs:
                continue
            name = path.relative_to(ROOT).as_posix()
            covered.add(name)
            with self.subTest(builder=name):
                self.assertEqual(declared.get(name), sha256(raw).hexdigest())
                # Read the same complete tuple the builder uses, including
                # imported component tuples and expanded fixture paths.
                # Importing declarations does not call a builder or compiler.
                module = importlib.import_module("tools." + path.stem)
                self.assertEqual(Path(module.__file__).resolve(), path.resolve())
                self.assertIs(type(module.INPUTS), tuple)
                self.assertTrue(module.INPUTS)
                for filename in module.INPUTS:
                    with self.subTest(builder=name, input=filename):
                        self.assertIs(type(filename), str)
                        self.assertEqual(
                            declared.get(filename),
                            sha256((ROOT / filename).read_bytes()).hexdigest())
        self.assertTrue({
            "tools/build_hia_vm_integer_divrem.py",
            "tools/build_hia_vm_integer_arithmetic.py",
            "tools/build_hia_vm_integer_scalar.py",
        }.issubset(covered), covered)

    def test_capacity_growth_preserves_workspace_and_core_byte_limits(self):
        from hepta.hia_program import MAX_BYTES, MAX_NODES
        from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES,
            MAX_RELOCATIONS, RELOCATION_UPPER_BOUND, CORE_BYTES_UPPER_BOUND)
        contract = validate_contract()
        self.assertEqual(contract["limits"]["instructions"], MAX_INSTRUCTIONS)
        self.assertEqual(contract["limits"]["core_structural_nodes"], MAX_NODES)
        self.assertEqual(MAX_CORE_NODES, MAX_NODES)
        self.assertEqual(RELOCATION_UPPER_BOUND, 11522)
        self.assertEqual(MAX_RELOCATIONS, 12000)
        self.assertFalse(contract["limits"]["block_entry_must_be_first_in_source"])
        self.assertEqual(contract["limits"]["function_entry_block_index_record_offset"], 264)
        self.assertLessEqual(RELOCATION_UPPER_BOUND, MAX_RELOCATIONS)
        self.assertLess(CORE_BYTES_UPPER_BOUND, MAX_BYTES)
        for key in ("source_bytes", "output_capacity_bytes", "workspace_required_bytes"):
            self.assertEqual(contract["limits"][key], 1 << 20)
        self.assertFalse(contract["capacity_derivation"]["capacity_growth_changes_source_output_workspace_bytes"])

    def test_upgrade_refuses_an_unpinned_historical_image_before_execution(self):
        from tools.replay_hia_selfhost_upgrade import upgrade_replay
        with tempfile.TemporaryDirectory(prefix="hia-upgrade-refusal-") as temporary:
            root = Path(temporary)
            (root / "B3.input.bin").write_bytes(b"untrusted source")
            (root / "B3.image.bin").write_bytes(b"untrusted image")
            (root / "B3.receipt.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "pinned upgrade input"):
                upgrade_replay(root, root / "result.json")
            self.assertFalse((root / "result.evidence").exists())

    def test_changed_loader_or_broadened_support_cannot_reuse_the_contract(self):
        declared = validate_contract()
        with tempfile.TemporaryDirectory(prefix="hia-selfhost-contract-") as temporary:
            root = Path(temporary)
            for name in [*declared["source_identity"]["files"], CONTRACT_PATH]:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            validate_contract(root)
            loader = root / "tools/hia_selfhost_child.py"
            original = loader.read_bytes()
            loader.write_bytes(original + b"\n# changed loader\n")
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)
            loader.write_bytes(original)
            broadened = json.loads((root / CONTRACT_PATH).read_text())
            broadened["limits"]["functions"] = 1024
            (root / CONTRACT_PATH).write_text(json.dumps(broadened))
            with self.assertRaisesRegex(ValueError, "source closure"):
                validate_contract(root)

    def test_cold_output_refuses_existing_and_symbolic_paths_before_creating_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-output-refusal-") as temporary:
            root = Path(temporary)
            existing = root / "existing.json"
            existing.write_text("original")
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(existing)
            self.assertEqual(existing.read_text(), "original")
            leaf = root / "leaf.json"
            leaf.symlink_to(root / "absent.json")
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing", target_is_directory=True)
            for output in (leaf, linked / "report.json", dangling / "report.json"):
                with self.subTest(path=output), self.assertRaisesRegex(ValueError, "symbolic links"):
                    cold_replay(output)
            self.assertFalse((root / "absent.json").exists())
            self.assertEqual(list(actual.iterdir()), [])
            self.assertFalse((root / "missing").exists())


    def test_flat_native_helper_registry_keeps_current_literals_without_recursive_eval(self):
        from unittest.mock import patch
        from tools.hia_selfhost_contract import _native_worker_helper_count
        expected = _retained_native_worker_helper_count(ROOT)
        self.assertGreater(expected, 0)
        # Poison the old recursive evaluator only for the new actual path.
        # The complete live registry, including all its current declarations,
        # still must be read and admitted; no stored count substitutes for it.
        with patch.object(ast, 'literal_eval', side_effect=AssertionError('recursive evaluator entered')):
            self.assertEqual(_native_worker_helper_count(ROOT), expected)

    def test_flat_native_helper_registry_preserves_original_literal_and_refusal_domain(self):
        from tools.hia_selfhost_contract import _native_worker_helper_count
        values = [
            "{}", "{'HEPTA_HIA_X_MANIFEST': ('module', 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('mod' 'ule', 'Factory')}",
            "{'HEPTA_HIA_Ω_MANIFEST': ('δοκιμή', '𐐷')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', 'Factory'), 'HEPTA_HIA_Y_MANIFEST': ('other', 'Type')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', 'Factory'), 'HEPTA_HIA_X_MANIFEST': ('other', 'Type')}",
            "{'X': ('module', 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('not.a.name', 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', '')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', '9type')}",
            "{'HEPTA_HIA_X_MANIFEST': ['module', 'Factory']}",
            "{'HEPTA_HIA_X_MANIFEST': ('module',)}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', 'Factory', 'extra')}",
            "{'HEPTA_HIA_X_MANIFEST': (b'module', 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', b'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': (1, 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': (True, 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': (None, 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', 1+2j)}",
            "{'HEPTA_HIA_X_MANIFEST': ('module', -1)}",
            "{1: ('module', 'Factory')}", "{True: ('module', 'Factory')}",
            "{b'HEPTA_HIA_X_MANIFEST': ('module', 'Factory')}",
            "{[]: ('module', 'Factory')}", "{{}: ('module', 'Factory')}",
            "{('tuple',): ('module', 'Factory')}",
            "{**{'HEPTA_HIA_X_MANIFEST': ('module', 'Factory')}}",
            "{'HEPTA_HIA_X_MANIFEST': tuple(('module', 'Factory'))}",
            "{'HEPTA_HIA_X_MANIFEST': (unknown, 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': (f'module', 'Factory')}",
            "{'HEPTA_HIA_X_MANIFEST': ('mod' + 'ule', 'Factory')}",
            "dict(HEPTA_HIA_X_MANIFEST=('module', 'Factory'))", "[]", "None",
        ]
        sources = ['HELPERS = ' + value + '\n' for value in values]
        sources += ["", "HELPERS = {}\nHELPERS = {}\n", "HELPERS = OTHER = {}\n",
                    "HELPERS: dict = {}\n", "HELPERS += {}\n", "HELPERS = {\n"]
        with tempfile.TemporaryDirectory(prefix='hia-flat-registry-domain-') as temporary:
            root = Path(temporary)
            path = root / 'hepta/hia_native_helpers.py'
            path.parent.mkdir()
            for source in sources:
                path.write_text(source)
                with self.subTest(source=source):
                    try:
                        expected = _retained_native_worker_helper_count(root)
                    except Exception as original:
                        with self.assertRaises(type(original)):
                            _native_worker_helper_count(root)
                    else:
                        self.assertEqual(_native_worker_helper_count(root), expected)

    def test_flat_native_helper_registry_reads_each_source_without_executing_it(self):
        from unittest.mock import patch
        from tools.hia_selfhost_contract import _native_worker_helper_count
        with tempfile.TemporaryDirectory(prefix='hia-flat-registry-read-') as temporary:
            root = Path(temporary)
            path = root / 'hepta/hia_native_helpers.py'
            path.parent.mkdir()
            # Top-level provider code is parsed, just as before, never executed.
            prefix = "raise RuntimeError('module must not execute')\n"
            with patch.object(ast, 'literal_eval', side_effect=AssertionError('recursive evaluator entered')):
                for count in (0, 1, 3, 2, 1, 0):
                    entries = {f'HEPTA_HIA_{index}_MANIFEST': ('module', 'Factory')
                               for index in range(count)}
                    path.write_text(prefix + 'HELPERS = ' + repr(entries) + '\n')
                    self.assertEqual(_native_worker_helper_count(root), count)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                _native_worker_helper_count(root)



def cold_failure_diagnostic(output, result):
    """Retain actual bounded child diagnosis before temporary cleanup."""
    if result.get("status") == "COLD_SELFHOST_REPLAY_PASS":
        return result["checks"]
    diagnostic = {key: result.get(key) for key in
        ("status", "checks", "returncode", "wall_elapsed_ns", "process_owner")}
    directory = Path(output).with_suffix(".cold")
    for name in ("stdout.log", "stderr.log", "qualification.evidence/phase-index.json"):
        path = directory / name
        if not path.is_file():
            continue
        # The diagnostic cannot consume an unbounded log or replace the
        # original failed assertion with a secondary parser exception.
        try:
            size = path.stat().st_size
            with path.open("rb") as stream:
                stream.seek(max(0, size - 4096))
                tail = stream.read(4096)
                stream.seek(0)
                phase_bytes = stream.read(65537) if name.endswith("phase-index.json") else None
        except OSError as exc:
            diagnostic[name] = {"diagnostic_read_error": str(exc)}
            continue
        diagnostic[name] = {"bytes": size, "tail_sha256": sha256(tail).hexdigest(),
                            "actual_tail": tail.decode("utf-8", "replace")}
        if phase_bytes is not None and len(phase_bytes) <= 65536:
            try:
                phase = json.loads(phase_bytes)
                if isinstance(phase, dict):
                    diagnostic[name].update({k: phase.get(k) for k in ("completed", "exceptions")})
            except (ValueError, UnicodeError):
                diagnostic[name]["phase_json_malformed"] = True
    return diagnostic


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and shutil.which("ld"), "Linux x86-64 and GNU ld required")
class SelfhostColdReplayTests(unittest.TestCase):
    def test_source_only_clean_rebuild_has_original_and_modified_fixed_points(self):
        with tempfile.TemporaryDirectory(prefix="hia-cold-replay-test-") as temporary:
            output = Path(temporary) / "cold.json"
            result = cold_replay(output)
            self.assertEqual(result["status"], "COLD_SELFHOST_REPLAY_PASS", cold_failure_diagnostic(output, result))
            self.assertEqual(len(result["checks"]), 11)
            self.assertTrue(result["checks"]["owned_process_tree_cleanup_confirmed"])
            self.assertEqual(result["qualification_wall_limit_seconds"], 180)
            self.assertEqual(result["cleanup_wall_limit_seconds"], 3)
            self.assertEqual(result["process_owner"]["status"], "OWNED_PROCESS_COMPLETED")
            self.assertTrue(result["process_owner"]["cleanup"]["observed_echild"])
            self.assertTrue(result["process_owner"]["cleanup"]["leader_reaped"])
            self.assertEqual(len(set(result["generation_sha256"])), 1)
            first, second, third = result["modified_generation_sha256"]
            self.assertNotEqual(first, second)
            self.assertEqual(second, third)
            self.assertNotEqual(third, result["generation_sha256"][0])
            self.assertFalse(result["isolation"]["virtual_machine"])
            with self.assertRaisesRegex(ValueError, "new report"):
                cold_replay(output)


if __name__ == "__main__":
    unittest.main()
