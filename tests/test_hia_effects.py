"""Independent reachability oracle and real HIA effect/resource decisions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
from hashlib import sha256
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_effects as effects
from hepta.ast import HeptaError
from hepta.checker import check
from hepta.parser import parse

ROOT = Path(__file__).resolve().parents[1]


def oracle(rows, edges, **_):
    """Reachability definition, independently of the HIA propagation worklist."""
    result = []
    adjacency = [[] for _ in rows]
    for caller, callee in edges:
        adjacency[caller].append(callee)
    for root, (local, declared, clauses) in enumerate(rows):
        seen, pending = set(), list(adjacency[root])
        inferred = local
        while pending:
            reached = pending.pop()
            if reached in seen:
                continue
            seen.add(reached)
            inferred |= rows[reached][0] | rows[reached][1]
            pending.extend(adjacency[reached])
        upper = inferred | declared
        conflicts = (int(bool(upper & 1) and bool(clauses & 1))
                     + 2 * int(bool(upper & 2) and bool(clauses & 2))
                     + 4 * int(bool(upper & 32) and bool(clauses & 4)))
        result.append(effects.EffectDecision(inferred, inferred & ~declared,
                                             upper & 100, conflicts))
    return tuple(result)


def wire(rows, edges):
    return (struct.pack("<4Q", effects.MAGIC, 1, len(rows), len(edges))
            + b"".join(struct.pack("<3Q", *row) for row in rows)
            + b"".join(struct.pack("<2Q", *edge) for edge in edges))


class EffectSourceTests(unittest.TestCase):
    def test_authoritative_source_is_ordinary_verified_HIA(self):
        program, raw = effects._program()
        self.assertEqual(raw, effects.SOURCE.read_bytes())
        self.assertEqual(program.report()["functions_checked"], 11)
        self.assertTrue(program.report()["ok"])

    def test_independent_VM_before_native_build_on_cycles_and_declared_only_effects(self):
        cases = [
            ((), ()), (((0, 255, 7),), ()), (((0, 255, 7),), ((0, 0),)),
            (((0, 0, 7), (1, 8, 7), (2, 32, 7)), ((0, 1), (1, 2))),
            (((0, 0, 7), (4, 0, 7), (0, 64, 7)), ((0, 1), (1, 2), (2, 0))),
        ]
        with patch.object(effects, "_native_engine", side_effect=AssertionError("native before reference")):
            for rows, edges in cases:
                self.assertEqual(effects.decide(rows, edges, execution="vm"), oracle(rows, edges))


@unittest.skipUnless(effects._native_host(), "qualified native ABI requires Linux x86-64")
class EffectNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This actual independent HIA interpretation precedes this class's B0.
        rows, edges = ((1, 0, 7), (0, 32, 7)), ((0, 1), (1, 0))
        assert effects.decide(rows, edges, execution="vm") == oracle(rows, edges)
        cls.engine = effects._native_engine()

    def test_every_three_node_graph_and_deterministic_random_graphs(self):
        rows = ((1, 4, 7), (2, 32, 3), (128, 64, 5))
        for graph in range(512):
            edges = tuple((a, b) for a in range(3) for b in range(3) if graph & (1 << (a * 3 + b)))
            self.assertEqual(effects.decide(rows, edges), oracle(rows, edges))
        rng = random.Random(0x484941454646)
        for _ in range(160):
            n = rng.randrange(0, 81)
            rows = tuple((rng.randrange(256), rng.randrange(256), rng.randrange(8)) for _ in range(n))
            edges = tuple((rng.randrange(n), rng.randrange(n)) for _ in range(5 * n))
            self.assertEqual(effects.decide(rows, edges), oracle(rows, edges))
            self.assertEqual(effects.decide(rows, tuple(reversed(edges))), oracle(rows, edges))

    def test_vm_and_native_match_on_random_graphs(self):
        rng = random.Random(0x564d)
        for _ in range(30):
            n = rng.randrange(1, 7)
            rows = tuple((rng.randrange(256), rng.randrange(256), rng.randrange(8)) for _ in range(n))
            edges = tuple((rng.randrange(n), rng.randrange(n)) for _ in range(2 * n))
            expected = oracle(rows, edges)
            self.assertEqual(effects.decide(rows, edges, execution="vm"), expected)
            self.assertEqual(effects.decide(rows, edges, execution="native"), expected)

    def test_long_chain_scc_and_dense_graph_worklist_termination(self):
        for n, kind in ((1000, "chain"), (1000, "cycle"), (64, "dense")):
            rows = tuple((1 << (i % 8), 1 << ((i + 1) % 8), 7) for i in range(n))
            edges = (tuple((i, i + 1) for i in range(n - 1)) if kind == "chain" else
                     tuple((i, (i + 1) % n) for i in range(n)) if kind == "cycle" else
                     tuple((i, j) for i in range(n) for j in range(n)))
            self.assertEqual(effects.decide(rows, edges), oracle(rows, edges))

    def test_invalid_source_and_capacity_refuse_without_publishing_output(self):
        valid = wire(((0, 0, 7), (1, 8, 0)), ((0, 1),))
        invalid = [valid[:size] for size in range(32)]
        invalid.extend([valid[:-1], valid + b"x"])
        for offset, value in ((0, 0), (8, 2), (16, (1 << 64) - 1), (24, (1 << 64) - 1),
                              (32, 256), (40, 256), (48, 8), (80, 2), (88, 2)):
            changed = bytearray(valid)
            struct.pack_into("<Q", changed, offset, value)
            invalid.append(bytes(changed))
        for execution in ("vm", "native"):
            for data in invalid:
                output, workspace = bytearray(b"\xa5" * 64), bytearray(b"\x5a" * 168)
                self.assertNotEqual(effects._invoke(data, output, workspace, execution=execution), 0)
                self.assertEqual(output, b"\xa5" * 64)
            for output_size, workspace_size in ((63, 168), (64, 167), (0, 0), (64, 95)):
                output, workspace = bytearray(b"\xa5" * output_size), bytearray(b"\x5a" * workspace_size)
                self.assertEqual(effects._invoke(valid, output, workspace, execution=execution), 0xfffffffe)
                self.assertEqual(output, b"\xa5" * output_size)

    def test_poisoned_workspace_last_slots_and_guard_bytes(self):
        rows, edges = ((0, 0, 7), (0, 128, 7)), ((1, 1), (0, 1))
        data = wire(rows, edges)
        source = ctypes.create_string_buffer(data)
        output = ctypes.create_string_buffer(b"\xa5" * 72, 72)
        workspace = ctypes.create_string_buffer(b"\x5a" * 184, 184)
        status = self.engine.entry(source, len(data), output, 64, workspace, 176)
        self.assertEqual(status, 0)
        self.assertEqual(output.raw[64:], b"\xa5" * 8)
        self.assertEqual(workspace.raw[176:], b"\x5a" * 8)
        self.assertEqual(tuple(effects.EffectDecision(*struct.unpack_from("<4Q", output, 32 * i))
                               for i in range(2)), oracle(rows, edges))
        self.assertEqual(source.raw[:-1], data)

    def test_concurrent_default_calls_retain_one_code_owner_and_private_buffers(self):
        rows = ((0, 0, 7), (1, 32, 7), (4, 0, 7))
        edges = ((0, 1), (1, 2), (2, 0))
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(lambda _: effects.decide(rows, edges), range(64))),
                             [oracle(rows, edges)] * 64)
        self.assertIs(effects._native_engine(), self.engine)

    def test_actual_selfhost_compiles_the_semantic_pass(self):
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        with tempfile.TemporaryDirectory(prefix="hia-effects-selfhost-") as directory:
            folder = Path(directory)
            seed, _ = build_seed(folder)
            compiler = (ROOT / "examples/hia_bootstrap/selfhost.hiaasm").read_bytes()
            b1, _ = compile_stage(folder, "B1", seed, compiler, image_format="seed-shared")
            b2, _ = compile_stage(folder, "B2", b1, compiler)
            self.assertEqual(b1.read_bytes(), b2.read_bytes())
            b3, _ = compile_stage(folder, "B3", b2, compiler)
            self.assertEqual(b2.read_bytes(), b3.read_bytes())
            image, receipt = compile_stage(folder, "effects", b3, effects.SOURCE.read_bytes())
            raw = image.read_bytes()
            successor = NativeHiaJsonImage(raw, sha256(raw).hexdigest())
            self.assertEqual(receipt["forbidden_compiler_modules_loaded"], [])
            rows, edges = ((0, 0, 7), (1, 32, 7), (4, 0, 7)), ((0, 1), (1, 2), (2, 0))
            data = wire(rows, edges)
            source = ctypes.create_string_buffer(data)
            output = ctypes.create_string_buffer(96)
            workspace = ctypes.create_string_buffer(216)
            self.assertEqual(successor._entry(source, len(data), output, 96, workspace, 216), 0)
            result = tuple(effects.EffectDecision(*struct.unpack_from("<4Q", output, 32 * i)) for i in range(3))
            self.assertEqual(result, oracle(rows, edges))


class EffectIntegrationTests(unittest.TestCase):
    def test_default_checker_matches_reachability_on_every_actual_source(self):
        paths = sorted((ROOT / "tests").rglob("*.hepta")) + sorted((ROOT / "examples").rglob("*.hepta"))
        self.assertGreater(len(paths), 0)
        for path in paths:
            source = path.read_text()
            try:
                program = parse(source, str(path))
            except HeptaError:
                continue
            with patch.object(effects, "decide", side_effect=oracle):
                expected = check(program)
            actual = check(parse(source, str(path)))
            with self.subTest(path=path):
                self.assertEqual(actual.effects, expected.effects)
                self.assertEqual([d.to_dict() for d in actual.diagnostics], [d.to_dict() for d in expected.diagnostics])

    def test_worker_and_resource_diagnostic_order_is_preserved(self):
        from hepta.checker import _Checker
        from hepta.ast import Span
        program = parse("fn a()->Unit effects{} resources{heap_allocations=0;may_block=false;may_spawn=false;} {} "
                        "fn b()->Unit effects{alloc,block,spawn,ffi,unsafe} {}")
        checker = _Checker(program)
        checker.declarations()
        checker.calls["a"].add("b")
        checker.worker_sites.append(("a", Span()))
        checker.finish_effects()
        self.assertEqual([d.code for d in checker.result.diagnostics],
                         ["E_TASK_WORKER_EFFECT", "E_EFFECT", "E_RESOURCE", "E_RESOURCE", "E_RESOURCE"])
        self.assertEqual(checker.result.effects["a"], {"alloc", "block", "spawn", "ffi", "unsafe"})
        self.assertIn("ffi, spawn, unsafe", checker.result.diagnostics[0].message)
        self.assertEqual(checker.result.effects["b"], set())

    def test_non_native_platform_uses_same_HIA_source(self):
        with patch.object(effects, "_native_host", return_value=False), \
                patch.object(effects, "_native_engine", side_effect=AssertionError("wrong native platform")):
            result = check(parse("fn a()->Unit effects{} {b();} fn b()->Unit effects{block} {}"))
        self.assertEqual(result.effects["a"], {"block"})
        self.assertEqual(result.effects["b"], set())
        self.assertEqual([d.code for d in result.diagnostics], ["E_EFFECT"])

    def test_unexecutable_linker_selects_same_HIA_before_building(self):
        with tempfile.TemporaryDirectory(prefix="hia-effects-no-linker-") as temporary:
            linker = Path(temporary) / "ld"
            linker.write_bytes(b"non-executable linker placeholder")
            with patch.object(effects, "_NATIVE", None), \
                    patch.object(effects.shutil, "which", return_value=str(linker)), \
                    patch.object(effects, "_native_engine", side_effect=AssertionError("unavailable linker used")):
                result = check(parse("fn a()->Unit effects{} {b();} fn b()->Unit effects{block} {}"))
            self.assertEqual(result.effects, {"a": {"block"}, "b": set()})
            self.assertEqual([d.code for d in result.diagnostics], ["E_EFFECT"])

    def test_native_error_and_refusal_never_retry_in_VM(self):
        if not effects._native_host():
            self.skipTest("native failure routing requires its actual ABI")
        with patch.object(effects, "_vm_call", side_effect=AssertionError("hidden VM retry")), \
                patch.object(effects, "_native_engine", side_effect=RuntimeError("native build failure")):
            with self.assertRaisesRegex(RuntimeError, "native build failure"):
                effects.decide(((0, 0, 0),), ())
        with patch.object(effects, "_vm_call", side_effect=AssertionError("hidden VM retry")):
            with self.assertRaisesRegex(ValueError, "refused"):
                effects.decide(((256, 0, 0),), ())

    def test_warm_source_identity_drift_cannot_hide_behind_cached_code(self):
        effects._program()
        with tempfile.TemporaryDirectory(prefix="hia-effects-source-drift-") as temporary:
            changed = Path(temporary) / "changed.hiaasm"
            changed.write_bytes(effects.SOURCE.read_bytes() + b"\n")
            with patch.object(effects, "SOURCE", changed), \
                    patch.object(effects, "_vm_call", side_effect=AssertionError("unbound source execution")), \
                    patch.object(effects, "_native_engine", side_effect=AssertionError("unbound source execution")):
                with self.assertRaisesRegex(RuntimeError, "source changed"):
                    effects.decide(((0, 0, 0),), ())

    @unittest.skipUnless(effects._native_host(), "native build custody requires Linux x86-64")
    def test_native_build_receipt_binds_the_captured_image_before_loading(self):
        def substituted_image(machine, *, program, output, **kwargs):
            output.write_bytes(b"substituted output, never executable")
            return {"artifact_sha256": sha256(b"original build bytes").hexdigest(),
                    "artifact_bytes": len(b"original build bytes"), "core_sha256": program.sha256}
        with patch("hepta.hia_program_native.compile_program_machine", side_effect=substituted_image), \
                patch.object(effects.ctypes, "CDLL", side_effect=AssertionError("unbound image loaded")):
            with self.assertRaisesRegex(RuntimeError, "does not bind"):
                effects._NativeEffects()

    def test_native_extent_is_not_a_new_language_limit(self):
        data = wire(((0, 32, 7),), ((0, 0),))
        output, workspace = bytearray(32), bytearray(effects.NATIVE_MAX_EXTENT + 1)
        with patch.object(effects, "_native_engine", side_effect=AssertionError("oversized native call")):
            self.assertEqual(effects._invoke(data, output, workspace), 0)
        self.assertEqual(effects.EffectDecision(*struct.unpack("<4Q", output)), oracle(((0, 32, 7),), ((0, 0),))[0])

    def test_installed_wheel_checks_source_after_build_tree_is_removed(self):
        # Build with already-installed tooling; no network or dependency fetch.
        with tempfile.TemporaryDirectory(prefix="hia-effects-wheel-") as temporary:
            folder = Path(temporary)
            source = folder / "source"
            source.mkdir()
            shutil.copy2(ROOT / "pyproject.toml", source / "pyproject.toml")
            shutil.copytree(ROOT / "hepta", source / "hepta",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            built = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-build-isolation",
                                    "--no-deps", "--wheel-dir", str(folder / "wheels"), str(source)],
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            wheel = next((folder / "wheels").glob("*.whl"))
            installed = folder / "installed"
            installed_run = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
                                            "--target", str(installed), str(wheel)],
                                           capture_output=True, text=True, timeout=60)
            self.assertEqual(installed_run.returncode, 0, installed_run.stdout + installed_run.stderr)
            shutil.rmtree(source)
            working = folder / "empty"
            working.mkdir()
            script = """import sys
sys.path.insert(0, sys.argv[1])
from hepta.parser import parse
from hepta.checker import check
from hepta import hia_effects
result = check(parse('fn a()->Unit effects{} { b(); } fn b()->Unit effects{block} {}'))
assert result.effects == {'a': {'block'}, 'b': set()}
assert [d.code for d in result.diagnostics] == ['E_EFFECT']
assert str(hia_effects.SOURCE).startswith(sys.argv[1])
assert hia_effects.SOURCE.is_file()
print('installed HIA semantic pass: PASS')
"""
            run = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(installed)],
                                 cwd=working, capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("installed HIA semantic pass: PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
