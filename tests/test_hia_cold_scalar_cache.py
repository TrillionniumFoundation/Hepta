"""Source authority, native authoring and clobber controls for the cold scalar cache."""
import ast
from collections import defaultdict
import copy
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_seed_cold_endian_shift_backend as author
from tools.generate_hia_worker_config_json import document

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "529cc4bc12eb3f783b15fd60eaf0ad4b65f6f410d8409368568512b5dbd228e7"
ORIGINAL_HIA = "069a4f223351e22ba1a2ee07db08ce5205c5de25f19fa1d3dcc04b33347c2ca8"
CHANGED = {"generate", "instruction", "scalar"}
ADDED = {"scalar_cache_reset", "scalar_cached_load", "scalar_cache_result"}


class ColdScalarCacheSourceTests(unittest.TestCase):
    def test_full_original_program_and_all_admission_functions_are_retained(self):
        source = author.shift_program()
        self.assertEqual(sha256(source.encode()).hexdigest(), ORIGINAL)
        raw = render_assembly(document(source, "seed_cold_endian_shift_backend")).encode()
        self.assertEqual(sha256(raw).hexdigest(), ORIGINAL_HIA)
        previous = ast.parse(source)
        current = ast.parse(author.program())
        originals = {node.name: node for node in previous.body}
        self.assertEqual({node.name for node in current.body} - set(originals), ADDED)
        inverse = copy.deepcopy(current)
        inverse.body = [originals[node.name] if node.name in CHANGED else node
                        for node in inverse.body if node.name not in ADDED]
        self.assertEqual(ast.dump(inverse), ast.dump(previous))
        for node in current.body:
            if node.name in originals and node.name not in CHANGED:
                self.assertEqual(ast.dump(node), ast.dump(originals[node.name]))
        scalar = next(node for node in current.body if node.name == "scalar")
        self.assertEqual(ast.dump(scalar.body[-3]), ast.dump(ast.parse(
            "value_save(o,w,0,word(s,at+8))").body[0]))
        self.assertEqual(ast.dump(scalar.body[-4]), ast.dump(ast.parse(
            "normalize(o,w,width)").body[0]))

    def test_modified_parent_bytes_and_reapplied_cache_are_refused(self):
        original = author.shift_program()
        changed = [
            original + "\n",
            original.replace("registers > 2048", "registers > 4096"),
            original.replace("length(w) < 1048576", "length(w) < 1048568"),
            original.replace("mark_shift_entries(s, w)", "mark_shift_entries(s, o)"),
            original.replace("normalize(o, w, width)", "normalize(o, w, 64)"),
            author.program(),
        ]
        for index, source in enumerate(changed):
            with self.subTest(case=index):
                self.assertNotEqual(source, original)
                with self.assertRaises(ValueError):
                    author.cache_program(source)

    def test_register_slot_overwrites_and_non_scalar_boundaries_invalidate(self):
        nodes = {node.name: node for node in ast.parse(author.program()).body}
        selected = [copy.deepcopy(nodes[name]) for name in sorted(ADDED)]
        selected.append(copy.deepcopy(nodes["instruction"]))
        loads = []
        workspace = defaultdict(int)
        namespace = {
            "readbuf": object, "mutbuf": object, "u64": int, "u32": int,
            "get": lambda view, at: view[at],
            "put": lambda view, at, value: view.__setitem__(at, value) or 0,
            "word": lambda view, at: view[at],
            "value_load": lambda out, work, reg, slot: loads.append((reg, slot)) or 0,
        }
        for name in ("scalar", "immediate", "value_save", "stage", "address",
                     "patch", "load", "save", "enc", "edge", "absolute_target",
                     "resource"):
            namespace[name] = lambda *args: 0
        exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                     "<actual HIA scalar cache controls>", "exec"), namespace)
        load = namespace["scalar_cached_load"]
        reset = namespace["scalar_cache_reset"]
        result = namespace["scalar_cache_result"]
        instruction = namespace["instruction"]
        reset(workspace)
        for _ in range(2):
            load(None, workspace, 0, 7)
            load(None, workspace, 1, 9)
        self.assertEqual(loads, [(0, 7), (1, 9)])
        result(workspace, 9)
        self.assertEqual((workspace[208], workspace[216], workspace[232]), (9, 1, 0))
        load(None, workspace, 1, 9)
        self.assertEqual(loads[-1], (1, 9))
        before = len(loads)
        load(None, workspace, 2, 3)
        load(None, workspace, 2, 3)
        self.assertEqual(loads[before:], [(2, 3), (2, 3)])
        reset(workspace)
        load(None, workspace, 0, 7)
        source = defaultdict(int, {0: 32, 8: 11, 16: 55})
        instruction(source, None, workspace, 0)
        self.assertEqual((workspace[208], workspace[216], workspace[224], workspace[232]),
                         (7, 1, 11, 1))
        source[8] = 7
        instruction(source, None, workspace, 0)
        self.assertEqual((workspace[216], workspace[224], workspace[232]), (0, 7, 1))
        for opcode in (33, 34, 35, 36, 37, 38):
            with self.subTest(opcode=opcode):
                workspace[216] = workspace[232] = 1
                instruction(defaultdict(int, {0: opcode}), None, workspace, 0)
                self.assertEqual((workspace[216], workspace[232]), (0, 0))
        generate = nodes["generate"]
        self.assertEqual(sum(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                             and isinstance(node.value.func, ast.Name)
                             and node.value.func.id == "scalar_cache_reset"
                             for node in generate.body), 1)
        loop = next(node for node in generate.body if isinstance(node, ast.While))
        resets = [node for node in loop.body if isinstance(node, ast.If)
                  and any(isinstance(child, ast.Call)
                          and isinstance(child.func, ast.Name)
                          and child.func.id == "scalar_cache_reset"
                          for child in ast.walk(node))]
        self.assertEqual(len(resets), 1)
        self.assertEqual(ast.dump(resets[0].test), ast.dump(ast.parse(
            "get(w,8192+((at-get(w,40))>>6)*8) != 0", mode="eval").body))

    def test_checked_in_native_profile_is_the_complete_current_author_output(self):
        raw = render_assembly(document(author.program(), "seed_cold_endian_shift_backend")).encode()
        self.assertEqual(raw, (ROOT / "examples/hia_bootstrap/seed_cold_endian_shift_backend.hepta").read_bytes())
        self.assertNotEqual(sha256(raw).hexdigest(), ORIGINAL_HIA)


if __name__ == "__main__":
    unittest.main()
