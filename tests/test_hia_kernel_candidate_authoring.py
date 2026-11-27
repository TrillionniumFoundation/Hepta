"""Current-author compatibility; original kernel native gates remain separate."""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
import unittest

from tools import generate_hia_selfhost as generation
from tools import qualify_hia_kernel_selfhost_invlpg as candidate

ROOT = Path(__file__).resolve().parents[1]


class KernelCandidateAuthoringTests(unittest.TestCase):
    def test_complete_original_call_checker_only_expands_private_stride(self):
        raw = (ROOT / "tests/fixtures/hia_kernel_original_call_checker_f33.py").read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), "a111c68bcea09c1bd63b4b8d7ef91f62301e6bcf446385ccb8892fca97801411")
        old = ast.parse(raw).body[0]
        self.assertEqual(old.name, "check_calls")
        old.name = "kernel_check_calls"
        for node in ast.walk(old):
            if isinstance(node, ast.Name):
                if node.id == "CBASE":
                    node.id = "KERNEL_CALL_GRAPH"
                elif node.id == "CSTATE":
                    node.id = "KERNEL_CALL_STATE"
            elif isinstance(node, ast.Constant) and type(node.value) is int and node.value == 128:
                node.value = 192
        actual = ast.parse(candidate.KERNEL_CALL_CHECK).body[0]
        self.assertEqual(ast.dump(actual, include_attributes=False),
                         ast.dump(old, include_attributes=False))

    def test_actual_current_authoring_and_all_original_limits(self):
        keys = ["SOURCE", "W", "MAX_INSTRUCTIONS", "MAX_RELOCATIONS",
                *candidate.candidate_layout()[0]]
        before = {key: getattr(generation, key, None) for key in keys}
        source, shape = candidate.candidate_source()
        self.assertEqual(before, {key: getattr(generation, key, None) for key in keys})
        self.assertTrue(source.startswith(b"hia-asm.v1 hepta.hia.program.v9 selfhost\n"))
        self.assertEqual((candidate.CANDIDATE_WORKSPACE, candidate.CANDIDATE_FUNCTIONS,
                          candidate.CANDIDATE_BLOCKS, candidate.CANDIDATE_INSTRUCTIONS,
                          candidate.CANDIDATE_RELOCATIONS, candidate.CANDIDATE_EXPORTS),
                         (2 << 20, 192, 2048, 10000, 16000, 128))
        self.assertLessEqual(len(source), 1 << 20)
        self.assertLessEqual(shape["functions"], 192)
        self.assertLessEqual(shape["blocks"], 2048)
        self.assertLessEqual(shape["ops"], 10000)
        layout, _, intervals, bound = candidate.candidate_layout()
        sizes = {name: stop - start for name, start, stop in intervals}
        self.assertEqual(sizes["result_names"], 6 * 16)
        self.assertEqual(sizes["schema_state"], 8)
        # The first actual 192-function gate exposed the old schema address
        # in graph row 30: token 405 wrote spurious edges to 48 and 49.
        graph = layout["KERNEL_CALL_GRAPH"]
        self.assertEqual(generation.SCHEMA_STATE - graph, 30 * 192 + 48)
        self.assertFalse(graph <= layout["SCHEMA_STATE"] < graph + 192 ** 2)
        self.assertLess(layout["SCHEMA_STATE"] + 7, layout["CONST_VALUES"])
        # Six-result transport is intentionally still inside the original
        # header. CALL_BUDGET is an emitted packed scalar, not an address.
        self.assertLessEqual(generation.RESULT_OUTPUTS + 6 * 16, 2048)
        self.assertLessEqual(generation.RESULT_RETURNED + 6 * 8, 2048)
        self.assertEqual(sizes["constant_values"], 2048 * 8)
        self.assertEqual(sizes["constant_flags"], 2048)
        self.assertEqual(sizes["kernel_call_graph"], 192 ** 2)
        self.assertEqual(sizes["kernel_call_state"], 192 * 8)
        self.assertEqual(sizes["relocations"], 16000 * 16)
        self.assertTrue(all(previous[2] <= following[1]
                            for previous, following in zip(intervals, intervals[1:])))
        self.assertLessEqual(intervals[-1][2], 2 << 20)
        self.assertEqual(bound, 14418)
        self.assertNotIn("CBASE", layout)
        self.assertNotIn("CSTATE", layout)

    def test_literal_compaction_preserves_actual_emitter_prefix_and_cursor(self):
        helper = ("def irq_emit_pair(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:\n"
                  "    emit_bytes(o, w, a, 8)\n"
                  "    emit_bytes(o, w, b, 8)\n"
                  "    return 0\n")
        sample = ("def subject(o:mutbuf, w:mutbuf) -> u64:\n"
                  "    emit(o, w, 72)\n"
                  "    emit(o, w, 184)\n"
                  "    emit_bytes(o, w, 72623859790382856, 8)\n"
                  "    emit_bytes(o, w, 18446744073709551615, 8)\n"
                  "    emit_bytes(o, w, 0, 4)\n"
                  "    return 0\n" + helper)
        compact, joins = candidate.compact_literal_emission(sample)
        self.assertGreater(joins, 0)
        original_source = generation.SOURCE
        definitions = []
        for name in ("emit", "emit_bytes"):
            start = original_source.index("def " + name + "(")
            stop = original_source.index("\ndef ", start + 1)
            definitions.append(original_source[start:stop])
        def execute(text, phase, capacity):
            code = ast.parse("\n".join(definitions) + "\n" + text)
            for node in ast.walk(code):
                if isinstance(node, ast.FunctionDef):
                    node.returns = None
                    for parameter in node.args.args:
                        parameter.annotation = None
            output = bytearray([0xa5] * capacity)
            state = {48: phase, 56: 0}
            def store(buffer, index, value):
                if not 0 <= index < len(buffer):
                    raise IndexError("original store extent")
                buffer[index] = value & 255
            scope = {"get": lambda w, at: w[at],
                     "put": lambda w, at, value: w.__setitem__(at, value),
                     "store": store, "length": len}
            exec(compile(ast.fix_missing_locations(code), "<exact-emitter-observer>", "exec"), scope)
            result = None
            try:
                result = ("returned", scope["subject"](output, state))
            except IndexError as error:
                result = ("store-refusal", str(error))
            return bytes(output), state, result
        for phase in (0, 1, 2):
            for capacity in range(25):
                with self.subTest(phase=phase, capacity=capacity):
                    self.assertEqual(execute(sample, phase, capacity),
                                     execute(compact, phase, capacity))

    def test_unknown_pair_body_and_nonliteral_writes(self):
        body = ("def irq_emit_pair(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:\n"
                "    emit_bytes(o, w, a, 8)\n"
                "    emit_bytes(o, w, b, 8)\n"
                "    return 0\n")
        source = ("def body(o:mutbuf,w:mutbuf,x:u64) -> u64:\n"
                  "    emit(o, w, x)\n"
                  "    emit(o, w, 72)\n"
                  "    return 0\n" + body)
        self.assertEqual(candidate.compact_literal_emission(source)[0], source)
        with self.assertRaisesRegex(ValueError, "pair helper changed"):
            candidate.compact_literal_emission(source.replace(
                "emit_bytes(o, w, b, 8)", "emit_bytes(o, w, a, 8)"))


if __name__ == "__main__":
    unittest.main()
