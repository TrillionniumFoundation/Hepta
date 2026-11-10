"""Real fixed-Core self-hosting, independently observable machine behavior."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected
from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, SAMPLE, SOURCE,
    compile_stage, invalid_sources, invoke, mutate_compiler, qualify, readonly_call_source,
    inspect_selfhost_object)
from tools.hia_selfhost_contract import validate_contract
from tools.hia_selfhost_limits import MAX_INSTRUCTIONS
from tools.hia_selfhost_cases import (backward_bytesum_source, backward_chain_source,
                                     call_graph_invalid_sources, recursion_refusals)

NATIVE = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"} and shutil.which("ld")


class SelfhostSourceTests(unittest.TestCase):
    def test_authoring_forwarders_preserve_parallel_values_and_ordered_effects(self):
        import ast
        from tools.generate_hia_selfhost import Builder, compact_authoring_cfg
        from tools.hia_selfhost_loans import reference_source
        from hepta.hia_program import execute_program, verify_program
        node = ast.parse('''def example(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    a = 17
    b = 73
    n = byte(s, 0)
    while n > 0:
        old = a
        if n > 0:
            a = b
            b = old
        store(o, 0, a)
        store(o, 1, b)
        n = n - 1
    return a * 256 + b
''').body[0]
        builder = Builder(node, {'example': 'f0'}, {})
        builder.statements(node.body)
        original = {'schema': 'hepta.hia.program.v8', 'module': 'forwarding_values', 'functions': [{
            'name': 'f0', 'params': [builder.param(v) for v in builder.params],
            'returns': ['u32'], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks}]}
        frozen = deepcopy(original)
        compacted = compact_authoring_cfg(original)
        self.assertEqual(original, frozen)
        self.assertLess(sum(len(f['blocks']) for f in compacted['functions']),
                        sum(len(f['blocks']) for f in original['functions']))
        self.assertEqual(compacted['functions'][0]['blocks'][0], original['functions'][0]['blocks'][0])
        for n in (0, 1, 2, 3, 8):
            a, b = (73, 17) if n % 2 else (17, 73)
            expected = [a * 256 + b] + ([a, b] if n else [201, 202])
            for doc in (original, compacted):
                verify_program(doc)
                case = {'source': render_assembly(doc), 'source_hex': bytes([n]).hex(), 'initial_hex': 'c9ca'}
                result = execute_program(assemble_program(reference_source(case)), 'reference_entry', [])
                self.assertEqual(result['values'], expected)
                self.assertEqual(result['resources']['live_owners'], 0)
                self.assertEqual(result['resources']['live_local_loans'], 0)

    def test_authoring_forwarders_keep_resource_joins_return_origins_and_loops(self):
        from tools.generate_hia_selfhost import compact_authoring_cfg
        from tools.hia_selfhost_cfg_worklist import cases as cfg_cases
        from tools.hia_selfhost_loans import loan_cases, reference_source
        from tools.hia_selfhost_returned_loans import cases as returned_cases
        from tools.hia_selfhost_owned_flow_cases import cases as owned_cases
        from hepta.hia_program import execute_program
        rows = [row for row in cfg_cases() if '256' not in row['id'] and '1536' not in row['id']]
        rows += [row for row in loan_cases() if row['id'] in
                 {'nested-mutable', 'call-shared-root-aliases', 'shared-siblings-under-mutable'}]
        from tools.hia_selfhost_owned_flow_cases import INITIAL
        rows += [{**row, 'source_hex': '', 'initial_hex': INITIAL.hex(),
                  'expected_hex': row['expected_output_hex']} for row in owned_cases() if row['id'] in
                 {'flow-owner-and-loan-loop', 'flow-chain-loop', 'flow-buffer-through-two-branches'}]
        rows += returned_cases()[:4]
        self.assertGreaterEqual(len(rows), 15)
        for row in rows:
            with self.subTest(row=row['id']):
                original = assemble_program(row['source']).as_dict()
                # Independently introduce two permuting transfers on every edge.
                # Resource-bearing parameters and their parents move together.
                routed = deepcopy(original)
                for fn in routed['functions']:
                    blocks = {b['id']: b for b in fn['blocks']}
                    serial = 0
                    for block in list(fn['blocks']):
                        term = block['term']
                        edges = ([term] if term['op'] == 'jump' else
                                 [term['then'], term['else']] if term['op'] == 'branch' else [])
                        for edge in edges:
                            destination = blocks[edge['target']]
                            for _ in range(2):
                                name = 'relay_' + str(serial)
                                serial += 1
                                params = [{'name': name + '_p' + str(i), 'type': p['type']}
                                          for i, p in enumerate(reversed(destination['params']))]
                                relay = {'id': name, 'params': params, 'ops': [], 'term': {
                                    'op': 'jump', 'target': edge['target'],
                                    'args': [p['name'] for p in reversed(params)]}}
                                edge['target'], edge['args'] = name, list(reversed(edge['args']))
                                fn['blocks'].append(relay)
                                destination = relay
                compacted = compact_authoring_cfg(routed)
                for doc in (original, routed, compacted):
                    case = {**row, 'source': render_assembly(doc)}
                    result = execute_program(assemble_program(reference_source(case)), 'reference_entry', [])
                    self.assertEqual(result['values'], [row['expected_result'], *bytes.fromhex(row['expected_hex'])])
                    self.assertEqual(result['resources']['live_owners'], 0)
                    self.assertEqual(result['resources']['live_local_loans'], 0)

    def test_authoring_forwarders_leave_entry_and_empty_cycles_intact(self):
        from tools.generate_hia_selfhost import compact_authoring_cfg
        from hepta.hia_program import execute_program
        from hepta.hia_program_runtime import HIAProgramBudgetExceeded
        source = '''hia-asm.v1 hepta.hia.program.v8 cycle
fn f0(x:u64) -> (u64) effects(trap) entry(start)
block start(x:u64)
  jump left(x)
block left(a:u64)
  jump right(a)
block right(b:u64)
  jump left(b)
end
'''
        doc = assemble_program(source).as_dict()
        compact_cycle = compact_authoring_cfg(doc)
        self.assertEqual([b['id'] for b in compact_cycle['functions'][0]['blocks']], ['start', 'left', 'right'])
        self.assertEqual([b['term']['target'] for b in compact_cycle['functions'][0]['blocks']], ['left', 'right', 'left'])
        self_loop = deepcopy(doc)
        self_loop['functions'][0]['blocks'][2]['term']['target'] = 'right'
        compacted = compact_authoring_cfg(self_loop)
        self.assertEqual([b['id'] for b in compacted['functions'][0]['blocks']], ['start', 'right'])
        for candidate in (doc, compact_cycle, self_loop, compacted):
            with self.assertRaises(HIAProgramBudgetExceeded) as trapped:
                execute_program(candidate, 'f0', [17], max_steps=20)
            self.assertEqual(trapped.exception.code, 'steps')

    def test_authoring_scalar_liveness_retains_unobserved_checked_operations(self):
        from tools.generate_hia_selfhost import compact_authoring_cfg
        from hepta.hia_program import execute_program
        from hepta.hia_program_runtime import HIAProgramTrap
        source = '''hia-asm.v1 hepta.hia.program.v8 scalar_liveness
fn f0(x:u64) -> (u64) effects(trap) entry(start)
block start(x:u64)
  jump work(x,x)
block work(dead:u64,live:u64)
  one:u64 = const() {"value":1}
  ignored:u64 = int.div.checked(one,live)
  jump finish(dead)
block finish(forwarded_dead:u64)
  result:u64 = const() {"value":42}
  ret(result)
end
'''
        original = assemble_program(source).as_dict()
        compacted = compact_authoring_cfg(original)
        blocks = compacted['functions'][0]['blocks']
        self.assertEqual([p['name'] for p in blocks[1]['params']], ['live'])
        self.assertEqual(blocks[2]['params'], [])
        self.assertEqual([b['ops'] for b in blocks], [b['ops'] for b in original['functions'][0]['blocks']])
        self.assertEqual(compacted['functions'][0]['params'], original['functions'][0]['params'])
        for doc in (original, compacted):
            self.assertEqual(execute_program(doc, 'f0', [1])['values'], [42])
            with self.assertRaises(HIAProgramTrap) as trapped:
                execute_program(doc, 'f0', [0])
            self.assertEqual(trapped.exception.code, 'division_by_zero')

    def test_shared_failure_guards_preserve_conditional_effects_and_argument_laziness(self):
        import ast
        from tools.generate_hia_selfhost import Builder, source_program
        from tools.hia_selfhost_loans import reference_source
        from hepta.hia_program import execute_program, verify_program
        guard = next(n for n in ast.parse(source_program()).body if n.name == 'guard_failure')
        helper = ast.parse('''def fail(o:mutbuf, code:u64) -> u64:
    old = byte(o, 0)
    store(o, 0, old + code)
    return code
''').body[0]

        def program(body, enabled):
            entry = ast.parse(body).body[0]
            nodes = [entry, helper, guard]
            names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
            signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
            functions = []
            for node in nodes:
                mapping = dict(names)
                if not enabled:
                    mapping.pop('guard_failure')
                builder = Builder(node, mapping, signatures)
                builder.statements(node.body)
                functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                    'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0',
                    'blocks': builder.blocks})
            doc = {'schema': 'hepta.hia.program.v8', 'module': 'guard_controls', 'functions': functions}
            verify_program(doc)
            return doc

        body = '''def example(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if byte(s, 0) > 1:
        fail(o, 5)
    if byte(s, 0) > 2:
        fail(o, 7)
    return 0
'''
        original, shared = (program(body, enabled) for enabled in (False, True))
        self.assertLess(len(shared['functions'][0]['blocks']), len(original['functions'][0]['blocks']))
        # The helper must not turn its own conditional call into recursion.
        self.assertFalse(any(op['op'] == 'call' and op['attrs']['function'] == 'f2'
            for block in shared['functions'][2]['blocks'] for op in block['ops']))
        for byte, initial, expected in ((0, '', [0]), (1, '', [0]), (0, '03', [0, 3]),
                (1, '03', [0, 3]), (2, '03', [0, 8]), (3, '03', [0, 15]), (255, '03', [0, 15])):
            for doc in (original, shared):
                case = {'source': render_assembly(doc), 'source_hex': bytes([byte]).hex(), 'initial_hex': initial}
                result = execute_program(assemble_program(reference_source(case)), 'reference_entry', [])
                self.assertEqual(result['values'], expected)
                self.assertEqual(result['resources']['live_owners'], 0)
                self.assertEqual(result['resources']['live_local_loans'], 0)
        # A memory argument is deliberately not eligible: evaluating byte(s,1)
        # before its false guard would trap with this one-byte input.
        effectful = body.replace('fail(o, 5)', 'fail(o, byte(s, 1))')
        for enabled in (False, True):
            doc = program(effectful, enabled)
            case = {'source': render_assembly(doc), 'source_hex': '00', 'initial_hex': ''}
            result = execute_program(assemble_program(reference_source(case)), 'reference_entry', [])
            self.assertEqual(result['values'], [0])
        # True guards with empty output still trap; sharing does not fabricate
        # a successful failure-store or suppress the original bounds check.
        for doc in (original, shared):
            case = {'source': render_assembly(doc), 'source_hex': '02', 'initial_hex': ''}
            from hepta.hia_program_runtime import HIAProgramTrap
            with self.assertRaises(HIAProgramTrap) as trapped:
                execute_program(assemble_program(reference_source(case)), 'reference_entry', [])
            self.assertEqual(trapped.exception.report['error']['code'], 'bounds')

    def test_inferred_total_helpers_refuse_loops_checked_shifts_memory_and_recursion(self):
        import ast
        from tools.generate_hia_selfhost import total_scalar_functions
        source = '''
def leaf(x:u64) -> u64:
    return x + 1
def parent(x:u64) -> u64:
    if leaf(x) == 0:
        return 7
    return leaf(x)
def checked(x:u64) -> u64:
    return 1 << x
def recursive(x:u64) -> u64:
    return recursive(x)
def cycle_a(x:u64) -> u64:
    return cycle_b(x)
def cycle_b(x:u64) -> u64:
    return cycle_a(x)
def memory(s:readbuf) -> u64:
    return byte(s,0)
def loop(x:u64) -> u64:
    while x > 0:
        x = x - 1
    return x
def disguised(x:u64) -> u64:
    return checked(x)
'''
        nodes = ast.parse(source).body
        self.assertEqual(total_scalar_functions(nodes), {"leaf", "parent"})
        changed = ast.parse(source.replace("return x + 1", "return 1 << x")).body
        self.assertEqual(total_scalar_functions(changed), set())

    def test_constant_sharing_stays_block_local_and_preserves_all_arithmetic(self):
        import ast
        from tools.generate_hia_selfhost import Builder
        from hepta.hia_program import verify_program, execute_program
        source = '''def example(x:u64) -> u64:
    a = x + 1
    b = x * 1
    if x > 0:
        c = a + 1
        d = b + 1
    else:
        c = a - 1
        d = b - 1
    return c + d
'''
        node = ast.parse(source).body[0]
        builder = Builder(node, {"example": "f0"}, {})
        builder.statements(node.body)
        checked = verify_program({"schema": "hepta.hia.program.v8", "module": "constant_sharing",
            "functions": [{"name": "f0", "params": [builder.param(p) for p in builder.params],
                "returns": ["u64"], "effects": ["trap"], "entry": "b0", "blocks": builder.blocks}]})
        for block in builder.blocks:
            keys = [(op["out"][0]["type"], type(op["attrs"]["value"]), op["attrs"]["value"])
                    for op in block["ops"] if op["op"] == "const"]
            self.assertEqual(len(keys), len(set(keys)))
        arithmetic = [op for block in builder.blocks for op in block["ops"]
                      if op["op"] in {"int.add.wrap", "int.sub.wrap", "int.mul.wrap"}]
        self.assertEqual(len(arithmetic), 7)
        for value in (0, 1, 63, 64, (1 << 64) - 1):
            expected = ((value + 1) + value + (2 if value > 0 else -2)) & ((1 << 64) - 1)
            self.assertEqual(execute_program(checked, "f0", [value])["values"], [expected])

    def test_total_scalar_if_conversion_preserves_values_without_speculating_traps(self):
        import ast
        from tools.generate_hia_selfhost import Builder
        from hepta.hia_program import verify_program, execute_program
        cases = (
            ("    y = 7\n    if x > 4:\n        y = x + 1\n    return y\n",
             [(0, 7), (4, 7), (5, 6), ((1 << 64) - 1, 0)], True),
            ("    if x > 7:\n        return x + 1\n    return 1\n",
             [(0, 1), (8, 9), ((1 << 64) - 1, 0)], True),
            ("    if x > 7:\n        return x + 1\n    else:\n        return 1\n",
             [(0, 1), (8, 9), ((1 << 64) - 1, 0)], True),
            ("    y = 7\n    if x < 64:\n        y = 1 << x\n    return y\n",
             [(0, 1), (63, 1 << 63), (64, 7), ((1 << 64) - 1, 7)], False),
        )
        for body, observations, fused in cases:
            node = ast.parse("def example(x:u64) -> u64:\n" + body).body[0]
            builder = Builder(node, {"example": "f0"}, {})
            builder.statements(node.body)
            checked = verify_program({"schema": "hepta.hia.program.v8", "module": "if_conversion",
                "functions": [{"name": "f0", "params": [builder.param(p) for p in builder.params],
                    "returns": ["u64"], "effects": ["trap"], "entry": "b0", "blocks": builder.blocks}]})
            self.assertEqual(len(builder.blocks) == 1, fused)
            for value, expected in observations:
                self.assertEqual(execute_program(checked, "f0", [value])["values"], [expected])

    def test_reference_process_envelopes_refuse_changed_identity_payload_and_provenance(self):
        from copy import deepcopy
        from tools.hia_selfhost_references import validate_envelope, digest, SCHEMA
        payload = {"cases": [{"id": "input-0", "expected_hex": "80"}]}
        report = {"schema": SCHEMA, "family": "signed", "before_B0": True,
                  "source_manifest_sha256": "pinned-source", "worker_pid": 123,
                  "reference": payload, "reference_sha256": digest(payload)}
        self.assertEqual(validate_envelope(report, "signed", "pinned-source"), payload)
        changes = ({"schema": "other"}, {"family": "keyword"}, {"before_B0": False},
                   {"source_manifest_sha256": "other-source"}, {"worker_pid": True},
                   {"reference_sha256": "changed"}, {"reference": {"cases": []}})
        for change in changes:
            changed = deepcopy(report); changed.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_envelope(changed, "signed", "pinned-source")

    def test_authoring_short_circuit_cfg_preserves_trap_order_and_join_values(self):
        import ast
        from tools.generate_hia_selfhost import Builder
        from hepta.hia_program import verify_program, execute_program

        expressions = (
            ("x < 64 and (1 << x) == 2", lambda x: x < 64 and (1 << x) == 2, 3),
            ("x >= 64 or (1 << x) == 2", lambda x: x >= 64 or (1 << x) == 2, 3),
            ("x < 64 and (1 << x) != 0 and (255 >> x) == 0",
             lambda x: x < 64 and (1 << x) != 0 and (255 >> x) == 0, 5),
            ("x >= 64 or (1 << x) == 2 or (255 >> x) == 0",
             lambda x: x >= 64 or (1 << x) == 2 or (255 >> x) == 0, 5),
        )
        for expression, oracle, expected_blocks in expressions:
            node = ast.parse("def example(x:u64) -> bool:\n    return " + expression).body[0]
            builder = Builder(node, {"example": "f0"}, {})
            builder.statements(node.body)
            program = verify_program({"schema": "hepta.hia.program.v8", "module": "shortcircuit",
                "functions": [{"name": "f0", "params": [builder.param(x) for x in builder.params],
                    "returns": ["bool"], "effects": ["trap"], "entry": "b0", "blocks": builder.blocks}]})
            self.assertEqual(len(builder.blocks), expected_blocks)
            for value in [*range(71), (1 << 64) - 1]:
                with self.subTest(expression=expression, value=value):
                    observed = execute_program(program, "f0", [value])
                    self.assertEqual(observed["status"], "returned")
                    self.assertEqual(observed["result"], oracle(value))

    def test_qualification_phase_merge_requires_complete_disjoint_boolean_results(self):
        from tools.qualify_hia_selfhost import QUALIFICATION_FAMILIES, _merge_qualification_phases
        rows = [({"family": family, "compiler_label": label, "status": "PASS",
                  "checks": {family + "-" + label: True}}, {})
                for family in QUALIFICATION_FAMILIES for label in ("original", "modified")]
        checks = {"generation_chain": True}
        self.assertEqual(len(_merge_qualification_phases(rows, checks)), 2 * len(QUALIFICATION_FAMILIES))
        self.assertEqual(len(checks), 2 * len(QUALIFICATION_FAMILIES) + 1)
        variants = [rows[:-1], [*rows[:-1], rows[0]]]
        for mutation in ("nonboolean", "overwritten", "empty", "inconsistent-status"):
            broken = deepcopy(rows)
            if mutation == "nonboolean":
                broken[-1][0]["checks"] = {"bad": 1}
            elif mutation == "overwritten":
                broken[-1][0]["checks"] = {"generation_chain": True}
            elif mutation == "empty":
                broken[-1][0]["checks"] = {}
            else:
                broken[-1][0]["status"] = "FAIL"
            variants.append(broken)
        for broken in variants:
            original = {"generation_chain": True}
            with self.assertRaises(AssertionError):
                _merge_qualification_phases(broken, original)
            self.assertEqual(original, {"generation_chain": True})
        failed = deepcopy(rows)
        failed[-1][0]["status"] = "FAIL"
        failed[-1][0]["checks"] = {"actual_failure": False}
        accepted = {}
        _merge_qualification_phases(failed, accepted)
        self.assertFalse(all(accepted.values()))

    def test_qualification_phase_inputs_require_pinned_bytes_and_closed_inventory(self):
        from tools.qualify_hia_selfhost import _read_phase_inputs, qualification_phase
        with tempfile.TemporaryDirectory(prefix="hia-phase-input-") as temporary:
            from hashlib import sha256
            path = Path(temporary) / "input"
            path.write_bytes(b"original bytes")
            identity = {"compiler": {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}}
            self.assertEqual(_read_phase_inputs(identity), {"compiler": b"original bytes"})
            path.write_bytes(b"changed bytes")
            with self.assertRaisesRegex(ValueError, "input changed"):
                _read_phase_inputs(identity)
            request = Path(temporary) / "request.json"
            for value in ({}, {"schema": "hepta.hia.selfhost-phase-request.v1", "family": "unknown",
                              "compiler_label": "original", "directory": temporary,
                              "inputs": {}, "source_manifest_sha256": "0" * 64}):
                request.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "unknown qualification phase"):
                    qualification_phase(request)

    def test_qualification_phase_process_failures_preserve_logs_and_refuse_merge(self):
        from concurrent.futures import Future
        from hashlib import sha256
        from unittest.mock import patch
        from tools import qualify_hia_selfhost as module
        with tempfile.TemporaryDirectory(prefix="hia-phase-failure-") as temporary:
            root = Path(temporary)
            image = root / "inert-image"
            image.write_bytes(b"not executed")
            inputs = {"compiler": {"path": str(image), "sha256": sha256(image.read_bytes()).hexdigest()}}
            for failure in ("nonzero", "missing-report", "wrong-identity"):
                directory = root / failure
                directory.mkdir()

                class FakeProcess:
                    pid = 12345

                    def __init__(self, command, **kwargs):
                        kwargs["stdout"].write(b"retained phase stdout\n")
                        kwargs["stderr"].write(b"retained phase failure\n")
                        if failure == "wrong-identity":
                            Path(command[-1]).write_text(json.dumps({
                                "schema": "hepta.hia.selfhost-phase.v1", "family": "bulk",
                                "compiler_label": "original", "worker_pid": self.pid,
                                "source_manifest_sha256": "different source"}))

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        pass

                    def wait(self):
                        return 1 if failure == "nonzero" else 0

                with patch.object(module, "_phase_inputs", return_value=inputs), \
                        patch.object(module.subprocess, "Popen", FakeProcess), \
                        self.assertRaises(AssertionError):
                    module._run_qualification_phase(directory, "bulk", "original", image, "0" * 64)
                stem = directory / "phase-bulk-original"
                self.assertEqual(stem.with_suffix(".stdout.log").read_bytes(), b"retained phase stdout\n")
                self.assertEqual(stem.with_suffix(".stderr.log").read_bytes(), b"retained phase failure\n")
                receipt = json.loads(stem.with_suffix(".process.json").read_text())
                self.assertEqual(receipt["returncode"], 1 if failure == "nonzero" else 0)
                self.assertTrue(stem.with_suffix(".request.json").is_file())
                self.assertTrue((directory / "phase-runs/bulk-original").is_dir())
            scheduled = []
            for family, outcome in (("capacity", RuntimeError("first phase failed")),
                                    ("cfg", FileNotFoundError("second phase failed before launch")),
                                    ("elf", ({"status": "PASS"}, {}))):
                future = Future()
                if isinstance(outcome, Exception):
                    future.set_exception(outcome)
                else:
                    future.set_result(outcome)
                scheduled.append((family, "original", future))
            with self.assertRaisesRegex(AssertionError, "qualification_phase_exceptions"):
                module._collect_qualification_phases(root, scheduled)
            index = json.loads((root / "phase-index.json").read_text())
            self.assertEqual(index["completed"], 3)
            self.assertEqual(index["exceptions"], 2)
            self.assertEqual([row["state"] for row in index["phases"]], ["exception", "exception", "completed"])
            self.assertEqual([row["exception_message"] for row in index["phases"][:2]],
                             ["first phase failed", "second phase failed before launch"])

    def test_complete_compiler_is_valid_core_and_reproducible_source(self):
        from tools.generate_hia_selfhost import document
        source = SOURCE.read_bytes()
        checked = assemble_program(source)
        doc, names = document()
        self.assertEqual(render_assembly(checked).encode(), source)
        self.assertEqual(render_assembly(doc).encode(), source)
        self.assertEqual(names["compile"], "f0")
        self.assertEqual(names["wrapper"], validate_contract()["compiler_symbols"]["mutation_wrapper"])
        self.assertTrue(any(int(o["attrs"]["function"][1:]) < int(f["name"][1:])
            for f in doc["functions"] for b in f["blocks"] for o in b["ops"] if o["op"] == "call"))
        self.assertGreater(len(source), 200000)
        self.assertLess(sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]), MAX_INSTRUCTIONS)
        self.assertLessEqual(sum(len(f["blocks"]) for f in doc["functions"]), 1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in doc["functions"]), 256)
        import re
        self.assertLessEqual(max(map(int, re.findall(rb"\bv(\d+)", source))), 2047)
        self.assertLessEqual(max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]), 16)

    def test_native_effect_table_matches_independent_core_instruction_contract(self):
        from hepta.hia_opcodes import OPCODES
        from tools.generate_hia_selfhost import WORDS
        from tools.hia_selfhost_effects import EFFECT_BITS, OPERATION_EFFECTS
        for word in set(WORDS) & OPCODES.keys():
            # int.cast adds its trap condition when checked mode is parsed;
            # calls use complete retained callee declarations.
            expected = sum(EFFECT_BITS[effect] for effect in OPCODES[word].effects)
            self.assertEqual(OPERATION_EFFECTS.get(word, 0), expected, word)

    def test_effect_witnesses_compare_all_declarations_and_refusals_with_general_core(self):
        from tools.hia_selfhost_effects import independent_reference
        reference = independent_reference()
        declarations = [row for row in reference["cases"] if row["id"].startswith("declaration-")]
        self.assertEqual(len(declarations), 65)
        self.assertEqual(len({frozenset(row["effects"]) for row in declarations}), 16)
        self.assertEqual(len(reference["cases"]), 101)
        self.assertEqual(len(reference["native_case_ids"]), 52)
        batch = next(row for row in reference["cases"] if row["id"] == "all-declaration-permutations-called")
        self.assertEqual(batch["expected_result"], 455)
        self.assertEqual(set(batch["declaration_case_ids"]), {row["id"] for row in declarations})
        self.assertEqual(len(reference["refusals"]), 64)
        for row in reference["refusals"]:
            if not row["id"].startswith("malformed-"):
                self.assertEqual(row["code"], "E_HIA_EFFECT", row)
        self.assertFalse(reference["all_input_correctness_proved"])

    def test_compiler_itself_fits_declared_per_function_block_and_ssa_limits(self):
        # General Core accepts larger functions than this native input profile.
        # Total instruction/block counts alone do not make its own source admissible.
        doc = assemble_program(SOURCE.read_bytes()).as_dict()
        limits = validate_contract()["limits"]
        self.assertLessEqual(len(doc["functions"]), limits["functions"])
        for function in doc["functions"]:
            with self.subTest(function=function["name"]):
                self.assertLessEqual(len(function["blocks"]), limits["blocks_per_function"])
                values = list(function["params"])
                for block in function["blocks"]:
                    values.extend(block["params"])
                    values.extend(value for op in block["ops"] for value in op["out"])
                self.assertLessEqual(max(int(value["name"][1:]) for value in values), limits["ssa_index_max"])

    def test_codegen_mutation_is_valid_core_and_changes_one_literal(self):
        source = SOURCE.read_bytes()
        changed = mutate_compiler(source)
        assemble_program(changed)
        self.assertEqual(len(source), len(changed))
        self.assertEqual(sum(a != b for a, b in zip(source, changed)), 2)

    def test_native_rejection_fixtures_also_fail_independent_core_frontend(self):
        for label, source in invalid_sources(SAMPLE.read_bytes()).items():
            with self.subTest(label=label), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_readonly_alias_rules_distinguish_calls_from_linear_edges(self):
        assemble_program(readonly_call_source())
        invalid = invalid_sources(SAMPLE.read_bytes())
        for name in ("readonly-jump-alias", "readonly-branch-alias"):
            with self.subTest(case=name), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_RESOURCE"):
                assemble_program(invalid[name])

    def test_resource_reference_and_refusals_are_independent_core_observations(self):
        from tools.hia_selfhost_resources import independent_resource_reference
        result = independent_resource_reference()
        self.assertEqual(len(result["cases"]), 9)
        self.assertEqual(sum(row["trap"] for row in result["cases"]), 5)
        self.assertEqual(len(result["rejections"]), 5)
        for row in result["cases"]:
            self.assertEqual(row["reference_result"]["status"], "trapped" if row["trap"] else "returned")

    def test_call_graph_admission_distinguishes_general_core_from_fixed_profile(self):
        assemble_program(backward_bytesum_source(SAMPLE.read_bytes()))
        assemble_program(backward_chain_source())
        for name, source in recursion_refusals().items():
            with self.subTest(case=name):
                assemble_program(source)  # valid general Core; outside this bounded recursive profile
        for name, source in call_graph_invalid_sources(SAMPLE.read_bytes()).items():
            with self.subTest(case=name), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_boolean_equality_admits_bool_but_rejects_ordering_and_mixed_types(self):
        from tools.hia_selfhost_select import independent_boolean_equality_reference
        result = independent_boolean_equality_reference()
        self.assertEqual(len(result["cases"]), 32)
        self.assertEqual(len(result["rejections"]), 13)
        for opcode in ("compare.eq", "compare.ne"):
            cases = [row for row in result["cases"] if row["opcode"] == opcode]
            self.assertEqual(len(cases), 16)
            self.assertEqual({row["expected"] for row in cases}, {False, True})
            self.assertTrue(all(row["reference_result"]["status"] == "returned" for row in cases))

    def test_tail_reference_uses_real_recursion_and_preserves_vm_budget_refusal(self):
        from tools.hia_selfhost_tailcalls import independent_tail_reference
        result = independent_tail_reference()
        self.assertEqual(len(result["scalar_cases"]), 5)
        self.assertEqual(len(result["buffer_cases"]), 3)
        self.assertEqual(len(result["rejections"]), 6)
        self.assertEqual(sum(r["general_core"] == "accepted" for r in result["rejections"]), 3)
        self.assertEqual(result["deep_case"]["reference_result"]["status"], "budget_exceeded")
        self.assertGreater(result["deep_case"]["native_frame_bytes"] * result["deep_case"]["count"], 8 << 20)

    def test_expanded_capacity_has_independent_execution_and_exact_structural_boundary(self):
        from tools.hia_selfhost_capacity import independent_capacity_reference
        from tools.hia_selfhost_limits import MAX_CORE_NODES
        rows = {row["case"]: row for row in independent_capacity_reference()["observations"]}
        maximum = rows["instructions-" + str(MAX_INSTRUCTIONS)]
        self.assertEqual(maximum["expected_result"], 8176)
        self.assertEqual(maximum["reference_result"]["result"], 8176)
        self.assertEqual(rows["instructions-" + str(MAX_INSTRUCTIONS + 1)]["general_core"], "accepted")
        self.assertEqual(rows["structural-nodes-" + str(MAX_CORE_NODES)]["general_core"], "accepted")
        self.assertEqual(rows["structural-nodes-" + str(MAX_CORE_NODES + 1)]["code"], "E_HIA_LIMIT")
        self.assertEqual(rows["structural-alloc-nodes-" + str(MAX_CORE_NODES)]["general_core"], "accepted")
        self.assertEqual(rows["structural-alloc-nodes-" + str(MAX_CORE_NODES + 1)]["code"], "E_HIA_LIMIT")

    def test_select_reference_covers_all_scalar_types_and_rejects_bad_signatures(self):
        from tools.hia_selfhost_select import independent_select_reference
        result = independent_select_reference()
        self.assertEqual(len(result["cases"]), 78)
        self.assertEqual(len(result["rejections"]), 13)
        self.assertEqual({row["type"] for row in result["cases"]}, {"u8", "u16", "u32", "u64", "usize", "bool"})
        for typ in ("u8", "u16", "u32", "u64", "usize", "bool"):
            self.assertEqual({row["condition"] for row in result["cases"] if row["type"] == typ}, {False, True})

    def test_loan_reference_covers_live_capability_graphs_and_lifecycle_refusals(self):
        from tools.hia_selfhost_loans import independent_loan_reference
        result = independent_loan_reference()
        self.assertEqual(len(result["cases"]), 29)
        self.assertEqual(len(result["rejected"]), 39)
        self.assertEqual(len(result["outside_profile"]), 0)
        from tools.hia_selfhost_loans import historical_loan_profile_refusals
        self.assertEqual({r["id"] for r in result["cases"] if r["id"].startswith("loan-profile-")},
                         {"loan-profile-" + x for x in historical_loan_profile_refusals()})
        names = {row["id"] for row in result["cases"]}
        self.assertTrue({"loan-through-loop-backedge", "incoming-from-later-source-block",
                         "root-parent-index-fifteen", "nested-graph-through-permuted-edge"} <= names)
        self.assertTrue(all(row["reference_result"]["status"] == "returned" for row in result["cases"]))
        codes = {row["id"]: row["code"] for row in result["rejected"]}
        for name in ("merge-disagrees-root", "merge-disagrees-parent", "end-parent-before-child"):
            self.assertEqual(codes[name], "E_HIA_LOAN")
        self.assertFalse(result["claims"]["all_input_proof"])

    def test_cfg_worklist_preserves_the_review_subjects_and_block_boundaries(self):
        from hashlib import sha256
        from tools.hia_selfhost_cfg_worklist import reverse_source, future_capability_source, cases
        subjects = (
            (reverse_source(), "5d26b74b3609f213e5205e22a68ad9b284ff4643fcf2fc8b60c439d85dd3b555"),
            (reverse_source(loan=True), "2e42fb643c05d95ff9860d1f9d967f3214c0fa58b7266746b615b6a20f804ede"),
            (future_capability_source(), "13346fbc7217cdce1c449a0b1d38de6f1ccfcf6eeb6db2a6cddc88365889b2fb"),
        )
        for source, expected in subjects:
            self.assertEqual(sha256(source).hexdigest(), expected)
        for source, _ in subjects[:2]:
            function = assemble_program(source).as_dict()["functions"][0]
            self.assertEqual(len(function["blocks"]), 256)
            self.assertEqual(function["blocks"][0]["term"]["target"], "b255")
            for index in range(2, 256):
                self.assertEqual(function["blocks"][index]["term"]["target"], "b" + str(index - 1))
        boundary = next(row for row in cases() if row["id"] == "reverse-1536-six-functions")
        functions = assemble_program(boundary["source"].encode()).as_dict()["functions"]
        self.assertEqual([len(fn["blocks"]) for fn in functions], [256] * 6)

    def test_cfg_worklist_reference_covers_replays_and_late_join_refusals(self):
        from tools.hia_selfhost_cfg_worklist import independent_reference
        result = independent_reference()
        self.assertEqual(len(result["cases"]), 12)
        self.assertEqual(len(result["refusals"]), 14)
        self.assertTrue(all(row["reference_result"]["status"] == "returned" for row in result["cases"]))
        codes = {row["id"]: row["code"] for row in result["refusals"]}
        for name in ("late-inconsistent-root-join", "late-inconsistent-parent-join",
                     "queued-owner-consumed-with-live-child"):
            self.assertEqual(codes[name], "E_HIA_LOAN")
        self.assertFalse(result["all_input_correctness_or_performance_proved"])


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld seed linker required")
class SelfhostNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-selfhost-test-")
        cls.output = Path(cls.temporary.name) / "qualification.json"
        cls.report = qualify(cls.output)
        cls.directory = cls.output.with_suffix(".evidence")
        cls.compiler = cls.directory / "B3.image.bin"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_B1_B2_B3_are_executed_self_compilations(self):
        self.assertEqual(self.report["status"], "SELF_HOSTED_FIXED_CORE_PASS", self.report["checks"])
        generations = self.report["generations"]
        self.assertEqual(len(generations), 3)
        self.assertEqual(len({x["produced_sha256"] for x in generations}), 1)
        for generation in generations:
            self.assertEqual(generation["input_sha256"], self.report["source_sha256"])
            self.assertGreater(generation["produced_bytes"], 300000)
            self.assertEqual(generation["workspace_header"]["48"], 2)
            self.assertEqual(generation["forbidden_compiler_modules_loaded"], [])
        for earlier, later in zip(generations, generations[1:]):
            self.assertEqual(earlier["produced_sha256"], later["artifact_sha256"])
        scheduling = self.report["qualification_scheduling"]
        self.assertEqual(scheduling["maximum_host_oracle_workers"], 2)
        self.assertTrue(scheduling["fresh_seed_and_generation_chain_sequential"])
        self.assertFalse(scheduling["native_child_processes_reused"])
        self.assertTrue(scheduling["independent_references_completed_before_B0"])
        from tools.hia_selfhost_references import BUILDERS
        references = scheduling["reference_processes"]
        self.assertEqual({r["family"] for r in references}, set(BUILDERS))
        self.assertEqual(len({r["worker_pid"] for r in references}), len(BUILDERS))
        for row in references:
            self.assertEqual(row["returncode"], 0)
            self.assertLessEqual(row["completed_monotonic_ns"], scheduling["seed_started_monotonic_ns"])
            self.assertEqual(row["command"][1:4], ["-I", "-S", "-B"])
        from tools.qualify_hia_selfhost import QUALIFICATION_FAMILIES
        self.assertEqual(len(scheduling["phase_inventory"]), 2 * len(QUALIFICATION_FAMILIES))
        self.assertEqual(len(scheduling["phases"]), 2 * len(QUALIFICATION_FAMILIES))
        intervals = []
        for phase in scheduling["phases"]:
            self.assertEqual(phase["returncode"], 0)
            self.assertEqual(phase["command"][1:4], ["-I", "-S", "-B"])
            intervals += [(phase["started_monotonic_ns"], 1), (phase["completed_monotonic_ns"], -1)]
        active = 0
        for _, delta in sorted(intervals):
            active += delta
            self.assertLessEqual(active, 2)
        self.assertEqual(active, 0)

    def test_loans_keep_live_graphs_through_native_original_and_mutated_compilers(self):
        selected = {name: value for name, value in self.report["checks"].items()
                    if name.startswith(("original-loan-", "modified-loan-"))}
        self.assertEqual(len(selected), 142)
        self.assertTrue(all(selected.values()), [name for name, value in selected.items() if not value])

    def test_entry_last_and_middle_whole_compilers_self_reproduce_and_preserve_owned_flow(self):
        from tools.hia_selfhost_names import qualify_entry_layout
        directory = self.directory / 'entry-layout'
        directory.mkdir()
        report = qualify_entry_layout(directory, [('original', self.compiler),
            ('modified', self.directory / 'M3.image.bin')])
        (directory / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        self.assertTrue(report['references_completed_before_native_compilation'])
        self.assertEqual(len(report['references']), 4)
        self.assertEqual(len(report['checks']), 20)
        self.assertTrue(all(report['checks'].values()), report['checks'])
        self.assertFalse(report['whole_stack_rewrite_complete'])

    def test_cfg_worklist_checks_reverse_order_replays_and_refusals_with_both_compilers(self):
        selected = {name: value for name, value in self.report["checks"].items()
                    if name.startswith(("original-cfg-worklist-", "modified-cfg-worklist-"))}
        self.assertEqual(len(selected), 52)
        self.assertTrue(all(selected.values()), [name for name, value in selected.items() if not value])
        reference = self.report["independent_cfg_worklist_reference"]
        self.assertEqual(len(reference["cases"]), 12)
        self.assertEqual(len(reference["refusals"]), 14)
        for row in self.report["cfg_worklist_observations"]:
            observed = row.get("build", row)
            self.assertEqual(observed["limits"]["cpu_seconds"], 10)
            self.assertEqual(observed["limits"]["workspace_bytes"], 1048576)

    def test_native_effect_contracts_match_core_for_original_and_mutated_compilers(self):
        selected = {name: value for name, value in self.report["checks"].items()
                    if name.startswith(("original-effect-contract-", "modified-effect-contract-"))}
        self.assertEqual(len(selected), 232)
        self.assertTrue(all(selected.values()), [name for name, value in selected.items() if not value])
        reference = self.report["independent_effect_reference"]
        self.assertEqual(len(reference["cases"]), 101)
        self.assertEqual(len(reference["native_case_ids"]), 52)
        self.assertEqual(len(reference["refusals"]), 64)

    def test_native_capacity_boundary_and_original_modified_node_accounting(self):
        from tools.hia_selfhost_capacity import count_nodes
        from tools.hia_selfhost_limits import MAX_CORE_NODES
        nodes = count_nodes(assemble_program(SOURCE.read_bytes()).as_dict())
        for generation in self.report["generations"]:
            self.assertEqual(generation["workspace_header"]["248"], nodes)
        for name, accepted in self.report["checks"].items():
            if "-capacity-" in name:
                self.assertTrue(accepted, name)
        rows = {r["case"]: r for r in self.report["expanded_capacity_observations"]}
        for compiler in ("original", "modified"):
            limit = rows[compiler + "-capacity-" + str(MAX_INSTRUCTIONS)]
            self.assertEqual(limit["workspace_header"]["112"], MAX_INSTRUCTIONS)
            self.assertGreater(limit["produced_bytes"], 100000)
            rejected = rows[compiler + "-capacity-over-limit"]
            self.assertEqual(rejected["core_u32"], INVALID)
            self.assertTrue(rejected["output_unchanged"])
            for prefix in ("-capacity-nodes-", "-capacity-alloc-nodes-"):
                allowed = rows[compiler + prefix + str(MAX_CORE_NODES)]
                self.assertEqual(allowed["core_u32"], NO_SPACE)
                self.assertEqual(allowed["workspace_header"]["248"], MAX_CORE_NODES)
                self.assertEqual(allowed["workspace_header"]["40"], 0)
                refused = rows[compiler + prefix + str(MAX_CORE_NODES + 1)]
                self.assertEqual(refused["core_u32"], INVALID)
                self.assertEqual(refused["workspace_header"]["248"], MAX_CORE_NODES + 1)
                self.assertEqual(refused["workspace_header"]["40"], 58)
                for observed in (allowed, refused):
                    self.assertTrue(observed["output_unchanged"])
                    self.assertTrue(observed["source_unchanged"])

    def test_modified_emitter_propagates_and_rebuilds_modified_self(self):
        m1, m2, m3 = self.report["modified_generations"]
        self.assertNotEqual(m1["produced_sha256"], m2["produced_sha256"])
        self.assertEqual(m2["produced_sha256"], m3["produced_sha256"])
        self.assertNotEqual(m3["produced_sha256"], self.report["generations"][2]["produced_sha256"])
        self.assertTrue(self.report["checks"]["modified_wrapper_machine_bytes"])
        for name, good in self.report["checks"].items():
            if "behavior" in name:
                self.assertTrue(good, name)

    def test_bad_sources_and_small_output_never_write_output(self):
        for result in self.report["rejection_observations"]:
            self.assertEqual(result["core_u32"], INVALID, result)
            self.assertTrue(result["output_unchanged"], result)
        for result in self.report["capacity_observations"]:
            self.assertEqual(result["core_u32"], NO_SPACE, result)
            self.assertTrue(result["output_unchanged"], result)

    def test_native_edges_reject_readonly_duplicates_but_calls_keep_legal_aliases(self):
        rejected = {row["case"]: row for row in self.report["rejection_observations"]}
        for name in ("readonly-jump-alias", "readonly-branch-alias"):
            result = rejected["reject-" + name]
            self.assertEqual(result["core_u32"], INVALID, result)
            self.assertTrue(result["output_unchanged"], result)
        self.assertTrue(self.report["checks"]["readonly_call_alias_remains_legal"])
        self.assertEqual(self.report["readonly_call_observations"][1]["core_u32"], 28)

    def test_backward_calls_and_full_depth_execute_in_original_and_modified_compilers(self):
        for compiler in ("original", "modified"):
            self.assertTrue(self.report["checks"][compiler + "_128_function_backward_chain"])
            for index in range(3):
                self.assertTrue(self.report["checks"][compiler + "_backward_call_behavior_" + str(index)])
        self.assertTrue(self.report["checks"]["own_compiler_uses_backward_direct_calls"])
        references = self.report["independent_core_reference"]["general_core_observations"]
        self.assertEqual(references[-1]["result"], 127)

    def test_non_tail_recursion_and_bad_backward_signatures_are_transactionally_refused(self):
        results = [row for row in self.report["call_graph_observations"] if "-reject-" in row["case"]]
        self.assertEqual(len(results), 14)
        for result in results:
            self.assertEqual(result.get("core_u32"), INVALID, result)
            self.assertTrue(result.get("output_unchanged"), result)
            self.assertTrue(result.get("source_unchanged"), result)
        differences = self.report["independent_core_reference"]["admission_differences"]
        self.assertEqual(sum(row["general_core"] == "accepted" for row in differences), 3)

    def test_tail_self_calls_bootstrap_and_keep_frame_resource_and_capacity_boundaries(self):
        self.assertTrue(self.report["checks"]["own_compiler_uses_direct_tail_self_calls"])
        for name, accepted in self.report["checks"].items():
            if "-tail-" in name:
                self.assertTrue(accepted, name)
        rejections = [r for r in self.report["tail_call_observations"] if "-tail-refuse-" in r["case"]]
        self.assertEqual(len(rejections), 12)
        for result in rejections:
            self.assertEqual(result["core_u32"], INVALID)
            self.assertTrue(result["output_unchanged"])

    def test_hia_writes_elf_objects_that_link_and_rebuild_the_compiler(self):
        rows = [row for row in self.report["elf_object_observations"] if "inventory" in row]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["inventory"]["exports"], ["f0"])
            self.assertEqual(row["inventory"]["undefined_symbols"], [])
            self.assertEqual(row["inventory"]["external_relocations"], [])
            self.assertTrue(row["inventory"]["nonexecuting_stack_note"])
        for name, accepted in self.report["checks"].items():
            if "elf" in name:
                self.assertTrue(accepted, name)
        self.assertTrue(self.report["claims"]["HIA_successor_ELF_writer_used"])
        self.assertFalse(self.report["claims"]["Python_successor_ELF_writer_used"])
        self.assertFalse(self.report["claims"]["external_linker_in_flat_bootstrap_chain"])
        self.assertFalse(self.report["claims"]["python_parser_or_codegen_in_successor_compilation"])
        self.assertTrue(self.report["claims"]["host_reference_codegen_after_B0"])
        self.assertTrue(self.report["claims"]["python_parser_or_codegen_after_B0"])
        self.assertTrue(self.report["claims"]["external_assembler_after_B0"])
        self.assertFalse(self.report["claims"]["external_assembler_in_successor_compilation"])
        self.assertTrue(self.report["claims"]["host_native_fixture_compilation_after_B0"])

    def test_independent_elf_inspector_refuses_changed_class_flags_symbols_and_extent(self):
        row = next(row for row in self.report["elf_object_observations"]
                   if row["case"] == "original-elf-bytesum")
        # The completed native phase has already losslessly archived its raw
        # paths. Inspect the exact original bytes, never rebuild the witness or
        # silently skip the negative controls because the raw file was retired.
        import zipfile
        from hashlib import sha256
        from tools.hia_evidence_archive import verify_archive
        phase = next(p for p in self.report["qualification_scheduling"]["phases"]
                     if (p["family"], p["compiler_label"]) == ("elf", "original"))
        receipt = phase["raw_artifacts"]
        archive = Path(receipt["archive"])
        self.assertEqual(sha256(archive.read_bytes()).hexdigest(), receipt["archive_sha256"])
        manifest = verify_archive(archive)
        original = Path(row["compilation"]["produced_image"])
        self.assertEqual(original.parent, Path(manifest["source_directory"]))
        with zipfile.ZipFile(archive) as packed:
            data = packed.read(original.name)
        self.assertEqual(len(data), row["compilation"]["produced_bytes"])
        self.assertEqual(sha256(data).hexdigest(), row["compilation"]["produced_sha256"])
        inspect_selfhost_object(data)
        shoff = struct.unpack_from("<Q", data, 40)[0]
        symoff = struct.unpack_from("<Q", data, shoff + 2 * 64 + 24)[0]
        for label, offset, replacement in (("class", 4, b"\x01"),
                ("executable-stack", shoff + 5 * 64 + 8, struct.pack("<Q", 4)),
                ("undefined-f0", symoff + 48 + 6, b"\0\0"),
                ("bad-header-extent", 40, struct.pack("<Q", len(data)))):
            with self.subTest(case=label), self.assertRaises(ValueError):
                inspect_selfhost_object(data[:offset] + replacement + data[offset + len(replacement):])

    def test_swap_effects_bounds_refusals_and_trap_observer_positive_control(self):
        rows = self.report["resource_observations"]
        observations = [r for r in rows if "shared_output_observation" in r]
        self.assertEqual(len(observations), 20)
        for result in observations:
            self.assertTrue(result["shared_output_observation"]["available"], result)
            if result["status"] == "child_failed":
                self.assertEqual(result["returncode"], -4)
                # The positive control stores before a trapping swap; its
                # mutation must remain observable when the child has died.
                self.assertEqual(result["shared_output_observation"]["unchanged"],
                                 not result["case"].endswith("observer-control"), result)
        for name, accepted in self.report["checks"].items():
            if "swap" in name:
                self.assertTrue(accepted, name)

    def test_generated_byte_bounds_and_checked_shift_really_trap(self):
        sample = self.directory / "original-bytesum.image.bin"
        result, _ = invoke(self.directory, "bounds-trap", sample, b"x", capacity=0, workspace_size=1)
        self.assertEqual(result["status"], "child_failed", result)
        self.assertEqual(result["returncode"], -4, result)  # UD2 / SIGILL
        source = SAMPLE.read_bytes().replace(b'{"value":33}', b'{"value":32}').replace(b"int.mul.wrap(v0,v2)", b"int.shl.checked(v0,v2)")
        executable, _ = compile_stage(self.directory, "shift-trap-code", self.compiler, source)
        result, _ = invoke(self.directory, "shift-trap", executable, b"x", capacity=1, workspace_size=1)
        self.assertEqual(result["status"], "child_failed", result)
        self.assertEqual(result["returncode"], -4, result)

    def test_boolean_and_unsigned_comparison_encodings(self):
        cases = [
            '  v3:bool = const() {"value":true}\n'
            '  v4:bool = const() {"value":false}\n'
            '  v5:bool = bool.or(v3,v4)\n'
            '  v6:bool = bool.not(v5)\n'
            '  v7:bool = bool.and(v3,v6)\n',
            '  v3:u64 = const() {"value":18446744073709551615}\n'
            '  v4:u64 = const() {"value":1}\n'
            '  v7:bool = compare.lt(v3,v4)\n',
        ]
        for index, operations in enumerate(cases):
            source = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
                "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n" + operations +
                "  branch v7 b1() b2()\nblock b1()\n"
                '  v8:u32 = const() {"value":1}\n  ret(v8)\nblock b2()\n'
                '  v9:u32 = const() {"value":2}\n  ret(v9)\nend\n').encode()
            executable, _ = compile_stage(self.directory, "bool-code-" + str(index), self.compiler, source)
            result, _ = invoke(self.directory, "bool-" + str(index), executable, b"", capacity=0, workspace_size=0)
            self.assertEqual(result["status"], "returned", result)
            self.assertEqual(result["core_u32"], 2, result)

    def test_width_normalization_uses_real_generated_machine_code(self):
        cases = [("u8", 250, 10, "int.add.wrap", 4),
                 ("u32", 0x80000000, 1, "int.shl.checked", 0),
                 ("u64", 0xffffffffffffffff, 2, "int.add.wrap", 1),
                 ("u64", 0xffffffffffffffff, 63, "int.shr.checked", 1)]
        for index, (typ, left, right, operation, expected) in enumerate(cases):
            source = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
                "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n"
                f'  v3:{typ} = const() {{"value":{left}}}\n'
                f'  v4:{typ} = const() {{"value":{right}}}\n'
                f"  v5:{typ} = {operation}(v3,v4)\n"
                '  v6:u32 = int.cast(v5) {"mode":"wrap"}\n'
                "  ret(v6)\nend\n").encode()
            executable, _ = compile_stage(self.directory, "width-code-" + str(index), self.compiler, source)
            result, _ = invoke(self.directory, "width-" + str(index), executable, b"", capacity=0, workspace_size=0)
            self.assertEqual(result["status"], "returned", result)
            self.assertEqual(result["core_u32"], expected, result)

    def test_native_select_uses_input_dependent_values_and_full_width_outputs(self):
        rows = self.report["select_observations"]
        for compiler in ("original", "modified"):
            cases = [row for row in rows if row["case"].startswith(compiler + "-select-") and "-case-" in row["case"]]
            self.assertEqual(len(cases), 78)
            for row in cases:
                self.assertTrue(self.report["checks"][row["case"]], row)
                self.assertEqual(row["core_u32"], int(row["expected"]) & 0xffffffff)
            for typ in ("u8", "u16", "u32", "u64", "usize", "bool"):
                chosen = [row for row in cases if row["type"] == typ]
                self.assertEqual({row["condition"] for row in chosen}, {False, True})
                self.assertGreater(len({row["input_sha256"] for row in chosen}), 1)
                self.assertGreater(len({row["core_u32"] for row in chosen}), 1)
            for key, accepted in self.report["checks"].items():
                if key.startswith(compiler + "-select-"):
                    self.assertTrue(accepted, key)


if __name__ == "__main__":
    unittest.main()
