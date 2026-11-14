"""Independent pre-native VM decisions and complete body-policy witnesses."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_core_admission_native import (SOURCE, SCHEMA, SELECTOR, ERROR_CODES,
                                           NativeCoreAdmission, scratch_sizes)

VALID = {'schema': 'hepta.hia.program.v8', 'module': 'independent', 'functions': [
    {'name': 'f', 'params': [], 'returns': [], 'effects': [], 'entry': 'entry',
     'blocks': [{'id': 'entry', 'params': [], 'ops': [],
                 'term': {'op': 'ret', 'values': []}}]}]}


def wire(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def borrowed_owner():
    value = copy.deepcopy(VALID)
    fn = value['functions'][0]
    fn['params'] = [{'name': 'owner', 'type': 'buffer'}]
    fn['effects'] = ['read']
    fn['blocks'][0]['params'] = copy.deepcopy(fn['params'])
    fn['blocks'][0]['ops'] = [
        {'op': 'borrow.read', 'args': ['owner'], 'out': [{'name': 'view', 'type': 'readbuf'}], 'attrs': {}},
        {'op': 'owner.drop', 'args': ['owner'], 'out': [], 'attrs': {}}]
    return value


def returned_aliases(types):
    """A body-independent interface can declare mutually conflicting results.

    The callee traps, so its own body is legal. Its caller must still enforce
    the complete returned-capability contract before admitting later code.
    """
    from tests.test_hia_program import f, b, i, ret
    callee = f('never_returns', [('p', 'mutbuf')], list(types), ['trap'], [
        b('entry', [('p', 'mutbuf')], [], {'op': 'trap', 'code': 'user'})])
    callee['return_loans'] = ['p' if typ in ('readbuf', 'mutbuf') else None
                              for typ in types]
    outputs = [('result_' + str(index), typ) for index, typ in enumerate(types)]
    ops = [i('call', ['input'], outputs, function='never_returns')]
    for name, typ in outputs:
        if typ in ('readbuf', 'mutbuf'):
            ops.append(i('loan.end', [name]))
        elif typ in ('buffer', 'chain'):
            ops.append(i('owner.drop', [name]))
    caller = f('caller', [('input', 'mutbuf')], [], ['alloc', 'trap'], [
        b('entry', [('input', 'mutbuf')], ops, ret())])
    return {'schema': 'hepta.hia.program.v8', 'module': 'returned_aliases',
            'functions': [callee, caller]}


def interpreted(raw):
    from tests import test_hia_function_shape_native as observer
    with patch.object(observer, 'SOURCE', SOURCE), patch.object(observer, 'scratch_sizes', scratch_sizes):
        return observer.interpreted(raw)


class CoreAdmissionSourceTests(unittest.TestCase):
    def test_generated_source_is_unchanged_and_core_admitted(self):
        from tools.generate_hia_core_admission import document
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        assemble_program(SOURCE.read_bytes())

    def test_independent_vm_body_decisions_before_any_native_image(self):
        self.assertEqual(interpreted(wire(VALID)), 0)
        bad = copy.deepcopy(VALID)
        bad['functions'][0]['blocks'][0]['term']['values'] = ['undefined']
        self.assertEqual(interpreted(wire(bad)), 0xfffffff5)
        bad = copy.deepcopy(VALID)
        bad['functions'][0]['blocks'][0]['ops'] = [
            {'op': 'const', 'args': [], 'out': [{'name': 'b', 'type': 'bool'}],
             'attrs': {'value': 1}}]
        self.assertEqual(interpreted(wire(bad)), 0xfffffff9)

    def test_independent_vm_rejects_conflicting_results_of_one_call(self):
        # Earlier returned loans must be live while admitting each next result.
        self.assertEqual(interpreted(wire(returned_aliases(('mutbuf', 'mutbuf')))),
                         0xfffffff8)
        self.assertEqual(interpreted(wire(returned_aliases(('readbuf', 'readbuf')))), 0)

    def test_independent_vm_complete_diagnostic_bytes_with_unchanged_budgets(self):
        import struct
        from tests.hia_core_diagnostic_cases import vm_buffers, closure_before_join
        from hepta.hia_core_diagnostic_protocol import diagnostic_scratch_bytes, TABLE_CAPACITY
        from tools.generate_hia_core_admission import document
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        generated = document()
        self.assertLessEqual(len(generated['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in generated['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in generated['functions']
                                 for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(scratch_sizes(8388608)[0], 64 << 20)
        bad = copy.deepcopy(VALID)
        bad['functions'][0]['blocks'][0]['term']['values'] = ['independent_missing']
        witnesses = [(bad, 0xfffffff5, b'f/entry: undefined/nonlocal value independent_missing'),
                     (closure_before_join(), 0xfffffff8,
                      b'loan must travel with its owner/parent capability')]
        for value, expected_status, expected in witnesses:
            raw = wire(value)
            status, (source, state, arena), steps = vm_buffers(raw)
            self.assertEqual(source, raw)
            self.assertEqual(status, expected_status)
            self.assertLessEqual(steps, 3000000)
            table = len(state) - diagnostic_scratch_bytes(len(raw))
            output = table + TABLE_CAPACITY
            self.assertEqual(state[output:output + len(expected)], expected)
            self.assertEqual(struct.unpack_from('<Q', state, len(state) - 48)[0], len(expected))


class CoreAdmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An independent ordinary Core VM observes this raw witness first.
        assert interpreted(wire(VALID)) == 0
        assert interpreted(wire(borrowed_owner())) == 0xfffffff8
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-core-admission-')
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cold = os.environ.get('HEPTA_HIA_CORE_ADMISSION_COLD_REPORT')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            assert report['status'] == 'COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256'] == [sha256(compiler.read_bytes()).hexdigest()] * 3
        else:
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'core-admission', compiler, SOURCE.read_bytes())
        cls.compiler = compiler
        raw = image.read_bytes()
        cls.native = NativeCoreAdmission(raw, sha256(raw).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compare(self, value):
        from hepta.hia_program import verify_program, HIAProgramRejected
        expected = None
        expected_message = None
        try:
            verify_program(value)
        except HIAProgramRejected as error:
            expected = error.code
            expected_message = str(error)
        result = self.native.status(wire(value))
        self.assertNotEqual(result, 0xfffffffd)
        self.assertEqual(ERROR_CODES.get(result) if result else None, expected, value)
        if expected_message is None:
            self.native.admit(wire(value))
        else:
            with self.assertRaises(HIAProgramRejected) as caught:
                self.native.admit(wire(value))
            self.assertEqual(str(caught.exception), expected_message, value)

    def test_complete_diagnostic_declarations_catalog_and_first_refusal_order(self):
        from tests.hia_core_diagnostic_cases import (
            structured_mutations, opcode_documents, closure_before_join,
        )
        from tests.test_hia_program import resource_program
        from tests.test_hia_returned_loans import loan_program
        for document in (VALID, resource_program(), loan_program()):
            for label, value in structured_mutations(document):
                with self.subTest(label=label):
                    self.compare(value)
        for label, value in opcode_documents():
            with self.subTest(label=label):
                self.compare(value)
        from hepta.hia_program import HIAProgramRejected
        with self.assertRaises(HIAProgramRejected) as caught:
            self.native.admit(wire(closure_before_join()))
        self.assertEqual(str(caught.exception),
                         'E_HIA_LOAN: loan must travel with its owner/parent capability')
        self.compare(closure_before_join())

    def test_complete_diagnostic_long_names_unicode_and_large_return_interfaces(self):
        from tests.hia_core_diagnostic_cases import long_return_interface
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        fn['name'] = 'f' * 128
        fn['entry'] = fn['blocks'][0]['id'] = 'b' * 128
        fn['blocks'][0]['term']['values'] = ['v' * 128]
        self.compare(value)
        for opcode in ('', '🧪 unknown\x00 operation\n', 'x' * 200000):
            value = copy.deepcopy(VALID)
            value['functions'][0]['blocks'][0]['ops'] = [
                {'op': opcode, 'args': [], 'out': [], 'attrs': {}}]
            self.compare(value)
        value = copy.deepcopy(VALID)
        instruction = {'op': '', 'args': [], 'out': [], 'attrs': {}}
        value['functions'][0]['blocks'][0]['ops'] = [instruction]
        instruction['op'] = 'x' * (8388608 - len(wire(value)))
        self.assertEqual(len(wire(value)), 8388608)
        self.compare(value)
        # Python-style commas/spaces make this message longer than its source
        # fragment; the original node/byte/function profiles stay unchanged.
        self.compare(long_return_interface(16384))

    def test_diagnostic_bytes_are_native_and_foreign_checkers_are_forbidden(self):
        from contextlib import ExitStack
        from hepta.hia_program import HIAProgramRejected
        value = copy.deepcopy(VALID)
        value['functions'][0]['blocks'][0]['term']['values'] = ['native_name']
        raw = wire(value)
        forbidden = ('hepta.hia_program._reference_primitive_structure',
                     'hepta.hia_program._reference_function_shape',
                     'hepta.hia_program._verify_function',
                     'hepta.hia_program.check_instruction',
                     'hepta.hia_program.rename_capabilities', 'json.loads')
        with ExitStack() as stack:
            for target in forbidden:
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            with patch.object(self.native, '_entry', wraps=self.native._entry) as entry:
                with self.assertRaises(HIAProgramRejected) as caught:
                    self.native.admit(raw)
                self.assertEqual(entry.call_count, 1)
        self.assertEqual(str(caught.exception),
                         'E_HIA_SSA: f/entry: undefined/nonlocal value native_name')

    def test_diagnostic_transport_thread_reentry_exception_and_missing_invocation(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from hepta.hia_program import HIAProgramRejected
        from hepta.hia_core_admission_native import _DIAGNOSTIC_SINK
        raws = []
        for name in ('first_missing', 'second_missing'):
            value = copy.deepcopy(VALID)
            value['functions'][0]['blocks'][0]['term']['values'] = [name]
            raws.append(wire(value))

        def observed(raw):
            try:
                self.native.admit(raw)
            except HIAProgramRejected as error:
                return str(error)
            self.fail('expected missing-name refusal')

        expected = ['E_HIA_SSA: f/entry: undefined/nonlocal value ' + name
                    for name in ('first_missing', 'second_missing')]
        barrier = Barrier(2)
        original = self.native._invoke

        def overlap(raw):
            result = original(raw)
            barrier.wait(timeout=10)
            return result

        with patch.object(self.native, '_invoke', side_effect=overlap):
            with ThreadPoolExecutor(max_workers=2) as workers:
                self.assertEqual(list(workers.map(observed, raws)), expected)
        status = self.native.status
        nested = []

        def reenter(raw):
            if raw == raws[0]:
                nested.append(observed(raws[1]))
            return status(raw)

        with patch.object(self.native, 'status', side_effect=reenter):
            self.assertEqual(observed(raws[0]), expected[0])
        self.assertEqual(nested, [expected[1]])
        self.assertIsNone(_DIAGNOSTIC_SINK.get())
        with patch.object(self.native, 'status', side_effect=RuntimeError('injected failure')):
            with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                self.native.admit(raws[0])
        self.assertIsNone(_DIAGNOSTIC_SINK.get())
        with patch.object(self.native, 'status', return_value=0xfffffff5):
            with self.assertRaisesRegex(RuntimeError, 'missing native whole Core diagnostic invocation'):
                self.native.admit(raws[1])
        # Even an actual native observation for a different input cannot be
        # borrowed into this exception merely because its u32 code matches.
        with patch.object(self.native, 'status', side_effect=lambda raw: status(raws[1])):
            with self.assertRaisesRegex(RuntimeError, 'missing native whole Core diagnostic invocation'):
                self.native.admit(raws[0])
        self.assertEqual(observed(raws[1]), expected[1])
        self.assertIsNone(_DIAGNOSTIC_SINK.get())

    def test_diagnostic_trailer_and_utf8_are_validated_before_exception_transport(self):
        import ctypes
        from hepta.hia_core_diagnostic_protocol import TRAILER_BYTES
        value = copy.deepcopy(VALID)
        value['functions'][0]['blocks'][0]['term']['values'] = ['missing']
        raw = wire(value)
        entry = self.native._entry
        for offset in range(0, TRAILER_BYTES, 8):
            def corrupt(source, size, state, state_size, arena, arena_size):
                result = entry(source, size, state, state_size, arena, arena_size)
                at = ctypes.addressof(state) + state_size - TRAILER_BYTES + offset
                ctypes.memmove(at, (2**64 - 1).to_bytes(8, 'little'), 8)
                return result
            with self.subTest(offset=offset), patch.object(self.native, '_entry', side_effect=corrupt):
                with self.assertRaisesRegex(RuntimeError, 'diagnostic trailer'):
                    self.native.admit(raw)

        def invalid_utf8(source, size, state, state_size, arena, arena_size):
            result = entry(source, size, state, state_size, arena, arena_size)
            trailer = ctypes.addressof(state) + state_size - TRAILER_BYTES
            output = int.from_bytes(ctypes.string_at(trailer + 8, 8), 'little')
            ctypes.memmove(ctypes.addressof(state) + output, b'\xff', 1)
            return result
        with patch.object(self.native, '_entry', side_effect=invalid_utf8):
            with self.assertRaisesRegex(RuntimeError, 'diagnostic UTF-8'):
                self.native.admit(raw)

    def test_diagnostic_entire_native_buffers_match_independent_vm(self):
        import ctypes
        from tests.hia_core_diagnostic_cases import vm_buffers, closure_before_join
        witnesses = [VALID, borrowed_owner(), closure_before_join()]
        for name in ('missing', 'other_missing'):
            value = copy.deepcopy(VALID)
            value['functions'][0]['blocks'][0]['term']['values'] = [name]
            witnesses.append(value)
        for value in witnesses:
            raw = wire(value)
            expected, buffers, steps = vm_buffers(raw)
            source = ctypes.create_string_buffer(raw, len(raw))
            state_size, arena_size = scratch_sizes(len(raw))
            state = ctypes.create_string_buffer(state_size)
            arena = ctypes.create_string_buffer(arena_size)
            actual = self.native._entry(source, len(raw), state, state_size, arena, arena_size)
            self.assertEqual(actual, expected)
            self.assertEqual((source.raw, state.raw, arena.raw), buffers)
            self.assertLessEqual(steps, 3000000)

    def test_raw_native_has_no_foreign_declaration_body_or_json_decoder(self):
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])
        with (patch('hepta.hia_program._primitive_structure', side_effect=AssertionError('host declarations')),
              patch('hepta.hia_program._verify_function', side_effect=AssertionError('host body')),
              patch('json.loads', side_effect=AssertionError('host decoder'))):
            self.assertEqual(self.native.status(wire(VALID)), 0)
            for raw in (b'', b'{', wire(VALID) + b'x', b'{"schema":0,"schema":1}'):
                self.assertNotEqual(self.native.status(raw), 0)

    def test_native_ownership_branches_origins_and_mutated_complete_documents(self):
        from tests.test_hia_program import joined_loan_program
        self.compare(borrowed_owner())
        safe = borrowed_owner()
        safe['functions'][0]['blocks'][0]['ops'].insert(1,
            {'op': 'loan.end', 'args': ['view'], 'out': [], 'attrs': {}})
        self.compare(safe)
        self.compare(joined_loan_program())
        rng = random.Random(734162)
        for _ in range(180):
            value = copy.deepcopy(joined_loan_program())
            fn = value['functions'][0]
            block = rng.choice(fn['blocks'])
            if rng.randrange(3) == 0:
                term = block['term']
                key = rng.choice(tuple(term))
                term[key] = rng.choice((None, False, 0, 'missing', [], {}))
            elif block['ops']:
                ins = rng.choice(block['ops'])
                key = rng.choice(tuple(ins))
                ins[key] = rng.choice((None, False, 0, 'missing', [], {}))
            else:
                fn['effects'] = rng.choice(([], ['alloc'], ['read'], ['trap'], ['bogus']))
            self.compare(value)

    def test_returned_alias_conflicts_are_checked_within_each_call(self):
        for types in (('mutbuf', 'mutbuf'), ('mutbuf', 'readbuf'),
                      ('readbuf', 'mutbuf'),
                      ('u32', 'mutbuf', 'buffer', 'readbuf')):
            with self.subTest(types=types):
                value = returned_aliases(types)
                self.compare(value)
                self.assertEqual(self.native.status(wire(value)), 0xfffffff8)
        for types in (('readbuf', 'readbuf'),
                      ('u32', 'readbuf', 'buffer', 'readbuf'),
                      ('buffer', 'chain', 'u64', 'mutbuf')):
            with self.subTest(types=types):
                value = returned_aliases(types)
                self.compare(value)
                self.assertEqual(self.native.status(wire(value)), 0)

    def test_full_function_block_and_arity_profiles_are_not_compiler_profiles(self):
        value = copy.deepcopy(VALID)
        template = copy.deepcopy(value['functions'][0])
        value['functions'] = [{**copy.deepcopy(template), 'name': 'f' + str(i)} for i in range(1024)]
        self.compare(value)
        value['functions'].append({**copy.deepcopy(template), 'name': 'extra'})
        self.compare(value)
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        fn['blocks'] = [{'id': 'b' + str(i), 'params': [], 'ops': [],
                         'term': {'op': 'jump', 'target': 'b' + str(i + 1), 'args': []}
                         if i < 4095 else {'op': 'ret', 'values': []}} for i in range(4096)]
        fn['entry'] = 'b0'
        random.Random(824).shuffle(fn['blocks'])
        self.compare(value)
        fn['blocks'].append({'id': 'extra', 'params': [], 'ops': [], 'term': {'op': 'ret', 'values': []}})
        self.compare(value)
        value = copy.deepcopy(VALID)
        fn = value['functions'][0]
        fn['params'] = [{'name': 'p' + str(i), 'type': 'u32'} for i in range(16384)]
        fn['blocks'][0]['params'] = copy.deepcopy(fn['params'])
        fn['returns'] = ['u32'] * 1024
        fn['blocks'][0]['term']['values'] = ['p' + str(i) for i in range(1024)]
        self.compare(value)

    def test_selected_complete_admission_and_missing_image_never_fall_back(self):
        from hepta.hia_program import verify_program, HIAProgramRejected
        from tests.test_hia_program import joined_loan_program
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_program._primitive_structure', side_effect=AssertionError('host declarations')),
              patch('hepta.hia_program._verify_function', side_effect=AssertionError('host body'))):
            verify_program(joined_loan_program())
            bad = copy.deepcopy(VALID)
            bad['functions'][0]['blocks'][0]['term']['values'] = ['missing']
            with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_SSA'):
                verify_program(bad)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest) + '.missing'}):
            with self.assertRaises(FileNotFoundError):
                verify_program(VALID)

    def test_selected_incremental_rechecks_complete_bodies_without_host_cache_authority(self):
        from hepta.hia_incremental import IncrementalVerifier
        from hepta.hia_program import HIAProgramRejected
        from tests.test_hia_incremental import graph
        document = graph()
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_program._primitive_structure', side_effect=AssertionError('host declarations')),
              patch('hepta.hia_program._verify_function', side_effect=AssertionError('host body'))):
            session = IncrementalVerifier(document)
            checked, report = session.verify(copy.deepcopy(document))
            self.assertEqual(report['mode'], 'native_whole')
            self.assertTrue(report['native_whole_body_checked'])
            self.assertEqual(report['functions_body_reused'], [])
            self.assertEqual(set(report['functions_body_completed']), {fn['name'] for fn in document['functions']})
            bad = copy.deepcopy(document)
            bad['functions'][0]['blocks'][0]['ops'][0]['attrs']['value'] = True
            with self.assertRaisesRegex(HIAProgramRejected, 'E_HIA_TYPE'):
                session.verify(bad)

    def test_complete_json_byte_node_depth_limits_precede_body_policy(self):
        value = copy.deepcopy(VALID)
        value['functions'][0]['blocks'][0]['ops'] = [
            {'op': 'opaque', 'args': [], 'out': [], 'attrs': {'payload': []}}]
        def nodes(root):
            pending = [root]
            total = 0
            while pending:
                item = pending.pop()
                total += 1
                if type(item) is dict: pending.extend(item.values())
                if type(item) is list: pending.extend(item)
            return total
        attrs = value['functions'][0]['blocks'][0]['ops'][0]['attrs']
        attrs['payload'].extend([None] * (262144 - nodes(value)))
        self.assertEqual(nodes(value), 262144)
        self.assertEqual(self.native.status(wire(value)), 0xfffffff0)
        attrs['payload'].append(None)
        self.assertEqual(self.native.status(wire(value)), 0xfffffffe)
        nested = None
        for _ in range(56): nested = [nested]
        attrs['payload'] = nested
        self.assertEqual(self.native.status(wire(value)), 0xfffffff0)
        attrs['payload'] = [nested]
        self.assertEqual(self.native.status(wire(value)), 0xfffffffe)
        attrs['payload'] = ''
        attrs['payload'] = 'x' * (8388608 - len(wire(value)))
        self.assertEqual(len(wire(value)), 8388608)
        self.assertEqual(self.native.status(wire(value)), 0xfffffff0)
        self.assertEqual(self.native.status(wire(value) + b' '), 0xfffffffe)

    def test_strict_builder_and_warm_image_source_drift_fail_closed(self):
        from tools.build_hia_core_admission import build
        from hepta import hia_core_admission_native as bridge
        wrong = self.folder / 'wrong-cold.json'
        wrong.write_text(json.dumps({'status': 'COLD_SELFHOST_REPLAY_PASS', 'profile': 'wrong', 'source_manifest': {}}))
        output = self.folder / 'wrong-build'
        with self.assertRaisesRegex(ValueError, 'source identity'):
            build(output, self.compiler, wrong)
        self.assertFalse(output.exists())
        bridge.installed_core_admission(self.manifest)
        changed = self.folder / 'changed-source.hepta'
        changed.write_bytes(SOURCE.read_bytes() + b'\n')
        with patch.object(bridge, 'SOURCE', changed):
            with self.assertRaisesRegex(ValueError, 'source identity'):
                bridge.installed_core_admission(self.manifest)
