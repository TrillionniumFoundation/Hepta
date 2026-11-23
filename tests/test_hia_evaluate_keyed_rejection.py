"""Check the retained ABI and admitted workload at the native Evaluate boundary."""
import ast
from pathlib import Path
import json
import struct
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_agent_store import wire
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_worker_evaluate_input_binding import SOURCE
from tools.generate_hia_worker_evaluate_request import SOURCE as REQUEST_SOURCE
from tools.generate_hia_worker_evaluate_intake_flow import program as intake_program
from tools.generate_hia_worker_evaluate_run_input_flow import SOURCE as RUN_INPUT_SOURCE
from tools.generate_hia_worker_artifact_flow import policy_constants
from tools.generate_hia_store_transport import SOURCE as STORE_TRANSPORT_SOURCE, source_program as store_transport_program


class TypedWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.program = assemble_program((root / SOURCE).read_bytes())
        cls.entry = next(fn for fn in cls.program.as_dict()['functions'] if fn['name'] == 'f0')

    def evaluate(self, arguments, *, signature=None, name="transform", argument_lists=False):
        metadata = {'signatures': {'transform': signature or {'params': ['u8'], 'returns': ['u8']}}}
        workload = {'cases': [{'function': name, 'arguments': arg if argument_lists else [arg]} for arg in arguments]}
        size, result = self.project([metadata, workload])
        self.assertEqual(size, 16)
        return struct.unpack('<8sQ', result)

    def project(self, records, *, raw=None):
        source = _Owner(-1, bytearray(wire(records) if raw is None else raw))
        output = _Owner(-2, bytearray(1 << 20))
        work = _Owner(-3, bytearray(1 << 20))
        machine = _Machine(self.program, 10000000, 16 << 20, None, 128)
        size, = machine.invoke(self.entry, [_View(source, False), _View(output, True), _View(work, True)])
        return size, output.data[:16]

    def test_first_issued_native_scope_uses_decoded_identity_fields(self):
        install = {k: str(i) * 64 for i, k in enumerate(
            ('worker_sha256', 'backend_sha256', 'catalog_sha256', 'native_helpers_sha256'), 1)}
        scope = {'id': 'ctx-' + 'c' * 32, 'sha256': 'a' * 64}
        args = {'context': scope}
        base = {'installation': install, 'context': scope}
        for issued, expected in [
                (base, 0),
                ({'installation': dict(reversed(tuple(install.items()))),
                  'context': dict(reversed(tuple(scope.items())))}, 0),
                (dict(base, context=dict(scope, id='ctx-' + 'd' * 32)), 28),
                (dict(base, context=dict(scope, sha256='b' * 64)), 28),
                (dict(base, installation=dict(install, backend_sha256='0' * 64)), 28),
                (dict(base, installation={k: v for k, v in install.items() if k != 'native_helpers_sha256'}), 28)]:
            with self.subTest(issued=issued):
                records = [install, args, {}, issued]
                raw = json.dumps(records, separators=(',', ':')).encode()
                size, output = self.project(records, raw=raw)
                self.assertEqual((size, struct.unpack('<8sQ', output)), (16, (b'HIAEQB01', expected)))
        for invalid in [dict(base, context={'id': 'x'}), dict(base, installation={'worker_sha256': 'a' * 64})]:
            self.assertGreaterEqual(self.project([install, args, {}, invalid])[0], 0xfffffffc)

    def test_window_uses_the_retained_context_and_current_catalog(self):
        digest = 'a' * 64
        installed = {'catalog_sha256': digest}
        args = {'catalog_sha256': digest}
        ctx = {'schema': 'hepta.hia.agent.context.v1', 'installation': installed,
               'catalog_sha256': digest, 'budget': {'max_total_wall_ms': 1234}}
        size, result = self.project([installed, args, ctx])
        self.assertEqual((size, struct.unpack('<8sQ', result)), (16, (b'HIAEWD01', 1234)))
        for stale in (dict(ctx, catalog_sha256='b' * 64), dict(ctx, installation={'name': 'other'})):
            size, result = self.project([installed, args, stale])
            self.assertEqual((size, struct.unpack('<8sQ', result)), (16, (b'HIAEQB01', 23)))
        for modified in (dict(ctx, catalog_sha256='malformed'), dict(ctx, budget={'max_total_wall_ms': 0})):
            self.assertEqual(self.project([installed, args, modified])[0], 4294967293)
        self.assertEqual(self.project([installed, {'catalog_sha256': 'b' * 64}, ctx])[0], 4294967293)

    def test_integer_matches_the_retained_unsigned_byte(self):
        self.assertEqual(self.evaluate((0, 255)), (b'HIAEQB01', 0))

    def test_first_scalar_type_mismatch_is_an_admission_refusal(self):
        self.assertEqual(self.evaluate((0, True)), (b'HIAEQB01', 2))

    def test_unknown_entry_and_call_shape(self):
        self.assertEqual(self.evaluate((0,), name='absent'), (b'HIAEQB01', 11))
        self.assertEqual(self.evaluate(([],), argument_lists=True), (b'HIAEQB01', 20))

    def test_borrowed_snapshot_refusals_follow_the_original_signature(self):
        signature = {'params': ['readbuf'], 'returns': ['u32'],
                     'abi': 'hepta.hia.agent.borrowed-byte-snapshots.v1', 'max_buffer_bytes': 4}
        unbound = dict(signature, abi='unavailable')
        self.assertEqual(self.evaluate(({},), signature=unbound), (b'HIAEQB01', 13))
        cases = [(True, 14), ({'bytes_hex': 'AZ'}, 15),
                 ({'byte_length': 1, 'fill_byte': 256}, 16),
                 ({'extra': 1}, 17), ({'bytes_hex': '0000000000'}, 18)]
        for argument, reason in cases:
            with self.subTest(argument=argument):
                self.assertEqual(self.evaluate((argument,), signature=signature), (b'HIAEQB01', reason))
        self.assertEqual(self.evaluate(({'bytes_hex': 'ffff'},), signature=signature), (b'HIAEQB01', 0))

    def test_aggregate_snapshot_budget(self):
        signature = {'params': ['mutbuf'], 'returns': ['u32'],
                     'abi': 'hepta.hia.agent.borrowed-byte-snapshots.v1', 'max_buffer_bytes': 1048576}
        arguments = [{'byte_length': 1048576, 'fill_byte': 0}] * 33
        self.assertEqual(self.evaluate(arguments, signature=signature), (b'HIAEQB01', 19))


class RetainedEvaluateBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.generate_hia_worker_artifact_authority import SOURCE as artifact_authority
        root = Path(__file__).resolve().parents[1]
        cls.program = assemble_program((root / artifact_authority).read_bytes())
        cls.entry = next(fn for fn in cls.program.as_dict()['functions'] if fn['name'] == 'f0')

    def observe(self, *, mode=b'HIAEAR01', requested_kind=7, count=0, epoch=19):
        ref = wire({'id':'a-' + 'a' * 32,'sha256':'c' * 64,'uri':'hia://artifacts/' + 'b' * 32})
        packet = (struct.pack('<8s4Q',mode,0,71,19,requested_kind) + ref
                  + struct.pack('<6Q',5,0,count,0,71,epoch))
        vm = _Machine(self.program,1000000,1 << 20,None,128)
        output = _Owner(-2,bytearray(2048))
        length, = vm.invoke(self.entry,[_View(_Owner(-1,bytearray(packet)),False),
                                        _View(output,True),_View(_Owner(-3,bytearray(65536)),True)])
        return length,bytes(output.data[:16])

    def test_empty_result_requires_the_original_typed_read_and_store_generation(self):
        self.assertEqual(self.observe(), (16,struct.pack('<8sQ',b'HIAEAR02',26)))
        for change in ({'count':1},{'epoch':20},{'requested_kind':5}):
            with self.subTest(change=change):
                self.assertEqual(self.observe(**change)[0],0xfffffffd)
        self.assertEqual(self.observe(mode=b'HIARFG02')[0],0xfffffff8)


class VariableEvaluateContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.checked = assemble_program((root / REQUEST_SOURCE).read_bytes())
        cls.entry = next(fn for fn in cls.checked.as_dict()['functions'] if fn['name'] == 'f0')

    def query(self, identity, marker):
        digest = 'a' * 64
        ref = {'id': 'a-' + 'b' * 32, 'sha256': digest, 'uri': 'hia://artifacts/' + 'b' * 32}
        scope = {'id': identity, 'sha256': digest}
        args = dict(catalog_sha256=digest, context=scope, request_key='r', baseline_artifact=ref,
                    candidate_artifact=ref, build_receipt=ref, verification_receipts=[ref])
        envelope = [digest, args] if marker is None else [digest, args, marker]
        source = _Owner(-1, bytearray(wire(envelope)))
        output = _Owner(-2, bytearray(1 << 20))
        work = _Owner(-3, bytearray(1 << 20))
        vm = _Machine(self.checked, 5_000_000, 16 << 20, None, 128)
        size, = vm.invoke(self.entry, [_View(source, False), _View(output, True), _View(work, True)])
        return size, output.data

    def test_private_probe_binds_the_entire_admitted_identifier_and_never_classifies_a_store_row(self):
        for name in ('x', 'A.0_B/C:D-1', 'q' * 192):
            with self.subTest(name=name):
                size, out = self.query(name, 1)
                self.assertEqual(size, 64 + len(name))
                self.assertEqual(struct.unpack_from('<8s8s6Q', out), (
                    b'HIAEVC01', b'HIAQPA01', 1, 1, 56 + len(name), 3, 56, len(name)))
                self.assertEqual(bytes(out[64:size]), name.encode())
        for name, marker in [('x', None), ('x', 2), ('/start', 1), ('x!', 1), ('q' * 193, 1)]:
            with self.subTest(identity=name, marker=marker):
                self.assertGreaterEqual(self.query(name, marker)[0], 0xfffffffc)

    def test_only_a_correlated_empty_context_query_can_charge_unknown_identity(self):
        checked = assemble_program((Path(__file__).resolve().parents[1] / RUN_INPUT_SOURCE).read_bytes())
        names = {fn['name']: fn for fn in checked.as_dict()['functions']}
        functions = {node.name: names[f'f{i}'] for i, node in enumerate(ast.parse(intake_program(claim=True, run_input=True)).body)}
        constants = policy_constants()
        for request, epoch, found, size, refusal, bad in [
                (5, 9, 0, 0, 32, False), (5, 9, 1, 0, 0, False), (5, 9, 0, 8, 0, False),
                (4, 9, 0, 0, 0, True), (5, 8, 0, 0, 0, True)]:
            with self.subTest(request=request, epoch=epoch, found=found, size=size):
                vm = _Machine(checked, 1_000_000, 16 << 20, None, 128)
                private = _Owner(-3, bytearray(4096))
                work = _View(private, True)
                for offset, value in ((3360, 1), (constants['STORE_PURPOSE'], 51),
                                      (constants['STORE_REQUEST'], 4), (constants['STORE_STEP'], 1),
                                      (constants['STORE_EPOCH'], 9)):
                    struct.pack_into('<Q', private.data, offset, value)
                vm.invoke(functions['keep'], [work, constants['STORE_RESULT'], 41, size + 48])
                event = bytearray(112)
                struct.pack_into('<Q', event, 40, size + 48)
                struct.pack_into('<6Q', event, 64, 5, size, found, 0, request, epoch)
                result, = vm.invoke(functions['settle_transaction'], [
                    _View(_Owner(-1, event), False), _View(_Owner(-2, bytearray(2048)), True), work])
                self.assertEqual(result == constants['BAD'], bad)
                self.assertEqual(struct.unpack_from('<Q', private.data, 3224)[0], refusal)

    def test_public_id_transport_only_selects_the_existing_context_query(self):
        checked = assemble_program(STORE_TRANSPORT_SOURCE.read_bytes())
        names = {fn['name']: fn for fn in checked.as_dict()['functions']}
        index = next(i for i, node in enumerate(ast.parse(store_transport_program()).body) if node.name == 'request_unique')
        for plan, mode, identity, accepted in [
                (38, 0, 'x', True), (38, 1, 'x', False), (38, 2, 'x', False),
                (38, 0, '.invalid', False), (4, 0, 'x', False), (4, 0, 'ctx-' + 'a'*32, True)]:
            with self.subTest(plan=plan, mode=mode, identity=identity):
                width = len(identity)
                query = struct.pack('<8s6Q', b'HIAQPA01', 1, 1, 56+width, 3, 56, width) + identity.encode()
                raw = struct.pack('<8s5Q', b'HIASTUP1', 1, plan, mode, 9, len(query)) + query
                output = _Owner(-2, bytearray(4096))
                work = _Owner(-3, bytearray(2304))
                vm = _Machine(checked, 1_000_000, 16 << 20, None, 128)
                size, = vm.invoke(names[f'f{index}'], [
                    _View(_Owner(-1, bytearray(raw)), False), _View(output, True), _View(work, True)])
                self.assertEqual(size > 0, accepted)
                if accepted:
                    self.assertEqual(struct.unpack_from('<Q', work.data, 16)[0], 4)
                    self.assertEqual(struct.unpack_from('<Q', output.data, 64)[0], 7)
                    self.assertEqual(output.data[80:size], query)
