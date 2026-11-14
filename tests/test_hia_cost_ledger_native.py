"""Frozen ledger semantics, independent VM and real selected installation."""
from __future__ import annotations
import ast
import builtins
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_cost_ledger_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tools import generate_hia_cost_ledger as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cost_ledger_b569c210.py.txt'
FIXTURE_SHA = 'c83b0ef706ee505735f87b43e07e206853625e0f8f13b7c3d4c5b65405620049'
COLD = 'HEPTA_HIA_COST_LEDGER_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_COST_LEDGER_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_COST_LEDGER_EVIDENCE'


def frozen():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('original ledger fixture changed')
    namespace = {'decode_data': api.decode_data}
    exec(compile(raw, str(FIXTURE), 'exec'), namespace)
    return namespace['FrozenCostLedger']._cost_ledger


def observe(call):
    try:
        return 'returned', call()
    except Exception as error:
        return 'raised', type(error).__name__, str(error)


def vm(program, raw, size, state=b''):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate((raw, b'\xa5' * size, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'], [_View(owner, index != 0)
        for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('VM changed immutable input')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def protocol():
    # Frozen original order, not selected from an image's next-port result:
    # two rows, scoped then unscoped; two unknown external fields.
    return [(1, 2), (2, 0), (3, 0), (3, 0), (4, 0), (5, 0), (6, 0),
            (7, 2), (8, 0), (8, 0), (9, 0), (10, 0), (11, 1), (12, 0),
            (13, 0), (11, 0), (14, 0), (14, 1), (12, 0), (13, 0), (15, 0)]


def protocol_witness(program, actual=None, failure=None):
    state = bytes(native.STATE_BYTES)
    port, sequence, count = 0, 0, 0
    def call(event, observation=0):
        nonlocal state, port, sequence, count
        raw = struct.pack('<10Q', native.REQUEST_MAGIC, event, sequence, port, observation, 0, 17, 23, 0, 0)
        expected = vm(program, raw, 80, state)
        if actual is not None and actual(raw) != expected:
            raise AssertionError('native continuation differs from independent VM')
        code, result, state = expected
        if code != 80:
            raise AssertionError('VM refused original continuation')
        fields = struct.unpack('<10Q', result)
        port, sequence = fields[2:4]
        count += 1
        return fields
    call(0)
    for expected, observation in protocol():
        if port != expected:
            raise AssertionError(('wrong next foreign operation', port, expected))
        call(1)
        answer = call(3 if expected == failure else 2, 0 if expected == failure else observation)
        if expected == failure:
            if answer[4] != 5:
                raise AssertionError('foreign error not propagated')
            return count
    if answer[4] != 4:
        raise AssertionError('ledger did not finish')
    return count


class CostLedgerSourceTests(unittest.TestCase):
    def test_source_and_frozen_original_body_are_exact_with_existing_bounds(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for fn in document['functions'] for b in fn['blocks']), 8192)
        self.assertLessEqual(max(len(b['params']) for fn in document['functions'] for b in fn['blocks']), 16)
        old = ast.parse(FIXTURE.read_bytes()).body[0].body[0]
        cls = next(n for n in ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes()).body
                   if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        current = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_cost_ledger_reference')
        current.name = old.name
        self.assertEqual(ast.dump(current), ast.dump(old))
        frozen()

    def test_independent_VM_precedes_native_construction(self):
        program = assemble_program(native.SOURCE.read_bytes())
        self.assertEqual(protocol_witness(program), 43)
        for failure in (1, 3, 4, 6, 8, 11, 12, 13, 14, 15):
            self.assertGreater(protocol_witness(program, failure=failure), 1)
        for left, right in ((0, 0), (127, 1), (-128, -1), (2**65, -2**65 + 9)):
            a, b = native.integer_bytes(left), native.integer_bytes(right)
            code, output, state = vm(program, native.binary_packet(10, a, b), max(len(a), len(b)) + 17)
            self.assertEqual((code, state), (16, b''))
            size = struct.unpack_from('<Q', output, 8)[0]
            self.assertEqual(int.from_bytes(output[16:16+size], 'little', signed=True), left + right)

    def test_unselected_route_remains_lazy_and_unqualified_build_refuses(self):
        original_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.endswith('hia_cost_ledger_native'):
                raise AssertionError('unselected ledger imported optional native owner')
            return original_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            service = api.HIAAgentService(directory)
            try:
                policy = service.store.json({'external_costs': {}, 'external_costs_complete': False,
                    'expected_invocations': '0'}, 'cost-policy')
                context = {'ref': {'id': 'ctx'}, 'budget': {'cost_policy': policy}}
                with patch('builtins.__import__', guarded):
                    self.assertEqual(service._cost_ledger(context, 1, 2), frozen()(service, context, 1, 2))
            finally:
                service.close()
        from tools.build_hia_cost_ledger import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'compiler').write_bytes(b'not a compiler'); (root / 'cold').write_text('{}')
            with self.assertRaises(ValueError):
                build(root / 'absent', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'absent').exists())


class CostLedgerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_cost_ledger import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-cost-ledger-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute(); cls.root.mkdir(mode=0o700, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw, cls.sources = compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_cost_ledger(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        stable = cls.compiler.read_bytes() == cls.compiler_raw and current_sources() == cls.sources
        record = {'schema': 'hepta.hia.cost-ledger-test-custody.v1',
            'manifest': str(cls.manifest), 'matching_cold_report': cls.cold,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'compiler_unchanged': cls.compiler.read_bytes() == cls.compiler_raw,
            'source_manifest_before': cls.sources, 'source_manifest_after': current_sources(),
            'source_and_compiler_unchanged': stable, 'test_result_owned_by_outer_runner': True,
            'foreign_sqlite_json_int_str_and_objects_hosted': True, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None: cls.temporary.cleanup()
        if not stable: raise AssertionError('cost-ledger inputs changed during native tests')

    def setUp(self):
        self.case = self.root / self._testMethodName; self.case.mkdir()
        self.service = api.HIAAgentService(self.case / 'state')
        self.addCleanup(self.service.close)
        self.policy = {'external_costs': {'model_tokens': 0, 'model_wall_ns': '37', 'discovery_wall_ns': None},
                       'external_costs_complete': False, 'expected_invocations': '9'}
        self.context = {'ref': {'id': 'ctx'}, 'budget': {'cost_policy': self.service.store.json(self.policy, 'cost-policy')}}

    def row(self, context, cost, details='{}', *, status='completed'):
        self.service.store.db.execute('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES(?,?,?,?,?,?)',
            (context, 'tool', 'request', cost, status, details))

    def compare(self, wall=19, native_wall=7):
        started = time.monotonic_ns()
        expected = observe(lambda: frozen()(self.service, self.context, wall, native_wall))
        reference_ns = time.monotonic_ns() - started
        started = time.monotonic_ns()
        actual = observe(lambda: native.CostLedgerFrame(self.image, self.service, self.context, wall, native_wall).finish())
        self.last_times = {'reference_ns': reference_ns, 'native_ns': time.monotonic_ns() - started}
        self.assertEqual(actual, expected)
        return actual

    def test_native_protocol_and_signed_bytes_match_independent_VM(self):
        for failure in (None, 3, 12):
            state = ctypes.create_string_buffer(128)
            def actual(raw):
                source = ctypes.create_string_buffer(raw, len(raw)); output = ctypes.create_string_buffer(b'\xa5' * 96, 96)
                code = self.image._entry(source, len(raw), output, 80, state, 128)
                self.assertEqual(source.raw, raw); self.assertEqual(output.raw[80:], b'\xa5' * 16)
                return code, output.raw[:80], state.raw
            protocol_witness(self.program, actual, failure)
        for a, b in ((0, 0), (255, 1), (-256, -1), (-17, 100), (2**129, -2**129 + 11)):
            left, right = native.integer_bytes(a), native.integer_bytes(b)
            code, result, _ = vm(self.program, native.binary_packet(10, left, right), max(len(left), len(right)) + 17)
            size = struct.unpack_from('<Q', result, 8)[0]
            self.assertEqual(code, 16); self.assertEqual(self.image.add(left, right), result[16:16+size])
        for a, b in (('ctx', 'ctx'), ('ctx', None), (None, None), ('é', b'\xc3\xa9'), ('12', 12)):
            left, right = native.identity_bytes(a), native.identity_bytes(b)
            code, result, _ = vm(self.program, native.binary_packet(11, left, right), 16)
            self.assertEqual((code, self.image.equal(a, b)), (16, struct.unpack_from('<Q', result, 8)[0]))
            self.assertEqual(self.image.equal(a, b), int(a == b))

    def test_real_SQL_projection_unknown_external_and_two_sums(self):
        self.row('other', 'not an integer', '{bad')
        for context, cost in ((None, '-11'), ('ctx', '+17'), ('ctx', '0'), (None, '19')):
            self.row(context, cost, '{"nested":[1,true,null]}', status='rejected')
        _, result = self.compare()
        self.assertEqual([row['sequence'] for row in result['entries']], [2, 3, 4, 5])
        self.assertEqual(result['context_tool_wall_ns_before_evaluation'], '17')
        self.assertEqual(result['unattributed_discovery_artifact_read_wall_ns'], '8')
        self.assertEqual(result['external_costs'], dict.fromkeys(self.policy['external_costs']))
        self.assertIs(result['context'], self.context['ref'])
        for complete in (True, False):
            self.policy['external_costs_complete'] = complete
            self.context['budget']['cost_policy'] = self.service.store.json(self.policy, 'cost-policy')
            self.compare()

    def test_exact_10001_query_cut_does_not_decode_or_sum_omitted_row(self):
        self.service.store.db.executemany('INSERT INTO costs(context_id,tool,request_id,wall_ns,status,details) VALUES(?,?,?,?,?,?)',
            ((None if i % 2 else 'ctx', 'tool', str(i), '-1' if i % 2 else '2', 'failed', '{}') for i in range(10000)))
        self.row('ctx', 'not an integer', '{bad')
        _, result = self.compare()
        self.assertTrue(result['entries_truncated']); self.assertEqual(len(result['entries']), 10000)
        timings = [{'queried_rows': 10001, 'retained_rows': 10000, **self.last_times}]
        self.assertEqual(result['context_tool_wall_ns_before_evaluation'], '10000')
        self.assertEqual(result['unattributed_discovery_artifact_read_wall_ns'], '-5000')
        self.service.store.db.execute('DELETE FROM costs WHERE sequence=10001')
        self.assertFalse(self.compare()[1]['entries_truncated'])
        timings.append({'queried_rows': 10000, 'retained_rows': 10000, **self.last_times})
        (self.case / 'max-rows-timing.json').write_text(json.dumps({
            'schema': 'hepta.hia.cost-ledger-observed-max-rows-timing.v1',
            'observations': timings, 'original_budgets_changed': False,
            'performance_qualification_claimed': False}, indent=2, sort_keys=True) + '\n')

    def test_original_decode_policy_and_selected_int_first_refusal_order(self):
        self.row(None, 'bad-unscoped')
        self.row('ctx', 'bad-scoped')
        self.assertIn('bad-scoped', str(self.compare()))
        self.service.store.db.execute("UPDATE costs SET wall_ns='7' WHERE context_id='ctx'")
        self.assertIn('bad-unscoped', str(self.compare()))
        self.service.store.db.execute("UPDATE costs SET details='{bad' WHERE sequence=2")
        expected = self.compare(); self.assertEqual(expected[1], 'ValueError')
        self.assertNotIn('bad-unscoped', expected[2])
        self.service.store.db.execute("UPDATE costs SET details='{}'")
        self.context['budget']['cost_policy'] = {'id': 'missing'}
        self.assertEqual(self.compare()[1], 'AgentRejected')

    def test_arbitrary_width_negative_unicode_and_original_conversion_limits(self):
        limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(0)
            for value in (str(2**18000), str(-2**18000 + 23), '\u2003+\u0661_\u0662\u2003', b' -0007 '):
                self.row('ctx', value)
            self.row(None, str(-2**17000))
            self.assertEqual(self.compare()[1]['context_tool_wall_ns_before_evaluation'], '28')
            sys.set_int_max_str_digits(4300)
            result = self.compare()
            self.assertEqual(result[0], 'raised'); self.assertEqual(result[1], 'ValueError')
        finally:
            sys.set_int_max_str_digits(limit)

    def test_public_selection_never_uses_reference_and_rejects_changed_image(self):
        self.row('ctx', '-9')
        with patch.object(api.HIAAgentService, '_cost_ledger_reference', side_effect=AssertionError('reference entered')):
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
                self.assertEqual(self.service._cost_ledger(self.context, 3, 4)['context_tool_wall_ns_before_evaluation'], '-9')
            for value in ('', '/no/such/cost-ledger-manifest'):
                with patch.dict(os.environ, {native.SELECTOR: value}), self.assertRaises((ValueError, OSError)):
                    self.service._cost_ledger(self.context, 3, 4)
        manifest = self.case / 'manifest.json'; manifest.write_bytes(self.manifest.read_bytes())
        value = json.loads(manifest.read_bytes()); image = self.case / value['image_path']
        image.write_bytes((self.manifest.parent / value['image_path']).read_bytes())
        held = native.installed_cost_ledger(str(manifest))
        image.write_bytes(image.read_bytes() + b'\0')
        with self.assertRaises(ValueError): native.installed_cost_ledger(str(manifest))
        self.assertEqual(held.image_sha256, value['image_sha256'])

    def test_lost_read_ACK_is_fenced_without_repeating_SQL(self):
        self.row('ctx', '7')
        statements = []; self.service.store.db.set_trace_callback(statements.append)
        frame = native.CostLedgerFrame(self.image, self.service, self.context, 3, 4)
        entry = self.image._entry
        def lost(source, size, output, capacity, state, extent):
            request = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = entry(source, size, output, capacity, state, extent)
            if request[1] == 2 and request[3] == 1:
                raise KeyboardInterrupt('lost read observation')
            return result
        with patch.object(self.image, '_entry', lost), self.assertRaises(KeyboardInterrupt): frame.finish()
        self.assertTrue(frame.fenced)
        with self.assertRaises(native.CostLedgerUnknown): frame.finish()
        self.assertEqual(len([s for s in statements if s.startswith('SELECT * FROM costs')]), 1)
        self.service.store.db.set_trace_callback(None)
        self.compare()

    def test_replayed_or_cross_thread_continuation_cannot_repeat_foreign_read(self):
        frame = native.CostLedgerFrame(self.image, self.service, self.context, 3, 4)
        outcomes = []
        def foreign(): outcomes.append(observe(frame.finish))
        thread = threading.Thread(target=foreign); thread.start(); thread.join(5)
        self.assertFalse(thread.is_alive()); self.assertEqual(outcomes[0][1], 'CostLedgerUnknown')
        # The failed foreign thread does not claim or poison its creator's new frame.
        self.assertEqual(frame.finish()['entries'], [])
        with self.assertRaises(native.CostLedgerUnknown): frame.finish()
        state = ctypes.create_string_buffer(128)
        raw = struct.pack('<10Q', native.REQUEST_MAGIC, 0, 0, 0, 0, 0, 17, 23, 0, 0)
        source = ctypes.create_string_buffer(raw,80); output = ctypes.create_string_buffer(80)
        self.assertEqual(self.image._entry(source,80,output,80,state,128),80)
        state[24] = b'\x02'
        raw = struct.pack('<10Q', native.REQUEST_MAGIC,1,1,1,0,0,17,23,0,0)
        source = ctypes.create_string_buffer(raw,80)
        self.assertEqual(self.image._entry(source,80,output,80,state,128),4294967293)

    def test_actual_installed_wheel_and_original_worker_use_pinned_ledger(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
        staging = self.case / 'source'; staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/name,target)
        environment = {key:value for key,value in os.environ.items() if key not in ('PYTHONPATH','PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        environment['PYTHONDONTWRITEBYTECODE']='1'
        def run(args, *, body=None):
            result=subprocess.run([sys.executable,'-B',*map(str,args)],cwd=self.case,env=environment,
                input=body,capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
            return result
        run(['-m','pip','wheel','--no-deps','--no-build-isolation','--no-index','--wheel-dir',self.case/'wheels',staging])
        wheel,= (self.case/'wheels').glob('*.whl'); installed=self.case/'installed'
        run(['-m','pip','install','--no-deps','--no-index','--no-compile','--target',installed,wheel])
        bundle=self.case/'bundle.json'
        bundle.write_text(json.dumps({'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
            {'selector':native.SELECTOR,'manifest_path':str(self.manifest),
             'manifest_sha256':sha256(self.manifest.read_bytes()).hexdigest()}]},sort_keys=True))
        bundle_sha=sha256(bundle.read_bytes()).hexdigest()
        case=AgentToolCase('runTest')
        try:
            workload={'schema':'hepta.hia.agent.workload.v1','cases':[{'function':'transform','arguments':[0],
                'expected':{'status':'returned','values':[7]}}],'warmup_iterations':0,'repetitions':1}
            with patch.dict(os.environ,environment,clear=True), native_helpers_scope(str(bundle),bundle_sha):
                case.setUp()
                _,_,baseline,built,receipts=case.build_pair(workload=workload)
            arguments=case.session.arguments(baseline_artifact=baseline['native_artifact'],candidate_artifact=built['native_artifact'],
                build_receipt=built['build_receipt'],verification_receipts=receipts)
            envelope={'schema':'hia-agent-worker-request-v1','tool':'hia_evaluate','arguments':arguments,
                'profile_sha256':'a'*64,'catalog_sha256':case.service.catalog_sha256}
            encoded=lambda obj:json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            envelope['request_sha256']=sha256(encoded(envelope)).hexdigest()
            case.service.close()
            script=r'''import importlib.abc,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]);del sys.argv[1]
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_cost_ledger_native as native
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
assert '/installed/' in str(native.SOURCE)
def forbidden(*a,**k):raise AssertionError('installed ledger reference')
HIAAgentService._cost_ledger_reference=forbidden
actual=native.NativeCostLedger.add
counts=[0]
def observed(self,*args):counts[0]+=1;return actual(self,*args)
native.NativeCostLedger.add=observed
status=main(sys.argv[1:])
print('LEDGER_NATIVE_ADDITIONS='+str(counts[0]),file=sys.stderr)
raise SystemExit(status)
'''
            flags=['-I','-c',script,installed,'--state-root',case.state_root,'--request-json-stdin',
                '--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',bundle_sha]
            first=run(flags,body=encoded(envelope)); second=run(flags,body=encoded(envelope))
            report=json.loads(first.stdout); replay=json.loads(second.stdout)
            self.assertEqual(report['response']['status'],'completed',report)
            self.assertEqual(replay['response'],report['response'])
            self.assertEqual(report['native_helpers_sha256'],bundle_sha)
            self.assertNotIn(b'LEDGER_NATIVE_ADDITIONS=0\n',first.stderr)
            self.assertIn(b'LEDGER_NATIVE_ADDITIONS=0\n',second.stderr)
            case.service=api.HIAAgentService(case.state_root,artifact_roots=(case.files_root,))
            ledger,_=case.service.store.get_json(report['response']['result']['full_cost_ledger'],kind='cost-ledger')
            self.assertTrue(ledger['entries']);self.assertFalse(ledger['full_search_cost_complete'])
            for name,value in (('first-report.json',report),('replay-report.json',replay)):
                (self.case/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
            (self.case/'installed-observation.json').write_text(json.dumps({'wheel':str(wheel),'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),
                'bundle_sha256':bundle_sha,'first_native_stderr':first.stderr.decode(),'replay_native_stderr':second.stderr.decode(),
                'actual_installed_source_sha256':sha256((installed/'hepta/_data/examples/hia_bootstrap/cost_ledger.hepta').read_bytes()).hexdigest(),
                'old_reference_forbidden':True,'original_worker_replay':True,'whole_native_delivery_qualified':False},indent=2,sort_keys=True)+'\n')
        finally:case.tearDown()


if __name__ == '__main__':
    unittest.main()
