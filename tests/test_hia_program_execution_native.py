"""Full HIA VM controls against the retained independent Python interpreter.

Development runs use a named retained compiler and never claim current cold
qualification. A cold fixture admits the complete current source inventory.
"""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import HIAProgramRejected, verify_program, verify_core
from hepta import hia_program_runtime as runtime
from hepta.hia_program_execution_native import (
    ABI, BASE, ExternalBuffer, ExecutionContext, NativeProgramExecution, SOURCE,
    SCHEMA, SELECTOR, installed_program_execution, _pointer)
from tests.test_hia_program import arithmetic, resource_program, joined_loan_program, p,b,c,f,i,m,ret,jump,branch

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_PROGRAM_EXECUTION_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_PROGRAM_EXECUTION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_PROGRAM_EXECUTION_EVIDENCE'
OWNED_FILES = ('tools/generate_hia_program_execution.py', 'tools/hia_program_execution_resources.py',
    'tools/hia_program_execution_scalars.py', 'examples/hia_bootstrap/program_execution.hiaasm',
    'hepta/hia_program_execution_native.py', 'hepta/hia_program_runtime.py', 'hepta/hia_agent_buffers.py',
    'tests/test_hia_program_execution_native.py', 'docs/HIA_PROGRAM_EXECUTION_NATIVE.md')
# Exact original class source, independent of Python ast.dump version formatting.
REFERENCE_CLASS_SHA = '5770c8a3b956923da1c53cc8de7f6755bf736a94334ec9f437d137afbf2ebc97'


def observation(action):
    try:
        return {'returned': action()}
    except Exception as exc:
        return {'error_type': type(exc).__name__, 'message': str(exc),
                'code': getattr(exc, 'code', None), 'report': getattr(exc, 'report', None)}


def select(manifest):
    return patch.dict(os.environ, {SELECTOR: str(manifest) if manifest else ''})


def constant_program(values):
    ops = [c('v' + str(index), typ, value) for index, (typ, value) in enumerate(values)]
    return m(f('constant', [], [typ for typ, _ in values], [],
        [b('entry', [], ops, ret(*['v' + str(index) for index in range(len(values))]))]))


def fallible_program():
    maker = f('make', [('n', 'usize')], ['buffer', 'bool'], ['alloc'],
        [b('entry', [('n', 'usize')], [i('buffer.try_new', ['n'], [('o', 'buffer'), ('ok', 'bool')])], ret('o', 'ok'))])
    main = f('use', [('n', 'usize')], ['usize', 'bool'], ['alloc'],
        [b('entry', [('n', 'usize')], [
            i('call', ['n'], [('made', 'buffer'), ('ok', 'bool')], function='make'),
            i('buffer.len', ['made'], [('length', 'usize')]), i('owner.drop', ['made'])
        ], ret('length', 'ok'))])
    return m(maker, main)


def alternating_frames_program():
    params=[('a'+str(n),'u64') for n in range(300)]
    large=f('large',params,[],[],[b('entry',params,[],ret())])
    small=f('small',[('a','u64')],[],[],[b('entry',[('a','u64')],[],ret())])
    main=f('alternate',[('n','u32'),('v','u64')],[],[],[
        b('entry',[('n','u32'),('v','u64')],[],jump('loop','n','v')),
        b('loop',[('left','u32'),('value','u64')],[c('zero','u32',0),
          i('compare.eq',['left','zero'],[('done','bool')])],branch('done',('exit',),('body','left','value'))),
        b('body',[('n1','u32'),('v1','u64')],[i('call',['v1']*300,function='large'),
          i('call',['v1'],function='small'),c('one','u32',1),
          i('int.sub.wrap',['n1','one'],[('next','u32')])],jump('loop','next','v1')),
        b('exit',[],[],ret())])
    return m(large,small,main)


def late_container(document):
    """Original public object protocol whose final JSON sees the real dict.

    This is a retained normalization behavior, not an adapter bypass. Each
    invocation creates fresh comparison state; re-verifying its canonical
    bytes would follow the different, bounded submitted-text path.
    """
    class Meta(type):
        __hash__ = type.__hash__
        def __eq__(cls, other):
            if other is list:
                cls.seen += 1
                return cls.seen > 1
            return False
    class Foreign(dict, metaclass=Meta):
        seen = 0
        def __len__(self):
            return 0
        def __iter__(self):
            return iter(())
    return Foreign(document)


class ProgramExecutionSourceTests(unittest.TestCase):
    def test_development_cannot_override_cold_before_reading_inputs(self):
        with patch.dict(os.environ, {COLD_REPORT:'/unread-cold',DEVELOPMENT_COMPILER:'/unread-compiler'}),patch.object(
                Path,'read_bytes',side_effect=AssertionError('input read before fixture conflict refusal')):
            with self.assertRaisesRegex(RuntimeError,'mutually exclusive'):
                ProgramExecutionNativeTests.setUpClass()

    def test_checked_source_matches_authoring_and_original_compiler_limits(self):
        from tools.generate_hia_program_execution import document
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        value = document()
        checked = verify_core(value)
        self.assertEqual(render_assembly(value).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(value['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in value['functions'] for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in value['functions'] for block in fn['blocks']), 16)
        self.assertLessEqual(len(SOURCE.read_bytes()), 1 << 20)
        self.assertTrue(checked.sha256)

    def test_complete_opcode_roster_and_original_reference_remain(self):
        from hepta.hia_opcodes import OPCODES
        from tools.generate_hia_program_execution import OP_IDS, FIELDS, source_program
        self.assertEqual(tuple(OP_IDS), tuple(OPCODES))
        self.assertEqual(list(OP_IDS.values()), list(range(1, 51)))
        self.assertEqual(sha256(inspect.getsource(runtime._Machine).encode()).hexdigest(), REFERENCE_CLASS_SHA)
        reader = next(n for n in ast.parse(source_program()).body if n.name == 'src_validate')
        comparisons = {n.left.id: ast.unparse(n.comparators[0])
                       for n in ast.walk(reader) if isinstance(n, ast.Compare)
                       and isinstance(n.left, ast.Name) and n.left.id in {'nodes', 'children'}}
        self.assertEqual(comparisons, {'nodes':'length(s) // 16', 'children':'(size - 8) // 16'})

    def test_bridge_has_no_opcode_signature_block_or_resource_policy_dispatch(self):
        import hepta.hia_program_execution_native as bridge
        tree = ast.parse(inspect.getsource(bridge))
        self.assertNotIn('_Machine(', inspect.getsource(bridge))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else ''
                self.assertNotIn(name, {'scalar_value_valid','check_instruction','validate_execution_observation',
                                       'verify_core','integer_range','fill_bytes','move_bytes'})
        self.assertNotIn('16', inspect.getsource(bridge._scalar_row))
        self.assertIn('bit_length', inspect.getsource(bridge._scalar_row))

    def test_private_decoder_root_count_is_relocated_with_its_stack(self):
        from tools.generate_hia_program_execution import source_program
        node = next(n for n in ast.parse(source_program()).body if n.name == 'src_validate')
        addresses = []
        for item in ast.walk(node):
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == 'put':
                if isinstance(item.args[1], ast.Constant):
                    addresses.append(item.args[1].value)
        self.assertIn(4096, addresses)
        self.assertIn(4104, addresses)
        self.assertNotIn(136, addresses)


class ProgramExecutionAdapterTests(unittest.TestCase):
    def test_huge_exact_integer_representation_never_uses_decimal_conversion(self):
        from hepta.hia_program_execution_native import _scalar_row
        with patch('sys.get_int_max_str_digits', return_value=640):
            for value in (1 << 100000, -(1 << 100000), (1 << 64) - 1, -128, True, None):
                row = _scalar_row(value)
                self.assertEqual(len(row), 4)
                if type(value) is int:
                    self.assertEqual((row[1], row[2], row[3]),
                                     (int(value < 0), value.bit_length(), value & ((1 << 64) - 1)))
        self.assertEqual(_scalar_row(object()), [7, 0, 0, 0])

    def test_partial_context_allocation_failure_closes_exact_owned_arena(self):
        import hepta.hia_program_execution_native as bridge
        checked = verify_program(constant_program([]))
        original = bridge.mmap.mmap
        held = []
        def create(*args, **kwargs):
            value = original(*args, **kwargs)
            held.append(value)
            return value
        failure = KeyboardInterrupt('after arena before source storage')
        with patch.object(bridge.mmap, 'mmap', create), patch.object(bridge, 'bytearray', side_effect=failure, create=True):
            try:
                ExecutionContext(checked, 'constant', (), (100, 0, None, 1))
            except KeyboardInterrupt as exc:
                self.assertIs(exc, failure)
            else:
                self.fail('controlled allocation boundary did not raise')
        self.assertEqual(len(held), 1)
        self.assertTrue(held[0].closed)


class ProgramExecutionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:
            raise RuntimeError('cold and retained development execution fixtures are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('an explicit cold report or retained development compiler is required')
        source_names = set(OWNED_FILES)
        for folder in ('hepta', 'tools', 'tests'):
            source_names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / folder).rglob('*.py'))
        cls.source_inputs = {name: (ROOT / name).read_bytes() for name in sorted(source_names)}
        cls.cold_bytes = None
        if cold:
            from tools.build_hia_json_preflight import build, admit_cold_build
            report = Path(cold)
            cls.cold_bytes = report.read_bytes()
            value = json.loads(cls.cold_bytes)
            nested = json.loads(Path(value['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.cold_sources = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            cls.folder = Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-execution-cold-')) / 'candidate'
            cls.manifest_path = build(cls.folder, cls.compiler, report, candidate='program-execution')
            cls.scope = 'CURRENT_SOURCE_COLD_BUILT_COMPONENT'
        else:
            cls.compiler = Path(development)
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.folder = Path(os.environ.get(EVIDENCE) or tempfile.mkdtemp(prefix='hia-execution-development-')) / 'candidate'
            cls.folder.mkdir(parents=True)
            image, receipt = compile_stage(cls.folder, 'program-execution', cls.compiler, SOURCE.read_bytes())
            manifest = {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler_bytes).hexdigest()}
            cls.manifest_path = cls.folder / 'manifest.json'
            cls.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
            (cls.folder / 'compile-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
            cls.scope = 'DEVELOPMENT_FROM_RETAINED_COMPILER'
        cls.native = installed_program_execution(str(cls.manifest_path))
        for name, data in cls.source_inputs.items():
            frozen = cls.folder / 'frozen-inputs' / name
            frozen.parent.mkdir(parents=True, exist_ok=True)
            frozen.write_bytes(data)
        cls.manifest_bytes = cls.manifest_path.read_bytes()
        cls.image_path = cls.manifest_path.parent / json.loads(cls.manifest_bytes)['image_path']
        cls.image_bytes = cls.image_path.read_bytes()
        cls.entries = cls.differentials = cls.vm_entries = 0
        entry = cls.native._entry
        def counted(*args):
            cls.entries += 1
            return entry(*args)
        cls.native._entry = counted
        (cls.folder / 'source-before.json').write_text(json.dumps(
            {name:sha256(value).hexdigest() for name,value in cls.source_inputs.items()}, indent=2, sort_keys=True)+'\n')

    @classmethod
    def tearDownClass(cls):
        unchanged = all((ROOT / name).read_bytes() == data for name,data in cls.source_inputs.items())
        held_unchanged = (cls.compiler.read_bytes() == cls.compiler_bytes
            and cls.manifest_path.read_bytes() == cls.manifest_bytes and cls.image_path.read_bytes() == cls.image_bytes)
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            held_unchanged = held_unchanged and Path(os.environ[COLD_REPORT]).read_bytes() == cls.cold_bytes and current_sources() == cls.cold_sources
        (cls.folder / 'observations.json').write_text(json.dumps({'scope':cls.scope,
            'native_entries':cls.entries,'differentials':cls.differentials,'independent_vm_entries':cls.vm_entries,
            'source_unchanged':unchanged,'build_inputs_unchanged':held_unchanged},indent=2,sort_keys=True)+'\n')
        if not unchanged or not held_unchanged:
            raise AssertionError('execution fixture inputs changed')

    def compare(self, document, function, args, **limits):
        checked = verify_program(document)
        with select(None):
            expected = observation(lambda:runtime.execute_program(checked, function, args, **limits))
        with select(self.manifest_path):
            actual = observation(lambda:runtime.execute_program(checked, function, args, **limits))
        self.assertEqual(actual, expected, (function, args, limits))
        type(self).differentials += 1
        return actual

    def test_all_scalar_literals_and_dispatch_operations(self):
        from tests.test_hia_program_execution_scalars import integer_cases, compare_cases, cast_cases, boolean_select_cases, TYPES
        values = [('bool', False), ('bool', True), ('unit', None)]
        for typ in ('i8','i16','i32','i64','u8','u16','u32','u64','isize','usize'):
            lo,hi=runtime.integer_range(typ);values += [(typ,lo),(typ,0),(typ,hi)]
        self.compare(constant_program(values),'constant',[])
        self.compare(constant_program([]),'constant',[])
        cases = []
        for group in (integer_cases(),compare_cases(),cast_cases(),boolean_select_cases()):
            seen = set()
            for case in group:
                key=(case.op,case.t,case.at,case.mode)
                if key not in seen:
                    seen.add(key);cases.append(case)
        self.assertEqual({case.op for case in cases},set(range(2,28)))
        for case in cases:
            args=case.arguments()
            types=[TYPES[case.at]]*len(args)
            if case.op==27:types=['bool',TYPES[case.t],TYPES[case.t]]
            ops=[c('a'+str(n),typ,value) for n,(typ,value) in enumerate(zip(types,args))]
            attrs={'mode':'checked' if case.mode==1 else 'wrap'} if case.op==26 else {}
            ops.append(i(('',*__import__('hepta.hia_opcodes',fromlist=['OPCODES']).OPCODES)[case.op],
                ['a'+str(n) for n in range(len(args))],[('answer',TYPES[case.t])],**attrs))
            doc=m(f('scalar',[],[TYPES[case.t]],['trap'],[b('entry',[],ops,ret('answer'))]))
            self.compare(doc,'scalar',[])

    def test_resource_allocation_failure_and_every_step_prefix(self):
        for n in (0,1,17):
            for limits in ({},{'allocation_fail_at':1},{'max_heap_bytes':0}):
                self.compare(resource_program(),'owned',[n,97],**limits)
        for steps in range(1,14):
            self.compare(resource_program(),'owned',[3,31],max_steps=steps)
        for size,fail in ((0,1),(7,None),(7,1),((1<<64)-1,1),(7,1<<10000)):
            self.compare(fallible_program(),'use',[size],allocation_fail_at=fail)
        self.compare(resource_program(),'owned',[(1<<64)-1,0],max_heap_bytes=0)

    def test_all_bulk_and_swap_memory_success_and_prewrite_bounds(self):
        from tests.test_hia_bulk_memory import bulk_program
        from tests.test_hia_overlap_move import move_program,empty_program
        from tests.test_hia_offset_copy_v5 import copy_program
        from tests.test_hia_range_fill_v6 import fill_program
        for args in ([1,1,255],[16,0,7],[16,10,7],[0,0,7],[1,2,7]):
            self.compare(bulk_program(),'bulk',args)
        for dst,src,count in ((1,0,4),(0,1,4),(2,2,3),(5,5,0),(6,0,0),(0,6,0),(0,0,(1<<64)-1)):
            for probe in range(5):
                self.compare(move_program(),'move_bytes',[5,dst,src,count,probe])
                self.compare(copy_program(),'copy_offset',[5,dst,src,count,probe])
        self.compare(empty_program(),'empty',[0])
        for length,offset,count in ((0,0,0),(5,1,3),(5,5,0),(5,6,0),(5,4,2),(5,2,(1<<64)-1)):
            self.compare(fill_program(read=False),'fill_range',[length,offset,count,71,0])
        for left,right in ((0,1),(1,0),(0,0),(2,0),(0,2),((1<<64)-1,0)):
            doc=m(f('swap',[],['u8'],['alloc','read','write','trap'],[b('entry',[],[
                c('size','usize',2),i('buffer.new',['size'],[('o','buffer')]),
                i('borrow.mut',['o'],[('v','mutbuf')]),c('zero','usize',0),c('byte','u8',19),
                i('buffer.store',['v','zero','byte']),c('left','usize',left),c('right','usize',right),
                i('buffer.swap',['v','left','right']),i('buffer.load',['v','zero'],[('answer','u8')]),
                i('loan.end',['v']),i('owner.drop',['o'])],ret('answer'))]))
            doc['schema']='hepta.hia.program.v4'
            self.compare(doc,'swap',[])

    def test_closed_edges_recursion_and_root_inclusive_call_budget(self):
        from tests.test_hia_vm_call_depth import sequential_calls,recursively_nested
        for limit in (1,2,3,5,256):
            self.compare(recursively_nested(),'again',[9],max_call_depth=limit)
        for limit in (1,2,5):
            self.compare(sequential_calls(),'outer',[17],max_call_depth=limit)
        for flag in (False,True):
            self.compare(joined_loan_program(),'join',[flag])
        for code in ('user','overflow','division_by_zero','bounds','allocation'):
            self.compare(m(f('trap',[],[],['trap'],[b('entry',[],[],{'op':'trap','code':code})])),'trap',[])

    def test_forwarded_child_cfg_recursive_and_multiple_returned_loans(self):
        from tests.test_hia_returned_loans import loan_program,multiple_shared,swapped_mutable,fallible_return_program
        for mode in ('read','mut'):
            for construction in ('forward','child','cfg','recursive'):
                doc=loan_program(mode,construction)
                for limit in ({},{'max_steps':16},{'max_call_depth':2}):
                    self.compare(doc,doc['exports'][0],[2,253],**limit)
        for construction in ('forward','children','mixed'):
            self.compare(multiple_shared(construction),'shared',[91])
        self.compare(swapped_mutable(),'swapped',[])
        for fail in (None,1,2,3):
            self.compare(fallible_return_program(),'fallible_entry',[],allocation_fail_at=fail)

    def test_all_chain_operations_and_stopped_destruction(self):
        doc=json.loads((ROOT/'examples/hia_recursive_chain/core_v7.json').read_text())
        for function in ('chain_checksum','chain_cancel','chain_head_update','chain_empty_payloads','chain_recover'):
            for n in (0,1,3,19):
                for fail in (None,1,2,4):
                    self.compare(doc,function,[n],allocation_fail_at=fail)
        for function in ('chain_empty_pop','chain_empty_head'):
            self.compare(doc,function,[])
        full=self.compare(doc,'chain_cancel',[3])['returned']['steps']
        for limit in range(1,full+1):
            self.compare(doc,'chain_cancel',[3],max_steps=limit)
        from tests.test_hia_returned_chain_loans import chain_program
        for mode in ('read','mut'):
            for construction in ('forward','child','cfg'):
                value=chain_program(mode,construction)
                entry=value['exports'][0]
                self.compare(value,entry,[71])

    def test_unbounded_core_signature_return_inventory_and_arena_growth(self):
        count=4097
        names=['p'+str(n) for n in range(count)]
        params=[(name,'u64') for name in names]
        inner=f('wide',params,['u64']*count,[],[b('entry',params,[],ret(*names))])
        output=['r'+str(n) for n in range(count)]
        caller=f('call_wide',params,['u64']*count,[],[b('entry',params,[
            i('call',names,[(name,'u64') for name in output],function='wide')],ret(*output))])
        doc=m(inner,caller)
        self.compare(doc,'call_wide',list(range(count)))
        zero=m(f('zero',[],['unit']*4097,[],[b('entry',[],[c('u','unit',None)],ret(*(['u']*4097)))]))
        self.compare(zero,'zero',[])

    def test_actual_public_late_core_domain_preserves_large_return_inventory(self):
        count = 262145
        plain = m(f('late', [], ['unit'] * count, [],
            [b('entry', [], [c('u','unit',None)], {'op':'ret','values':['u'] * count})]))
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(plain)
        self.assertEqual(caught.exception.code, 'E_HIA_LIMIT')
        with select(None):
            expected = runtime.execute_program(late_container(plain), 'late', [], max_steps=10, max_heap_bytes=0)
        with select(self.manifest_path), patch.object(runtime, '_Machine', side_effect=AssertionError('host machine')):
            actual = runtime.execute_program(late_container(plain), 'late', [], max_steps=10, max_heap_bytes=0)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual['values']), count)
        self.assertTrue(all(value is None for value in actual['values']))
        self.assertEqual(actual['steps'], 3)
        type(self).differentials += 1

    def test_actual_private_decoder_rejects_counts_outside_packet_extents(self):
        checked = verify_program(constant_program([]))
        for offset, word in ((8, (1 << 64) - 1), (16, (1 << 63)), (16, 7)):
            context = ExecutionContext(checked, 'constant', (), (10, 0, None, 1))
            try:
                struct.pack_into('<Q', context.input, offset, word)
                context.source_wire = bytes(context.input)
                with self.assertRaisesRegex(HIAProgramRejected, 'native ABI refusal'):
                    self.native.step(context)
                self.assertTrue(context.closed)
                self.assertIsNone(context.workspace)
            finally:
                context.close()

    def test_exact_input_error_order_and_arbitrary_precision_failure_index(self):
        for args in ([],[1],[1,2,3],[True,0],[1.0,0],['1',0],[object(),0],[1<<10000,0],[-(1<<10000),0]):
            self.compare(arithmetic(),'calculate',args)
        for typ in ('i8','u8','i64','u64'):
            lo,hi=runtime.integer_range(typ)
            for value in (lo-1,lo,hi,hi+1):
                self.compare(arithmetic(typ=typ),'calculate',[value,0])
        for fail in (1<<10000,(1<<10000)+1):
            self.compare(fallible_program(),'use',[1],allocation_fail_at=fail)

    def test_borrowed_agent_path_and_full_stopped_bytes_ledger(self):
        from hepta.hia_agent_buffers import reference_observation
        from tests.test_hia_agent_external_roots import stopped_program,CALL,EXPORTS
        for returned,steps in ((False,100),(True,5),(True,100)):
            with select(None):
                expected=reference_observation(stopped_program(returned=returned),CALL,EXPORTS,steps=steps,heap=0)
            with select(self.manifest_path),patch.object(runtime,'_Machine',side_effect=AssertionError('host runtime used')):
                actual=reference_observation(stopped_program(returned=returned),CALL,EXPORTS,steps=steps,heap=0)
            self.assertEqual(actual,expected)
            type(self).differentials+=1
        params=[('input','readbuf')]
        doc={'schema':'hepta.hia.program.v8','module':'external_empty','functions':[f('entry',params,['u32'],['read','trap'],[
            b('entry',params,[i('borrow.read',['input'],[('child','readbuf')]),c('n','usize',0),
            i('buffer.load',['child','n'],[('x','u8')]),i('loan.end',['child']),
            c('result','u32',0)],ret('result'))])]}
        call={'function':'entry','arguments':[{'bytes_hex':''}]}
        with select(None):expected=reference_observation(doc,call,EXPORTS,steps=100,heap=0)
        with select(self.manifest_path):actual=reference_observation(doc,call,EXPORTS,steps=100,heap=0)
        self.assertEqual(actual,expected)
        type(self).differentials+=1

    def test_selected_public_path_never_invokes_host_semantic_runtime(self):
        with select(self.manifest_path),patch.object(runtime,'_Machine',side_effect=AssertionError('host machine')):
            with patch.object(runtime,'_wrap',side_effect=AssertionError('host wrap')),patch.object(runtime,'_checked',side_effect=AssertionError('host checked')):
                self.assertEqual(runtime.execute_program(resource_program(),'owned',[3,91])['result'],91)
                self.assertEqual(runtime.execute_program(arithmetic('int.mul.wrap','i8'),'calculate',[127,127])['result'],1)
        with select('/missing/exact-selected-native-image'):
            with self.assertRaisesRegex(HIAProgramRejected,'selected native execution refused'):
                runtime.execute_program(arithmetic(),'calculate',[1,2])

    def test_actual_allocator_failure_is_requested_once_with_native_optional_policy(self):
        import hepta.hia_program_execution_native as bridge
        original=bytearray
        attempts=[]
        def allocate(value=0,*args,**kwargs):
            if type(value) is int and value > 0:
                attempts.append(value)
                raise MemoryError('controlled raw allocator failure')
            return original(value,*args,**kwargs)
        with patch.object(bridge,'bytearray',allocate,create=True),select(self.manifest_path):
            result=runtime.execute_program(fallible_program(),'use',[17])
        self.assertEqual(result['values'],[0,False])
        self.assertEqual(attempts,[17])
        self.assertEqual((result['resources']['allocation_attempts'],result['resources']['owners_created'],
                          result['resources']['owners_dropped']),(1,1,1))

    def test_exact_issued_storage_frames_replay_refusal_and_interruption_cleanup(self):
        checked=verify_program(arithmetic())
        context=ExecutionContext(checked,'calculate',(1,2),(100,0,None,3))
        first=self.native.step(context)
        self.assertEqual(first.request,1)
        from dataclasses import replace
        forged=replace(first,words=(99,0,0,0))
        with self.assertRaisesRegex(HIAProgramRejected,'issued frame'):
            context.service(forged)
        self.assertTrue(context.closed)
        self.assertIsNone(context.workspace)
        context=ExecutionContext(checked,'calculate',(1,2),(100,0,None,3))
        first=self.native.step(context)
        original=context._service
        fault=KeyboardInterrupt('after actual native-requested callback')
        def interrupted(frame):
            original(frame)
            raise fault
        context._service=interrupted
        try:
            context.service(first)
        except KeyboardInterrupt as exc:
            self.assertIs(exc,fault)
        else:self.fail('callback interruption absent')
        self.assertTrue(context.closed)
        self.assertIsNone(context.workspace)
        self.assertEqual(context.pool,{})
        with self.assertRaises(HIAProgramRejected):context.service(first)
        with self.assertRaises(HIAProgramRejected):self.native.step(context)

    def test_independent_reference_vm_full_initial_and_argument_frames(self):
        from tools.generate_hia_program_execution import document
        kernel=verify_core(document())
        checked=verify_program(arithmetic())
        context=ExecutionContext(checked,'calculate',(7,-2),(100,0,None,8))
        try:
            for stage in range(2):
                before=bytes(context.workspace)
                source=bytes(context.input)
                output=bytes(context.output)
                frame=self.native.step(context)
                actual=bytes(context.workspace)
                roots=[runtime._Owner(-1,bytearray(source)),runtime._Owner(-2,bytearray(output)),
                       runtime._Owner(-3,bytearray(before))]
                machine=runtime._Machine(kernel,10_000_000,0,None,256)
                result=machine.invoke(machine.functions['f0'],[runtime._View(root,n!=0) for n,root in enumerate(roots)])
                type(self).vm_entries+=1
                self.assertEqual(result,[frame.request])
                self.assertEqual(bytes(roots[0].data),source)
                self.assertEqual(bytes(roots[1].data),bytes(context.output))
                self.assertEqual(bytes(roots[2].data),actual)
                if frame.request:context.service(frame)
        finally:context.close()

    def test_repeated_alternating_frames_reuse_private_storage(self):
        checked=verify_program(alternating_frames_program())
        extents=[]
        for loops in (10,100,512):
            context=ExecutionContext(checked,'alternate',(loops,7),(100000,0,None,3))
            try:
                while True:
                    frame=self.native.step(context)
                    if frame.request:context.service(frame)
                    else:
                        actual=context.accept(frame)
                        extents.append(len(context.workspace))
                        break
                with select(None):expected=runtime.execute_program(checked,'alternate',[loops,7],max_steps=100000,max_heap_bytes=0,max_call_depth=3)
                self.assertEqual(actual,expected)
                type(self).differentials+=1
            finally:context.close()
        self.assertEqual(extents,[extents[0]]*len(extents))

    def test_near_public_node_bound_argument_transport_has_no_width_reduction(self):
        # Each formal occurs in both the function and entry declarations:
        # 43,680*6 = 262,080 value nodes, below the unchanged 262,144 cap.
        count=43680
        params=[('u'+str(n),'unit') for n in range(count)]
        doc=m(f('near_limit',params,['unit'],[],[b('entry',params,[],ret('u0'))]))
        result=self.compare(doc,'near_limit',[None]*count)
        self.assertEqual(result['returned']['values'],[None])

    def test_actual_native_argument_capture_and_image_remain_pinned(self):
        from tests.test_hia_runtime_argument_snapshot import _identity,_owned_size
        subjects=[(_identity(),'identity',[7],[300],{}),(_identity(),'identity',[7],[],{}),
            (_identity(),'identity',[300],[7],{}),(_identity(),'identity',[7],[8],{}),
            (_owned_size(),'owned_size',[5],[0],{'max_heap_bytes':5}),
            (_owned_size(),'owned_size',[5],[0],{'max_heap_bytes':4}),
            (_owned_size(),'owned_size',[5],[0],{'allocation_fail_at':1})]
        original=ExecutionContext._service
        for document,function,arguments,replacement,limits in subjects:
            with select(None):expected=observation(lambda:runtime.execute_program(document,function,list(arguments),**limits))
            invoked=[]
            def mutate(context,frame):
                if frame.request==1:
                    invoked.append(frame.sequence)
                    arguments[:]=replacement
                    os.environ[SELECTOR]='/changed-after-actual-image-admission'
                return original(context,frame)
            with select(self.manifest_path),patch.object(ExecutionContext,'_service',mutate):
                actual=observation(lambda:runtime.execute_program(document,function,arguments,**limits))
            self.assertEqual(actual,expected)
            self.assertEqual(len(invoked),1)
            self.assertEqual(arguments,replacement)
            type(self).differentials+=1

    def test_actual_arena_swap_interruptions_retain_and_release_both_maps(self):
        params=[('p'+str(n),'u64') for n in range(4097)]
        checked=verify_program(m(f('wide',params,['u64'],[],[b('entry',params,[],ret('p0'))])))
        lines,start=inspect.getsourcelines(ExecutionContext._service)
        anchors=('self._created_arena = None','self._previous_arena.close()','self._previous_arena = None')
        for anchor in anchors:
            context=ExecutionContext(checked,'wide',tuple(range(4097)),(100,0,None,3))
            frame=self.native.step(context)
            self.assertEqual(frame.request,2)
            old=context.workspace
            held=[]
            fault=KeyboardInterrupt('actual arena swap '+anchor)
            target=next(start+n for n,line in enumerate(lines) if line.strip()==anchor)
            def trace(fr,event,arg):
                if fr.f_code is ExecutionContext._service.__code__ and event=='line' and fr.f_lineno==target:
                    held.extend([context.workspace,context._created_arena,context._previous_arena])
                    sys.settrace(None)
                    raise fault
                return trace
            try:
                sys.settrace(trace)
                context.service(frame)
            except KeyboardInterrupt as exc:
                self.assertIs(exc,fault)
                self.assertIsNotNone(exc.__traceback__)
            else:self.fail('swap interruption was not observed')
            finally:sys.settrace(None)
            self.assertTrue(context.closed)
            self.assertTrue(old.closed)
            self.assertTrue(all(value is None or value.closed for value in held))
            self.assertIsNone(context.workspace)
            self.assertIsNone(context._created_arena)
            self.assertIsNone(context._previous_arena)
            with self.assertRaises(HIAProgramRejected):context.service(frame)

    def test_actual_release_export_failure_revokes_and_cleanup_can_retry(self):
        checked=verify_program(resource_program())
        context=ExecutionContext(checked,'owned',(1,91),(100,10,None,8))
        while True:
            frame=self.native.step(context)
            if frame.request==4:break
            self.assertTrue(frame.request)
            context.service(frame)
        data=context.pool[frame.words[0]][0]
        exported=memoryview(data)
        old=context.workspace
        try:
            try:
                context.service(frame)
            except BufferError as failure:
                self.assertIsNotNone(failure.__traceback__)
            else:self.fail('actual exported-storage release did not fail')
            self.assertTrue(context.closed)
            self.assertTrue(old.closed)
            self.assertIsNone(context.workspace)
            self.assertTrue(context.pool)
            self.assertIsInstance(context.cleanup_error,BufferError)
            with self.assertRaises(HIAProgramRejected):context.service(frame)
        finally:
            exported.release()
            context.close()
        self.assertEqual(context.pool,{})
        self.assertEqual(data,bytearray())
        self.assertIsNone(context.cleanup_error)

    def test_actual_terminal_frame_canonical_words_are_checked_before_use(self):
        cases=[('u8',7,96,1),('u8',7,384,2),('u8',7,544,(1<<64)-1),
               ('u8',7,552,(1<<64)-1),('u8',7,'value',256),
               ('i8',-1,'value',(1<<64)-1),('bool',True,'value',2),('unit',None,'value',1)]
        for typ,value,field,word in cases:
            context=ExecutionContext(verify_program(constant_program([(typ,value)])),
                'constant',(),(100,0,None,3))
            actual_entry=self.native._entry
            def altered(*args):
                result=actual_entry(*args)
                workspace=args[4]
                status=ctypes.c_uint64.from_address(workspace+88).value
                if status==1:
                    offset=field
                    if field=='value':
                        offset=ctypes.c_uint64.from_address(workspace+544).value+8
                    ctypes.c_uint64.from_address(workspace+offset).value=word
                return result
            try:
                with patch.object(self.native,'_entry',altered):
                    with self.assertRaises(HIAProgramRejected):
                        while True:
                            frame=self.native.step(context)
                            if frame.request:context.service(frame)
                            else:context.accept(frame)
                self.assertTrue(context.closed)
                self.assertIsNone(context.workspace)
            finally:context.close()

    def test_actual_issued_frame_rejects_rich_equality_metaclass_word(self):
        called=[]
        class Meta(type):
            def __eq__(cls,other):
                called.append('metaclass equality')
                return other is int or other is cls
        class Fake(metaclass=Meta):
            def __init__(self,value):self.value=value
            def __eq__(self,other):
                called.append('value equality')
                return other==self.value
            def __ne__(self,other):return not self==other
            def __index__(self):
                called.append('index')
                return self.value
        context=ExecutionContext(verify_program(arithmetic()),'calculate',(1,2),(100,0,None,3))
        frame=self.native.step(context)
        self.assertEqual(frame.request,1)
        object.__setattr__(frame,'sequence',Fake(frame.sequence))
        with self.assertRaisesRegex(HIAProgramRejected,'invalid representation'):
            context.service(frame)
        self.assertEqual(called,[])
        self.assertEqual(context.executed,0)
        self.assertTrue(context.closed)
        self.assertIsNone(context.workspace)


if __name__=='__main__':
    unittest.main()

