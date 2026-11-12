"""Explicit native byte-ABI ownership, effect and installed-custody controls."""
from __future__ import annotations
import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from dataclasses import fields
import dis
import gc
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_native_byte_abi as api, hia_program_native as backend
from hepta import hia_machine_plan_control_native as protocol
from hepta.hia_native_byte_abi_native import ByteABIFrame, NativeByteABI, SOURCE, SCHEMA, SELECTOR
from hepta import hia_native_byte_abi_selection as selection
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_native_byte_abi_4b.py.txt'
FIXTURE_SHA = '0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6'
COLD = 'HEPTA_HIA_NATIVE_BYTE_ABI_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_NATIVE_BYTE_ABI_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_BYTE_ABI_EVIDENCE'
_BUILT = None


def reference():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('original byte ABI reference changed')
    module = types.ModuleType('hepta.byte_abi_reference')
    module.__package__ = 'hepta'
    exec(compile(raw, str(FIXTURE), 'exec'), vars(module))
    return module


def observed(call, *args):
    try:
        return ('value', call(*args))
    except BaseException as error:
        return ('error', type(error), error.args)


def _inputs():
    from tools.build_hia_native_byte_abi import DEVELOPMENT_INPUT_NAMES
    return {name: (ROOT / name).read_bytes() for name in DEVELOPMENT_INPUT_NAMES}


class _Fixture:
    @classmethod
    def setUpClass(cls):
        global _BUILT
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise ValueError('byte ABI cold and retained development compiler inputs conflict')
        if not cold and not development:
            raise unittest.SkipTest('explicit current cold report or retained development compiler required')
        current = _inputs()
        key = (cold, development, os.environ.get(EVIDENCE))
        if _BUILT is None:
            temporary = None
            if os.environ.get(EVIDENCE):
                folder = Path(os.environ[EVIDENCE]).resolve()
                folder.mkdir(parents=True, exist_ok=True)
            else:
                temporary = tempfile.TemporaryDirectory(prefix='hia-native-byte-abi-')
                folder = Path(temporary.name)
            from tools.build_hia_native_byte_abi import build, build_development
            if cold:
                cold_path = Path(cold).resolve()
                cold_raw = cold_path.read_bytes()
                outer = json.loads(cold_raw)
                nested = json.loads(Path(outer['nested_report']).read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image']).resolve()
                manifest = build(folder / 'image', compiler, cold_path)
                authority = {cold_path: cold_raw, compiler: compiler.read_bytes()}
                scope = 'MATCHING_CURRENT_SOURCE_COLD_BUILT_COMPONENT'
            else:
                compiler = Path(development).resolve()
                authority = {compiler: compiler.read_bytes()}
                manifest = build_development(folder / 'image', compiler)
                scope = 'RETAINED_COMPILER_DEVELOPMENT_COMPONENT'
            record = json.loads(manifest.read_bytes())
            image = manifest.parent / record['image_path']
            authority.update({manifest: manifest.read_bytes(), image: image.read_bytes()})
            _BUILT = (key, current, folder, manifest, authority, temporary, scope)
        if _BUILT[0] != key or _BUILT[1] != current:
            raise AssertionError('byte ABI fixture cannot reuse different source or authority')
        cls.folder = _BUILT[2] / cls.__name__
        cls.folder.mkdir()
        cls.manifest, cls.authority, cls.scope = _BUILT[3], _BUILT[4], _BUILT[6]
        cls.inputs = current
        cls.ref = reference()
        cls.native = selection.installed_native_byte_abi(cls.manifest, vars(cls.ref))

    @classmethod
    def tearDownClass(cls):
        if _inputs() != cls.inputs:
            raise AssertionError('byte ABI component sources changed during controls')
        for path, raw in cls.authority.items():
            if path.read_bytes() != raw:
                raise AssertionError('byte ABI compiler/image/manifest authority changed: ' + str(path))
        if os.environ.get(COLD):
            from tools.build_hia_json_preflight import admit_cold_build, current_sources
            cold_path = Path(os.environ[COLD]).resolve()
            compiler = next(p for p in cls.authority if p not in (cold_path, cls.manifest)
                            and p.suffix == '.bin' and p.parent != cls.manifest.parent)
            admitted = admit_cold_build(cls.authority[compiler], cls.authority[cold_path])
            if current_sources() != admitted:
                raise AssertionError('byte ABI matching-cold source closure changed')

    def new_owner(self, namespace=None):
        manifest = json.loads(self.manifest.read_bytes())
        raw = (self.manifest.parent / manifest['image_path']).read_bytes()
        return NativeByteABI(raw, manifest['image_sha256'], vars(self.ref) if namespace is None else namespace)


class NativeByteABISourceTests(unittest.TestCase):
    def test_global_nameerror_preserves_name_and_active_context(self):
        from tests.hia_native_name_resolution import assert_missing_global_port
        assert_missing_global_port(self, ByteABIFrame)

    def test_complete_original_two_bodies_and_three_closed_helpers_are_retained(self):
        ref = reference()
        original = ast.parse(FIXTURE.read_bytes())
        current = ast.parse(inspect.getsource(api))
        from tools import hia_native_byte_abi_policy as policy
        authored = ast.parse(inspect.getsource(policy))
        for name in ('normalize_exports', 'emit_wrapper'):
            before = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == name)
            after = next(n for n in current.body if isinstance(n, ast.FunctionDef) and n.name == '_reference_' + name)
            after.name = name
            ported = next(n for n in authored.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(ast.dump(before), ast.dump(after))
            self.assertEqual(ast.dump(before), ast.dump(ported))
            self.assertEqual(inspect.signature(getattr(api, name)), inspect.signature(getattr(ref, name)))
        backend_nodes = ast.parse(inspect.getsource(backend))
        for name in ('_reject', '_normalize', '_prologue'):
            before = next(n for n in backend_nodes.body if isinstance(n, ast.FunctionDef) and n.name == '_reference' + name)
            before.name = name
            after = next(n for n in authored.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(ast.dump(before), ast.dump(after))

    def test_no_runtime_authoring_or_retained_business_dependency(self):
        from hepta import hia_native_byte_abi_native, hia_native_byte_abi_selection
        for module in (hia_native_byte_abi_native, hia_native_byte_abi_selection):
            source = inspect.getsource(module)
            self.assertNotIn('_reference_', source)
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse(node.module and (node.module == 'tools' or node.module.startswith('tools.')))
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        self.assertIn('examples/hia_bootstrap/native_byte_abi.hiaasm', NATIVE_SOURCE_FILES)
        self.assertIn(SELECTOR, HELPERS)

    def test_lexical_cells_follow_actual_original_fastlocals_then_cellvars(self):
        from tools.generate_hia_native_byte_abi import program
        from tools import hia_native_byte_abi_policy
        code = compile(inspect.getsource(hia_native_byte_abi_policy), '<observed-original-lexical-layout>', 'exec')
        codes = {}
        def walk(c):
            for value in c.co_consts:
                if isinstance(value, types.CodeType):
                    codes[(value.co_firstlineno, value.co_name)] = value
                    walk(value)
        walk(code)
        for function in program().functions:
            name = '<genexpr>' if function.kind == 'generator' else function.node.name
            expected = codes[(function.node.lineno, name)]
            self.assertEqual(function.lexical_names,
                             tuple(dict.fromkeys((*expected.co_varnames, *expected.co_cellvars))))
            self.assertEqual(function.lexical_cells, expected.co_cellvars)
            self.assertEqual(function.lexical_freevars, expected.co_freevars)
            for name in expected.co_cellvars:
                self.assertIn(function.locals[name].slot, function.cell_slots)

    def test_generated_source_keeps_all_original_compiler_limits(self):
        from tools.generate_hia_native_byte_abi import document, program
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        raw = render_assembly(document()).encode()
        self.assertEqual(SOURCE.read_bytes(), raw)
        doc = assemble_program(raw).as_dict()
        blocks = [b for f in doc['functions'] for b in f['blocks']]
        self.assertLessEqual(len(raw), 1 << 20)
        self.assertLessEqual(len(raw.splitlines()), 16384)
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(b['ops']) + 1 for b in blocks), 8192)
        for fn in doc['functions']:
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(fn['params']), 16)
            names = {p['name'] for p in fn['params']}
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                names.update(p['name'] for p in block['params'])
                for op in block['ops']:
                    names.update(p['name'] for p in op['out'])
                    self.assertLessEqual(len(op.get('args', ())), 16)
            self.assertLessEqual(len(names), 2048)
        self.assertEqual(len(program().functions), 7)

    def test_claimed_CALL_arguments_are_unique_consumed_noncell_temporaries(self):
        from copy import deepcopy
        from types import SimpleNamespace
        from tools.generate_hia_native_byte_abi import program
        from tools.hia_native_byte_abi_control import _validate_call_operands, OPS
        from tools.hia_machine_plan_control import Ref
        calls = []
        for function in program().functions:
            _validate_call_operands(function)
            for instruction in function.instructions:
                if instruction['kind'] == 'effect' and instruction['opcode'] == OPS['CALL']:
                    calls.append(instruction)
                    self.assertEqual(instruction['consume'], instruction['arguments'])
                    self.assertEqual(len({r.slot for r in instruction['arguments']}),
                                     len(instruction['arguments']))
                    for ref in instruction['arguments']:
                        self.assertTrue(ref.temporary)
                        self.assertIn(ref.slot, function.temporary_slots)
                        self.assertNotIn(ref.slot, function.cell_slots)
        self.assertGreater(len(calls), 1)
        original = next(call for call in calls if len(call['arguments']) >= 2)
        for mutation in ('named', 'cell', 'duplicate', 'incomplete_consume', 'keyword'):
            with self.subTest(mutation=mutation):
                call = deepcopy(original)
                slots = {ref.slot for ref in call['arguments']}
                cells = set()
                if mutation == 'named':
                    call['arguments'][0] = Ref(call['arguments'][0].slot, False)
                    call['consume'] = list(call['arguments'])
                elif mutation == 'cell':
                    cells.add(call['arguments'][0].slot)
                elif mutation == 'duplicate':
                    call['arguments'][1] = call['arguments'][0]
                    call['consume'] = list(call['arguments'])
                elif mutation == 'incomplete_consume':
                    call['consume'].pop()
                else:
                    call['raw'][1] = 1
                counterfeit = SimpleNamespace(instructions=[call],
                    temporary_slots=slots, cell_slots=cells)
                with self.assertRaisesRegex(ValueError, 'complete temporary operands'):
                    _validate_call_operands(counterfeit)

    def test_incomplete_cold_refuses_before_any_output_mutation(self):
        from tools.build_hia_native_byte_abi import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'not-a-qualified-compiler')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaises(ValueError):
                build(root / 'absent-parent' / 'output', compiler, cold)
            self.assertFalse((root / 'absent-parent').exists())

    def test_unselected_empty_manifest_does_not_touch_the_program(self):
        class Program:
            def __getattribute__(self, name):
                raise AssertionError('empty exports touched the program: ' + name)
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertEqual(api.normalize_exports((), Program()), ())
        self.assertEqual(observed(api._reference_normalize_exports, [], object()),
                         observed(reference().normalize_exports, [], object()))


def _normalization_lifecycle(owner, selected, case, outer):
    events, refs, held = [], [], []
    def mark(label):
        active = sys.exception()
        events.append((label, None if active is None else type(active).__name__))
    error = TypeError('controlled parameter type failure')
    class Parameter(dict):
        def __getitem__(self, key):
            mark('parameter:' + key)
            if case == 'error' and key == 'type':
                raise error
            return super().__getitem__(key)
        def __del__(self): mark('parameter:del')
    class Iterator:
        def __init__(self): self.index = 0
        def __iter__(self): return self
        def __next__(self):
            if self.index >= 2: raise StopIteration
            self.index += 1
            p = Parameter(name='p' + str(self.index), type='readbuf' if self.index == 1
                          else ('invalid' if case == 'short' else 'u32'))
            refs.append(weakref.ref(p)); mark('next:' + str(self.index))
            return p
        def __del__(self): mark('iterator:del')
    class Parameters:
        def __iter__(self): mark('params:iter'); return Iterator()
    class Fn(dict):
        def __getitem__(self, key): mark('fn:' + key); return super().__getitem__(key)
        def __del__(self): mark('fn:del')
    class Document(dict):
        def __del__(self): mark('doc:del')
    class Program:
        structured_bytes = None
        def as_dict(self):
            mark('program:as_dict')
            return Document(functions=[Fn(name='f', params=Parameters(), returns=['u32'])])
        def __del__(self): mark('program:del')
    def body():
        try:
            call = owner.normalize_exports if selected else reference().normalize_exports
            value = call((('f', 12),), Program())
            events.append(('value', value))
        except BaseException as actual:
            events.append(('error', type(actual).__name__, str(actual), actual is error))
            held.append(actual)
    if outer:
        try: raise LookupError('outer')
        except LookupError: body(); mark('aftercall')
    else:
        body(); mark('aftercall')
    events.append(('alive', sum(ref() is not None for ref in refs)))
    held.clear(); error = None
    gc.collect(); mark('afterclear')
    if not any(row[0] == 'params:iter' for row in events):
        raise AssertionError('lifecycle fixture did not reach the parameter objects')
    return events


def _wrapper_lifecycle(owner, selected, case, outer):
    events, held, calls = [], [], []
    failure = TypeError('controlled code operation')
    def mark(label):
        active = sys.exception()
        events.append((label, None if active is None else type(active).__name__))
    class Result:
        def __del__(self): mark('result:del')
    class Label:
        def __init__(self, n): self.n = n
        def __del__(self): mark('label:del:' + self.n)
    class Method:
        def __init__(self, name): self.name = name
        def __call__(self, *args):
            mark('call:' + self.name); calls.append(self.name)
            if case == 'error' and self.name == 'load': raise failure
            return Result()
        def __del__(self): mark('method:del:' + self.name)
    class Code:
        data = bytearray()
        def __getattr__(self, name): mark('attr:' + name); return Method(name)
        def __del__(self): mark('code:del')
    class Emitter:
        def __init__(self): self.c = Code(); self.symbols = []; self.exports = []; self.n = 0
        def label(self, n):
            self.n += 1; mark('label:' + n)
            return Label(n + ':' + str(self.n))
        def function_symbol(self, n): mark('function_symbol:' + n); return 'internal_' + n
        def __del__(self): mark('emitter:del')
    class Function(dict):
        def __getitem__(self, key): mark('fn:' + key); return super().__getitem__(key)
        def __del__(self): mark('fn:del')
    def body():
        try:
            call = owner.emit_wrapper if selected else reference().emit_wrapper
            value = call(Emitter(), Function(name='f', params=[{'type': 'readbuf'},
                {'type': 'readbuf' if case == 'readonly' else 'mutbuf'}, {'type': 'u8'}]), 32)
            events.append(('value', value))
        except BaseException as actual:
            events.append(('error', type(actual).__name__, str(actual), actual is failure))
            held.append(actual)
    if outer:
        try: raise LookupError('outer')
        except LookupError: body(); mark('aftercall')
    else:
        body(); mark('aftercall')
    held.clear(); failure = None
    gc.collect(); mark('afterclear')
    if 'push' not in calls or (case != 'error' and 'ret' not in calls):
        raise AssertionError('wrapper lifecycle did not execute its intended path')
    return events


def _temporary_call_lifecycle(call,outer,throw):
    events=[];held=[];counts={'names':0}
    failure=TypeError('controlled function_symbol')
    def mark(label):
        active=sys.exception()
        events.append([label,None if active is None else type(active).__name__])
    class Name(str):
        def __new__(cls):
            counts['names']+=1;value=super().__new__(cls,'f');value.number=counts['names'];return value
        def __del__(self):mark('name-del:'+str(self.number))
    class Order:
        def get(self,name):
            mark('get-enter')
            if throw:raise failure
            return str(name)
        def __del__(self):mark('order-del')
    class Function:
        def __getitem__(self,key):
            if key=='params':return [{'type':'readbuf'},{'type':'u8'}]
            if key=='name':mark('name-read');return Name()
            raise KeyError(key)
    class Code:
        def __init__(self):self.data=bytearray()
        def __getattr__(self,name):
            def operation(*args):
                if name=='call':mark('code-call')
            return operation
    class Emitter:
        def __init__(self):self.c=Code();self.symbols=[];self.exports=[];self.labels=0
        def label(self,name):self.labels+=1;return name+'_'+str(self.labels)
        @property
        def function_symbol(self):mark('function_symbol-read');return Order().get
    def body():
        try:
            result=call(Emitter(),Function(),32);events.append(['returned',result])
        except BaseException as error:
            events.append(['error',type(error).__name__,str(error),error is failure]);held.append(error)
    if outer:
        try:raise LookupError('outer')
        except LookupError:body();mark('after-call')
    else:body();mark('after-call')
    held.clear();failure=None;gc.collect();mark('after-clear')
    if not any(row[0]=='get-enter' for row in events):raise AssertionError('intended function_symbol CALL not reached')
    return events


class NativeByteABINativeTests(_Fixture, unittest.TestCase):
    def _new_global_owner(self):
        record = json.loads(self.manifest.read_bytes())
        return NativeByteABI((self.manifest.parent / record['image_path']).read_bytes(),
                             record['image_sha256'], vars(api))

    def test_imported_helpers_observe_replacement_and_deletion_before_and_after_admission(self):
        from tests.hia_native_name_resolution import assert_helper_rebindings
        rows = assert_helper_rebindings(self, 'byte', self._new_global_owner)
        (self.folder / 'imported-helper-rebindings.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')

    def test_import_groups_keep_fromlist_namespace_order_and_module_retirement(self):
        from tests.hia_native_name_resolution import assert_byte_import_groups
        rows = assert_byte_import_groups(self, self._new_global_owner)
        (self.folder / 'import-group-observations.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')

    def test_held_importerror_releases_original_module_before_error_traceback(self):
        from tests.hia_native_name_resolution import assert_import_error_retirement
        rows = assert_import_error_retirement(self, 'byte', self._new_global_owner)
        (self.folder / 'import-error-retirement.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')

    def test_all_normalization_refusals_limits_and_empty_early_return(self):
        class Program:
            structured_bytes = None
            def __init__(self, count=1, returns=None): self.count, self.returns = count, returns
            def as_dict(self):
                return {'functions': [{'name': 'f' + str(i),
                    'params': [{'type': 'readbuf'} for _ in range(self.count)],
                    'returns': ['u32'] if self.returns is None else self.returns} for i in range(129)]}
        values = [(), [], (('f0', True),), (('f0', 0),), (('f0', 1 << 20),),
                  (('f0', (1 << 20) + 1),), (('f0', 2), ('f0', 2)),
                  (('missing', 1),), (('__hia_internal', 1),), (('_init', 1),),
                  tuple(('f' + str(i), 1) for i in range(128)),
                  tuple(('f' + str(i), 1) for i in range(129))]
        for value in values:
            with self.subTest(value=repr(value)[:90]):
                self.assertEqual(observed(self.ref.normalize_exports, value, Program()),
                                 observed(self.native.normalize_exports, value, Program()))
        for count in (0, 1, 8, 9):
            for returns in (['u32'], ['i32'], []):
                self.assertEqual(observed(self.ref.normalize_exports, (('f0', 1),), Program(count, returns)),
                                 observed(self.native.normalize_exports, (('f0', 1),), Program(count, returns)))
        class Untouchable:
            def __getattribute__(self, name): raise AssertionError(name)
        self.assertEqual(self.native.normalize_exports((), Untouchable()), ())

    def test_chained_comparison_truth_finalizer_keeps_original_order(self):
        def run(selected, pass_bound):
            events = []
            class Truth:
                def __bool__(self): events.append('truth'); return pass_bound
                def __del__(self): events.append('truth-del')
            class Bound:
                def __ge__(self, other): events.append(('bound-ge', other)); return Truth()
            class Program:
                structured_bytes = None
                def as_dict(self):
                    events.append('document')
                    return {'functions': [{'name': 'f', 'params': [{'type': 'readbuf'}], 'returns': ['u32']}]}
            with patch.object(self.ref, 'MAX_EXTENT', Bound()):
                result = observed(self.native.normalize_exports if selected else self.ref.normalize_exports,
                                  (('f', 2),), Program())
            return result, events
        for passed in (False, True):
            self.assertEqual(run(False, passed), run(True, passed))

    def test_normalization_generators_and_error_tracebacks_release_actual_objects(self):
        rows = []
        for case in ('normal', 'error', 'short'):
            for outer in (False, True):
                expected = _normalization_lifecycle(self.native, False, case, outer)
                actual = _normalization_lifecycle(self.native, True, case, outer)
                rows.append({'case': case, 'outer': outer, 'expected': expected, 'actual': actual})
                self.assertEqual(actual, expected)
        (self.folder / 'normalization-lifecycles.json').write_text(json.dumps(rows, indent=2) + '\n')

    def test_named_load_closure_cells_retire_after_fastlocals(self):
        rows = []
        for case in ('normal', 'readonly', 'error'):
            for outer in (False, True):
                expected = _wrapper_lifecycle(self.native, False, case, outer)
                actual = _wrapper_lifecycle(self.native, True, case, outer)
                rows.append({'case': case, 'outer': outer, 'expected': expected, 'actual': actual})
                self.assertEqual(actual, expected)
        (self.folder / 'wrapper-lifecycles.json').write_text(json.dumps(rows, indent=2) + '\n')

    def test_original_exception_instance_and_outer_context_are_delivered(self):
        for typ in (ValueError, StopIteration, KeyboardInterrupt):
            error = typ('foreign original instance')
            class Program:
                def as_dict(self): raise error
            for outer in (False, True):
                def call():
                    try:
                        self.native.normalize_exports((('f', 1),), Program())
                    except BaseException as actual:
                        self.assertIs(actual, error)
                        self.assertIsNotNone(actual.__traceback__)
                        return
                    self.fail('missing original error')
                if outer:
                    try: raise LookupError('outer')
                    except LookupError:
                        outer_error = sys.exception(); call()
                        self.assertIs(sys.exception(), outer_error)
                else:
                    call(); self.assertIsNone(sys.exception())

    def test_temporary_python_call_operands_retire_inside_the_original_CALL(self):
        owner = self.new_owner()
        for throw in (False, True):
            for outer in (False, True):
                with self.subTest(throw=throw, outer=outer):
                    expected = _temporary_call_lifecycle(reference().emit_wrapper, outer, throw)
                    actual = _temporary_call_lifecycle(owner.emit_wrapper, outer, throw)
                    self.assertEqual(actual, expected)
        (self.folder / 'temporary-call-operands.json').write_text(json.dumps({
            'python': sys.version, 'cases': 4, 'actual_original_body': True,
            'same_HIA_claim_ack': True, 'product_compared': True}, indent=2) + '\n')

    def test_closed_helpers_have_native_ownership_and_same_Code_effects(self):
        from hepta.hia_machine_x64 import Code
        for typ in ('unit', 'bool', 'u8', 'i8', 'u16', 'i16', 'u32', 'i32', 'u64', 'i64', 'usize'):
            expected, actual = Code(), Code()
            backend._reference_normalize(expected, 'rax', typ)
            with patch.object(backend, '_reference_normalize', side_effect=AssertionError('old normalize')):
                self.native.run('_normalize', actual, 'rax', typ)
            self.assertEqual(actual.finalize(), expected.finalize())
        for frame in (0, 16, 4096, 4112, 65536):
            expected, actual = Code(), Code()
            backend._reference_prologue(expected, frame)
            with patch.object(backend, '_reference_prologue', side_effect=AssertionError('old prologue')):
                self.native.run('_prologue', actual, frame)
            self.assertEqual(actual.finalize(), expected.finalize())
        self.assertEqual(observed(self.native.run, '_reject', 'original', 'E_TEST'),
                         observed(backend._reference_reject, 'original', 'E_TEST'))

    def test_complete_original_object_bytes_under_selected_public_facades(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_native_byte_abi import byte_program
        checked = verify_program(byte_program())
        exports = tuple((name, 4096) for name in ('copy_bytes', 'echo_status', 'readonly', 'mixed'))
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = backend.emit_program_machine(checked, foreign_buffer_exports=exports)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), selection.native_byte_abi_scope(), \
             patch.object(api, '_reference_normalize_exports', side_effect=AssertionError('old normalization')), \
             patch.object(api, '_reference_emit_wrapper', side_effect=AssertionError('old wrapper')):
            actual = backend.emit_program_machine(checked, foreign_buffer_exports=exports)
        for field in fields(expected):
            if field.name != 'implementation_sha256':
                self.assertEqual(getattr(actual, field.name), getattr(expected, field.name), field.name)

    def test_issued_identity_claim_ack_and_terminal_cannot_be_replayed(self):
        frame = self.native.prepare('normalize_exports', ((), object()))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        count = self.native.entries
        with self.assertRaises(RuntimeError): frame.service(protocol.Issued(issued.raw))
        self.assertEqual(self.native.entries, count)
        frame.service(issued)
        count = self.native.entries
        with self.assertRaises(RuntimeError): frame.service(issued)
        self.assertEqual(self.native.entries, count)
        status = frame.step()
        while status == 1:
            frame.service(frame.pending); status = frame.step()
        self.assertEqual(status, 0); self.assertEqual(frame.take(), ())
        with self.assertRaises(RuntimeError): frame.take()
        frame.close(); self.assertTrue(frame._retired)

    def test_native_preclaim_ack_loss_never_launches_the_foreign_effect(self):
        owner = self.new_owner()
        frame = owner.prepare('normalize_exports', ((), object()))
        self.assertEqual(frame.step(), 1)
        issued, actual_entry = frame.pending, owner._entry
        calls = []
        original = frame._effect
        def effect(): calls.append(True); return original()
        frame._effect = effect
        failure = KeyboardInterrupt('native preclaim ACK lost')
        def entry(source, size, output, outsize, workspace, worksize):
            command = struct.unpack_from('<Q', ctypes.string_at(workspace, 8))[0]
            result = actual_entry(source, size, output, outsize, workspace, worksize)
            if command == 2: raise failure
            return result
        owner._entry = entry
        with self.assertRaises(KeyboardInterrupt) as captured: frame.service(issued)
        self.assertIs(captured.exception, failure)
        self.assertTrue(frame._uncertain); self.assertEqual(calls, [])
        owner._entry = actual_entry
        for retry in (lambda: frame.service(issued), frame.step, frame.take):
            with self.assertRaises(RuntimeError): retry()
        frame.close(); self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)

    def test_actual_reply_STORE_ATTR_interruption_retains_unknown_once_only(self):
        frame = self.native.prepare('normalize_exports', ((), object()))
        self.assertEqual(frame.step(), 1)
        issued, original, calls = frame.pending, frame._effect, []
        def effect(): calls.append(True); return original()
        frame._effect = effect
        offsets = {i.offset for i in dis.get_instructions(protocol.PlanFrame.service)
                   if i.opname == 'STORE_ATTR' and i.argval == 'reply'}
        self.assertTrue(offsets)
        failure, fired = KeyboardInterrupt('actual observed result handoff lost'), []
        def trace(current, event, arg):
            if current.f_code is protocol.PlanFrame.service.__code__:
                current.f_trace_opcodes = True
                if event == 'opcode' and current.f_lasti in offsets and calls and not fired:
                    fired.append(True); raise failure
            return trace
        previous, arming = sys.gettrace(), sys._getframe()
        old_opcodes = arming.f_trace_opcodes
        actual = None
        try:
            arming.f_trace_opcodes = True; sys.settrace(trace)
            frame.service(issued)
        except KeyboardInterrupt as error: actual = error
        finally:
            sys.settrace(previous); arming.f_trace_opcodes = old_opcodes
        self.assertIs(actual, failure); self.assertEqual(fired, [True]); self.assertEqual(calls, [True])
        for retry in (lambda: frame.service(issued), frame.step, frame.take):
            with self.assertRaises(RuntimeError): retry()
        self.assertEqual(calls, [True])
        frame.close(); self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)

    def test_foreign_nonce_raw_frame_and_reserved_profile_refuse_without_effects(self):
        first = self.native.prepare('normalize_exports', ((), object()))
        second = self.native.prepare('normalize_exports', ((), object()))
        first.step(); second.step()
        count = self.native.entries
        with self.assertRaises(RuntimeError): first.service(second.pending)
        self.assertEqual(self.native.entries, count)
        raw = first.pending.raw
        object.__setattr__(first.pending, 'raw', raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(RuntimeError): first.service(first.pending)
        object.__setattr__(first.pending, 'raw', raw)
        # A requested but unobserved effect is not a terminal frame.
        # Cleanup cannot erase that pending authority or manufacture an ACK.
        for frame in (first, second):
            with self.assertRaises(RuntimeError): frame.close()
            self.assertTrue(frame._uncertain)
            self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)
        owner = self.new_owner()
        for profile in (0, 311, 315, (1 << 64) - 1):
            frame = owner.prepare('normalize_exports', ((), object()))
            frame._runtime_profile = profile
            with self.assertRaises(RuntimeError): frame.step()
            self.assertTrue(frame._uncertain)
            frame.close()

    def test_partial_constructor_frees_only_its_allocated_arena(self):
        allocate = protocol._private_zeroed_buffer
        calls, refs = [], []
        failure = MemoryError('second arena refused')
        def observed_allocate(size):
            calls.append(size)
            if len(calls) == 2: raise failure
            buffer = allocate(size); refs.append(weakref.ref(buffer)); return buffer
        held = None
        with patch.object(protocol, '_private_zeroed_buffer', observed_allocate):
            try: self.native.prepare('normalize_exports', ((), object()))
            except MemoryError as error: held = error
        self.assertIs(held, failure); self.assertEqual(len(calls), 2)
        self.assertEqual(len(refs), 1); self.assertIsNone(refs[0]())

    def test_captured_owner_and_absence_survive_environment_mutation_and_reentry(self):
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with selection.native_byte_abi_scope(vars(self.ref)):
                held = selection.active_native_byte_abi()
                self.assertIsNotNone(held)
                with patch.dict(os.environ, {SELECTOR: '/not/a/valid/manifest'}):
                    with selection.native_byte_abi_scope(vars(self.ref)):
                        self.assertIs(selection.active_native_byte_abi(), held)
                        self.assertEqual(selection.selected_native_byte_abi().normalize_exports((), object()), ())
            with patch.dict(os.environ, {SELECTOR: '/not/a/valid/manifest'}):
                with self.assertRaises(FileNotFoundError): selection.selected_native_byte_abi()
        with patch.dict(os.environ, {SELECTOR: ''}):
            with selection.native_byte_abi_scope():
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
                    self.assertIsNone(selection.selected_native_byte_abi())
                    self.assertEqual(selection.captured_checker_owner(), (True, None))
        self.assertEqual(selection.captured_checker_owner(), (False, None))

    def test_captured_scope_is_thread_local_and_retains_checker_owner(self):
        failures, snapshots = [], []
        barrier = threading.Barrier(2)
        def worker():
            try:
                self.assertIsNone(selection.active_native_byte_abi())
                with selection.native_byte_abi_scope(vars(self.ref)):
                    active = selection.active_native_byte_abi()
                    snapshots.append(selection.captured_checker_owner())
                    self.assertEqual(active.normalize_exports((), object()), ())
                    barrier.wait(timeout=5)
                self.assertEqual(selection.captured_checker_owner(), (False, None))
            except BaseException as error: failures.append(error)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), selection.native_byte_abi_scope(vars(self.ref)):
            thread = threading.Thread(target=worker); thread.start()
            barrier.wait(timeout=5); thread.join(timeout=5)
            self.assertFalse(thread.is_alive()); self.assertFalse(failures)
            self.assertIsNotNone(selection.active_native_byte_abi())
        self.assertEqual(len(snapshots), 1); self.assertTrue(snapshots[0][0])
        self.assertIsNotNone(snapshots[0][1])

    def test_warm_selection_rechecks_source_image_manifest_and_missing_inputs(self):
        record = json.loads(self.manifest.read_bytes())
        case = self.folder / 'warm'; case.mkdir()
        manifest = case / 'manifest.json'; image = case / record['image_path']
        image.write_bytes((self.manifest.parent / record['image_path']).read_bytes())
        manifest.write_bytes(self.manifest.read_bytes())
        source = case / 'source.hiaasm'; source.write_bytes(SOURCE.read_bytes())
        with patch.object(selection, 'SOURCE', source):
            self.assertEqual(selection.installed_native_byte_abi(manifest).normalize_exports((), object()), ())
            for path in (source, image, manifest):
                raw = path.read_bytes()
                for absent in (False, True):
                    try:
                        if absent: path.unlink()
                        elif path is manifest:
                            altered = json.loads(raw); altered['image_sha256'] = '0' * 64
                            path.write_text(json.dumps(altered))
                        else: path.write_bytes(raw + b'\n')
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            selection.installed_native_byte_abi(manifest)
                    finally: path.write_bytes(raw)
            self.assertEqual(selection.installed_native_byte_abi(manifest).normalize_exports((), object()), ())


class NativeByteABIVMTests(_Fixture, unittest.TestCase):
    def test_complete_frame_and_canary_equality_for_emissions_success_and_error(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        owner = self.new_owner(); real_entry = owner._entry; rows = []
        def entry(source, size, output, outsize, workspace, worksize):
            original = tuple(ctypes.string_at(p, n) for p, n in
                             ((source, size), (output, outsize), (workspace, worksize)))
            guards = [ctypes.create_string_buffer(b'Z' * 16 + raw + b'Y' * 16, len(raw) + 32)
                      for raw in original]
            result = real_entry(ctypes.byref(guards[0], 16), size,
                                ctypes.byref(guards[1], 16), outsize,
                                ctypes.byref(guards[2], 16), worksize)
            owners = [_Owner(-1-i, bytearray(raw)) for i, raw in enumerate(original)]
            vm = _Machine(checked, 20_000_000, 4 << 20, None, 128)
            expected = vm.invoke(function, [_View(owners[0], False),
                                _View(owners[1], True), _View(owners[2], True)])[0]
            self.assertEqual(result, expected)
            for guard, memory in zip(guards, owners):
                self.assertEqual(guard.raw[:16], b'Z' * 16)
                self.assertEqual(guard.raw[-16:], b'Y' * 16)
                self.assertEqual(guard.raw[16:-16], bytes(memory.data))
            self.assertEqual(guards[0].raw[16:-16], original[0])
            ctypes.memmove(output, guards[1].raw[16:-16], outsize)
            ctypes.memmove(workspace, guards[2].raw[16:-16], worksize)
            rows.append({'return': result, 'command': struct.unpack_from('<Q', original[2])[0],
                'source_sha256': sha256(original[0]).hexdigest(),
                'output_sha256': sha256(guards[1].raw[16:-16]).hexdigest(),
                'workspace_sha256': sha256(guards[2].raw[16:-16]).hexdigest()})
            return result
        owner._entry = entry; owner._initialize_control(); owner._bind_namespace(vars(self.ref))
        self.assertEqual(owner.normalize_exports((), object()), ())
        self.assertEqual(observed(owner.normalize_exports, [], object()),
                         observed(self.ref.normalize_exports, [], object()))
        counts = Counter(row['command'] for row in rows)
        self.assertGreater(counts[2], 0); self.assertGreater(counts[4], 0)
        self.assertIn(3, [row['return'] for row in rows])
        (self.folder / 'all-native-VM-frames.json').write_text(json.dumps(rows, indent=2) + '\n')


class NativeByteABIInstalledTests(_Fixture, unittest.TestCase):
    def test_real_wheel_without_authoring_and_both_warm_resource_refusals(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
            PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES)
        source, wheels, installed = (self.folder / name for name in ('source', 'wheels', 'installed'))
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + \
                    PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES
        for name in (*dict.fromkeys(resources), 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        commands = []
        def command(argv, name, *, env=None):
            result = subprocess.run(argv, cwd=self.folder, env=env, capture_output=True, timeout=120)
            (self.folder / (name + '.stdout')).write_bytes(result.stdout)
            (self.folder / (name + '.stderr')).write_bytes(result.stderr)
            commands.append({'argv': argv, 'returncode': result.returncode,
                'stdout_sha256': sha256(result.stdout).hexdigest(), 'stderr_sha256': sha256(result.stderr).hexdigest()})
            (self.folder / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        command([packaging, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
                 '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        command([packaging, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
                 '--target', str(installed), str(wheel)], 'wheel-install')
        child = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='tools' or fullname.startswith('tools.') or fullname=='tests' or fullname.startswith('tests.'):
   raise AssertionError('installed byte ABI imported authoring or tests')
sys.meta_path.insert(0,NoTools())
from hepta import hia_native_byte_abi as api
from hepta.hia_native_byte_abi_native import SOURCE,SELECTOR
from hepta.hia_native_byte_abi_selection import installed_native_byte_abi,native_byte_abi_scope
assert Path(sys.argv[1]) in SOURCE.parents
assert '_data' in SOURCE.parts
os.environ[SELECTOR]=sys.argv[2]
def forbidden(*args,**kwargs):raise AssertionError('old byte ABI policy')
api._reference_normalize_exports=api._reference_emit_wrapper=forbidden
class Program:
 structured_bytes=None
 def as_dict(self):return {'functions':[{'name':'f','params':[{'type':'readbuf'}],'returns':['u32']}]}
owner=installed_native_byte_abi(sys.argv[2])
with native_byte_abi_scope():assert api.normalize_exports((('f',12),),Program())==( ('f',12), )
assert owner.entries>0
raw=SOURCE.read_bytes()
for missing in (False,True):
 try:
  if missing:SOURCE.unlink()
  else:SOURCE.write_bytes(raw+b'\n')
  try:installed_native_byte_abi(sys.argv[2])
  except (ValueError,FileNotFoundError):pass
  else:raise AssertionError('changed/missing installed HIA source accepted')
 finally:SOURCE.write_bytes(raw)
assert not any(k=='tools' or k.startswith('tools.') for k in sys.modules)
assert sys.flags.isolated and sys.flags.no_site
print(json.dumps({'status':'INSTALLED_NATIVE_BYTE_ABI_PASS','entries':owner.entries,'source':str(SOURCE)}))
'''
        script = self.folder / 'installed-control.py'; script.write_text(child)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
        env.update(PATH='', PYTHONPATH='')
        result = command([sys.executable, '-I', '-S', '-B', str(script), str(installed), str(self.manifest)],
                         'installed-execution', env=env)
        self.assertEqual(json.loads(result.stdout)['status'], 'INSTALLED_NATIVE_BYTE_ABI_PASS')


if __name__ == '__main__':
    unittest.main()
