"""Independent frozen-original, full-buffer VM and installed native controls."""
from __future__ import annotations
import copy
import ctypes
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_static_budget as owner
from hepta import hia_static_budget_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.test_hia_program import b, f, jump, m, ret, resource_program
from tests.test_hia_static_budget import acyclic_calls, acyclic_choice, cyclic_calls, cyclic_control_flow
from tests.test_hia_rust_static_budget import expanding_calls, multiple_return_loan
from tools import generate_hia_static_budget as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/static_budget_ad352ee.py.txt'
FIXTURE_SHA = 'c26ec6ba5badc4c8c4863dbbfab9cfbe99e8167c8b674f216763694f1995b1d5'
REFERENCE_OWNERS = ('_reference_topological', '_reference_bound_function',
                    '_reference_audit_resource_profile', '_reference_frame_rows', '_reference_first_exceeded')


def original():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('independent original static-budget fixture changed')
    scope = {'__name__': 'hepta._original_static_budget', '__package__': 'hepta'}
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope


def observed(function, *args, **kwargs):
    try:
        return 'return', function(*args, **kwargs)
    except Exception as error:
        return type(error).__name__, str(error)


def poison(stack):
    for name in REFERENCE_OWNERS:
        stack.enter_context(patch.object(owner, name, side_effect=AssertionError('host resource owner entered: ' + name)))


def frame(image, raw, mode, count, children=0, width=8, *, out_adjust=0, work_adjust=0):
    outsize, worksize = native.sizes(mode, count, children, width)
    outsize += out_adjust
    worksize += work_adjust
    source = ctypes.create_string_buffer(raw, max(1, len(raw)))
    output = ctypes.create_string_buffer(b'\xa5' * (outsize + 16), outsize + 16)
    workspace = ctypes.create_string_buffer(worksize + 16)
    ctypes.memset(ctypes.addressof(workspace) + worksize, 0x91, 16)
    code = image._entry(source, len(raw), output, outsize, workspace, worksize)
    if (source.raw != (raw or b'\0') or output.raw[outsize:] != b'\xa5' * 16
            or workspace.raw[worksize:] != b'\x91' * 16):
        raise AssertionError('native resource facts or canaries changed')
    return code, output.raw[:outsize], workspace.raw[:worksize]


def interpret(program, raw, mode, count, children=0, width=8):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    outsize, worksize = native.sizes(mode, count, children, width)
    values = [_Owner(i + 1, bytearray(data)) for i, data in enumerate((raw, b'\xa5' * outsize, bytes(worksize)))]
    machine = _Machine(program, 10_000_000, 8 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'], [_View(value, i != 0) for i, value in enumerate(values)])[0]
    if bytes(values[0].data) != raw:
        raise AssertionError('independent VM changed verified facts')
    return code, bytes(values[1].data), bytes(values[2].data)


def witnesses():
    names = ['b', 'a', 'c', 'z']
    edges = {'a': {'z'}, 'b': {'c'}, 'c': set(), 'z': set()}
    for mode in (0, 2):
        yield native.graph_packet(names, edges, mode), mode, len(names), 0, 8
    fn = acyclic_calls()['functions'][1]
    bank = {'inner': {'max_allocator_interactions': 1 << 140, 'max_vm_ticks': (1 << 150) + 7, 'max_call_depth': 11}}
    raw, width = native.function_packet(fn, bank)
    yield raw, 1, len(fn['blocks']), len(bank), width
    doc = multiple_return_loan()
    yield native.profile_packet(doc, doc['schema'], False), 3, len(doc['functions']), 0, 8
    raw = (struct.pack('<4Q', native.REQUEST_MAGIC, 4, 1, 2) + native._text(native._magnitude(1 << 141))
           + native._text(native._magnitude(1 << 140)) + native._text(native._magnitude((1 << 141) + 1)))
    yield raw, 4, 2, 0, 8


class StaticBudgetSourceTests(unittest.TestCase):
    def test_reproducible_source_retains_original_compiler_profile(self):
        self.assertEqual(render_assembly(generator.document(generator.source(), 'static_budget')), native.SOURCE.read_text())
        data = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(data['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in data['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in data['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in data['functions'] for block in fn['blocks']), 16)
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA)

    def test_absent_selection_preserves_complete_original_reports_and_no_optional_import(self):
        frozen = original()
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            for document in (resource_program(), acyclic_calls(), acyclic_choice(), multiple_return_loan(), cyclic_calls()):
                with patch('builtins.__import__', wraps=__import__) as imports:
                    actual = observed(owner.analyze_static_budget, document)
                self.assertFalse(any('hia_static_budget_native' in str(call) for call in imports.call_args_list))
                self.assertEqual(actual, observed(frozen['analyze_static_budget'], document))

    def test_independent_vm_retains_fifo_exact_wide_events_and_ordered_profile(self):
        program = assemble_program(native.SOURCE.read_bytes())
        cases = list(witnesses())
        results = [interpret(program, *case) for case in cases]
        self.assertTrue(all(row[0] == 0 for row in results))
        self.assertEqual(struct.unpack_from('<4Q', results[0][1], 16), (1, 0, 3, 2))
        width = cases[2][-1]
        self.assertEqual(int.from_bytes(results[2][1][24:24+width], 'little'), 1 << 141)
        self.assertEqual(int.from_bytes(results[2][1][24+width:], 'little'), 2 * ((1 << 150) + 7) + 4)
        self.assertEqual(struct.unpack_from('<2Q', results[-1][1], 16), (1, 0))

    def test_existing_policy_and_core_admission_precede_selected_image(self):
        with patch.dict(os.environ, {native.SELECTOR: ''}):
            with self.assertRaisesRegex(owner.HIAStaticBudgetRejected, 'E_HIA_BUDGET_POLICY'):
                owner.analyze_static_budget(acyclic_calls(), max_vm_ticks=True)
            with self.assertRaisesRegex(ValueError, 'selector must not be empty'):
                owner.analyze_static_budget(acyclic_calls())
            bad = acyclic_calls(); bad['functions'][0]['blocks'][0]['ops'][0]['op'] = 'unreviewed.future'
            with self.assertRaisesRegex(ValueError, 'E_HIA_'):
                owner.analyze_static_budget(bad)


class StaticBudgetNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_static_budget import build
        evidence = os.environ.get('HEPTA_HIA_STATIC_BUDGET_EVIDENCE')
        cls.temp = None
        if evidence is not None:
            if not evidence:
                raise ValueError('static budget evidence selector must not be empty')
            cls.root = Path(evidence); cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix='hia-static-budget-'); cls.root = Path(cls.temp.name)
        cold = os.environ.get('HEPTA_HIA_STATIC_BUDGET_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER')
        if cold is not None and development is not None:
            raise ValueError('select exactly one static-budget compiler authority')
        if cold is not None:
            if not cold: raise ValueError('empty static-budget cold report')
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        elif development is not None:
            if not development: raise ValueError('empty static-budget development compiler')
            compiler = Path(development)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
        cls.compiler, cls.compiler_bytes, cls.cold = compiler, compiler.read_bytes(), cold
        cls.manifest = build(cls.root / 'build', compiler, cold, development=cold is None)
        cls.image = native.installed_static_budget(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        same = cls.compiler.read_bytes() == cls.compiler_bytes
        (cls.root / 'component-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.static-budget-test-custody.v1', 'compiler_unchanged': same,
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(), 'manifest': str(cls.manifest),
            'matching_cold_report': cls.cold, 'test_result_owned_by_outer_runner': True}, indent=2, sort_keys=True) + '\n')
        if cls.temp is not None: cls.temp.cleanup()
        if not same: raise AssertionError('static-budget compiler bytes changed')

    def test_actual_machine_complete_buffers_equal_independent_vm(self):
        for case in witnesses():
            with self.subTest(mode=case[1]):
                self.assertEqual(frame(self.image, *case), interpret(self.program, *case))

    def test_public_apis_and_original_reports_with_all_reference_owners_forbidden(self):
        frozen = original()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})); poison(stack)
            for doc in (resource_program(), acyclic_choice(), acyclic_calls(), cyclic_control_flow(), cyclic_calls(), multiple_return_loan()):
                for policy in ({}, {'max_vm_ticks': 0}, {'max_call_depth': 1}, {'max_allocator_interactions': 1}, {'max_vm_ticks': 10**600}):
                    self.assertEqual(observed(owner.analyze_static_budget, doc, **policy), observed(frozen['analyze_static_budget'], doc, **policy))
                for limit in (1, 2, 256):
                    self.assertEqual(observed(owner.qualify_vm_call_depth, doc, max_call_depth=limit), observed(frozen['qualify_vm_call_depth'], doc, max_call_depth=limit))

    def test_exact_original_1024_function_domain_keeps_large_integer_counts(self):
        frozen = original()
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            for count in (63, 128, 1024):
                document = expanding_calls(count)
                actual = owner.analyze_static_budget(document)
                self.assertEqual(actual, frozen['analyze_static_budget'](document))
                self.assertEqual(actual['functions'][0]['max_vm_ticks'].bit_length(), count + 2)

    def test_original_4096_block_domain_and_fifo_graph_error_precedence(self):
        frozen = original()
        blocks = [b('b' + str(index), [], [], jump('b' + str(index + 1)) if index < 4095 else ret()) for index in range(4096)]
        document = m(f('long', [], [], [], blocks))
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            self.assertEqual(owner.analyze_static_budget(document), frozen['analyze_static_budget'](document))
        cases = [([], {}), (['a'], {'a': set(), 'unknown': set()}), (['a'], {'a': {'unknown'}}),
                 (['z', 'a'], {}), (['a', 'a'], {'a': set()}), (['a', 'a'], {}),
                 (['a', 'a'], {'a': {'unknown'}})]
        rng = random.Random(7113)
        for _ in range(100):
            names = ['n' + str(i) for i in range(rng.randrange(1, 22))]; rng.shuffle(names)
            edges = {name: {target for target in names if rng.randrange(20) == 0} for name in names}
            cases.append((names, edges))
        for names, edges in cases:
            self.assertEqual(observed(self.image.topological, names, edges, 'fixture'), observed(frozen['_topological'], names, edges, 'fixture'))

    def test_all_reviewed_types_opcodes_and_ordered_first_profile_refusal(self):
        frozen = original()
        for schema in ('hepta.hia.program.v7', 'hepta.hia.program.v8'):
            for allow in (False, True):
                fn = {'name': 'z', 'params': [], 'returns': list(owner._V8_BYTE_TYPES),
                      'blocks': [{'params': [], 'term': {'op': 'ret'},
                                  'ops': [{'op': op, 'out': []} for op in sorted(owner._V8_BYTE_OPS)]}]}
                doc = {'schema': schema, 'functions': [fn, copy.deepcopy(fn)]}; doc['functions'][1]['name'] = 'a'
                variants = [doc]
                for target in ('schema', 'term', 'op', 'type'):
                    bad = copy.deepcopy(doc)
                    if target == 'schema': bad['schema'] = 'future'
                    if target == 'term': bad['functions'][0]['blocks'][0]['term']['op'] = 'future'
                    if target == 'op': bad['functions'][0]['blocks'][0]['ops'][0]['op'] = 'future'
                    if target == 'type': bad['functions'][0]['returns'].append('chain')
                    variants.append(bad)
                bad = copy.deepcopy(doc); bad['functions'][0]['returns'].append('future')
                bad['functions'][1]['blocks'][0]['term']['op'] = 'future'; variants.append(bad)
                bad = copy.deepcopy(doc); bad['functions'][0]['returns'].append('future')
                bad['functions'][0]['blocks'][0]['ops'][0]['op'] = 'future'; variants.append(bad)
                for candidate in variants:
                    self.assertEqual(observed(self.image.audit_profile, candidate, schema=schema, allow_chain=allow),
                                     observed(frozen['_audit_resource_profile'], candidate, schema=schema, allow_chain=allow))

    def test_truncated_transport_bad_dimensions_and_refusals_preserve_canaries(self):
        raw, mode, count, children, width = next(witnesses())
        variants = [raw[:index] for index in range(len(raw))] + [raw + b'\0']
        for at, value in ((0, 0), (8, 99), (16, 4097), (24, 1025), (32, 4097)):
            bad = bytearray(raw); struct.pack_into('<Q', bad, at, value); variants.append(bytes(bad))
        for candidate in variants:
            result = frame(self.image, candidate, mode, count, children, width)
            self.assertNotEqual(result[0], 0)
            self.assertEqual(result[1], b'\xa5' * native.sizes(mode, count, children, width)[0])
        for adjustments in ({'out_adjust': -1}, {'work_adjust': -1}):
            result = frame(self.image, raw, mode, count, children, width, **adjustments)
            self.assertNotEqual(result[0], 0); self.assertEqual(set(result[1]), {0xa5})

    def test_pinned_helper_scope_uses_native_owners_restores_selection_and_refuses_drift(self):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_identity, native_helpers_scope
        folder = self.root / 'bundle'; folder.mkdir()
        source = folder / 'static_budget.hepta'; source.write_bytes(native.SOURCE.read_bytes())
        manifest_data = json.loads(self.manifest.read_bytes())
        image = folder / 'owner.image.bin'; image.write_bytes((self.manifest.parent / manifest_data['image_path']).read_bytes())
        manifest_data['image_path'] = image.name
        manifest = folder / 'owner.json'; manifest.write_text(json.dumps(manifest_data, sort_keys=True))
        bundle = folder / 'helpers.json'; bundle.write_text(json.dumps({
            'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
            'helpers': [{'selector': native.SELECTOR, 'manifest_path': manifest.name,
                         'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}]}, sort_keys=True))
        digest = sha256(bundle.read_bytes()).hexdigest()
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        environment[native.SELECTOR] = ''
        document = multiple_return_loan(); expected = original()['analyze_static_budget'](document)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            stack.enter_context(patch.object(native, 'SOURCE', source)); poison(stack)
            before = dict(os.environ)
            with native_helpers_scope(str(bundle), digest):
                with patch('hepta.hia_json_preflight_native._load_manifest', side_effect=AssertionError('pinned owner used general loader')):
                    self.assertEqual(owner.analyze_static_budget(document), expected)
                self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': digest})
                raw = source.read_bytes()
                try:
                    source.write_bytes(raw + b'\n')
                    with self.assertRaisesRegex(ValueError, 'inputs changed'): native_helpers_identity()
                finally: source.write_bytes(raw)
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(native_helpers_identity(), {})
            raw = manifest.read_bytes()
            try:
                manifest.write_bytes(raw + b'\n')
                with self.assertRaisesRegex(ValueError, 'manifest identity mismatch'):
                    with native_helpers_scope(str(bundle), digest): self.fail('changed child manifest admitted')
            finally: manifest.write_bytes(raw)
            self.assertEqual(dict(os.environ), before)
            with native_helpers_scope(str(bundle), digest):
                self.assertEqual(owner.analyze_static_budget(document), expected)
            self.assertEqual(dict(os.environ), before)

    def test_invalid_selection_refuses_before_any_reference_fallback(self):
        with ExitStack() as stack:
            poison(stack)
            for selected in ('', '/does-not-exist/static-budget.json'):
                with patch.dict(os.environ, {native.SELECTOR: selected}):
                    with self.assertRaises((ValueError, OSError)):
                        owner.analyze_static_budget(acyclic_calls())

    def test_actual_clean_wheel_uses_packaged_source_and_refuses_source_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        self.assertIn('examples/hia_bootstrap/static_budget.hepta', RESOURCES)
        directory = self.root / 'installation'; directory.mkdir()
        source = directory / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT / name, target)
        environment = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        def run(arguments, cwd=source):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cwd,
                env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        wheels = directory / 'wheels'; run(['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', wheels, source])
        wheel, = wheels.glob('*.whl'); installed = directory / 'installed'
        run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
        data = directory / 'input.json'; data.write_text(json.dumps(multiple_return_loan()))
        expected = original()['analyze_static_budget'](json.loads(data.read_bytes()))
        script = '''import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hepta import hia_static_budget as owner
from hepta import hia_static_budget_native as native
assert Path(owner.__file__).is_relative_to(Path(sys.argv[1]))
assert native.SOURCE.is_relative_to(Path(sys.argv[1]))
def forbidden(*a,**k): raise AssertionError('installed reference fallback')
for name in json.loads(sys.argv[5]): setattr(owner,name,forbidden)
os.environ[native.SELECTOR]=sys.argv[2]
program=json.loads(Path(sys.argv[3]).read_bytes())
if sys.argv[4]=='accept': print(json.dumps(owner.analyze_static_budget(program),sort_keys=True))
else:
    try: owner.analyze_static_budget(program)
    except ValueError as error:
        assert 'source identity mismatch' in str(error),str(error)
        print('REFUSED_CHANGED_INSTALLED_SOURCE')
    else: raise AssertionError('changed source accepted')
'''
        accepted = run(['-I', '-c', script, installed, self.manifest, data, 'accept', json.dumps(REFERENCE_OWNERS)], cwd=directory)
        self.assertEqual(json.loads(accepted.stdout), expected)
        packaged = installed / 'hepta/_data/examples/hia_bootstrap/static_budget.hepta'; packaged.write_bytes(packaged.read_bytes() + b'\n')
        refused = run(['-I', '-c', script, installed, self.manifest, data, 'refuse', json.dumps(REFERENCE_OWNERS)], cwd=directory)
        self.assertEqual(refused.stdout.strip(), 'REFUSED_CHANGED_INSTALLED_SOURCE')


if __name__ == '__main__':
    unittest.main()
