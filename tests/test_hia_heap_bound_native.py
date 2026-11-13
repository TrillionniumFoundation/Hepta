"""Complete selected HIA heap owner: source, foreign-boundary and actual controls.

A current-source cold receipt or an explicit retained development compiler is
required. No historical compiler receipt grants this source qualification.
The seven original public bodies remain independent differential references.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import importlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_heap_bound as heap, hia_heap_bound_native as adapter
from hepta import hia_static_budget_native as static_adapter
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_core

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_HEAP_BOUND_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_HEAP_BOUND_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_HEAP_BOUND_EVIDENCE'
SELECTORS = (adapter.SELECTOR, adapter.LIVE_SELECTOR,
             adapter.STATIC_SELECTOR, adapter.PAYLOAD_SELECTOR)
RESOURCES = ('examples/hia_bootstrap/heap_bound.hepta',
             'examples/hia_bootstrap/heap_live_engine.hepta',
             'examples/hia_bootstrap/static_budget.hepta',
             'examples/hia_bootstrap/heap_payload.hepta')
OWNED = (
    'hepta/hia_heap_bound.py', 'hepta/hia_heap_bound_native.py',
    'hepta/hia_heap_live_native.py', 'hepta/hia_heap_payload_native.py',
    'hepta/hia_static_budget_native.py', 'hepta/hia_native_value_graph.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_checker_identity.py',
    'hepta/hia_agent_contract.py', 'MANIFEST.in',
    'tools/generate_hia_heap_bound.py', 'tools/hia_heap_payload.py',
    'tools/hia_heap_live_engine.py', 'tools/hia_heap_live_state.py',
    'tools/hia_heap_live_transfers.py', 'tools/hia_heap_scoped_cycle.py',
    'tools/hia_native_heap_intervals.py', 'tools/hia_heap_bound_graphs.py',
    'tools/hia_native_bigints.py', 'tools/hia_native_value_graph.py',
    'tools/build_hia_json_preflight.py',
    'tests/test_hia_heap_bound_native.py',
    'tests/test_hia_heap_bound_integration.py',
    'tests/hia_heap_public_controls.py', 'tests/hia_heap_native_fixture.py',
    'tests/test_hia_borrowed_extent_heap.py', 'tests/test_hia_finite_v8_heap.py',
    'tests/test_hia_partial_finite_bounds.py', 'docs/HIA_HEAP_BOUND_NATIVE.md',
    *RESOURCES,
)
REFERENCE_HASHES = {
    "analyze_constant_live_heap": "85e3b26132264ae25d498debf3b1c08c903c3ebedd88f309c44d177a74655882",
    "qualify_live_heap_budget": "41c16ab264b7bbda6626663736e6b686973a468ba6b4871f38999f00f7956228",
    "qualify_entry_live_heap_budget": "67b49e23e45d21682f4a01b772cb3f8c6465b8142fb990701db407bf50cc88bb",
    "qualify_finite_entry_live_heap_budget": "381f6a8fc8ed2428efeb97fb288de8c77823c5635f533d67a927bebafcbea936",
    "qualify_finite_entry_live_heap_budget_v8": "a032701285ef3d1609cbffc674945be8afb57d4e8d4ef5577ca2789da7ea36b0",
    "qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents": "e0f3a932284b706a14197d26efc47582747de781644e40f510fc8f44f9d36b5e",
    "analyze_entry_payload_bound": "c8997388b760fd4a4dc031eae3b3eddf8104aee37bb932a63b1a894e31632645"
}


def components():
    from hepta import hia_heap_live_native as live, hia_heap_payload_native as payload
    return (('heap-bound', adapter.SOURCE, adapter.SCHEMA, adapter.NativeHeapController,
             adapter.installed_heap_controller),
            ('heap-live-engine', live.SOURCE, live.SCHEMA, live.NativeLiveHeap,
             live.installed_heap_live),
            ('static-budget', static_adapter.SOURCE, static_adapter.SCHEMA,
             static_adapter.NativeStaticBudget, static_adapter.installed_static_budget),
            ('heap-payload', payload.SOURCE, payload.SCHEMA, payload.NativePayloadHeap,
             payload.installed_heap_payload))


@contextmanager
def selected(paths=None):
    values = {key: value for key, value in os.environ.items()
              if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
    if paths is not None:
        values.update({key: str(path) for key, path in zip(SELECTORS, paths)})
    with patch.dict(os.environ, values, clear=True):
        yield


def source_snapshot():
    names = set(OWNED)
    for folder in ('hepta', 'tools', 'tests'):
        names.update(path.relative_to(ROOT).as_posix() for path in (ROOT/folder).rglob('*.py'))
    names.update(path.relative_to(ROOT).as_posix()
                 for path in (ROOT/'examples/hia_bootstrap').rglob('*.hepta'))
    return {name: (ROOT/name).read_bytes() for name in sorted(names)}


class HeapBoundSourceTests(unittest.TestCase):
    def test_generators_exactly_match_owned_hia_and_original_compiler_limits(self):
        from tools.generate_hia_heap_bound import document as controller_document
        from tools.hia_heap_live_engine import document as live_document
        from tools.hia_heap_payload import document as payload_document
        for relative, generator in zip((RESOURCES[0], RESOURCES[1], RESOURCES[3]),
                                       (controller_document, live_document, payload_document)):
            with self.subTest(source=relative):
                value = generator()
                self.assertEqual((ROOT/relative).read_text(), render_assembly(value))
                verify_core(value)
                self.assertLessEqual(len(value['functions']), 128)
                self.assertLessEqual(sum(len(fn['blocks']) for fn in value['functions']), 1536)
                self.assertLessEqual(sum(len(block['ops']) for fn in value['functions']
                                         for block in fn['blocks']), 8192)
                for fn in value['functions']:
                    self.assertLessEqual(len(fn['blocks']), 256)
                    self.assertLessEqual(len(fn['params']), 16)
                    for block in fn['blocks']:
                        self.assertLessEqual(len(block['params']), 16)

    def test_seven_original_policy_bodies_and_public_signatures_are_preserved(self):
        source = (ROOT/'hepta/hia_heap_bound.py').read_text()
        nodes = {node.name: node for node in ast.parse(source).body
                 if isinstance(node, ast.FunctionDef)}
        for name, expected in REFERENCE_HASHES.items():
            reference = '_reference_' + name
            text = ast.get_source_segment(source, nodes[reference]).replace(
                'def '+reference+'(', 'def '+name+'(', 1)
            self.assertEqual(sha256(text.encode()).hexdigest(), expected, name)
            self.assertEqual(ast.dump(nodes[name].args), ast.dump(nodes[reference].args), name)
            self.assertEqual(ast.dump(nodes[name].returns) if nodes[name].returns else None,
                             ast.dump(nodes[reference].returns) if nodes[reference].returns else None)

    def test_runtime_has_no_authoring_or_retained_heap_policy_callback(self):
        source = (ROOT/'hepta/hia_heap_bound_native.py').read_text()
        for text in ('from tools', 'import tools', '_reference_', '_FiniteInvocationAnalysis(',
                     '_scoped_allocating_cycle_peak(', '_function(', '_dag('):
            self.assertNotIn(text, source)
        self.assertIn('extent_bounds=True', source)
        self.assertIn('binary_integers=True', source)
        for path in ('hepta/hia_heap_live_native.py', 'hepta/hia_heap_payload_native.py'):
            tree = ast.parse((ROOT/path).read_text())
            functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
            self.assertEqual(len(functions), 1)
            self.assertEqual(len(functions[0].body), 1)
            self.assertIsInstance(functions[0].body[0], ast.Return)

    def test_packaging_worker_checker_and_builder_name_the_same_three_resources(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_checker_identity import CORE_SOURCE_FILES, NATIVE_OWNERS
        expected = (
            (SELECTORS[0], 'hia_heap_bound_native', 'NativeHeapController', 'installed_heap_controller', RESOURCES[0]),
            (SELECTORS[1], 'hia_heap_live_native', 'NativeLiveHeap', 'installed_heap_live', RESOURCES[1]),
            (SELECTORS[3], 'hia_heap_payload_native', 'NativePayloadHeap', 'installed_heap_payload', RESOURCES[3]),
        )
        manifest_lines = (ROOT/'MANIFEST.in').read_text().splitlines()
        for selector, module, factory, loader, resource in expected:
            self.assertEqual(HELPERS[selector], (module, factory))
            self.assertEqual(NATIVE_OWNERS[selector], (module, loader))
            self.assertIn(module+'.py', CORE_SOURCE_FILES)
            self.assertIn(resource, NATIVE_SOURCE_FILES)
            self.assertIn('include '+resource, manifest_lines)
            loaded = importlib.import_module('hepta.'+module)
            self.assertEqual(loaded.SOURCE, ROOT/resource)
            self.assertEqual(loaded.SCHEMA, 'hepta.hia.'+resource.rsplit('/',1)[1].removesuffix('.hepta').replace('_','-')+'-native.v1')
        text = (ROOT/'tools/build_hia_json_preflight.py').read_text()
        for name in ('heap-bound', 'heap-live-engine', 'heap-payload'):
            self.assertIn(repr(name)+':', text)

    def test_cold_and_development_conflict_refuses_before_any_input_io(self):
        from tests.test_hia_heap_bound_integration import InstalledHeapBoundTests
        with patch.dict(os.environ, {COLD_REPORT:'/unread-cold',
                                    DEVELOPMENT_COMPILER:'/unread-development'}), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('early input read')):
            for fixture in (HeapBoundNativeTests, InstalledHeapBoundTests):
                with self.subTest(fixture=fixture.__name__):
                    with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                        fixture.setUpClass()


class HeapBoundAdapterTests(unittest.TestCase):
    def test_opaque_policy_is_not_inspected_or_decimalized_before_native_admission(self):
        class Opaque:
            def __hash__(self): raise AssertionError('early hash')
            def __eq__(self, other): raise AssertionError('early equality')
            def __int__(self): raise AssertionError('early conversion')
        original = Opaque()
        saved = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            context = adapter.HeapContext(1, original, None, None, -(1<<20000), None)
            self.assertIs(context.pool.get(1), original)
            self.assertLess(len(context.input), 512)
            self.assertEqual(adapter._metadata(-(1<<20000)), [2,1,20001,0])
            context.close()
        finally:
            sys.set_int_max_str_digits(saved)

    def test_exact_private_frame_admission_does_not_invoke_metaclass_equality(self):
        calls = []
        class Meta(type):
            def __eq__(cls, other): calls.append(other); return True
        class Forged(metaclass=Meta): pass
        frame = adapter.HeapFrame(1,1,(0,0,0,0),0,None)
        object.__setattr__(frame, 'sequence', Forged())
        with self.assertRaisesRegex(heap.HIAHeapBoundRejected, 'exact representation'):
            adapter.HeapContext._fields(frame)
        self.assertEqual(calls, [])

    def test_partial_arena_construction_closes_first_mapping_with_original_error(self):
        mappings = []
        real = mmap.mmap
        marker = MemoryError('second actual heap arena allocation')
        def allocate(*args, **kwargs):
            if mappings:
                raise marker
            value = real(*args, **kwargs)
            mappings.append(value)
            return value
        with patch.object(adapter.mmap, 'mmap', allocate):
            with self.assertRaises(MemoryError) as raised:
                adapter.HeapContext(0, {}, None, None, None, None)
        self.assertIs(raised.exception, marker)
        self.assertTrue(mappings[0].closed)

    def test_cleanup_revokes_before_buffer_error_and_can_finish_without_authority(self):
        context = adapter.HeapContext(0, {}, None, None, None, None)
        arena = context.workspace
        held = memoryview(arena)
        try:
            with self.assertRaises(BufferError):
                context.close()
            self.assertTrue(context.closed)
            self.assertIs(context.workspace, arena)
            self.assertIsNone(context.output)
            self.assertIsInstance(context.cleanup_error, BufferError)
        finally:
            held.release()
        context.close()
        self.assertTrue(arena.closed)
        self.assertIsNone(context.workspace)

    def test_worker_incomplete_heap_group_refuses_before_import_or_mapping(self):
        from hepta import hia_native_helpers as helpers
        value = {'schema':helpers.SCHEMA, 'target':helpers.TARGET, 'abi':helpers.ABI,
                 'helpers':[{'selector':adapter.SELECTOR,
                             'manifest_path':'/definitely/not-opened/manifest.json',
                             'manifest_sha256':'0'*64}]}
        with tempfile.TemporaryDirectory(prefix='hia-heap-incomplete-') as directory:
            path = Path(directory)/'bundle.json'
            raw = (json.dumps(value,sort_keys=True)+'\n').encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            with patch.object(helpers.importlib, 'import_module',
                              side_effect=AssertionError('adapter import before closure check')):
                with self.assertRaisesRegex(ValueError, 'complete pinned dependency set'):
                    helpers.NativeHelpersBinding(str(path), sha256(raw).hexdigest())


class HeapBuildFixture:
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:
            raise ValueError('cold and retained development heap inputs are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('an explicit cold report or retained development compiler is required')
        from tools.qualify_hia_selfhost import compile_stage
        cls.inputs = source_snapshot()
        cls.cold_bytes = None
        cls.held = {}
        cls.entries = {}
        cls.observations = {}
        if cold:
            from tools.build_hia_json_preflight import build, admit_cold_build
            cls.cold_path = Path(cold)
            cls.cold_bytes = cls.cold_path.read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.cold_sources = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            cls.scope = 'CURRENT_SOURCE_COLD_BUILT_HEAP_COMPONENTS'
        else:
            cls.compiler = Path(development)
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.scope = 'PREDECESSOR_COMPILER_DEVELOPMENT_HEAP_COMPONENTS'
        parent = Path(os.environ[EVIDENCE]) if os.environ.get(EVIDENCE) else Path(
            tempfile.mkdtemp(prefix='hia-heap-components-'))
        cls.folder = parent/cls.__name__
        cls.folder.mkdir(parents=True, exist_ok=False)
        cls.paths = []
        cls.image_instances = []
        cls.entry_originals = []
        for candidate, source, schema, factory, loader in components():
            folder = cls.folder/candidate
            if cold:
                manifest = build(folder, cls.compiler, cls.cold_path, candidate=candidate)
            else:
                folder.mkdir()
                image, receipt = compile_stage(folder, candidate, cls.compiler, source.read_bytes())
                manifest = folder/'manifest.json'
                manifest.write_text(json.dumps({
                    'schema':schema, 'source_sha256':sha256(source.read_bytes()).hexdigest(),
                    'image_path':image.name, 'image_sha256':sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256':sha256(cls.compiler_bytes).hexdigest()},
                    sort_keys=True,indent=2)+'\n')
                (folder/'compile-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
            image = manifest.parent/json.loads(manifest.read_bytes())['image_path']
            manifest.chmod(0o600)
            image.chmod(0o600)
            cls.paths.append(manifest)
            cls.held[manifest] = manifest.read_bytes()
            cls.held[image] = image.read_bytes()
            native = loader(str(manifest))
            cls.image_instances.append(native)
            original = native._entry
            cls.entry_originals.append((native,original))
            cls.entries[candidate] = 0
            def counted(*args, candidate=candidate, original=original):
                cls.entries[candidate] += 1
                return original(*args)
            native._entry = counted
        cls.paths = tuple(cls.paths)
        cls.native = adapter.installed_heap_bound(*(str(path) for path in cls.paths))
        (cls.folder/'source-before.json').write_text(json.dumps({
            name:sha256(raw).hexdigest() for name,raw in cls.inputs.items()},
            indent=2,sort_keys=True)+'\n')
        (cls.folder/'build-scope.json').write_text(json.dumps({
            'scope':cls.scope, 'compiler_sha256':sha256(cls.compiler_bytes).hexdigest(),
            'manifest_paths':[str(path) for path in cls.paths],
            'whole_native_delivery_qualified':False},indent=2,sort_keys=True)+'\n')

    @classmethod
    def tearDownClass(cls):
        for image, original in cls.entry_originals:
            image._entry = original
        stable = (source_snapshot() == cls.inputs
                  and cls.compiler.read_bytes() == cls.compiler_bytes
                  and all(path.read_bytes() == raw for path,raw in cls.held.items()))
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            stable = stable and cls.cold_path.read_bytes() == cls.cold_bytes and current_sources() == cls.cold_sources
        (cls.folder/'observations.json').write_text(json.dumps({
            'scope':cls.scope, 'inputs_unchanged':stable, 'native_entries':cls.entries,
            'observations':cls.observations, 'whole_native_delivery_qualified':False},
            indent=2,sort_keys=True)+'\n')
        if not stable:
            raise AssertionError('heap qualification inputs changed')


ORIGINAL_CHILD = "import contextlib,hashlib,importlib,json,os,pathlib,subprocess,sys,time,traceback,unittest\nfrom unittest.mock import patch\nS=pathlib.Path(sys.argv[1]);F=pathlib.Path(sys.argv[2]);mode=sys.argv[3]\nfor key in list(os.environ):\n    if key.startswith('HEPTA_'):os.environ.pop(key)\nos.chdir(S);sys.path.insert(0,str(S))\nfrom hepta import hia_heap_bound as heap,hia_heap_bound_native as ad,hia_static_budget as static\nfrom importlib.metadata import version\nimport z3\nassert z3.get_version_string()=='4.15.4'\npaths=tuple(pathlib.Path(value) for value in json.loads(sys.argv[4]))\nselectors=(ad.SELECTOR,ad.LIVE_SELECTOR,ad.STATIC_SELECTOR,ad.PAYLOAD_SELECTOR)\nif mode=='native':os.environ.update({key:str(path) for key,path in zip(selectors,paths)})\nelse:assert mode=='reference'\nexpected_blobs={\"tests/test_hia_heap_bound.py\":\"c165ed101c24ccd5d526275a4f4796e494973c21\",\"tests/test_hia_heap_intervals.py\":\"d6bb59add86ef22007bad54fe7f57d0b1ddcc6f5\",\"tests/test_hia_heap_borrowed.py\":\"64cf658f4f3ae60f424f39a38a586555f096137c\",\"tests/test_hia_entry_payload_bound.py\":\"bb02ae772b820cbf3c4d400c71ea597d08247494\",\"tests/test_hia_borrowed_extent_heap.py\":\"06f5178113b6495265a23f926106916e3f06fa8d\",\"tests/test_hia_finite_v8_heap.py\":\"c76fcf09a2e5cda1c4e9bb03c31626a10ecb82b1\",\"tests/test_hia_partial_finite_bounds.py\":\"69c45039d0ae423d9cbdd974d20910e1bb6c1eb1\",\"tests/test_hia_returned_loan_budgets.py\":\"0189fbb55329ccd613b675cbcece37dec2bae0fd\",\"tests/test_hia_zero_heap_loops.py\":\"a7b87e39a994d0d651d599424cc492696370f639\",\"tests/test_hia_scoped_alloc_loops.py\":\"061dc7f263ca918718924902d2fdff5780d95505\",\"tests/test_hia_p0p1_v7_guard.py\":\"f4d9e183a51eb1a835fe329eb3ded2312b67f41e\",\"tests/test_hia_p1_scoped_try_new_v7_guard.py\":\"54ab42d1e35a6bbfccb316ee5d157541cf124096\",\"tests/test_hia_returned_loans.py\":\"2c5a2dd655efdd8bb646992cb0a1eafa87c6d0cf\"}\nchanged={\"tests/test_hia_borrowed_extent_heap.py\":\"29cb3313a02f87656fd582979f6b766dd3776b762f9fc0b8a86c8d6c2d94b5de\",\"tests/test_hia_finite_v8_heap.py\":\"bdce6033ba3a51315c0118bc3e99d5c63a6cccd96fe242f4e51106dee583c47e\",\"tests/test_hia_partial_finite_bounds.py\":\"1efe720bea5bc3a5f3ccb44ece16e43aea25e09869cde17a8c3107068db9ada6\"}\nexpected={\"tests/test_hia_borrowed_extent_heap.py\":\"29cb3313a02f87656fd582979f6b766dd3776b762f9fc0b8a86c8d6c2d94b5de\",\"tests/test_hia_entry_payload_bound.py\":\"43ea10a4dc356f157fe9a95ff23f9ddcdf682d13a6f29f877fd672064340ee52\",\"tests/test_hia_finite_v8_heap.py\":\"bdce6033ba3a51315c0118bc3e99d5c63a6cccd96fe242f4e51106dee583c47e\",\"tests/test_hia_heap_borrowed.py\":\"a6c69d306aaf9651dd37a79c01e1fea923374bb711e4c1778a2dea9b18382030\",\"tests/test_hia_heap_bound.py\":\"df80df2c83e26b82b0b0c5071f51fe8a4a3818b0e3569404e6cca3b895f920b5\",\"tests/test_hia_heap_intervals.py\":\"61cb7b1ea9bb232990c17e54105756ef096b802fb5d7e47567cec89019098d64\",\"tests/test_hia_p0p1_v7_guard.py\":\"93f498d5ce03a28219912d248eab72d6bb31ead0f4bfe4fb39952600c37cebc5\",\"tests/test_hia_p1_scoped_try_new_v7_guard.py\":\"f9be3e032050a57d0c36e119d1b0b40b0c87135057d46ee5550e04328bc46c62\",\"tests/test_hia_partial_finite_bounds.py\":\"1efe720bea5bc3a5f3ccb44ece16e43aea25e09869cde17a8c3107068db9ada6\",\"tests/test_hia_returned_loan_budgets.py\":\"73c0cc1af2e02106459cd5c54b0b664f0d29bd3a345536ec97dd1b1b868c4a06\",\"tests/test_hia_returned_loans.py\":\"f3589f3eb906b5f0d4409d79287578c62972ee1810a89b0ea8f3bcd66f9d18c3\",\"tests/test_hia_scoped_alloc_loops.py\":\"972c248dd6f1368459f8fe6d6f05dbd8732b8941f37a1142e6196ff355c73e43\",\"tests/test_hia_zero_heap_loops.py\":\"b38c2ca968a571f1e00a361786ce0ab684af701450e6dfa0810394de4967a33a\"}\nfor path,want in expected.items():\n    assert hashlib.sha256((S/path).read_bytes()).hexdigest()==want,(path,'retained public fixture bytes differ')\nclasses=[\"tests.test_hia_heap_bound.HIAHeapBoundTests\",\"tests.test_hia_heap_intervals.HIAHeapIntervalTests\",\"tests.test_hia_heap_borrowed.HIAHeapBorrowedExtentTests\",\"tests.test_hia_entry_payload_bound.EntryPayloadBoundTests\",\"tests.test_hia_borrowed_extent_heap.BorrowedExtentHeapTests\",\"tests.test_hia_finite_v8_heap.FiniteV8HeapTests\",\"tests.test_hia_partial_finite_bounds.PartialFiniteBounds\",\"tests.test_hia_returned_loan_budgets.ReturnedLoanBudgetTests\",\"tests.test_hia_zero_heap_loops.ZeroHeapLoopQualification\",\"tests.test_hia_scoped_alloc_loops.ScopedAllocatingLoopTests\",\"tests.test_hia_p0p1_v7_guard.GuardedV7HeapProfileTests\",\"tests.test_hia_p1_scoped_try_new_v7_guard.V7FallibleHeapVersionGuard\",\"tests.test_hia_returned_loans.ReturnedLoans\",\"tests.test_hia_returned_loans.ReturnedLoanSemantics\"]\nsuite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in classes)\ntests=[]\ndef visit(suite):\n    for item in suite:\n        if isinstance(item,unittest.TestSuite):visit(item)\n        else:tests.append(item.id())\nvisit(suite)\nassert len(tests)==134,len(tests)\nreport={'mode':mode,'scope':'PUBLIC_HEAP_ORIGINAL_REFERENCE_AND_EXPLICIT_NATIVE_FIXTURE_BRANCHES','classes':classes,'test_ids':tests,\n        'expected_count':len(tests),'source_test_hashes':expected,'original_git_blobs':expected_blobs,'native_fixture_deltas':changed,'python':sys.version,\n        'packages':{p:version(p) for p in ('jsonschema','z3-solver')},'native_step_count':0,'old_policy_calls':[],\n        'separate_foreign_clang_rust_classes_not_in_scope':True,'started':time.time()}\ndef forbidden(name):\n    def invoke(*args,**kwargs):\n        report['old_policy_calls'].append(name)\n        raise AssertionError('selected native public heap entered retained policy: '+name)\n    return invoke\noriginal_step=ad.NativeHeapController.step\ndef counted_step(*args,**kwargs):\n    report['native_step_count']+=1\n    return original_step(*args,**kwargs)\nwith (F/(mode+'-unittest.log')).open('w') as stream,contextlib.ExitStack() as stack:\n    if mode=='native':\n        for name in [name for name in vars(heap) if name.startswith('_reference_')]+['_function','_dag','_scoped_allocating_cycle_peak']:\n            stack.enter_context(patch.object(heap,name,forbidden('heap.'+name)))\n        stack.enter_context(patch.object(heap._FiniteInvocationAnalysis,'__init__',forbidden('heap._FiniteInvocationAnalysis.__init__')))\n        for name in [name for name in vars(static) if name.startswith('_reference_')]+['_audit_v7_byte_resource_profile','_audit_v8_resource_profile']:\n            stack.enter_context(patch.object(static,name,forbidden('static.'+name)))\n        stack.enter_context(patch.object(ad.NativeHeapController,'step',counted_step))\n    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)\nreport.update(tests_run=result.testsRun,failures=[{'id':t.id(),'traceback':txt} for t,txt in result.failures],\n              errors=[{'id':t.id(),'traceback':txt} for t,txt in result.errors],\n              skips=[{'id':t.id(),'reason':why} for t,why in result.skipped],\n              expected_failures=[{'id':t.id(),'traceback':txt} for t,txt in result.expectedFailures],\n              unexpected_successes=[t.id() for t in result.unexpectedSuccesses],finished=time.time())\nfrom tests.hia_heap_native_fixture import OBSERVATIONS\nreport['native_fixture_observations']=OBSERVATIONS\nreport['status']='PASS' if result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and result.testsRun==len(tests) and (mode!='native' or report['native_step_count']>0) else 'FAIL'\n(F/(mode+'-RESULT.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\\n')\nprint(json.dumps({'mode':mode,'status':report['status'],'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'native_step_count':report['native_step_count'],'old_policy_calls':report['old_policy_calls']}),flush=True)\nraise SystemExit(0 if report['status']=='PASS' else 1)\n"


class HeapBoundNativeTests(HeapBuildFixture, unittest.TestCase):
    def test_all_public_reports_errors_aliases_and_original_container_lifetimes(self):
        from tests.hia_heap_public_controls import run_public_controls
        self.observations['public_controls'] = run_public_controls(self.folder/'public-controls', self.paths)

    def test_pinned_composition_scope_revocation_and_unknown_outcomes(self):
        from tests.hia_heap_public_controls import run_scope_controls
        self.observations['scope_controls'] = run_scope_controls(self.folder/'scope-controls', self.paths)

    def test_full_original_public_heap_groups_and_real_unmodified_analysis_limits(self):
        folder = self.folder/'original-public'
        folder.mkdir()
        script = folder/'run_original_public.py'
        script.write_text(ORIGINAL_CHILD)
        runs = []
        for mode in ('reference','native'):
            result = subprocess.run(
                [sys.executable,'-I','-B',str(script),str(ROOT),str(folder),mode,
                 json.dumps([str(path) for path in self.paths])],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150)
            (folder/(mode+'.stdout')).write_bytes(result.stdout)
            (folder/(mode+'.stderr')).write_bytes(result.stderr)
            report = json.loads((folder/(mode+'-RESULT.json')).read_bytes())
            runs.append(report)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(report['status'],'PASS',report)
            self.assertEqual(report['tests_run'],134)
            for key in ('failures','errors','skips','expected_failures','unexpected_successes','old_policy_calls'):
                self.assertEqual(report[key],[],key)
        self.assertEqual(runs[0]['test_ids'],runs[1]['test_ids'])
        self.assertGreater(runs[1]['native_step_count'],0)
        self.observations['retained_public_runs'] = runs

    def test_independent_original_vm_matches_complete_controller_frames(self):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_heap_bound import document
        from tests.test_hia_heap_bound import local_buffers
        checked = verify_core(document())
        comparisons = 0
        for limit in (True,0):
            context = adapter.HeapContext(1,local_buffers(),None,None,limit,self.native.dependencies)
            try:
                while True:
                    source,output,work = bytes(context.input),bytes(context.output),bytes(context.workspace)
                    frame = self.native.controller.step(context)
                    roots = [_Owner(-1,bytearray(source)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(work))]
                    machine = _Machine(checked,10_000_000,0,None,256)
                    returned = machine.invoke(machine.functions['f0'],[_View(root,index!=0)
                                                                       for index,root in enumerate(roots)])
                    self.assertEqual(returned,[frame.request])
                    self.assertEqual(bytes(roots[0].data),source)
                    self.assertEqual(bytes(roots[1].data),bytes(context.output))
                    self.assertEqual(bytes(roots[2].data),bytes(context.workspace))
                    comparisons += 1
                    if not frame.request:
                        self.assertEqual(frame.status,2)
                        break
                    context.service(frame)
            finally:
                context.close()
        self.assertGreater(comparisons,2)
        self.observations['independent_vm_complete_frames'] = comparisons

    def test_changed_manifest_source_and_image_refuse_before_native_entry(self):
        folder = self.folder/'drift'
        folder.mkdir()
        original = json.loads(self.paths[0].read_bytes())
        image = self.paths[0].parent/original['image_path']
        copied = folder/image.name
        copied.write_bytes(image.read_bytes())
        manifest = folder/'manifest.json'
        manifest.write_text(json.dumps({**original,'image_path':copied.name})+'\n')
        asset = folder/'heap_bound.hiaasm'
        asset.write_bytes(adapter.SOURCE.read_bytes()+b'\n# controlled source drift\n')
        with patch.object(adapter,'SOURCE',asset):
            with self.assertRaisesRegex(ValueError,'source'):
                adapter.installed_heap_controller(str(manifest))
        changed = bytearray(copied.read_bytes())
        changed[-1] ^= 1
        copied.write_bytes(changed)
        with self.assertRaisesRegex(ValueError,'image|hash|executable'):
            adapter.installed_heap_controller(str(manifest))
        copied.write_bytes(image.read_bytes())
        manifest.write_text(json.dumps({**original,'schema':'wrong','image_path':copied.name})+'\n')
        with self.assertRaisesRegex(ValueError,'schema|manifest'):
            adapter.installed_heap_controller(str(manifest))
        self.observations['controlled_drift_refusals'] = 3


if __name__ == '__main__':
    unittest.main()
