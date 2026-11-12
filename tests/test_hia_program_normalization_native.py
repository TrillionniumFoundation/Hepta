"""Permanent controls for the explicit HIA normalization development owner.

The retained fixture preserves original external control source verbatim.
Only its definitions and already executed control blocks are loaded. No old
remote harness is run, no prior qualification is transferred, and no test
silently substitutes the reference for selected native execution.
"""
from __future__ import annotations
import ast
import copy
import ctypes
import gc
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import weakref
import zipfile

import hepta.hia_program_normalization_native as normalization
from hepta.hia_program import HIAProgramRejected, VerifiedProgram
from hepta.hia_program_normalization_notes import require_supported_interpreter

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = normalization.SELECTOR
COLD_REPORT = 'HEPTA_HIA_PROGRAM_NORMALIZATION_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_PROGRAM_NORMALIZATION_DEVELOPMENT_MANIFEST'
EVIDENCE_DIRECTORY = 'HEPTA_HIA_PROGRAM_NORMALIZATION_EVIDENCE'
FIXTURE = ROOT / 'tests/fixtures/hia_normalization_retained_v70.json'
FIXTURE_SHA256 = 'e9e050347cd546599cd0f7153eb0f55effddc80d47cbd68a2c8db67e8e33b1a7'


def digest(raw):
    return sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode('ascii')


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()


def retained_fixture():
    raw = FIXTURE.read_bytes()
    if digest(raw) != FIXTURE_SHA256:
        raise AssertionError('retained original control fixture changed')
    value = json.loads(raw)
    if value['schema'] != 'hepta.hia.normalization-retained-controls.v1':
        raise AssertionError('retained control fixture schema differs')
    for row in value['sources'].values():
        data = row['text'].encode('utf-8')
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise AssertionError('retained original source bytes changed')
    return value


def load_functions(path, wanted_sha, names, extra=None):
    """Setup-only replacement for remote paths; original definitions are exact."""
    row = retained_fixture()['sources'][Path(path).name]
    if row['sha256'] != wanted_sha:
        raise AssertionError('retained helper identity differs')
    tree = ast.parse(row['text'], filename=Path(path).name)
    selected = [node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name in names]
    if sorted(node.name for node in selected) != sorted(names):
        raise AssertionError('retained helper inventory differs')
    namespace = {'__name__': '__main__', 'digest': digest, 'sys': sys, 'weakref': weakref}
    if extra:
        namespace.update(extra)
    exec(compile(ast.Module(body=selected, type_ignores=[]), Path(path).name, 'exec'), namespace)
    return namespace


def selected(function, *args):
    with patch('json.dumps', side_effect=AssertionError('hosted full serializer entered')), \
         patch('json.loads', side_effect=AssertionError('hosted full parser entered')):
        return function(*args)


def reference_decode():
    import hepta.hia_program as program
    return getattr(program, '_reference_decode', program._decode)


def _native_fixture(cls):
    if sys.flags.optimize:
        raise RuntimeError('retained assert controls require normal Python execution')
    require_supported_interpreter()
    cold = os.environ.get(COLD_REPORT)
    development = os.environ.get(DEVELOPMENT_MANIFEST)
    if bool(cold) == bool(development):
        raise ValueError('select exactly one current cold report or explicit development manifest')
    base = os.environ.get(EVIDENCE_DIRECTORY)
    cls.temporary = None
    if base:
        base = Path(base).resolve()
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        cls.folder = base / cls.__name__
        cls.folder.mkdir(mode=0o700)
    else:
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-norm-')
        cls.folder = Path(cls.temporary.name)
    if cold:
        from tools.build_hia_program_normalization import build
        report = json.loads(Path(cold).read_bytes())
        nested = json.loads(Path(report['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        cls.manifest = build(cls.folder / 'native', compiler, Path(cold))
        cls.scope = 'MATCHING_SOURCE_COLD'
    else:
        cls.manifest = Path(development).resolve(strict=True)
        cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
    cls.metadata = json.loads(cls.manifest.read_bytes())
    cls.owner = normalization.installed_program_normalization(cls.manifest)
    paths = {cls.manifest, FIXTURE, *normalization.SOURCES.values(),
             *normalization.NOTE_SOURCES.values()}
    paths.update(cls.manifest.parent / row['image_path']
                 for row in cls.metadata['images'].values())
    note = cls.metadata['hosted_mechanisms']['cpython_notes']
    paths.update((cls.manifest.parent / note['image_path'],
                  cls.manifest.parent / note['production']['receipt_path'],
                  cls.manifest.parent / note['production']['packer_image_path']))
    cls.snapshots = {path: path.read_bytes() for path in paths}
    cls.observations = []
    print(json.dumps({'normalization_fixture_scope': cls.scope,
                      'manifest_sha256': digest(cls.snapshots[cls.manifest]),
                      'required_images': sorted(cls.metadata['images']),
                      'whole_owner_qualified': False}, sort_keys=True))


def _native_teardown(cls):
    for path, raw in cls.snapshots.items():
        if path.read_bytes() != raw:
            raise AssertionError('normalization fixture custody changed: ' + str(path))
    report = {'schema': 'hepta.hia.normalization-permanent-observations.v1',
              'status': 'OBSERVATIONS_RECORDED_SEE_TEST_RUNNER_RESULT',
              'scope': cls.scope, 'observations': cls.observations,
              'inputs': {str(path): digest(raw) for path, raw in cls.snapshots.items()},
              'source_inputs_unchanged': True, 'physical_recursion_qualified': False,
              'whole_owner_qualified': False, 'default_changed': False}
    put(cls.folder / 'observations.json', encoded(report))
    if cls.temporary is not None:
        cls.temporary.cleanup()


class ProgramNormalizationSourceTests(unittest.TestCase):
    def test_reproduces_exact_source_without_reading_the_final_output(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_program_normalization import document
        source = normalization.SOURCES['normalization']
        expected = source.read_bytes()
        original_bytes, original_text = Path.read_bytes, Path.read_text
        def read_bytes(path):
            if path == source:
                raise AssertionError('generator consumed its own final output')
            return original_bytes(path)
        def read_text(path, *args, **kwargs):
            if path == source:
                raise AssertionError('generator consumed its own final output')
            return original_text(path, *args, **kwargs)
        with patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
            value = document()
            actual = render_assembly(value).encode('utf-8')
        self.assertEqual(actual, expected)
        self.assertEqual(len(value['functions']), 100)
        self.assertLessEqual(max(len(f['blocks']) for f in value['functions']), 256)
        self.assertLessEqual(max(len(b['params']) for f in value['functions'] for b in f['blocks']), 16)

    def test_original_decode_snapshot_and_structure_definitions_are_retained(self):
        import hepta.hia_program as program
        fixture = retained_fixture()
        rows = {'_decode': fixture['original_decode'], **fixture['original_helpers']}
        for name, row in rows.items():
            with self.subTest(function=name):
                original = ast.parse(row['text']).body[0]
                actual_function = reference_decode() if name == '_decode' else getattr(program, name)
                actual = ast.parse(textwrap.dedent(inspect.getsource(actual_function))).body[0]
                actual.name = original.name
                self.assertEqual(ast.dump(actual, include_attributes=False),
                                 ast.dump(original, include_attributes=False))

    def test_independent_materialization_fragment_closure_is_real_input(self):
        from tools import hia_program_normalization_materialize as materialize
        path = Path(materialize.__file__).with_suffix('.hiaasm')
        self.assertEqual(digest(path.read_bytes()), materialize.FRAGMENT_SHA256)
        self.assertEqual(len(materialize.FRAGMENT_FUNCTIONS), 11)
        self.assertEqual(len(materialize.EXPORTS), 3)
        self.assertEqual(len(materialize.IMPORTS), 7)
        with self.assertRaises(ValueError):
            materialize.exported_bindings(True)
        names, signatures = materialize.exported_bindings(40)
        names.update({name: 'f' + str(i) for i, (name, _, _) in enumerate(materialize.IMPORTS.values())})
        signatures.update({name: (list(params), result)
                           for name, params, result in materialize.IMPORTS.values()})
        functions = materialize.fragment_functions(names, signatures, 40)
        self.assertEqual([f['name'] for f in functions], ['f' + str(i) for i in range(40, 51)])
        invalid = dict(names)
        invalid['norm_read'] = 'f40'
        with self.assertRaises(ValueError):
            materialize.fragment_functions(invalid, signatures, 40)

    def test_retained_controls_have_exact_original_definitions_and_order(self):
        fixture = retained_fixture()
        coordinator = fixture['sources']['late_errors_r8.py']['text']
        tree = ast.parse(coordinator)
        defined = {node.name for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        self.assertTrue({'coordinator_note_observe', 'coordinator_note_lifetime',
                         'coordinator_note_ack_fault', 'true_large_key_observe',
                         'late_error_lifetime', 'late_diagnostic_ack_fault'} <= defined)
        start = coordinator.index('    cases=[\n')
        stop = coordinator.index('    assert len(report["observations"])==108', start)
        block = coordinator[start:stop]
        self.assertIn('assert len(report["observations"])==51', block)
        self.assertIn('assert len(report["observations"])==78', block)
        self.assertIn('assert len(report["observations"])==92', block)
        self.assertIn('"late_integer_key_700"', block)
        self.assertIn('"true_key_"+name', block)
        self.assertEqual(set(normalization.SOURCES), {'normalization', 'front', 'binary64', 'binary64_format'})
        source = Path(normalization.__file__).read_text()
        self.assertNotIn('def _materialize_packet(', source)
        self.assertNotIn('NativeNominalJSON', source)


class ProgramNormalizationAdapterTests(unittest.TestCase):
    def test_unsupported_interpreters_refuse_before_manifest_io_or_mapping(self):
        import hepta.hia_program_normalization_notes as notes
        for version in ((3, 12, 14), (3, 13, 5), (3, 14, 10), (3, 15, 0)):
            with self.subTest(version=version), patch.object(notes.sys, 'version_info', version), \
                 patch.object(Path, 'read_bytes', side_effect=AssertionError('unqualified ABI read a manifest')), \
                 patch.object(normalization, '_mapped', side_effect=AssertionError('unqualified ABI mapped code')):
                with self.assertRaises(ValueError):
                    normalization.installed_program_normalization('/absent/manifest.json')
        with patch.object(notes.sys, 'version_info', (3, 14, 4)), \
             patch.object(notes.sysconfig, 'get_config_var', return_value=1):
            with self.assertRaises(ValueError):
                notes.require_supported_interpreter()

    def test_invalid_cold_admission_has_no_output_directory(self):
        from tools import build_hia_program_normalization as builder
        with tempfile.TemporaryDirectory(prefix='hia-norm-admit-') as folder:
            base = Path(folder)
            compiler, cold, output = base/'compiler', base/'cold.json', base/'out'
            compiler.write_bytes(b'controlled compiler fixture')
            cold.write_bytes(b'{}')
            with patch('hepta.hia_program_normalization_notes.require_supported_interpreter'), \
                 patch.object(builder, 'compile_stage', side_effect=AssertionError('invalid cold invoked compiler')):
                with self.assertRaises(ValueError):
                    builder.build(output, compiler, cold)
            self.assertFalse(output.exists())

    def test_compile_receipt_exact_numeric_types_and_hashes(self):
        from tools.build_hia_core_json_bytes import admit_compile_receipt
        compiler, source, image = b'compiler', b'input', b'code'
        receipt = {'status':'returned', 'format':'flat-x86-64',
            'return_encoding':'zero-extended-u32', 'artifact_sha256':digest(compiler),
            'image_sha256':digest(compiler), 'input_sha256':digest(source),
            'source_sha256':digest(source), 'produced_sha256':digest(image),
            'source_unchanged':True, 'forbidden_compiler_modules_loaded':[],
            'input_bytes':len(source), 'produced_bytes':len(image),
            'result_u64':len(image), 'core_u32':len(image), 'abi_status':0}
        admit_compile_receipt(receipt, compiler_bytes=compiler, source_bytes=source, image_bytes=image)
        for key in ('input_bytes','produced_bytes','result_u64','core_u32','abi_status'):
            for wrong in (True, False, float(receipt[key]), -1):
                with self.subTest(field=key, value=wrong):
                    changed = dict(receipt); changed[key] = wrong
                    with self.assertRaises(ValueError):
                        admit_compile_receipt(changed, compiler_bytes=compiler, source_bytes=source, image_bytes=image)
        for key in ('artifact_sha256','image_sha256','input_sha256','source_sha256','produced_sha256'):
            with self.subTest(field=key):
                changed = dict(receipt); changed[key] = '0' * 64
                with self.assertRaises(ValueError):
                    admit_compile_receipt(changed, compiler_bytes=compiler, source_bytes=source, image_bytes=image)

    def test_retained_standalone_builders_bind_typed_disk_receipts_and_final_inputs(self):
        import importlib
        from tools import build_hia_json_preflight as admission
        from tools import qualify_hia_selfhost as qualifier
        for module in ('build_hia_core_json_bytes', 'build_hia_nominal_json'):
            builder = importlib.import_module('tools.' + module)
            for mutation in ('none', 'receipt_type', 'duplicate_receipt_field',
                             'compiler_after_manifest', 'source_after_report',
                             'receipt_after_manifest', 'manifest_after_report'):
                with self.subTest(builder=module, mutation=mutation), \
                     tempfile.TemporaryDirectory(prefix='hia-json-builder-') as folder:
                    base=Path(folder);output=base/'out'
                    compiler,cold,source=base/'compiler',base/'cold',base/builder.SOURCE_NAME
                    compiler.write_bytes(b'compiler');cold.write_bytes(b'cold')
                    source.parent.mkdir(parents=True);source.write_bytes(b'original source')
                    sources={builder.SOURCE_NAME:digest(source.read_bytes())}
                    receipt_path=None
                    def current():
                        return {builder.SOURCE_NAME:digest(source.read_bytes())}
                    def compile_stage(directory,label,image,raw_source):
                        nonlocal receipt_path
                        raw=b'code';path=directory/(label+'.image.bin');path.write_bytes(raw)
                        receipt={'status':'returned','format':'flat-x86-64',
                            'return_encoding':'zero-extended-u32','artifact_sha256':digest(b'compiler'),
                            'image_sha256':digest(b'compiler'),'input_sha256':digest(raw_source),
                            'source_sha256':digest(raw_source),'produced_sha256':digest(raw),
                            'source_unchanged':True,'forbidden_compiler_modules_loaded':[],
                            'input_bytes':len(raw_source),'produced_bytes':len(raw),
                            'result_u64':len(raw),'core_u32':len(raw),'abi_status':0}
                        recorded=dict(receipt)
                        if mutation=='receipt_type':recorded['abi_status']=False
                        raw_receipt=encoded(recorded)
                        if mutation=='duplicate_receipt_field':
                            raw_receipt=b'{"abi_status":0,'+raw_receipt[1:]
                        receipt_path=directory/(label+'.receipt.json')
                        receipt_path.write_bytes(raw_receipt)
                        return path,receipt
                    original_write=Path.write_bytes
                    def write(path,data):
                        result=original_write(path,data)
                        if path==output/'manifest.json':
                            if mutation=='compiler_after_manifest':original_write(compiler,b'changed')
                            if mutation=='receipt_after_manifest':original_write(receipt_path,b'{}')
                        if path==output/'build.json':
                            if mutation=='source_after_report':original_write(source,b'changed')
                            if mutation=='manifest_after_report':original_write(output/'manifest.json',b'{}')
                        return result
                    # These fixed compile/transport stubs exercise actual disk
                    # readback only; no native compiler or cold run is claimed.
                    with patch.object(builder,'ROOT',base), \
                         patch.object(admission,'admit_cold_build',return_value=sources), \
                         patch.object(admission,'current_sources',side_effect=current), \
                         patch.object(qualifier,'compile_stage',side_effect=compile_stage), \
                         patch.object(Path,'write_bytes',write):
                        if mutation=='none':
                            self.assertEqual(builder.build(output,compiler,cold),output/'manifest.json')
                        else:
                            with self.assertRaises(ValueError):builder.build(output,compiler,cold)

    def test_builder_rechecks_actual_inputs_receipts_and_final_publications(self):
        from tools import build_hia_program_normalization as builder
        from tools.generate_hia_cpython_note_packer import reference_image
        note_image = reference_image()
        # Fixed transport stubs only. This tests custody/refusal order, not an
        # actual compiler, current-source cold run, or executable semantics.
        for mutation in ('none', 'compiler', 'cold', 'source', 'receipt', 'image',
                         'bool_emission', 'receipt_type', 'emission_receipt_type',
                         'manifest', 'report'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix='hia-norm-pub-') as folder:
                base = Path(folder); output = base/'out'
                compiler, cold = base/'compiler', base/'cold'
                compiler.write_bytes(b'compiler'); cold.write_bytes(b'cold')
                source_map = {}
                for name in builder.REQUIRED_SOURCE_NAMES:
                    path = base/name; path.parent.mkdir(parents=True, exist_ok=True)
                    data = ('source:' + name).encode()
                    path.write_bytes(data); source_map[name] = digest(data)
                def current():
                    return {name:digest((base/name).read_bytes()) for name in source_map}
                def receipt_for(label, source, image):
                    return {'status':'returned', 'format':'flat-x86-64',
                        'return_encoding':'zero-extended-u32', 'artifact_sha256':digest(b'compiler'),
                        'image_sha256':digest(b'compiler'), 'input_sha256':digest(source),
                        'source_sha256':digest(source), 'produced_sha256':digest(image),
                        'source_unchanged':True, 'forbidden_compiler_modules_loaded':[],
                        'input_bytes':len(source), 'produced_bytes':len(image),
                        'result_u64':len(image), 'core_u32':len(image), 'abi_status':0}
                def compile_stage(directory, label, image, source):
                    raw = ('native:' + label).encode()
                    path = directory/(label+'.image.bin'); path.write_bytes(raw)
                    receipt = receipt_for(label, source, raw)
                    recorded = dict(receipt)
                    if mutation == 'receipt' and label == 'normalization':
                        recorded['result_u64'] = True
                    if mutation == 'receipt_type' and label == 'normalization':
                        recorded['abi_status'] = False
                    (directory/(label+'.receipt.json')).write_bytes(encoded(recorded))
                    return path, receipt
                def invoke(directory, label, image, source, **kwargs):
                    raw = image.read_bytes()
                    result = {'status':'returned', 'format':'flat-x86-64',
                        'return_encoding':'zero-extended-u32', 'artifact_sha256':digest(raw),
                        'image_sha256':digest(raw), 'input_sha256':digest(b''),
                        'source_sha256':digest(b''), 'output_sha256':digest(note_image),
                        'source_unchanged':True, 'forbidden_compiler_modules_loaded':[],
                        'input_bytes':0, 'result_u64':len(note_image),
                        'core_u32':len(note_image), 'abi_status':0}
                    if mutation == 'bool_emission':
                        result['abi_status'] = False
                    recorded = dict(result)
                    if mutation == 'emission_receipt_type':
                        recorded['abi_status'] = False
                    (directory/(label+'.receipt.json')).write_bytes(encoded(recorded))
                    if mutation in ('compiler', 'cold'):
                        (compiler if mutation == 'compiler' else cold).write_bytes(b'changed')
                    elif mutation == 'source':
                        (base/builder.NOTE_SOURCE).write_bytes(b'changed')
                    elif mutation == 'image':
                        image.write_bytes(b'changed')
                    return result, note_image
                interpreter = base/'interpreter'; interpreter.write_bytes(b'actual identity fixture')
                class Notes:
                    def __init__(self, raw, digest_):
                        self.interpreter_identity = {'executable':str(interpreter), 'version':'fixed test',
                            'hexversion':1, 'soabi':'fixed', 'executable_sha256':digest(interpreter.read_bytes())}
                        self.api_identity = tuple({'name':name,'image':str(interpreter),
                            'image_sha256':digest(interpreter.read_bytes())}
                            for name in normalization.NOTE_API_NAMES)
                    def close(self): pass
                publish = builder._publish
                def checked_publish(path, raw):
                    publish(path, raw)
                    if (mutation == 'manifest' and path.name == 'manifest.json'
                            or mutation == 'report' and path.name == 'build.json'):
                        path.write_bytes(raw + b' ')
                with patch.object(builder, 'ROOT', base), \
                     patch.object(builder, 'admit_cold_build', return_value=source_map), \
                     patch.object(builder, 'current_sources', side_effect=current), \
                     patch.object(builder, 'compile_stage', side_effect=compile_stage), \
                     patch.object(builder, 'invoke', side_effect=invoke), \
                     patch.object(builder, '_publish', side_effect=checked_publish), \
                     patch('hepta.hia_program_normalization_notes.require_supported_interpreter'), \
                     patch('hepta.hia_program_normalization_notes.NativeCPythonNotes', Notes):
                    if mutation == 'none':
                        manifest = builder.build(output, compiler, cold)
                        self.assertTrue(manifest.is_file())
                        report = json.loads((output/'build.json').read_bytes())
                        self.assertFalse(report['whole_stack_rewritten_in_hia'])
                        self.assertEqual(set(report['manifest']['images']), set(builder.COMPONENTS))
                    else:
                        with self.assertRaises(ValueError):
                            builder.build(output, compiler, cold)


class ProgramNormalizationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _native_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        _native_teardown(cls)

    def test_retained_102_original_normalization_controls(self):
        fixture = retained_fixture()
        text = fixture['sources']['late_errors_r8.py']['text']
        selected_names = {'NoteChildError', 'NoteReplacement',
            'coordinator_note_observe', 'coordinator_note_lifetime',
            'coordinator_note_ack_fault', 'true_large_key_observe',
            'late_error_lifetime', 'late_diagnostic_ack_fault'}
        nodes = [n for n in ast.parse(text).body
                 if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in selected_names]
        self.assertEqual({n.name for n in nodes}, selected_names)
        helpers = load_functions('probe_cpython314_notes_r1.py',
            fixture['sources']['probe_cpython314_notes_r1.py']['sha256'], {'state'})
        baseline = load_functions('cause_terminal_r4.py',
            fixture['sources']['cause_terminal_r4.py']['sha256'],
            {'safe_value','error_state','outcome','late','fixture','observe_foreign','held_error_lifetime'})
        temporary = load_functions('temporary_cause_r4_original_r1.py',
            fixture['sources']['temporary_cause_r4_original_r1.py']['sha256'],
            {'late','fixture','observe'})
        properties = load_functions('front_diagnostics_r4_independent_r1.py',
            fixture['sources']['front_diagnostics_r4_independent_r1.py']['sha256'], {'property_case'},
            {'VerifiedProgram':VerifiedProgram,'outcome':baseline['outcome'],'first':b'1'*700})
        report = {'observations':[], 'differences':[]}
        def record(group, name, original, actual):
            row = {'group':group,'case':name,'original':original,'native':actual,'equal':original==actual}
            report['observations'].append(row)
            if not row['equal']:
                report['differences'].append(name)
        namespace = {'__name__':'__main__','sys':sys,'gc':gc,'weakref':weakref,'patch':patch,
            'ROOT':ROOT,'baseline':baseline,'temporary':temporary,'properties':properties,
            'note_state':helpers['state'],'HIAProgramRejected':HIAProgramRejected,
            'owner':self.owner,'_decode':reference_decode(),'outcome':baseline['outcome'],
            'report':report,'record':record,'selected':selected,'load_functions':load_functions}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'late_errors_r8.py','exec'),namespace)
        start = text.index('    cases=[\n')
        stop = text.index('    for name in ("receipt_path_escape"', start)
        block = 'if True:\n' + text[start:stop]
        try:
            with patch.dict(os.environ,{key:'' for key in os.environ if key.startswith('HEPTA_HIA_')}):
                exec(compile(block,'retained-normalization-102','exec'),namespace)
        finally:
            self.observations.extend(report['observations'])
        self.assertEqual(len(report['observations']),102)
        self.assertEqual(report['differences'],[])

    def test_six_producer_admission_controls_before_mapping(self):
        note = self.metadata['hosted_mechanisms']['cpython_notes']
        production_path = self.manifest.parent / note['production']['receipt_path']
        production = json.loads(production_path.read_bytes())
        packer = (self.manifest.parent / note['production']['packer_image_path']).read_bytes()
        for name in ('receipt_path_escape','packer_bytes_changed','source_snapshot_changed',
                     'bool_compile_result','different_emitted_image','bool_emission_result'):
            with self.subTest(case=name):
                folder = self.folder/('admission-'+name);folder.mkdir(mode=0o700)
                # Each trial has its own immutable source-image/receipt copies.
                for path, raw in self.snapshots.items():
                    if path.parent == self.manifest.parent:
                        put(folder/path.name,raw)
                changed = copy.deepcopy(self.metadata)
                declaration = changed['hosted_mechanisms']['cpython_notes']['production']
                receipt = copy.deepcopy(production)
                cold = receipt['schema'] == 'hepta.hia.cpython-note-packer-production.v2'
                if name == 'receipt_path_escape':
                    declaration['receipt_path'] = '../outside.json'
                elif name == 'packer_bytes_changed':
                    raw = bytes([packer[0]^1])+packer[1:]
                    filename = 'changed-packer.image.bin';put(folder/filename,raw)
                    declaration['packer_image_path'], declaration['packer_image_sha256'] = filename,digest(raw)
                else:
                    if name == 'source_snapshot_changed':
                        if cold:
                            receipt['source_manifest'][normalization.NOTE_PACKER_SOURCE] = '0'*64
                        else:
                            for field in ('packer_source_before','packer_source_after'):
                                receipt[field]['sha256'] = '0'*64
                    elif name == 'bool_compile_result':
                        receipt['native_compilation']['result_u64'] = True
                    elif name == 'different_emitted_image':
                        if cold: receipt['native_emission']['output_sha256'] = '0'*64
                        else: receipt['observations'][0]['actual']['output_sha256'] = '0'*64
                    elif name == 'bool_emission_result':
                        if cold: receipt['native_emission']['result_u64'] = True
                        else: receipt['observations'][0]['actual']['result_u64'] = True
                    raw = encoded(receipt);put(folder/'changed.receipt.json',raw)
                    declaration['receipt_path'], declaration['receipt_sha256'] = 'changed.receipt.json',digest(raw)
                path=folder/'changed.manifest.json';put(path,encoded(changed))
                with patch.object(normalization,'_mapped',side_effect=AssertionError('invalid production reached mapping')):
                    with self.assertRaises(ValueError):
                        normalization.installed_program_normalization(path)
                self.observations.append({'group':'HIA_note_production_admission','case':name,
                    'refused_before_mapping':True,'original_inputs_unchanged':True,
                    'receipt_setup':'current-schema mutation; original semantic assertions retained'})

    def test_removed_packet_dependency_is_neither_selected_nor_executed(self):
        from hepta.hia_nominal_json_native import NativeNominalJSON
        self.assertEqual(set(self.owner.images),{'normalization','front','binary64','binary64_format'})
        image = self.owner.images['normalization']
        entry = image._entry
        calls=[]
        def counted(*args):
            calls.append(True)
            return entry(*args)
        with patch.object(NativeNominalJSON,'__init__',side_effect=AssertionError('obsolete packet admitted')), \
             patch.object(NativeNominalJSON,'packet',side_effect=AssertionError('obsolete packet executed')), \
             patch.object(image,'_entry',side_effect=counted):
            value,wire=selected(self.owner.normalize_program,b'{"z":[0,null],"a":true}')
        self.assertEqual(value,{'a':True,'z':[0,None]})
        self.assertEqual(wire,b'{"a":true,"z":[0,null]}')
        self.assertGreater(len(calls),0)
        changed=copy.deepcopy(self.metadata);changed['images']['packet']={}
        path=self.folder/'obsolete-packet.manifest.json';put(path,encoded(changed))
        with patch.object(normalization,'_mapped',side_effect=AssertionError('obsolete protocol mapped')):
            with self.assertRaises(ValueError):
                normalization.installed_program_normalization(path)
        self.observations.append({'case':'removed_packet_actual_entries','native_entries':len(calls),
                                  'obsolete_admission_refused':True})

    def test_exact_issued_frames_outcomes_and_no_replay(self):
        Context=normalization.NormalizationContext
        Error=normalization.NormalizationProtocolError
        for altered in ('frame','reply','observed_again'):
            with self.subTest(altered=altered):
                context=Context(self.owner,{'key':[0]})
                frame=context._issued
                if altered=='frame':
                    changed=tuple(list(frame));self.assertIsNot(changed,frame)
                    with self.assertRaises(Error):context.observe(changed)
                else:
                    reply=context.observe(frame)
                    if altered=='reply':
                        changed=tuple(list(reply));self.assertIsNot(changed,reply)
                        with self.assertRaises(Error):context.accept(frame,changed)
                    else:
                        with self.assertRaises(Error):context.observe(frame)
                self.assertTrue(context.closed)
                self.assertIsNone(context.output);self.assertIsNone(context.workspace)
                with self.assertRaises(Error):context.observe(frame)

    def test_real_partial_constructor_allocations_close_and_preserve_error_identity(self):
        import mmap
        Context=normalization.NormalizationContext
        original=mmap.mmap
        image=self.owner.images['normalization']
        for fail_at in (1,2):
            for kind in (MemoryError,KeyboardInterrupt):
                with self.subTest(allocation=fail_at,error=kind.__name__):
                    context=object.__new__(Context)
                    allocated=[];calls=[]
                    error=kind('controlled arena allocation boundary')
                    def allocate(*args,**kwargs):
                        calls.append(True)
                        if len(calls)==fail_at:raise error
                        result=original(*args,**kwargs);allocated.append(result)
                        return result
                    with patch.object(normalization.mmap,'mmap',side_effect=allocate), \
                         patch.object(image,'_entry',side_effect=AssertionError('partial constructor entered native code')):
                        try:Context.__init__(context,self.owner,None)
                        except BaseException as observed:self.assertIs(observed,error)
                        else:self.fail('constructor allocation fault did not fire')
                    self.assertEqual(len(calls),fail_at)
                    self.assertTrue(context.closed and context._failed)
                    self.assertIsNone(context.workspace);self.assertIsNone(context.output)
                    self.assertTrue(all(arena.closed for arena in allocated))
                    self.observations.append({'case':'actual_partial_constructor',
                        'allocation':fail_at,'exception':kind.__name__,
                        'actual_prior_allocations':len(allocated),'all_closed':True,
                        'original_error_identity_preserved':True,'native_entries':0})

    def test_failed_close_retains_own_mapping_and_original_exception(self):
        context=normalization.NormalizationContext(self.owner,None)
        output,workspace=context.output,context.workspace
        close_error=OSError('controlled close handoff')
        original=KeyboardInterrupt('original operation interruption')
        calls=[]
        class FailingClose:
            def __init__(self,arena):self.arena=arena
            def close(self):
                calls.append(True)
                raise close_error
        retained=FailingClose(output)
        context.output=retained
        try:
            try:raise original
            except KeyboardInterrupt:
                context._failed=True
                context._close_preserving_error()
                self.assertIs(sys.exception(),original)
            self.assertTrue(context.closed)
            self.assertIs(context.output,retained)
            self.assertIs(context.cleanup_error,close_error)
            self.assertEqual(len(calls),1)
            self.assertFalse(output.closed)
            self.assertTrue(workspace.closed)
            self.assertIsNone(context.workspace)
            self.observations.append({'case':'controlled_close_failure_custody',
                'actual_mapping_retained':True,'unaffected_mapping_closed':True,
                'original_exception_preserved':True,'close_attempts':1,
                'scope':'injected transport close failure; not an OS close failure claim'})
        finally:
            # Release only the test-owned actual mapping after the observation.
            output.close()
            context.output=None

    def test_all_frames_and_complete_workspace_match_independent_Core_VM(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        with patch.dict(os.environ,{key:'' for key in os.environ if key.startswith('HEPTA_HIA_')}):
            checked=assemble_program(normalization.SOURCES['normalization'].read_bytes())
        libc=ctypes.CDLL(None)
        memcmp=libc.memcmp
        memcmp.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t]
        memcmp.restype=ctypes.c_int
        for name,value in (('null',None),('detached-list',[True,0])):
            with self.subTest(case=name):
                machine=_Machine(checked,10_000_000,512<<20,None,256)
                work=bytearray(normalization.WORKSPACE_BYTES)
                output=bytearray(normalization.MAX_BYTES+normalization.FRAME.size)
                work_root,output_root=_Owner(1,work),_Owner(2,output)
                work_view,output_view=_View(work_root,True),_View(output_root,True)
                image=self.owner.images['normalization'];entry=image._entry
                frames=[]
                def compare(source,size,out_address,out_size,work_address,work_size):
                    self.assertEqual(out_size,len(output))
                    self.assertEqual(work_size,len(work))
                    raw=ctypes.string_at(source,size)
                    request_root=_Owner(3,bytearray(raw))
                    status=machine.invoke(machine.functions['f0'],
                        [_View(request_root,False),output_view,work_view])
                    self.assertEqual(len(status),1)
                    actual=entry(source,size,out_address,out_size,work_address,work_size)
                    self.assertEqual(actual,status[0])
                    self.assertEqual(bytes(request_root.data),raw)
                    self.assertEqual(ctypes.string_at(source,size),raw)
                    output_pointer=ctypes.addressof(ctypes.c_char.from_buffer(output))
                    work_pointer=ctypes.addressof(ctypes.c_char.from_buffer(work))
                    self.assertEqual(memcmp(out_address,output_pointer,len(output)),0)
                    self.assertEqual(memcmp(work_address,work_pointer,len(work)),0)
                    frames.append({'request_sha256':digest(raw),
                        'return':actual,'frame':list(normalization.FRAME.unpack_from(output)),
                        'complete_output_equal':True,'complete_workspace_equal':True})
                    return actual
                with patch.object(image,'_entry',side_effect=compare), \
                     patch.dict(os.environ,{key:'' for key in os.environ if key.startswith('HEPTA_HIA_')}):
                    actual=selected(self.owner.normalize_program,value)
                    expected=reference_decode()(value)
                self.assertEqual(actual,expected)
                self.assertGreater(len(frames),2)
                self.observations.append({'case':'whole_Core_VM_frames_'+name,
                    'frames':frames,'VM_steps':machine.steps,
                    'workspace_bytes_compared_per_frame':len(work),
                    'output_bytes_compared_per_frame':len(output),
                    'scope':'direct private three-buffer ABI; original independent Core machine'})
                del work_view,output_view,work_root,output_root,work,output,machine

    def test_installed_wheel_without_authoring_or_source_tree_fallback(self):
        work=self.folder/'installed-wheel';work.mkdir(mode=0o700)
        source=work/'project';source.mkdir(mode=0o700)
        for name in ('pyproject.toml','setup.py','MANIFEST.in','README.md'):
            shutil.copyfile(ROOT/name,source/name)
        for path in ROOT.glob('LICENSE*'):
            if path.is_file():shutil.copyfile(path,source/path.name)
        shutil.copytree(ROOT/'hepta',source/'hepta',
                        ignore=shutil.ignore_patterns('__pycache__','*.pyc','_data'))
        contract=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
        resources=[]
        for name in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','PUBLICATION_BUILD_FILES'):
            rows=[node for node in contract.body if isinstance(node,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id==name for t in node.targets)]
            self.assertEqual(len(rows),1,name)
            names=ast.literal_eval(rows[0].value)
            resources.extend(('docs/'+p for p in names) if name=='DISCOVERY_FILES' else names)
        required={str(path.relative_to(ROOT)) for path in
                  {*normalization.SOURCES.values(),*normalization.NOTE_SOURCES.values()}}
        self.assertTrue(required<=set(resources),('unregistered installed resources',sorted(required-set(resources))))
        for name in resources:
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,target)
        wheels=work/'wheels';wheels.mkdir()
        result=subprocess.run([sys.executable,'-B','-m','pip','wheel','--no-deps',
            '--no-build-isolation','--wheel-dir',str(wheels),str(source)],
            capture_output=True,timeout=120)
        put(work/'wheel.stdout',result.stdout);put(work/'wheel.stderr',result.stderr)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        packages=list(wheels.glob('*.whl'));self.assertEqual(len(packages),1)
        installed=work/'installed';installed.mkdir()
        with zipfile.ZipFile(packages[0]) as wheel:
            for name in wheel.namelist():
                self.assertFalse(Path(name).is_absolute() or '..' in Path(name).parts)
            wheel.extractall(installed)
        child = r'''
import importlib.abc,json,os,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed application imported authoring tools')
sys.meta_path.insert(0,NoAuthoring())
import hepta.hia_program_normalization_native as native
assert Path(native.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
owner=native.installed_program_normalization(sys.argv[2])
with patch('json.dumps',side_effect=AssertionError('hosted serializer')), patch('json.loads',side_effect=AssertionError('hosted parser')):
    value,wire=owner.normalize_program(b' {"z":0,"a":[true,null]} ')
assert value=={'a':[True,None],'z':0} and wire==b'{"a":[true,null],"z":0}'
source=native.SOURCES['normalization'];raw=source.read_bytes()
source.unlink()
try:
    try:native.installed_program_normalization(sys.argv[2])
    except OSError:pass
    else:raise AssertionError('missing installed source fell back to checkout or warm image')
finally:source.write_bytes(raw)
source.write_bytes(raw+b'\n')
try:
    try:native.installed_program_normalization(sys.argv[2])
    except ValueError:pass
    else:raise AssertionError('changed installed source reused a warm image')
finally:source.write_bytes(raw)
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
print(json.dumps({'actual_normalization':True,'missing_resource_refused':True,'tampered_resource_refused':True,'authoring_imported':False}))
'''
        environment={key:value for key,value in os.environ.items()
                     if not key.startswith('HEPTA_HIA_') and key not in ('PYTHONPATH','PYTHONHOME')}
        environment['PATH']=''
        result=subprocess.run([sys.executable,'-I','-B','-c',child,str(installed),str(self.manifest)],
            cwd=work,env=environment,capture_output=True,timeout=30)
        put(work/'application.stdout',result.stdout);put(work/'application.stderr',result.stderr)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        self.observations.append({'case':'installed_wheel_no_authoring_empty_PATH',
                                  'result':json.loads(result.stdout)})


if __name__ == '__main__':
    unittest.main()
