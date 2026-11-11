"""Snapshot-bound native edits, independent VM and real whole-Core refusals."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import copy
import ctypes
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

from hepta.hia_program import verify_program
from hepta.hia_program_tools import (apply_program_patch, HIAEditRejected,
                                    PATCH_SCHEMA, PATCH_SCHEMA_V2)
from hepta.hia_core_patch_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    ERROR_MESSAGES, NativeCorePatch, envelope, scratch_sizes, installed_core_patch)
from tests.test_hia_program_tools import scalar_program, add_two_patch


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def request_wire(program, request):
    return envelope(verify_program(program).canonical_bytes, wire(request))


def interpreted(raw, *, extract=False, result_schema=None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes())
    out_size, arena_size = scratch_sizes(len(raw))
    if result_schema is not None:
        from hepta.hia_agent_candidate_native import MAX_RESULT
        out_size = MAX_RESULT
    arena = bytearray(arena_size)
    struct.pack_into('<Q', arena, 0, int(not extract) if result_schema is None else 2)
    if result_schema is not None:
        struct.pack_into('<Q', arena, 8, result_schema)
    roots = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(out_size)), _Owner(-3, arena)]
    machine = _Machine(checked, 20_000_000, 256 << 20, None, 256)
    result = machine.invoke(checked.as_dict()['functions'][0],
        [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)])[0]
    return result, bytes(roots[1].data[:result]) if result < 0xffffffe0 else None


def four_kinds():
    program = scalar_program()
    operation = add_two_patch(program)
    terminator = copy.deepcopy(operation)
    terminator['edits'] = [{'action':'replace_terminator', 'function':'increment',
                          'block':'entry', 'term':{'op':'ret', 'values':['x']}}]
    function = copy.deepcopy(operation)
    definition = copy.deepcopy(program['functions'][0])
    definition['blocks'][0]['ops'][0]['attrs']['value'] = 4
    function['edits'] = [{'action':'replace_function', 'function':'increment',
                         'definition':definition}]
    added = copy.deepcopy(function)
    definition = copy.deepcopy(definition)
    definition['name'] = 'another'
    added.update(schema=PATCH_SCHEMA_V2, interface_policy='migrate')
    added['edits'] = [{'action':'add_function', 'function':'another', 'definition':definition}]
    return program, [operation, terminator, function, added]


class CorePatchSourceTests(unittest.TestCase):
    def test_checked_in_HIA_source_and_independent_VM_before_native(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from tools.generate_hia_core_patch import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 59)
        program, cases = four_kinds()
        raw = request_wire(program, cases[0])
        expected = verify_program(program).canonical_bytes
        code, output = interpreted(raw, extract=True)
        self.assertEqual(code, 32 + len(expected))
        self.assertEqual(output, struct.pack('<4Q', MAGIC, 0, 0, 0) + expected)
        for request in cases:
            with self.subTest(action=request['edits'][0]['action']):
                wanted = apply_program_patch(program, request)[0].canonical_bytes
                code, output = interpreted(request_wire(program, request))
                self.assertEqual(code, 32 + len(wanted))
                self.assertEqual(output[32:], wanted)

    def test_independent_VM_stale_overlap_and_exact_types(self):
        program = scalar_program()
        request = add_two_patch(program)
        request['expected_sha256'] = '0' * 64
        self.assertEqual(interpreted(request_wire(program, request))[0], 0xfffffff9)
        request = add_two_patch(program)
        request['edits'] *= 2
        self.assertEqual(interpreted(request_wire(program, request))[0], 0xfffffff3)
        request = add_two_patch(program)
        request['edits'][0]['index'] = False
        self.assertEqual(interpreted(request_wire(program, request))[0], 0xfffffff4)

    def test_mode2_independent_VM_returns_exact_sorted_migration_diagnostics(self):
        from hepta.hia_agent_candidate_native import result_payloads
        from hepta.hia_agent_store import wire as canonical_wire
        program = scalar_program()
        request = {**add_two_patch(program), 'schema':PATCH_SCHEMA_V2,
                   'interface_policy':'migrate', 'edits':[]}
        for name in ('zeta','alpha'):
            definition = copy.deepcopy(program['functions'][0])
            definition['name'] = name
            request['edits'].append({'action':'add_function','function':name,'definition':definition})
        expected, receipt = apply_program_patch(program, request)
        code, output = interpreted(request_wire(program,request), result_schema=2)
        self.assertEqual(code,32+len(expected.canonical_bytes)+len(canonical_wire(receipt)))
        self.assertEqual(result_payloads(output),(expected.canonical_bytes,canonical_wire(receipt)))
        self.assertEqual(receipt['interface_changes'],['alpha','zeta'])


class CorePatchNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        program = scalar_program()
        request = add_two_patch(program)
        expected = apply_program_patch(program, request)[0].canonical_bytes
        code, output = interpreted(request_wire(program, request))
        assert code == len(expected) + 32 and output[32:] == expected
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-core-patch-')
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cold = os.environ.get('HEPTA_HIA_CORE_PATCH_COLD_REPORT')
        if cold:
            from tools.build_hia_core_patch_cli import current_sources, REQUIRED_CHECKS
            from tools.hia_selfhost_contract import PROFILE
            report = json.loads(Path(cold).read_bytes())
            assert (report.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
                    and report.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
                    and type(report.get('returncode')) is int and report['returncode'] == 0
                    and report.get('profile') == PROFILE
                    and report.get('source_manifest') == current_sources()
                    and type(report.get('checks')) is dict
                    and set(report['checks']) == REQUIRED_CHECKS
                    and all(value is True for value in report['checks'].values()))
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256'] == [sha256(compiler.read_bytes()).hexdigest()] * 3
        else:
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
        cls.compiler = compiler
        image, cls.receipt = compile_stage(cls.folder, 'patch', compiler, SOURCE.read_bytes())
        raw = image.read_bytes()
        cls.native = NativeCorePatch(raw, sha256(raw).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
        from hepta.hia_core_admission_native import SOURCE as ASOURCE, SCHEMA as ASCHEMA, NativeCoreAdmission
        admission, cls.admission_receipt = compile_stage(cls.folder, 'admission', compiler, ASOURCE.read_bytes())
        raw = admission.read_bytes()
        cls.admission = NativeCoreAdmission(raw, sha256(raw).hexdigest())
        cls.admission_manifest = cls.folder / 'admission-manifest.json'
        cls.admission_manifest.write_text(json.dumps(dict(schema=ASCHEMA, source_sha256=sha256(ASOURCE.read_bytes()).hexdigest(),
            image_path=admission.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def checked_apply(self, program, request):
        raw = request_wire(program, request)
        original, _, _, _ = self.native.transform(raw, extract=True)
        self.admission.admit(original)
        result = self.native.transform(raw)
        self.admission.admit(result[0])
        return result

    def test_all_four_edits_match_independent_reference_and_complete_bytes(self):
        program, cases = four_kinds()
        for request in cases:
            expected, receipt = apply_program_patch(program, request)
            result, schema, policy, count = self.checked_apply(program, request)
            self.assertEqual(result, expected.canonical_bytes)
            self.assertEqual(schema, 2 if request['schema'] == PATCH_SCHEMA_V2 else 1)
            self.assertEqual(policy, int(request.get('interface_policy') == 'migrate'))
            self.assertEqual(count, len(request['edits']))
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])
        self.assertEqual(self.admission_receipt['forbidden_compiler_modules_loaded'], [])

    def test_native_payload_pipeline_uses_no_host_JSON_or_patch_transform(self):
        program = scalar_program()
        request = add_two_patch(program)
        raw = request_wire(program, request)
        expected = apply_program_patch(program, request)[0].canonical_bytes
        with patch('json.loads', side_effect=AssertionError('host payload parser')), \
             patch('json.dumps', side_effect=AssertionError('host payload serializer')), \
             patch.object(json.JSONDecoder, 'decode', side_effect=AssertionError('host decoder')):
            original, _, _, _ = self.native.transform(raw, extract=True)
            self.admission.admit(original)
            actual = self.native.transform(raw)[0]
            self.admission.admit(actual)
        self.assertEqual(actual, expected)

    def test_generated_inputs_and_concurrent_native_mutations_are_isolated(self):
        program = scalar_program()
        rng = random.Random(0x484941)
        requests = []
        expected = []
        for _ in range(64):
            request = add_two_patch(program)
            request['edits'][0]['operation']['attrs']['value'] = rng.randrange(1 << 32)
            requests.append(request_wire(program, request))
            expected.append(apply_program_patch(program, request)[0].canonical_bytes)
        self.assertEqual(list(ThreadPoolExecutor(8).map(lambda raw:self.native.transform(raw)[0], requests)), expected)
        self.assertEqual(program, scalar_program())

    def test_duplicate_overlap_in_both_orders_and_distinct_simultaneous_sites(self):
        program = scalar_program()
        op = add_two_patch(program)['edits'][0]
        whole = {'action':'replace_function', 'function':'increment', 'definition':program['functions'][0]}
        term = {'action':'replace_terminator', 'function':'increment', 'block':'entry',
                'term':{'op':'ret','values':['x']}}
        for edits in ([op,op], [op,whole], [whole,op], [whole,whole], [term,term]):
            request = {**add_two_patch(program), 'edits':edits}
            with self.assertRaises(HIAEditRejected):self.checked_apply(program, request)
        request = {**add_two_patch(program), 'edits':[op,term]}
        self.assertEqual(self.checked_apply(program,request)[0], apply_program_patch(program,request)[0].canonical_bytes)

    def test_reject_fields_stale_hash_indices_unknown_kinds_and_wrong_names(self):
        program = scalar_program()
        changes = [lambda p:p.update(schema='unknown'), lambda p:p.update(extra=True),
            lambda p:p.update(expected_sha256='0'*64), lambda p:p.update(expected_sha256='F'*64),
            lambda p:p.update(expected_sha256='a'*63), lambda p:p.update(edits=[]),
            lambda p:p.update(edits=p['edits']*65),
            lambda p:p['edits'][0].update(action='remove_function'),
            lambda p:p['edits'][0].update(function='missing'), lambda p:p['edits'][0].update(block='missing'),
            lambda p:p['edits'][0].update(index=False), lambda p:p['edits'][0].update(index=-1),
            lambda p:p['edits'][0].update(index=2), lambda p:p['edits'][0].update(index=1 << 64),
            lambda p:p['edits'][0].update(index=0.0), lambda p:p['edits'][0].update(extra=True)]
        for change in changes:
            request = add_two_patch(program)
            change(request)
            with self.assertRaises(ValueError):apply_program_patch(program,request)
            with self.assertRaises(ValueError):self.checked_apply(program,request)
        raw = request_wire(program, add_two_patch(program))
        with self.assertRaisesRegex(HIAEditRejected,'duplicate'):
            self.native.transform(raw.replace(b'"index":0', b'"index":0,"index":0'))
        with self.assertRaises(ValueError):self.native.transform(b'[{},{}] trailing')

    def test_full_64_edit_boundary_and_original_snapshot_canonicalization(self):
        program = scalar_program()
        block = program['functions'][0]['blocks'][0]
        block['ops'] = [{'op':'const','args':[], 'out':[{'name':'n'+str(i),'type':'u32'}],
                         'attrs':{'value':i}} for i in range(64)]
        block['term'] = {'op':'ret','values':['n63']}
        request = {'schema':PATCH_SCHEMA,'expected_sha256':verify_program(program).sha256,
            'edits':[{'action':'replace_operation','function':'increment','block':'entry',
                      'index':i,'operation':{**block['ops'][i],'attrs':{'value':100+i}}} for i in range(64)]}
        expected = apply_program_patch(program,request)[0].canonical_bytes
        actual = self.checked_apply(program,request)
        self.assertEqual(actual[0],expected)
        self.assertEqual(actual[3],64)
        # Identity is the canonical snapshot, independent of JSON spacing and
        # escaped spelling of an existing key; no host canonicalizer is used.
        raw = b'[\n'+json.dumps(program,indent=2).encode()+b',\n'+wire(request)+b'\n]'
        raw = raw.replace(b'"module"', b'"modul\\u0065"')
        self.assertEqual(self.native.transform(raw)[0],expected)
        for prefix,suffix in ((b' \n\t',b''),(b'',b'\r\n\t '),(b' \r\n',b' \n')):
            padded = prefix+raw+suffix
            self.assertEqual(self.native.transform(padded,extract=True)[0],verify_program(program).canonical_bytes)
            self.assertEqual(self.native.transform(padded)[0],expected)
        request['edits'].append(copy.deepcopy(request['edits'][0]))
        with self.assertRaisesRegex(HIAEditRejected,'1..64'):
            self.native.transform(request_wire(program,request))

    def test_original_component_byte_quota_cannot_be_erased_by_canonicalization(self):
        from hepta.hia_core_patch_native import MAX_COMPONENT
        program = scalar_program()
        base = verify_program(program).canonical_bytes
        request = wire(add_two_patch(program))
        for component in ('base','patch'):
            source = base if component == 'base' else request
            exact = b'{' + b' '*(MAX_COMPONENT-len(source)) + source[1:]
            self.assertEqual(len(exact),MAX_COMPONENT)
            raw = b'['+(exact if component == 'base' else base)+b','+(request if component == 'base' else exact)+b']'
            self.assertEqual(self.native.transform(raw,extract=True)[0],base)
            too_large = b'{ '+exact[1:]
            raw = b'['+(too_large if component == 'base' else base)+b','+(request if component == 'base' else too_large)+b']'
            with self.assertRaisesRegex(HIAEditRejected,'capacity'):
                self.native.transform(raw,extract=True)

    def test_explicit_migration_and_default_returned_loan_interface(self):
        program, cases = four_kinds()
        added = copy.deepcopy(cases[-1])
        added['interface_policy'] = 'preserve'
        with self.assertRaisesRegex(HIAEditRejected,'interface'):self.checked_apply(program,added)
        program['schema'] = 'hepta.hia.program.v8'
        definition = copy.deepcopy(program['functions'][0])
        definition['return_loans'] = [None]
        request = {**add_two_patch(program), 'edits':[{'action':'replace_function',
            'function':'increment', 'definition':definition}]}
        self.assertEqual(self.checked_apply(program,request)[0], apply_program_patch(program,request)[0].canonical_bytes)
        # Reordered effects are an interface change under the existing policy.
        definition['effects'] = ['trap','read']
        with self.assertRaisesRegex(HIAEditRejected,'interface'):self.checked_apply(program,request)
        request.update(schema=PATCH_SCHEMA_V2, interface_policy='migrate')
        self.assertEqual(self.checked_apply(program,request)[0], apply_program_patch(program,request)[0].canonical_bytes)

    def test_full_native_recheck_refuses_semantically_invalid_candidate(self):
        program = scalar_program()
        request = add_two_patch(program)
        request['edits'][0]['operation'] = {'op':'int.add.wrap','args':['x','undefined'],
            'out':[{'name':'one','type':'u32'}], 'attrs':{}}
        raw = request_wire(program, request)
        # Transform success alone does not claim an admitted candidate.
        candidate, _, _, _ = self.native.transform(raw)
        self.assertNotEqual(self.admission.status(candidate), 0)
        with patch.dict(os.environ, {SELECTOR:str(self.manifest)}):
            with self.assertRaisesRegex(HIAEditRejected, 'admission refused'):
                apply_program_patch(program, request)

    def test_actual_public_patch_entry_selects_native_edits_and_keeps_receipts(self):
        import hepta.hia_program_tools as tools
        program, cases = four_kinds()
        expected = [apply_program_patch(program,request) for request in cases]
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}), \
             patch.object(tools,'_keys',side_effect=AssertionError('host edit path')):
            for request,(candidate,receipt) in zip(cases,expected):
                actual,actual_receipt = apply_program_patch(program, request)
                self.assertEqual(actual.canonical_bytes,candidate.canonical_bytes)
                self.assertEqual(actual_receipt,receipt)

    def test_malformed_and_undersized_ABI_preserves_external_canaries(self):
        raw = request_wire(scalar_program(),add_two_patch(scalar_program()))
        output_size,arena_size = scratch_sizes(len(raw))
        source = ctypes.create_string_buffer(raw)
        for mode,output_cap,arena_cap in ((2,output_size,arena_size),(1,100,arena_size),(1,output_size,100)):
            output = ctypes.create_string_buffer(b'\xa5'*(output_size+8),output_size+8)
            arena = ctypes.create_string_buffer(b'\0'*arena_size+b'\x5a'*8,arena_size+8)
            struct.pack_into('<Q',arena,0,mode)
            code = self.native._entry(source,len(raw),output,output_cap,arena,arena_cap)
            self.assertIn(code,ERROR_MESSAGES)
            self.assertEqual(output.raw[output_cap:],b'\xa5'*(output_size+8-output_cap))
            self.assertEqual(arena.raw[arena_size:],b'\x5a'*8)

    def test_selected_bad_build_and_missing_admission_never_fall_back(self):
        program = scalar_program()
        request = add_two_patch(program)
        bad = self.folder/'bad.json'
        bad.write_text('{}')
        with patch.dict(os.environ,{SELECTOR:str(bad)}):
            with self.assertRaises(HIAEditRejected):apply_program_patch(program,request)
        installed_core_patch(str(self.manifest))
        original = self.admission_manifest.read_bytes()
        try:
            self.admission_manifest.write_text('{}')
            with patch.dict(os.environ,{SELECTOR:str(self.manifest)}):
                with self.assertRaises(HIAEditRejected):apply_program_patch(program,request)
        finally:
            self.admission_manifest.write_bytes(original)

    def test_actual_installed_wheel_patches_without_checkout_tools_and_refuses_missing_source(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        root = Path(__file__).resolve().parents[1]
        resources = tuple('docs/'+name for name in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/core_patch.hepta',resources)
        source = self.folder/'wheel-source'
        source.mkdir()
        shutil.copytree(root/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*resources,'setup.py','pyproject.toml','MANIFEST.in'):
            destination = source/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/name,destination)
        wheels = self.folder/'wheels'
        result = subprocess.run([sys.executable,'-B','-m','pip','wheel','--no-deps',
            '--no-build-isolation','--wheel-dir',str(wheels),str(source)],
            cwd=source,capture_output=True,timeout=120,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        wheel, = wheels.glob('*.whl')
        installed = self.folder/'installed'
        result = subprocess.run([sys.executable,'-B','-m','pip','install','--no-deps',
            '--no-index','--target',str(installed),str(wheel)],cwd=self.folder,
            capture_output=True,timeout=120,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        program = scalar_program()
        request = add_two_patch(program)
        expected = apply_program_patch(program,request)[0].canonical_bytes
        data = self.folder/'installed-input.json'
        data.write_bytes(wire([program,request]))
        child = '''import sys,importlib.abc,json
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed native patch imported checkout tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_tools as edit
from hepta.hia_core_patch_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*a,**kw):raise AssertionError('host edit transform used')
edit._keys=absent
program,request=json.loads(Path(sys.argv[2]).read_bytes())
try:
    result,receipt=edit.apply_program_patch(program,request)
except edit.HIAEditRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','selected bad source fell back'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        def run(mode):
            return subprocess.run([sys.executable,'-I','-S','-B','-c',child,
                str(installed),str(data),mode],cwd=self.folder,capture_output=True,
                timeout=30,env={'PATH':'','LANG':'C','LC_ALL':'C',SELECTOR:str(self.manifest)})
        result = run('accept')
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''))
        resource = installed/'hepta/_data/examples/hia_bootstrap/core_patch.hepta'
        original = resource.read_bytes()
        try:
            resource.unlink()
            result = run('refuse')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'REFUSED\n',b''))
        finally:
            resource.write_bytes(original)
        original_manifest = self.manifest.read_bytes()
        try:
            self.manifest.write_text('{}')
            result = run('refuse')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'REFUSED\n',b''))
        finally:
            self.manifest.write_bytes(original_manifest)


if __name__ == '__main__':
    unittest.main()
