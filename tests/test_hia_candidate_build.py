"""Fixed catalog, independent VM, and real standalone native build controls.

The development and matching-cold fixtures are mutually exclusive explicit
inputs. These tests do not manufacture cold authority or whole qualification.
"""
from __future__ import annotations

import ast
import base64
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import time
import unittest
import zlib
from unittest import mock

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_candidate_build import (
    BUNDLE_MAGIC, CATALOG_PATH, CONTROL_BYTES, CONTROL_MAGIC, IMAGE_LIMIT,
    LAYOUT, PACK_MAGIC, WIRE_LIMIT, WORK_BYTES, catalog, packer_source,
    policy_source, template,
)
from tools.qualify_hia_selfhost import compile_stage
from tests.test_hia_source_build import bundle, unpack, _restrict_runtime_syscalls

ROOT=Path(__file__).resolve().parents[1]
RAW_OBSERVATIONS=[]
VM_OBSERVATIONS=[]


def expected_manifest(row, source, image, compiler):
    value={'schema':'hepta.hia.'+row['protocol']+'-native.v'+str(row['schema_version']),
           'source_sha256':sha256(source).hexdigest(),
           'image_path':row['protocol']+'.image.bin',
           'image_sha256':sha256(image).hexdigest(),
           'compiler_sha256':sha256(compiler).hexdigest()}
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def vm_call(program, wire, work, output):
    machine=_Machine(program,4_000_000,8<<20,None,128)
    owners=[_Owner(i,bytearray(raw)) for i,raw in enumerate((wire,output,work))]
    result=machine.invoke(machine.functions['f0'],[_View(owners[0],False),
                                                  _View(owners[1],True),_View(owners[2],True)])
    directory=Path(os.environ['HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE'])/'vm'
    directory.mkdir(parents=True,exist_ok=True)
    buffers={}
    for name,raw in [('source',bytes(wire)),('output_before',bytes(output)),('workspace_before',bytes(work)),
                     ('output_after',bytes(owners[1].data)),('workspace_after',bytes(owners[2].data))]:
        compressed=zlib.compress(raw,6)
        assert zlib.decompress(compressed)==raw
        buffers[name]={'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
                       'encoding':'base64-zlib','data':base64.b64encode(compressed).decode()}
    row={'sequence':len(VM_OBSERVATIONS),'result':result,'steps':machine.steps,'buffers':buffers}
    (directory/(f'{len(VM_OBSERVATIONS):04d}.json')).write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
    VM_OBSERVATIONS.append({'sequence':row['sequence'],'result':result,'steps':machine.steps})
    return result[0],bytes(owners[1].data),bytes(owners[2].data),machine.steps


class CandidateBuildSourceTests(unittest.TestCase):
    def test_exact_original_catalog_all_55_and_three_dedicated_exclusions(self):
        raw=(ROOT/'tools/build_hia_json_preflight.py').read_bytes()
        saved=json.loads(CATALOG_PATH.read_bytes())
        self.assertEqual(len(raw),saved['origin']['bytes'])
        self.assertEqual(sha256(raw).hexdigest(),saved['origin']['sha256'])
        tree=ast.parse(raw)
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='build')
        declaration=next(n for n in function.body if isinstance(n,ast.Assign)
                         and any(isinstance(t,ast.Name) and t.id=='candidates' for t in n.targets))
        original=ast.literal_eval(declaration.value)
        rows=catalog()
        self.assertEqual(len(rows),55)
        self.assertEqual([(r['candidate'],(r['source_name'][:-6],r['protocol'])) for r in rows],list(original.items()))
        self.assertEqual(saved['excluded_dedicated_delegates'],
                         ['core-lowering-control','slot-ledger-continuation','service-emission'])
        self.assertTrue(set(saved['excluded_dedicated_delegates']).isdisjoint(original))
        for row in rows:
            source=(ROOT/'examples/hia_bootstrap'/row['source_name']).read_bytes()
            self.assertEqual(sha256(source).hexdigest(),row['source_sha256'])
            self.assertLessEqual(len(source),IMAGE_LIMIT)
            self.assertEqual(row['schema_version'],2 if row['candidate'] in ('agent-journal','machine-encoding') else 1)

    def test_complete_generated_hia_and_original_limits(self):
        for name,source in [('policy',policy_source()),('packer',packer_source())]:
            self.assertEqual((ROOT/'examples/hia_bootstrap'/('candidate_build_'+name+'.hepta')).read_text(),
                             render_assembly(document(source,'candidate_build_'+name)))
        from tools.generate_hia_source_build import WIRE_LIMIT as original_wire,IMAGE_LIMIT as original_image
        self.assertEqual((WIRE_LIMIT,IMAGE_LIMIT),(original_wire,original_image))
        self.assertEqual((WIRE_LIMIT,IMAGE_LIMIT),(64<<20,1<<20))
        self.assertEqual(LAYOUT['COMPWORK'],LAYOUT['WORK']+WORK_BYTES)
        self.assertEqual(LAYOUT['SHAWORK'],LAYOUT['COMPWORK']+IMAGE_LIMIT)
        self.assertEqual(LAYOUT['WIRE'],LAYOUT['OUT']+WIRE_LIMIT)
        self.assertEqual(LAYOUT['MAPSIZE'],LAYOUT['WIRE']+LAYOUT['WIRE_CAP'])

    def test_vm_actual_hia_catalog_selection_and_permanent_rejection(self):
        program=assemble_program((ROOT/'examples/hia_bootstrap/candidate_build_policy.hepta').read_text())
        for index,row in enumerate(catalog()):
            name=row['candidate'].encode();args=struct.pack('<2Q',1,len(name))+name
            work=bytearray(WORK_BYTES);struct.pack_into('<Q',work,88,673413)
            status,output,after,steps=vm_call(program,args,work,bytes([0xa5])*64)
            self.assertEqual(status,0);self.assertEqual(output,bytes([0xa5])*64)
            self.assertEqual(struct.unpack_from('<Q',after,32)[0],1032+index*64)
            self.assertEqual(struct.unpack_from('<Q',after,72)[0],CONTROL_MAGIC)
            self.assertGreater(steps,0)
        for args in [b'',struct.pack('<2Q',0,0),struct.pack('<2Q',1,3)+b'bad',
                     struct.pack('<2Q',2,9)+b'preflight',struct.pack('<2Q',1,128)+b'x'*128]:
            work=bytearray(WORK_BYTES);struct.pack_into('<Q',work,88,673413)
            status,output,after,_=vm_call(program,args,work,bytes([0xa5])*64)
            self.assertEqual(status,16);self.assertEqual(output,bytes([0xa5])*64)
            self.assertEqual(struct.unpack_from('<Q',after,8)[0],255)
            status,_,again,_=vm_call(program,struct.pack('<2Q',1,9)+b'preflight',after,bytes(64))
            self.assertEqual(status,16);self.assertEqual(again,after)

    def test_vm_sha_mismatch_refuses_before_compiler_request(self):
        program=assemble_program((ROOT/'examples/hia_bootstrap/candidate_build_policy.hepta').read_text())
        args=struct.pack('<2Q',1,9)+b'preflight';work=bytearray(WORK_BYTES)
        struct.pack_into('<Q',work,88,673413)
        status,_,after,_=vm_call(program,args,work,bytes(64));self.assertEqual(status,0)
        work=bytearray(after);struct.pack_into('<4Q',work,0,2,4,4,32)
        work[512:544]=bytes([0xff])*32
        status,output,after,_=vm_call(program,b'',work,bytes([0xa5])*64)
        self.assertEqual(status,16);self.assertEqual(output,bytes([0xa5])*64)
        self.assertEqual(struct.unpack_from('<Q',after,8)[0],255)
        self.assertEqual(struct.unpack_from('<Q',after,16)[0],0)

    def test_vm_packer_all_output_bytes_and_short_output_no_write(self):
        prefix,holes=template();images=(b'\xc3',b'\x90\xc3',b'\x90\x90\xc3',b'\xc3\x90\xc3')
        wire=struct.pack('<5Q',PACK_MAGIC,*map(len,images))+b''.join(images)
        expected=bytearray(prefix+b''.join(images))
        struct.pack_into('<Q',expected,96,len(expected));struct.pack_into('<Q',expected,104,len(expected))
        targets={'policy_hole':len(prefix),'source_policy_hole':len(prefix)+len(images[0]),
                 'compiler_hole':len(prefix)+len(images[0])+len(images[1]),
                 'compiler_data_hole':len(prefix)+len(images[0])+len(images[1]),
                 'sha_hole':len(prefix)+sum(map(len,images[:3]))}
        for key,target in targets.items():struct.pack_into('<i',expected,holes[key],target-holes[key]-4)
        struct.pack_into('<Q',expected,holes['compiler_size_hole'],len(images[2]))
        program=assemble_program((ROOT/'examples/hia_bootstrap/candidate_build_packer.hepta').read_text())
        status,output,work,_=vm_call(program,wire,bytes(64),bytes([0xa5])*len(expected))
        self.assertEqual(status,len(expected));self.assertEqual(output,bytes(expected));self.assertEqual(work,bytes(64))
        status,output,work,_=vm_call(program,wire,bytes(64),bytes([0xa5])*(len(expected)-1))
        self.assertEqual(status,0xfffffffe);self.assertEqual(output,bytes([0xa5])*(len(expected)-1))


class CandidateBuildNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_candidate_build import selected_cold_fixture, admit_fixture
        selected=selected_cold_fixture()
        if selected is None:
            cls.build_dir=Path(os.environ['HEPTA_HIA_CANDIDATE_BUILD_DEVELOPMENT_EVIDENCE']).resolve()
        else:
            cls.cold_fixture=admit_fixture(selected)
            cls.build_dir=Path(cls.cold_fixture['build_directory'])
        cls.app=cls.build_dir/'hia-candidate-build'
        cls.report=json.loads((cls.build_dir/'BUILD.json').read_bytes())
        if selected is None:
            if cls.report['development'] is not True or cls.report['cold_authority'] is not False:
                raise AssertionError('these development controls must not borrow cold authority')
        elif cls.report['development'] is not False or cls.report['cold_authority'] is not True:
            raise AssertionError('matching-cold controls require the actual production bootstrap')
        cls.original=cls.app.read_bytes()
        if sha256(cls.original).hexdigest()!=cls.report['executable_sha256']:
            raise AssertionError('actual executable differs from its immutable bootstrap report')
        cls.compiler=cls.build_dir/'captured-compiler.image.bin'
        cls.compiler_bytes=cls.compiler.read_bytes()
        if sha256(cls.compiler_bytes).hexdigest()!=cls.report['compiler_sha256']:
            raise AssertionError('actual captured compiler differs')
        cls.evidence=Path(os.environ['HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE']).resolve()
        cls.evidence.mkdir(parents=True,exist_ok=True)

    def run_native(self,name,wire,*,label,expected=0,restricted=False):
        case=self.evidence/label;case.mkdir()
        (case/'input.raw').write_bytes(wire)
        started=time.monotonic_ns()
        try:
            result=subprocess.run([str(self.app),name],input=wire,capture_output=True,
                env={'PATH':''},cwd=case,timeout=20,
                preexec_fn=_restrict_runtime_syscalls(len(self.original)) if restricted else None)
        except subprocess.TimeoutExpired as error:
            (case/'stdout.raw').write_bytes(error.stdout or b'')
            (case/'stderr.raw').write_bytes(error.stderr or b'')
            observation={'test_id':self.id(),'case':label,'candidate':name,'timed_out':True,
                'wall_limit_seconds':20,'elapsed_ns':time.monotonic_ns()-started,
                'input_sha256':sha256(wire).hexdigest(),'executable_sha256':sha256(self.original).hexdigest()}
            RAW_OBSERVATIONS.append(observation)
            (case/'OBSERVATION.json').write_text(json.dumps(observation,indent=2,sort_keys=True)+'\n')
            raise
        (case/'stdout.raw').write_bytes(result.stdout);(case/'stderr.raw').write_bytes(result.stderr)
        observation={'test_id':self.id(),'case':label,'candidate':name,
            'wall_limit_seconds':20,'elapsed_ns':time.monotonic_ns()-started,
            'returncode':result.returncode,'input_bytes':len(wire),'input_sha256':sha256(wire).hexdigest(),
            'output_bytes':len(result.stdout),'output_sha256':sha256(result.stdout).hexdigest(),
            'stderr_sha256':sha256(result.stderr).hexdigest(),'restricted_runtime':restricted,
            'executable_sha256':sha256(self.original).hexdigest(),'expected_returncode':expected}
        RAW_OBSERVATIONS.append(observation)
        (case/'OBSERVATION.json').write_text(json.dumps(observation,indent=2,sort_keys=True)+'\n')
        self.assertEqual(result.returncode,expected,result.stderr)
        self.assertEqual(result.stderr,b'')
        self.assertEqual(self.app.read_bytes(),self.original)
        if expected:self.assertEqual(result.stdout,b'')
        return case,result.stdout

    def test_all_55_real_canonical_images_and_exact_original_manifests(self):
        for index,row in enumerate(catalog()):
            with self.subTest(candidate=row['candidate']):
                source=(ROOT/'examples/hia_bootstrap'/row['source_name']).read_bytes()
                case,raw=self.run_native(row['candidate'],bundle([(row['source_name'],0o400,source)]),
                                         label=f'catalog-{index:02d}-{row["candidate"]}')
                actual=unpack(raw)
                self.assertEqual(list(actual),[row['source_name'].encode(),(row['protocol']+'.image.bin').encode(),b'manifest.json'])
                self.assertEqual(actual[row['source_name'].encode()],source)
                reference,receipt=compile_stage(case,'reference-compile',self.compiler,source)
                self.assertEqual(actual[(row['protocol']+'.image.bin').encode()],reference.read_bytes())
                expected=expected_manifest(row,source,reference.read_bytes(),self.compiler_bytes)
                (case/'expected-manifest.json').write_bytes(expected)
                (case/'actual-manifest.json').write_bytes(actual[b'manifest.json'])
                self.assertEqual(actual[b'manifest.json'],expected)

    def test_complete_preflight_rejections_publish_no_bytes(self):
        source=(ROOT/'examples/hia_bootstrap/json_preflight.hepta').read_bytes()
        correct=bundle([('json_preflight.hepta',0o400,source)])
        cases=[('unknown','unknown',correct),
               ('dedicated-core','core-lowering-control',correct),
               ('dedicated-ledger','slot-ledger-continuation',correct),
               ('dedicated-emission','service-emission',correct),
               ('wrong-name','preflight',bundle([('other.hepta',0o400,source)])),
               ('source-drift','preflight',bundle([('json_preflight.hepta',0o400,source+b' ')])),
               ('wrong-mode','preflight',bundle([('json_preflight.hepta',0o644,source)])),
               ('trailing','preflight',correct+b'x'),('truncated','preflight',correct[:-1]),
               ('empty','preflight',b''),('bad-magic','preflight',bytes(24)),
               ('zero-members','preflight',struct.pack('<3Q',BUNDLE_MAGIC,0,0)),
               ('129-members','preflight',struct.pack('<3Q',BUNDLE_MAGIC,129,0)),
               ('nonzero-reserved','preflight',struct.pack('<3Q',BUNDLE_MAGIC,1,1)+correct[24:]),
               ('duplicate','preflight',bundle([('json_preflight.hepta',0o400,source)]*2)),
               ('two-distinct','preflight',bundle([('json_preflight.hepta',0o400,source),('other.hepta',0o400,source)])),
               ('source-over-limit','preflight',bundle([('json_preflight.hepta',0o400,bytes(IMAGE_LIMIT+1))]))]
        for label,name,wire in cases:
            with self.subTest(case=label):self.run_native(name,wire,label='reject-'+label,expected=16)

    def test_runtime_has_no_file_open_exec_child_or_writable_executable_mapping(self):
        row=next(r for r in catalog() if r['candidate']=='preflight')
        source=(ROOT/'examples/hia_bootstrap'/row['source_name']).read_bytes()
        wire=bundle([(row['source_name'],0o400,source)])
        with mock.patch('tools.build_hia_json_preflight.build',side_effect=AssertionError('old Python build entered')):
            _,normal=self.run_native('preflight',wire,label='runtime-normal')
            _,restricted=self.run_native('preflight',wire,label='runtime-restricted',restricted=True)
        self.assertEqual(normal,restricted)

    def test_existing_installed_preflight_loader_accepts_actual_native_manifest(self):
        from hepta.hia_json_preflight_native import installed_preflight
        source=(ROOT/'examples/hia_bootstrap/json_preflight.hepta').read_bytes()
        case,raw=self.run_native('preflight',bundle([('json_preflight.hepta',0o400,source)]),label='existing-loader')
        actual=unpack(raw)
        for name,data in actual.items():(case/name.decode()).write_bytes(data)
        owner=installed_preflight(str(case/'manifest.json'))
        try:
            self.assertEqual(owner.image_sha256,sha256(actual[b'json-preflight.image.bin']).hexdigest())
            self.assertEqual(owner.admitted_source_sha256,sha256(source).hexdigest())
            result=owner.admit(b'{"x":[1,true,null]}',max_nodes=1000,max_depth=64)
            self.assertIsNone(result)
        finally:
            del owner
