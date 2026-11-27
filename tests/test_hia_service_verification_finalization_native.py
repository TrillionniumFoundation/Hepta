"""One independent actual-native child FINALIZE control.

The original Source3/Native8 and ten-row parent resource method stay intact.
This new gate preserves the earlier child failure revealed by that method.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from tests import hia_service_verification_controls as controls
ROOT=Path(__file__).resolve().parents[1]
COLD='HEPTA_HIA_SERVICE_VERIFICATION_COLD_REPORT'
DEV='HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_COMPILER'
EVIDENCE='HEPTA_HIA_SERVICE_VERIFICATION_FINALIZE_EVIDENCE'

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}

class ServiceVerificationChildFinalizeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_verification import build,INPUTS
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_service_context import build as context_build
        from tools.build_hia_json_preflight import current_sources
        cold,dev,evidence=(os.environ.get(name) for name in (COLD,DEV,EVIDENCE))
        if (cold is None)==(dev is None) or cold=='' or dev=='' or evidence=='':
            raise ValueError('independent child FINALIZE gate requires current cold xor explicit DEV')
        if evidence is None:
            cls.temporary=tempfile.TemporaryDirectory(prefix='hia-verification-child-finalize-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.root=Path(cls.temporary.name)
        else:
            cls.root=Path(evidence).absolute();cls.root.mkdir(mode=0o700,parents=True,exist_ok=False)
        cls.sources=current_sources()
        cls.cold=None if cold is None else Path(cold)
        cls.cold_raw=None if cls.cold is None else cls.cold.read_bytes()
        if cls.cold is None:
            cls.compiler=Path(dev)
        else:
            from tools.hia_cold_compiler import read_cold_build_inputs
            cls.cold_inputs=read_cold_build_inputs(cls.cold)
            if cls.cold_raw!=cls.cold_inputs.report_bytes:
                raise ValueError('FINALIZE cold report changed during admission')
            cls.compiler=cls.cold_inputs.compiler
        cls.compiler_raw=cls.compiler.read_bytes()
        cls.captured={}
        if cls.cold is not None:cls.captured.update(cls.cold_inputs.files)
        manifests={}
        for name,builder in (('verification',build),('store',store_build),('context',context_build)):
            path=builder(cls.root/name,cls.compiler,cold,development=cold is None)
            raw=path.read_bytes();manifest=json.loads(raw)
            report_path=path.parent/'build.json';build_raw=report_path.read_bytes()
            cls.captured[path]=raw;cls.captured[report_path]=build_raw
            image_path=path.parent/manifest['image_path']
            image_raw=image_path.read_bytes();cls.captured[image_path]=image_raw
            if (sha256(image_raw).hexdigest()!=manifest['image_sha256']
                    or manifest['compiler_sha256']!=sha256(cls.compiler_raw).hexdigest()):
                raise AssertionError('actual companion image/compiler identity differs')
            manifests[name]={'path':str(path.absolute()),'pin':pin(raw),
                'build_path':str(report_path.absolute()),'build_pin':pin(build_raw)}
        if current_sources()!=cls.sources or cls.compiler.read_bytes()!=cls.compiler_raw:
            raise AssertionError('construction changed current sources/compiler')
        if cls.cold is not None and cls.cold.read_bytes()!=cls.cold_raw:
            raise AssertionError('cold authority changed')
        authority={'schema':'hepta.hia.service-verification-finalize-authority.v1',
            'scope':'DEVELOPMENT_COMPONENT' if cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'source_inputs':{name:sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS},
            'compiler_path':str(cls.compiler.absolute()),'compiler':pin(cls.compiler_raw),
            'cold_report_path':None if cls.cold is None else str(cls.cold.absolute()),
            'cold_report':None if cls.cold_raw is None else pin(cls.cold_raw),
            'manifests':manifests,'whole_native_stack_qualified':False}
        cls.authority_path=cls.root/'authority.json'
        controls.write(cls.authority_path,authority)
        cls.authority_raw=cls.authority_path.read_bytes()
        cls.authority_pin=pin(cls.authority_raw)

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after=current_sources()
        stable=(after==cls.sources and cls.compiler.read_bytes()==cls.compiler_raw
            and cls.authority_path.read_bytes()==cls.authority_raw
            and all(path.read_bytes()==raw for path,raw in cls.captured.items())
            and (cls.cold is None or cls.cold.read_bytes()==cls.cold_raw))
        controls.write(cls.root/'component-custody.json',{
            'schema':'hepta.hia.service-verification-child-finalize-custody.v1',
            'source_before':cls.sources,'source_after':after,
            'source_compiler_images_cold_unchanged':stable,
            'authority':cls.authority_pin,'whole_native_stack_qualified':False})
        if not stable:raise AssertionError('independent FINALIZE component custody changed')

    def test_01_original_event_only_child_FINALIZE_before_SQL_retains_loss_and_closes_unused_Store(self):
        from tools.read_hia_service_verification_child_finalize import read
        directory=self.root/self._testMethodName;directory.mkdir()
        destination=directory/'child'
        arguments=[ROOT/'tests/hia_service_verification_child_finalize.py',
            '--authority',self.authority_path,
            '--authority-sha256',self.authority_pin['sha256'],
            '--authority-bytes',self.authority_pin['bytes'],
            '--output',destination]
        stdout,stderr,receipt=controls.run_process(directory,'child',arguments,
            env=controls.clean_environment(),timeout=60)
        self.assertEqual(stderr,b'')
        raw=(destination/'report.json').read_bytes()
        report=json.loads(raw)
        self.assertEqual(report['pid'],receipt['pid'])
        self.assertEqual(report['pgid'],receipt['pgid'])
        self.assertEqual(report['ppid'],os.getpid())
        self.assertEqual(report['argv'],receipt['command'][3:])
        self.assertEqual(receipt['returncode'],0)
        self.assertIs(receipt['timeout'],False)
        self.assertIsNone(receipt['cleanup_error'])
        self.assertEqual(receipt['cleanup']['after'],[])
        self.assertEqual(receipt['timeout_seconds'],60)
        self.assertEqual(receipt['cleanup_seconds'],3)
        result=read(destination/'report.json',self.authority_path,
            expected_report=pin(raw),expected_authority=self.authority_pin)
        self.assertEqual(result['status'],'PASS_READBACK_ONLY')
        self.assertEqual(result['actual_fault_count'],1)
        self.assertEqual(result['actual_fault_mode'],2)
        self.assertEqual(result['parent_mode'],3)
        self.assertEqual(result['SQL_count_after_constructor'],0)
        self.assertEqual(result['public_close_count'],1)
        self.assertIs(result['actual_SQLite_connection_closed'],True)
        self.assertIs(result['sticky_child_and_parent_loss_retained'],True)
        self.assertIs(result['original_Native8_qualified'],False)
        self.assertIs(result['parent_VERIFY_FINALIZE_qualified'],False)
        if (destination/'report.json').read_bytes()!=raw or self.authority_path.read_bytes()!=self.authority_raw:
            raise AssertionError('actual child report/authority changed during readback')
        controls.write(directory/'independent-readback.json',result)
        controls.write(directory/'method.json',{
            'schema':'hepta.hia.service-verification-child-finalize-method.v1',
            'status':'PASS_INDEPENDENT_NATIVE_METHOD_ONLY','id':self.id(),
            'child':receipt,'report':pin(raw),'authority':self.authority_pin,
            'readback':pin((directory/'independent-readback.json').read_bytes()),
            'source_custody_required_at_class_terminal':True,
            'whole_native_stack_qualified':False})
