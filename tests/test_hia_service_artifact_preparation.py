"""Preparation-v2 source controls; old exec runs only in a disposable child.

No product, VM, native image, business provider or observation comparison is
substituted by these controls. The unchanged LocalRelease three-method gate
separately runs all original146 twice and the independent VM146.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_service_artifact_preparation as preparation
from tests import hia_service_artifact_observer as observer

ROOT = Path(__file__).resolve().parents[1]


CODE_EQUIVALENCE = r'''
import ast, hashlib, json, marshal, sys, types, warnings
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from tests import hia_service_artifact_oracle as current
from tests import hia_service_artifact_preparation as authority
proof=authority.admit_preparation(root)
raw=(root/authority.ARCHIVE).read_bytes()
assert authority.pin(raw)==authority.LEGACY_PIN
tree=ast.parse(raw)
old_function,=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='frozen_code']
legacy={'sha256':hashlib.sha256}
exec(compile(ast.Module(body=[old_function],type_ignores=[]),str(root/authority.ARCHIVE),'exec',dont_inherit=True),legacy)
required={'co_argcount','co_posonlyargcount','co_kwonlyargcount','co_nlocals','co_stacksize',
          'co_flags','co_code','co_consts','co_names','co_varnames','co_filename','co_name',
          'co_qualname','co_firstlineno','co_linetable','co_exceptiontable','co_freevars','co_cellvars'}
def describe(value):
    if type(value) is types.CodeType:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',DeprecationWarning)
            attrs={name:getattr(value,name) for name in dir(value)
                   if name.startswith('co_') and not callable(getattr(value,name))}
        assert required<=set(attrs)
        return ['code',{name:describe(item) for name,item in sorted(attrs.items())},
                list(value.co_lines()),list(value.co_positions())]
    if type(value) is tuple:return ['tuple',[describe(item) for item in value]]
    if type(value) is frozenset:return ['frozenset',sorted((describe(item) for item in value),key=repr)]
    if type(value) is bytes:return ['bytes',value.hex()]
    if value is Ellipsis:return ['ellipsis']
    assert type(value) in (type(None),bool,int,float,complex,str),type(value)
    return [type(value).__name__,repr(value)]
rows=[]
for path,expected,name in ((current.ORIGINAL,current.ORIGINAL_SHA,'_hia_artifact'),
                           (current.PROFILE,current.PROFILE_SHA,'_profile')):
    old=legacy['frozen_code'](path,expected,name)
    new=current.frozen_code(path,expected,name)
    assert type(old) is type(new) is types.CodeType
    left,right=describe(old),describe(new)
    assert left==right,(name,left,right)
    assert marshal.dumps(old)==marshal.dumps(new),name
    rows.append({'name':name,'recursive_fields':sorted(left[1]),
                 'recursive_values_sha256':hashlib.sha256(json.dumps(left,sort_keys=True).encode()).hexdigest(),
                 'marshal_sha256':hashlib.sha256(marshal.dumps(new)).hexdigest(),
                 'all_static_attributes_and_line_iterators_equal':True})
assert not [name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')]
assert authority.admit_preparation(root)==proof
print(json.dumps({'status':'PASS','legacy_real_exec_isolated_from_observation_process':True,
                  'preparation_identity':current.PREPARATION_IDENTITY,'rows':rows},sort_keys=True))
'''


PREPARATION_SAFETY = r'''
import builtins,gc,hashlib,json,sys,types
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from tests import hia_service_artifact_oracle as oracle
from tests import hia_service_artifact_preparation as authority
proof=authority.admit_preparation(root)
policy=(gc.isenabled(),gc.get_threshold())
blocked=[];compiles=[];active=False
def audit(event,args):
    if active and (event=='exec' or event in ('subprocess.Popen','ctypes.dlopen','ctypes.dlsym',
                    'socket.__new__','sqlite3.connect','os.fork') or event.startswith('os.exec')):
        blocked.append(event);raise AssertionError(event)
sys.addaudithook(audit)
def forbidden(*args,**kwargs):
    blocked.append('forbidden preparation effect');raise AssertionError(blocked[-1])
real_compile=builtins.compile
def compile_only(source,filename,mode,**keywords):
    compiles.append({'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                     'filename':filename,'mode':mode,'keywords':keywords})
    return real_compile(source,filename,mode,**keywords)
pairs=[(builtins,'exec'),(builtins,'eval'),(builtins,'__build_class__'),(types,'FunctionType'),
       (gc,'collect'),(gc,'enable'),(gc,'disable'),(gc,'set_threshold'),(gc,'freeze'),(gc,'unfreeze'),
       (oracle,'original_factory'),(oracle,'observe'),(oracle,'namespace'),(oracle,'arguments'),
       (oracle.Harness,'__init__')]
saved=[(obj,name,getattr(obj,name)) for obj,name in pairs]
try:
    for obj,name,old in saved:setattr(obj,name,forbidden)
    builtins.compile=compile_only
    active=True
    codes=[oracle.frozen_code(oracle.ORIGINAL,oracle.ORIGINAL_SHA,'_hia_artifact'),
           oracle.frozen_code(oracle.PROFILE,oracle.PROFILE_SHA,'_profile')]
finally:
    active=False
    builtins.compile=real_compile
    for obj,name,old in reversed(saved):setattr(obj,name,old)
assert not blocked,blocked
assert (gc.isenabled(),gc.get_threshold())==policy
assert len(compiles)==2
for call,path in zip(compiles,(oracle.ORIGINAL,oracle.PROFILE)):
    assert call=={'source_sha256':hashlib.sha256(('class Original:\n'+path.read_text()).encode()).hexdigest(),
                 'filename':str(path),'mode':'exec','keywords':{'dont_inherit':True}}
assert [code.co_name for code in codes]==['_hia_artifact','_profile']
# Refuse a changed complete fixture or a different requested method identity.
refused=[]
for digest,name,error in [('0'*64,'_hia_artifact',AssertionError),
                          (oracle.ORIGINAL_SHA,'_wrong',ValueError)]:
    try:oracle.frozen_code(oracle.ORIGINAL,digest,name)
    except error:refused.append('digest-or-name')
    else:raise AssertionError('different fixed source or method admitted')
# A compiler result must contain one direct wrapper and one direct method.
# Nested first-match extraction and ambiguous or renamed code are not admitted.
module=real_compile('class Original:\n'+oracle.ORIGINAL.read_text(),str(oracle.ORIGINAL),'exec',dont_inherit=True)
cls,=[item for item in module.co_consts if type(item) is types.CodeType]
method,=[item for item in cls.co_consts if type(item) is types.CodeType]
bad_classes=[cls.replace(co_consts=(None,)),cls.replace(co_consts=(method,method,None)),
             cls.replace(co_consts=(method.replace(co_name='_other'),None)),
             cls.replace(co_consts=(method.replace(co_qualname='Other._hia_artifact'),None)),
             cls.replace(co_consts=(method.replace(co_name='nested',co_consts=(method,None)),None))]
bad_modules=[module.replace(co_consts=(None,)),module.replace(co_consts=(cls,cls,None)),
             module.replace(co_consts=(cls.replace(co_name='Other'),None)),
             module.replace(co_consts=(method,None))]
bad_modules += [module.replace(co_consts=(value,None)) for value in bad_classes]
for bad in bad_modules:
    oracle.__dict__['compile']=lambda *args,**kwargs:bad
    try:
        try:oracle.frozen_code(oracle.ORIGINAL,oracle.ORIGINAL_SHA,'_hia_artifact')
        except ValueError:refused.append('code-shape')
        else:raise AssertionError('ambiguous or nested code inventory admitted')
    finally:del oracle.__dict__['compile']
assert len(refused)==11
assert authority.admit_preparation(root)==proof
assert not [name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')]
print(json.dumps({'status':'PASS','preparation_identity':oracle.PREPARATION_IDENTITY,
    'fixed_compilations':len(compiles),'executed_class_or_business_or_gc_effects':blocked,
    'policy_unchanged':True,'new_strong_global_cache':False,'refused_controls':len(refused)},sort_keys=True))
'''


class ServiceArtifactPreparationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: (ROOT / name).read_bytes() for name in (
            *preparation.SOURCE_PATHS, 'tests/hia_service_artifact_observer.py',
            'tests/test_hia_service_artifact_preparation.py')}

    @classmethod
    def tearDownClass(cls):
        if any((ROOT / name).read_bytes() != raw for name, raw in cls.sources.items()):
            raise AssertionError('preparation Source inputs changed')

    def child(self, source):
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith(('HEPTA_HIA_', 'PYTHON'))}
        result = subprocess.run([sys.executable, '-I', '-B', '-c', source, str(ROOT)],
                                cwd=ROOT, env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def test_01_retained_original_authority_and_exact_complete_inverse(self):
        proof = observer.preparation_sources()
        self.assertEqual(proof, preparation.admit_preparation(ROOT))
        self.assertEqual(proof['preparation_identity'], preparation.IDENTITY)
        self.assertEqual(proof['original_case_count'], 146)
        self.assertEqual(proof['exact_preparation_splice_count'], 2)
        self.assertEqual(proof['business_or_observation_splices'], 0)
        self.assertEqual(proof['legacy_observation_status'], 'HOLD')
        self.assertIs(proof['legacy_failure_relabelled'], False)
        self.assertIs(proof['observation_success_established_by_source_admission'], False)
        self.assertEqual(proof['current_known_originals'], {})
        self.assertEqual(proof['legacy_known_originals'], observer.KNOWN_ORIGINALS)
        self.assertEqual(len(proof['captured_files']), 9)
        self.assertEqual(set(proof['captured_files']), set(preparation.SOURCE_PATHS))
        value = json.loads(self.sources[preparation.AUTHORITY])
        old, new = self.sources[preparation.ARCHIVE], self.sources[preparation.ORACLE]
        self.assertEqual(preparation.transform_oracle(new, value['oracle_relation'], reverse=True), old)
        self.assertEqual(preparation.transform_oracle(old, value['oracle_relation'], reverse=False), new)
        freeze = json.loads(self.sources[preparation.FREEZE])
        self.assertEqual(freeze['inputs'][preparation.ORACLE], preparation.LEGACY_PIN)
        self.assertEqual(value['preserved']['original_body_bytes'], 749)
        self.assertEqual(value['preserved']['profile_body_bytes'], 101)
        self.assertEqual(value['preserved']['child_deadline_seconds'], 180)
        self.assertEqual(value['preserved']['child_cleanup_deadline_seconds'], 3)
        cases = observer.original_inputs()
        self.assertEqual(len(cases), 146)
        self.assertEqual([case['id'] for case in cases], freeze['ordered_ids'])

    def test_02_all_captured_drift_missing_late_change_and_typed_splices_refused(self):
        negative = 0
        with tempfile.TemporaryDirectory(prefix='hia-artifact-preparation-source-') as temporary:
            tree = Path(temporary)
            for name in preparation.SOURCE_PATHS:
                target = tree / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(self.sources[name])
            def admit():
                with patch.object(observer, 'ROOT', tree):
                    return observer.preparation_sources()
            self.assertEqual(admit(), observer.preparation_sources())
            for name in preparation.SOURCE_PATHS:
                target = tree / name
                for mutation in ('missing', 'changed'):
                    with self.subTest(path=name, mutation=mutation):
                        if mutation == 'missing': target.unlink()
                        else: target.write_bytes(self.sources[name] + b'\n')
                        try:
                            with self.assertRaises((ValueError, AssertionError, OSError)):
                                admit()
                            negative += 1
                        finally:
                            target.write_bytes(self.sources[name])
                read = Path.read_bytes
                calls = [0]
                def changing(path, *, target=target):
                    raw = read(path)
                    if path == target:
                        calls[0] += 1
                        if calls[0] >= 2:
                            return raw + b'late-change'
                    return raw
                with self.subTest(path=name, mutation='late-reread'), patch.object(Path, 'read_bytes', changing):
                    with self.assertRaises(ValueError):
                        admit()
                    negative += 1
            self.assertEqual(admit(), observer.preparation_sources())
        record = json.loads(self.sources[preparation.AUTHORITY])['oracle_relation']
        bad_records = []
        for key in ('old', 'new', 'splices'):
            bad = deepcopy(record); bad.pop(key); bad_records.append(bad)
        bad = deepcopy(record); bad['extra'] = None; bad_records.append(bad)
        for key in ('old', 'new'):
            for field, bad_value in (('bytes', True), ('bytes', -1), ('sha256', '0' * 64)):
                bad = deepcopy(record); bad[key][field] = bad_value; bad_records.append(bad)
        for key, bad_value in (('id', 'other'), ('old_offset', True), ('new_offset', True),
                               ('old_offset', -1), ('new_offset', -1), ('old_hex', ''),
                               ('new_hex', ''), ('old_hex', None), ('new_hex', 'zz')):
            bad = deepcopy(record); bad['splices'][0][key] = bad_value; bad_records.append(bad)
        bad = deepcopy(record); bad['splices'].reverse(); bad_records.append(bad)
        bad = deepcopy(record); bad['splices'].append(bad['splices'][0]); bad_records.append(bad)
        bad = deepcopy(record); bad['splices'] = tuple(bad['splices']); bad_records.append(bad)
        for bad in bad_records:
            with self.subTest(record=bad), self.assertRaises(ValueError):
                preparation.transform_oracle(self.sources[preparation.ORACLE], bad, reverse=True)
            negative += 1
        for reverse in (1, None, 'true'):
            with self.subTest(reverse=reverse), self.assertRaises(ValueError):
                preparation.transform_oracle(self.sources[preparation.ORACLE], record, reverse=reverse)
            negative += 1
        for raw in (bytearray(self.sources[preparation.ORACLE]), self.sources[preparation.ORACLE].decode(),
                    self.sources[preparation.ORACLE] + b'\n'):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ValueError):
                preparation.transform_oracle(raw, record, reverse=True)
            negative += 1
        self.assertEqual(negative, 55)
        # The candidate cannot change either complete second-original evidence
        # or its preparation receipt, even to JSON with the same parsed value.
        evidence_negative = 0
        with tempfile.TemporaryDirectory(prefix='hia-artifact-replay-custody-') as temporary:
            output = Path(temporary)
            sealed = {'originals-repeat-146.json': b'[1,2]\n',
                      'original-replay-differences.json': b'[]\n',
                      'preparation-baseline.json': b'{"status":"PASS"}\n'}
            for name, raw in sealed.items():
                (output / name).write_bytes(raw)
            self.assertIs(observer.observation_readback(output, sealed)['unchanged'], True)
            for name, raw in sealed.items():
                target = output / name
                with self.subTest(evidence=name, mutation='equivalent-JSON-extra-space'):
                    target.write_bytes(raw + b' ')
                    self.assertEqual(json.loads(target.read_bytes()), json.loads(raw))
                    self.assertIs(observer.observation_readback(output, sealed)['unchanged'], False)
                    evidence_negative += 1
                with self.subTest(evidence=name, mutation='missing'):
                    target.unlink()
                    with self.assertRaises(OSError):
                        observer.observation_readback(output, sealed)
                    evidence_negative += 1
                target.write_bytes(raw)
            self.assertIs(observer.observation_readback(output, sealed)['unchanged'], True)
        self.assertEqual(evidence_negative, 6)

    def test_03_every_recursive_code_attribute_matches_real_legacy_exec(self):
        report = self.child(CODE_EQUIVALENCE)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['preparation_identity'], preparation.IDENTITY)
        self.assertIs(report['legacy_real_exec_isolated_from_observation_process'], True)
        self.assertEqual([row['name'] for row in report['rows']], ['_hia_artifact', '_profile'])
        for row in report['rows']:
            self.assertIs(row['all_static_attributes_and_line_iterators_equal'], True)
            self.assertTrue({'co_consts', 'co_flags', 'co_filename', 'co_firstlineno',
                             'co_linetable', 'co_exceptiontable', 'co_freevars', 'co_cellvars'}
                            <= set(row['recursive_fields']))

    def test_04_current_preparation_never_executes_class_business_or_gc_policy(self):
        report = self.child(PREPARATION_SAFETY)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['preparation_identity'], preparation.IDENTITY)
        self.assertEqual(report['fixed_compilations'], 2)
        self.assertEqual(report['executed_class_or_business_or_gc_effects'], [])
        self.assertIs(report['policy_unchanged'], True)
        self.assertIs(report['new_strong_global_cache'], False)
        self.assertEqual(report['refused_controls'], 11)


if __name__ == '__main__':
    unittest.main()
