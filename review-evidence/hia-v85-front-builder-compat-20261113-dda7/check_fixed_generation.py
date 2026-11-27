import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import traceback

SCOPE = Path(__file__).resolve().parent
SOURCE = SCOPE / 'source'
BASE = Path('/workspace/scratch/dda74a4fae35/recovered-v85/failed-r1-source')
OUTPUT = SCOPE / 'fixed-generation-r1'
OUTPUT.mkdir()
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'):
        del os.environ[key]
sys.path.insert(0, str(SOURCE))
sys.dont_write_bytecode = True

def identity(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def snapshot():
    result = {}
    for path in sorted(SOURCE.rglob('*')):
        if path.is_dir():
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('unexpected source type')
        result[path.relative_to(SOURCE).as_posix()] = {
            **identity(path.read_bytes()), 'mode':stat.S_IMODE(info.st_mode)}
    return result

before = snapshot()
(OUTPUT / 'SOURCE-BEFORE.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
report = {'schema':'hepta.front-local-frozen-builder-generation-check.v1',
          'status':'INCOMPLETE','scope':'LOCAL_CPYTHON_GENERATION_CHECK_ONLY',
          'python':sys.version,'base_tree':'f5610f07a4a43bfc83aaffaedec2c0c89933126a',
          'source_files':len(before),'native_execution':False,'cold_qualification':False,
          'full_source_suite_executed':False,'test_expected_hashes_changed':False,
          'observations':[],'failures':[]}
start = time.monotonic()
try:
    from tools import generate_hia_core_verification as core
    from tools import generate_hia_assembly_front as assembly
    from tools import generate_hia_selfhost as shared
    from tools.hia_front_generator import _FrontBuilder
    expected = (
        (core,'core_verification','2931664bb7af879f48c82bb36e897654ca25d3708d198b9edb06da34de647546',2),
        (assembly,'assembly_front','440e65fc0e41b8b586b44d3ab3bdad65bf4705eed50ab11d9a123d0d9a40d9d2',16),
    )
    for generator,stem,digest,count in expected:
        source,ports,policy,data = generator.generated()
        row = {'module':stem,'source':identity(source),'ports':identity(ports),'table':identity(data),
               'functions':len(policy.functions),'instructions':sum(len(f.instructions) for f in policy.functions),
               'expected_source_sha256':digest,
               'source_matches_original_literal':hashlib.sha256(source).hexdigest()==digest,
               'source_matches_existing_canonical_seed':source==(SOURCE/('examples/hia_bootstrap/'+stem+'.hepta')).read_bytes(),
               'ports_match_existing_seed':ports==(SOURCE/('hepta/hia_'+stem+'_ports.py')).read_bytes()}
        for suffix,raw in (('.hepta',source),('.ports.py',ports),('.table.bin',data)):
            (OUTPUT/(stem+suffix)).write_bytes(raw)
        report['observations'].append(row)
        assert row['functions']==count
        assert row['source_matches_original_literal']
        assert row['source_matches_existing_canonical_seed']
        assert row['ports_match_existing_seed']
    node = ast.parse('def sample(a:u64,b:u64) -> u64:\n    return a\n').body[0]
    allocation = []
    for name,cls in (('shared_main',shared.Builder),('front_local',_FrontBuilder)):
        builder = cls(node,{'sample':'f0'},{'sample':(['u64','u64'],'u64')})
        args = (builder.env['a'],builder.env['b'])
        first = builder.op('int.add.wrap',args,'u64')
        second = builder.op('int.add.wrap',args,'u64')
        allocation.append({'builder':name,'first':first,'second':second,
                           'same_ssa_result':first==second,'ops':len(builder.block['ops'])})
    assert allocation[0]['same_ssa_result'] and allocation[0]['ops']==1
    assert not allocation[1]['same_ssa_result'] and allocation[1]['ops']==2
    report['scalar_allocation_observation'] = allocation
    shared_path = 'tools/generate_hia_selfhost.py'
    test_path = 'tests/test_hia_front_registration.py'
    assert (SOURCE/shared_path).read_bytes()==(BASE/shared_path).read_bytes()
    assert (SOURCE/test_path).read_bytes()==(BASE/test_path).read_bytes()
    report['shared_builder_source_unchanged'] = True
    report['original_eight_source_methods_and_assertions_unchanged'] = True
    report['status'] = 'EXACT_ORIGINAL_FRONT_INPUTS_REPRODUCED'
except BaseException as error:
    report['status'] = 'FAIL'
    report['failures'].append({'type':type(error).__name__,'error':str(error),'traceback':traceback.format_exc()})
finally:
    after = snapshot()
    changed = sorted(name for name in set(before)|set(after) if before.get(name)!=after.get(name))
    report['source_unchanged'] = not changed
    report['source_changed_paths'] = changed
    report['source_before_manifest'] = identity((OUTPUT/'SOURCE-BEFORE.json').read_bytes())
    report['elapsed_seconds_observation_only'] = time.monotonic()-start
    if changed:
        report['status'] = 'FAIL'
        (OUTPUT/'SOURCE-AFTER.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
    (OUTPUT/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,indent=2))
raise SystemExit(0 if report['status']=='EXACT_ORIGINAL_FRONT_INPUTS_REPRODUCED' else 1)
