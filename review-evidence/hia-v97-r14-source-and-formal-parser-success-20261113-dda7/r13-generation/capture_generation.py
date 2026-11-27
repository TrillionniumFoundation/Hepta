"""Preserve completed R13 generation commands and its three derived outputs."""
from pathlib import Path
import base64
import hashlib
import json
import re
import subprocess
import zlib

ROOT=Path(__file__).resolve().parent
RAW=ROOT/'local-generation-r1/evidence/raw'

def enc(value):return (json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest(),'mode':'100644'}
def put(name,raw):
    with (ROOT/name).open('xb')as f:f.write(raw)

result_raw=(RAW/'LOCAL-RESULT.json').read_bytes();result=json.loads(result_raw)
assert result['status']=='LOCAL_GENERATION_PASS' and result['failures']==[]
assert result['generation']['generator_count']==131 and result['generation']['real_generation_passes']==2
plan=json.loads((ROOT/'harness/inputs/MATERIALIZATION-R13.json').read_bytes())
commands=[];groups={key:[]for key in ['generate','reproduce']}
for p in sorted((RAW/'commands').glob('*.json')):
    d=json.loads(p.read_bytes());commands.append(d)
    m=re.fullmatch(r'\d+-(generate|reproduce)-(\d+)-([a-z0-9_]+)\.json',p.name)
    if m:
        phase,index,name=m[1],int(m[2]),m[3]
        assert name==plan['generators'][index]
        assert d['returncode']==0 and d['timed_out'] is False and d['limit_seconds']==300
        assert d['argv']==[result['python'] and '/workspace/scratch/dda74a4fae35/v94-cli-parser-context-r11-r2/graph-probe-r2/interpreter/bin/python3.14','-B','-m','tools.generate_hia_'+name]
        groups[phase].append(index)
for rows in groups.values():assert rows==list(range(131))
assert all(d['returncode']==0 and d['timed_out'] is False for d in commands)
index_raw=(RAW/'terminal-worktree/INDEX.json').read_bytes();index=json.loads(index_raw)
frozen=json.loads((ROOT/'SOURCE-MANIFEST.json').read_bytes())
actual={x['path']:{'bytes':x['bytes'],'git_blob':x['blob'],'sha256':x['sha256'],'mode':'100644'}for x in index['files']}
assert len(actual)==len(frozen)==3121 and set(actual)==set(frozen)
changed=sorted(k for k in actual if actual[k]!=frozen[k])
assert changed==['docs/HIA_NATIVE_REWRITE_INVENTORY.json','docs/HIA_SELFHOST_CORE_SUPPORT.json','hepta/hia_checker_identity.py']
derived=[]
for name in changed:
    before=(ROOT/'source'/name).read_bytes();assert pin(before)==frozen[name]
    p=subprocess.run(['git','--no-lazy-fetch','cat-file','blob',actual[name]['git_blob']],cwd=ROOT/'local-source-r1',capture_output=True,timeout=30)
    assert p.returncode==0 and p.stderr==b'' and pin(p.stdout)==actual[name]
    derived.append({'path':name,'before':dict(pin(before),text=before.decode()),'after':dict(pin(p.stdout),text=p.stdout.decode())})
derived_raw=enc({'schema':'hia.r13.actual314-derived-source.v1','base_tree':'f9502ae42339254bd45d7910eb3d7319ab323dbd',
    'current_tree':result['generation']['tree'],'base_manifest':frozen,'current_manifest':actual,'files':derived,'whole_native':False})
put('GENERATION-DERIVED-SOURCE.json',derived_raw)
files=[]
paths=sorted(p for p in (RAW/'commands').iterdir()if p.is_file())
paths += [RAW/'LOCAL-RESULT.json',RAW/'terminal-worktree/INDEX.json']
paths += sorted(p for p in (RAW/'harness').iterdir()if p.is_file())
for p in paths:
    data=p.read_bytes();assert p.stat().st_mode&0o777==0o644
    files.append(dict(path=p.relative_to(RAW).as_posix(),**pin(data),encoding='base64',payload=base64.b64encode(data).decode()))
decoded=enc({'schema':'hia.r13.complete-generation-command-originals.v1','files':files,'generation_only':True,'whole_native':False})
transport=enc({'schema':'hia.lossless.zlib-json.v1','decoded':pin(decoded),'payload':base64.b64encode(zlib.compress(decoded,9)).decode()})
assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'],validate=True))==decoded
put('GENERATION-COMMANDS.zlib.json',transport)
report={'schema':'hia.root.r13.actual314-fixed-point-review.v1','status':'PASS','python':result['python'],
    'started_at':result['started_at'],'finished_at':result['finished_at'],'source_tree':result['generation']['tree'],'source_files':3121,
    'generators':131,'passes':2,'original_generator_command_limit_seconds':300,'actual_generator_commands':262,
    'all_commands':len(commands),'original_command_files':len(paths),'all_commands_returned_zero_without_timeout':True,
    'exact_generator_name_index_order_and_interpreter_verified':True,'derived_paths':changed,'derived_source':pin(derived_raw),
    'complete_command_originals':pin(transport),'complete_original_payload_files':len(files),
    'generation_result':pin(result_raw),'terminal_source_index':pin(index_raw),
    'physical_legacy_paths_retired_only_in_isolated_development_tree':55,'main_changed':False,
    'Source_tests_qualification':False,'Native_qualification':False,'current_source_cold_qualified':False,'whole_native':False}
put('GENERATION-FIXED-POINT-REPORT.json',enc(report));print(json.dumps(report,sort_keys=True))
