"""Isolated second instruction authoring; no native image or product tests."""
from __future__ import annotations
import ast
from hashlib import sha1,sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

root=Path(sys.argv[1]).resolve(strict=True)
request=json.loads((root/'request.json').read_bytes())
source=root/'source'
original=Path(request['original_source'])
state_objects=Path(request['state_object_repository'])
started=time.monotonic()
report={'schema':'hia.machine-instructions-complete-authoring.v2','status':'STARTED',
 'scope':'ISOLATED_SOURCE_AUTHORING_ONLY','frozen_prototype_commit':request['prototype_commit'],
 'commands':[],'native_compilation_executed':False,'product_tests_executed':False,
 'matching_current_cold':False,'whole_native_delivery':False,
 'python':sys.version,'executable':sys.executable}
def blob(raw):
    return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def digest(raw):
    return sha256(raw).hexdigest()
def save(name,value):
    (root/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def simple(arguments,cwd):
    return subprocess.check_output(arguments,cwd=cwd).decode().strip()
def metadata(path):
    expected=request['source_tree'] if path==original else request['state_tree']
    subprocess.run(['git','diff','--cached','--quiet',expected,'--'],cwd=path,check=True)
    index=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=path)
    return {'head':simple(['git','rev-parse','HEAD'],path),
     'tree':simple(['git','rev-parse','HEAD^{tree}'],path),
     'index_matches_expected_tree':expected,'index_entries_sha256':digest(index),
     'tracked_status':simple(['git','status','--porcelain','--untracked-files=no'],path),
     'owner_sha256':digest((path/'tools/hia_selfhost_process_owner.py').read_bytes())}
def run(label,arguments,cwd,stdin=None):
    at=time.monotonic()
    result=subprocess.run(arguments,cwd=cwd,input=stdin,capture_output=True,timeout=120)
    (root/(label+'.stdout')).write_bytes(result.stdout)
    (root/(label+'.stderr')).write_bytes(result.stderr)
    row={'label':label,'argv':arguments,'cwd':str(cwd),'returncode':result.returncode,
         'seconds':time.monotonic()-at,'stdout_sha256':digest(result.stdout),
         'stderr_sha256':digest(result.stderr)}
    report['commands'].append(row)
    if result.returncode:raise RuntimeError(label+' returned '+str(result.returncode))
    return result.stdout
def index_snapshot(path):
    raw=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=path)
    rows=[]
    for entry in raw.split(b'\0'):
        if not entry:continue
        header,name=entry.split(b'\t',1)
        mode,expected,stage=header.decode().split()
        name=name.decode()
        p=path/name
        info=p.lstat()
        if stage!='0' or mode!='100644' or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
            raise ValueError('nonregular/index source leaf '+name)
        data=p.read_bytes()
        if blob(data)!=expected or info.st_mode & 0o111:
            raise ValueError('source byte/mode differs from real index '+name)
        rows.append({'path':name,'mode':mode,'git_blob':expected,'bytes':len(data),'sha256':digest(data),'posix_mode':stat.S_IMODE(info.st_mode)})
    return rows
def document_caps(document,raw):
    functions=[]
    for function in document['functions']:
        definitions=list(function['params'])
        for block in function['blocks']:
            definitions+=block['params']
            for operation in block['ops']:
                definitions+=operation['out']
            if len(block['params'])>16:raise ValueError('original block parameter limit')
            term=block['term']
            edges=[term] if term['op']=='jump' else [term['then'],term['else']] if term['op']=='branch' else []
            if any(len(edge['args'])>16 for edge in edges):raise ValueError('original edge parameter limit')
        row={'name':function['name'],'parameters':len(function['params']),
             'blocks':len(function['blocks']),'operations':sum(len(b['ops']) for b in function['blocks']),
             'unique_ssa_names':len({v['name'] for v in definitions}),
             'largest_numeric_suffix_observed_only':max(int(v['name'][1:]) for v in definitions)}
        if row['parameters']>16 or row['blocks']>256 or row['unique_ssa_names']>2048:
            raise ValueError('original per-function caps exceeded '+str(row))
        functions.append(row)
    totals={'source_bytes':len(raw),'source_lines':len(raw.splitlines()),'functions':len(functions),
            'blocks':sum(f['blocks'] for f in functions),'operations':sum(f['operations'] for f in functions)}
    for key,limit in [('source_bytes',1048576),('source_lines',16384),('functions',128),('blocks',1536),('operations',8192)]:
        if totals[key]>limit:raise ValueError('original '+key+' limit exceeded')
    return {'totals':totals,'per_function':functions}
before=state_before=None
try:
    assert root==Path('/home/qian-qi/he26instructionsr2')
    assert request['source_head']=='608157e52b0b94e0d294f6b99c4e809869f183aa'
    binary=Path(sys.executable).resolve()
    assert digest(binary.read_bytes())==request['python_binary_sha256']
    report['python_binary_sha256']=digest(binary.read_bytes())
    volume=os.statvfs(root)
    report['actual_storage_before']={'available_bytes':volume.f_bavail*volume.f_frsize,
        'available_inodes':volume.f_favail,'device':root.stat().st_dev}
    if volume.f_bavail*volume.f_frsize<2*(1<<30):raise RuntimeError('authoring storage below original request')
    before=metadata(original)
    state_before=metadata(state_objects)
    report['original_before'],report['state_objects_before']=before,state_before
    if (before['head']!=request['source_head'] or before['tree']!=request['source_tree']
        or before['index_matches_expected_tree']!=request['source_tree'] or before['tracked_status']
        or before['owner_sha256']!=request['owner_sha256']):
        raise RuntimeError('original exact608 source metadata differs')
    if (state_before['head']!=request['source_head'] or state_before['index_matches_expected_tree']!=request['state_tree']
        or state_before['owner_sha256']!=request['owner_sha256']):
        raise RuntimeError('original r1 state object repository differs')
    run('clone',['git','clone','--no-local','--no-hardlinks','--',str(original),str(source)],root)
    report['actual_checkout_head']=simple(['git','rev-parse','HEAD'],source)
    if report['actual_checkout_head']!=request['source_head']:raise RuntimeError('new clone HEAD differs')
    specs=request['state_delta']
    stream=run('read-state-git-objects',['git','cat-file','--batch'],state_objects,
               ''.join(f['sha']+'\n' for f in specs).encode())
    cursor=0
    for item in specs:
        end=stream.index(b'\n',cursor)
        identity,kind,length=stream[cursor:end].decode().split()
        length=int(length);cursor=end+1
        raw=stream[cursor:cursor+length];cursor+=length
        if stream[cursor:cursor+1]!=b'\n':raise RuntimeError('Git batch separator differs')
        cursor+=1
        if (identity!=item['sha'] or kind!='blob' or len(raw)!=item['bytes']
            or blob(raw)!=item['sha'] or digest(raw)!=item['sha256']):
            raise RuntimeError('canonical state source object differs '+item['path'])
        target=source/item['path'];target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(0o644)
    if cursor!=len(stream):raise RuntimeError('extra Git batch payload')
    run('stage-state',['git','add','--',*[f['path'] for f in specs]],source)
    report['state_materialized_index_tree']=simple(['git','write-tree'],source)
    if report['state_materialized_index_tree']!=request['state_tree']:
        raise RuntimeError('real state index tree differs')
    baseline=index_snapshot(source)
    save('state-source-leaves.json',baseline)
    if len(baseline)!=3933:raise RuntimeError('complete state source leaf count differs')
    parsed=[]
    for item in request['files']:
        relative=Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('invalid source path')
        raw=item['content'].encode()
        if len(raw)!=item['bytes'] or blob(raw)!=item['sha'] or digest(raw)!=item['sha256']:
            raise RuntimeError('frozen author input differs '+str(relative))
        target=source/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(0o644)
        if relative.suffix=='.py':
            ast.parse(raw.decode(),filename=str(relative));parsed.append(str(relative))
    report['parsed_python_files']=parsed
    compiler_path=Path(request['compiler_path'])
    compiler=compiler_path.read_bytes()
    if len(compiler)!=668608 or digest(compiler)!=request['compiler_sha256']:
        raise RuntimeError('original development compiler differs')
    (root/'inputs').mkdir(mode=0o700)
    (root/'inputs/B3.image.bin').write_bytes(compiler)
    (root/'inputs/B3.image.bin').chmod(0o400)
    report['development_compiler']={'original_path':str(compiler_path),'bytes':len(compiler),
        'sha256':digest(compiler),'executed':False,
        'producer_scope':'FAILED_608_COLD_RUN_COMPLETED_B3_GENERATION_ONLY','matching_source_cold':False}
    run('generate-instructions',[sys.executable,'-B','-m','tools.generate_hia_machine_instructions'],source)
    sys.path.insert(0,str(source))
    from tools.generate_hia_machine_instructions import document,MODES
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    generated=source/'examples/hia_bootstrap/machine_instructions.hiaasm'
    raw=generated.read_bytes()
    doc=document()
    if render_assembly(doc).encode()!=raw or assemble_program(raw).as_dict()!=doc:
        raise RuntimeError('complete generated source/Core roundtrip differs')
    if len(MODES)!=41:raise RuntimeError('instruction mode denominator differs')
    report['source_caps']=document_caps(doc,raw)
    report['instruction_modes']=list(MODES)
    run('generate-coverage',[sys.executable,'-B','tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],source)
    run('generate-contract',[sys.executable,'-B','-m','tools.generate_hia_selfhost_contract'],source)
    run('check-contract',[sys.executable,'-B','-m','tools.generate_hia_selfhost_contract','--check'],source)
    run('check-source-scope',[sys.executable,'-B','tools/check_hia_core_only.py'],source)
    generated_names=['examples/hia_bootstrap/machine_instructions.hiaasm',
        'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json','docs/HIA_SELFHOST_CORE_SUPPORT.json']
    candidate_paths=sorted({f['path'] for f in request['files']}|set(generated_names))
    run('stage-candidate',['git','add','--',*candidate_paths],source)
    tree=simple(['git','write-tree'],source)
    changed=simple(['git','diff','--name-only',request['state_tree'],tree,'--'],source).splitlines()
    if changed!=candidate_paths:raise RuntimeError('candidate real tree delta differs '+repr(changed))
    leaves=index_snapshot(source)
    if len(leaves)!=3941:raise RuntimeError('candidate complete source leaf count differs')
    save('candidate-source-leaves.json',leaves)
    rows={r['path']:r for r in leaves}
    report['candidate_index_tree']=tree
    report['candidate_changed_paths']=changed
    report['candidate_source_leaves']=len(leaves)
    report['source_identity_binding']={'actual_HEAD':report['actual_checkout_head'],
        'base_product_commit':request['state_commit'],'base_product_index_tree':request['state_tree'],
        'actual_materialized_index_tree':tree,'not_claimed_checked_out_canonical_commit':True}
    from tools.hia_selfhost_contract import file_digests,CONTRACT_PATH
    pins=file_digests(source)
    pins[CONTRACT_PATH]=digest((source/CONTRACT_PATH).read_bytes())
    save('candidate-source-pins.json',pins)
    report['candidate_source_pins']=len(pins)
    parts=root/'publication-parts';parts.mkdir(mode=0o700)
    publication=[]
    for index,name in enumerate(candidate_paths):
        raw=(source/name).read_bytes()
        row={**rows[name],'parts':[]}
        # All generated HIA/support bytes are ASCII; source files may be UTF-8.
        # Chunk as bytes and encode with base64 only if a chunk is not full UTF-8.
        for number,at in enumerate(range(0,len(raw),49152)):
            piece=raw[at:at+49152]
            filename='file%02d.part%03d.bin'%(index,number)
            (parts/filename).write_bytes(piece)
            row['parts'].append({'path':str(parts/filename),'offset':at,
                'bytes':len(piece),'sha256':digest(piece)})
        publication.append(row)
    save('publication.json',{'schema':'hia.actual-generated-source-publication.v1',
        'base_commit':request['state_commit'],'base_tree':request['state_tree'],
        'actual_HEAD':report['actual_checkout_head'],'actual_index_tree':tree,
        'files':publication,'native_compilation_executed':False,'product_tests_executed':False})
    report['publication_manifest_sha256']=digest((root/'publication.json').read_bytes())
    report['development_compiler_stable']=compiler_path.read_bytes()==compiler
    if not report['development_compiler_stable']:raise RuntimeError('development compiler changed')
    report['status']='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
except BaseException:
    report['status']='HOLD';report['exception']=traceback.format_exc()
finally:
    if before is not None:
        try:
            report['original_after']=metadata(original)
            report['original_source_metadata_stable']=report['original_after']==before
            report['state_objects_after']=metadata(state_objects)
            report['state_object_repository_metadata_stable']=report['state_objects_after']==state_before
            if not report['original_source_metadata_stable'] or not report['state_object_repository_metadata_stable']:
                report['status']='HOLD'
        except BaseException:
            report['status']='HOLD';report['final_identity_error']=traceback.format_exc()
    report['seconds']=time.monotonic()-started
    save('report.json',report)
    print(json.dumps({k:report.get(k) for k in ('schema','status','scope','seconds',
        'candidate_index_tree','candidate_source_leaves','candidate_source_pins','source_caps','exception')},
        sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED' else 1)
