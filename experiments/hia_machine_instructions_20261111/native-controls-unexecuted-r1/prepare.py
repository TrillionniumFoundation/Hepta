"""Materialize one frozen candidate and compile three explicit development images."""
import ast
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import urllib.request
from development_common import blob, command, digest, original_metadata, path_bytes, save, snapshot, verified

root=Path(sys.argv[1]).resolve(strict=True)
request=json.loads((root/'request.json').read_bytes())
source=root/'source'
original=Path(request['original_source'])
state_objects=Path(request['state_object_repository'])
started=time.monotonic()
report={'schema':'hia.machine-instructions-development-prepare.v1','status':'STARTED',
    'scope':'EXPLICIT_DEVELOPMENT_ONLY','product_candidate_commit':request['candidate_commit'],
    'product_candidate_tree':request['candidate_tree'],'actual_checkout_HEAD':None,
    'commands':[],'native_compiles':[],'current_matching_cold':False,
    'product_tests_executed':False,'default_or_whole_native_claimed':False,
    'python':sys.version,'executable':sys.executable}
before=state_before=candidate_before=compiler_before=None

def run(label, argv, cwd, stdin=None):
    at=time.monotonic()
    result=subprocess.run(argv,cwd=cwd,input=stdin,capture_output=True)
    (root/(label+'.stdout')).write_bytes(result.stdout)
    (root/(label+'.stderr')).write_bytes(result.stderr)
    report['commands'].append({'label':label,'argv':argv,'cwd':str(cwd),
        'returncode':result.returncode,'seconds':time.monotonic()-at,
        'stdout_sha256':digest(result.stdout),'stderr_sha256':digest(result.stderr)})
    if result.returncode:
        raise RuntimeError(label+' returned '+str(result.returncode))
    return result.stdout

def download(row):
    relative=Path(row['path'])
    if relative.is_absolute() or '..' in relative.parts or row['mode']!='100644':
        raise ValueError('invalid frozen source path')
    url='https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/'+request['candidate_commit']+'/'+row['path']
    at=time.monotonic()
    with urllib.request.urlopen(url,timeout=45) as response:
        raw=response.read(row['bytes']+1)
        status=response.status
    if status!=200:
        raise RuntimeError('immutable source download status '+str(status))
    verified(raw,row)
    return row,raw,{'url':url,'status':status,'bytes':len(raw),
        'sha256':digest(raw),'git_blob':blob(raw),'seconds':time.monotonic()-at}

try:
    assert root==Path('/home/qian-qi/he26instructions-native-prepare-r1')
    assert request['source_head']=='608157e52b0b94e0d294f6b99c4e809869f183aa'
    binary=Path(sys.executable).resolve()
    assert digest(binary.read_bytes())==request['python_binary_sha256']
    report['python_binary_sha256']=digest(binary.read_bytes())
    before=original_metadata(original,request['source_tree'])
    state_before=original_metadata(state_objects,request['state_tree'])
    report['original_before'],report['state_objects_before']=before,state_before
    if (before['head']!=request['source_head'] or before['head_tree']!=request['source_tree']
        or before['tracked_status'] or before['owner_sha256']!=request['owner_sha256']):
        raise RuntimeError('original exact608 identity differs')
    if state_before['head']!=request['source_head'] or state_before['owner_sha256']!=request['owner_sha256']:
        raise RuntimeError('original state object repository differs')
    volume=os.statvfs(root)
    report['actual_storage_before']={'available_bytes':volume.f_bavail*volume.f_frsize,
        'available_inodes':volume.f_favail,'device':root.stat().st_dev}
    if volume.f_bavail*volume.f_frsize<2*(1<<30):
        raise RuntimeError('insufficient development preparation storage')
    run('clone',['git','clone','--no-local','--no-hardlinks','--',str(original),str(source)],root)
    head=command(['git','rev-parse','HEAD'],source)
    if head!=request['source_head']:
        raise RuntimeError('actual checkout HEAD differs')
    report['actual_checkout_HEAD']=head
    specs=request['state_delta']
    stream=run('state-git-objects',['git','cat-file','--batch'],state_objects,
        ''.join(row['sha']+'\n' for row in specs).encode())
    cursor=0
    for row in specs:
        end=stream.index(b'\n',cursor)
        identity,kind,length=stream[cursor:end].decode().split()
        length=int(length)
        cursor=end+1
        raw=stream[cursor:cursor+length]
        cursor+=length
        if stream[cursor:cursor+1]!=b'\n' or identity!=row['sha'] or kind!='blob':
            raise RuntimeError('original state Git object framing differs')
        cursor+=1
        verified(raw,row)
        target=source/row['path']
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o644)
    if cursor!=len(stream):
        raise RuntimeError('extra state Git object bytes')
    run('stage-state',['git','add','--',*[row['path'] for row in specs]],source)
    if command(['git','write-tree'],source)!=request['state_tree']:
        raise RuntimeError('materialized state tree differs')
    state_leaves=snapshot(source)
    if len(state_leaves)!=3933:
        raise RuntimeError('original state source denominator differs')
    save(root,'state-source-leaves.json',state_leaves)
    rows=request['candidate_delta']
    if len(rows)!=18 or len({row['path'] for row in rows})!=18:
        raise RuntimeError('candidate source delta denominator differs')
    # Every read is one attempt; there is no download or product retry.
    with ThreadPoolExecutor(max_workers=4) as pool:
        downloaded=list(pool.map(download,rows))
    report['downloads']=[]
    for row,raw,receipt in downloaded:
        target=source/row['path']
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o644)
        if target.suffix=='.py':
            ast.parse(raw.decode(),filename=str(target))
        report['downloads'].append(receipt)
    run('stage-candidate',['git','add','--',*[row['path'] for row in rows]],source)
    tree=command(['git','write-tree'],source)
    changed=command(['git','diff','--name-only',request['state_tree'],tree,'--'],source).splitlines()
    if tree!=request['candidate_tree'] or changed!=sorted(row['path'] for row in rows):
        raise RuntimeError('real candidate index tree or exact 18 delta differs')
    candidate_before=snapshot(source)
    if len(candidate_before)!=3941:
        raise RuntimeError('complete candidate leaf denominator differs')
    save(root,'candidate-source-before.json',candidate_before)
    report['actual_candidate_index_tree']=tree
    report['candidate_source_leaves']=len(candidate_before)
    report['source_identity_binding']={'actual_HEAD':head,'materialized_index_tree':tree,
        'canonical_product_tree':request['candidate_tree'],
        'publication_commit':request['candidate_commit'],
        'not_claimed_HEAD_is_publication_commit':True}
    sys.path.insert(0,str(source))
    from tools.hia_selfhost_contract import validate_contract, file_digests, CONTRACT_PATH
    validate_contract(source)
    pins={**file_digests(source),CONTRACT_PATH:digest((source/CONTRACT_PATH).read_bytes())}
    save(root,'candidate-source-pins.json',pins)
    report['candidate_source_pins']=len(pins)
    compiler_path=Path(request['compiler_path'])
    compiler_before,compiler_raw=path_bytes(compiler_path)
    if len(compiler_raw)!=668608 or digest(compiler_raw)!=request['compiler_sha256']:
        raise RuntimeError('actual development B3 differs')
    inputs=root/'inputs'
    inputs.mkdir(mode=0o700)
    compiler=inputs/'B3.image.bin'
    compiler.write_bytes(compiler_raw)
    compiler.chmod(0o400)
    report['development_compiler']={'original':compiler_before,'copy':path_bytes(compiler)[0],
        'producer_cold_status':'FAILED','matching_cold_admission':False}
    from tools.qualify_hia_selfhost import compile_stage
    components=[
        ('encoding','examples/hia_bootstrap/machine_encoding.hiaasm','hepta.hia.machine-encoding-native.v2'),
        ('state','examples/hia_bootstrap/machine_state.hiaasm','hepta.hia.machine-state-native.v1'),
        ('instructions','examples/hia_bootstrap/machine_instructions.hiaasm','hepta.hia.machine-instructions-native.v1')]
    manifests={}
    for label,relative,schema in components:
        output=root/label
        output.mkdir(mode=0o700)
        raw=(source/relative).read_bytes()
        if pins.get(relative)!=digest(raw):
            raise RuntimeError('compiled source differs from actual source manifest')
        at=time.monotonic()
        image,receipt=compile_stage(output,label,compiler,raw)
        manifest={'schema':schema,'source_sha256':digest(raw),'image_path':image.name,
            'image_sha256':digest(image.read_bytes()),'compiler_sha256':digest(compiler_raw)}
        path=output/'manifest.json'
        save(output,'manifest.json',manifest)
        manifests[label+'_manifest']=str(path)
        report['native_compiles'].append({'label':label,'source_path':relative,
            'source_bytes':len(raw),'source_sha256':digest(raw),'manifest':manifest,
            'image':path_bytes(image)[0],'manifest_file':path_bytes(path)[0],
            'receipt':receipt,'seconds':time.monotonic()-at})
        if (source/relative).read_bytes()!=raw or compiler.read_bytes()!=compiler_raw:
            raise RuntimeError('native compiler or source changed')
    save(root,'bundle.json',manifests)
    report['bundle']=path_bytes(root/'bundle.json')[0]
    report['status']='EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED'
except BaseException:
    report['status']='HOLD'
    report['exception']=traceback.format_exc()
finally:
    try:
        if before is not None:
            report['original_after']=original_metadata(original,request['source_tree'])
            report['original_source_metadata_stable']=report['original_after']==before
            if not report['original_source_metadata_stable']:
                report['status']='HOLD'
        if state_before is not None:
            report['state_objects_after']=original_metadata(state_objects,request['state_tree'])
            report['state_object_repository_metadata_stable']=report['state_objects_after']==state_before
            if not report['state_object_repository_metadata_stable']:
                report['status']='HOLD'
        if candidate_before is not None:
            after=snapshot(source)
            save(root,'candidate-source-after.json',after)
            report['candidate_source_stable']=after==candidate_before
            if not report['candidate_source_stable']:
                report['status']='HOLD'
        if compiler_before is not None:
            report['development_compiler_stable']=path_bytes(Path(request['compiler_path']))[0]==compiler_before
            if not report['development_compiler_stable']:
                report['status']='HOLD'
    except BaseException:
        report['status']='HOLD'
        report['final_identity_error']=traceback.format_exc()
    report['seconds']=time.monotonic()-started
    save(root,'report.json',report)
    print(json.dumps({key:report.get(key) for key in ('status','scope','seconds',
        'actual_candidate_index_tree','candidate_source_leaves','candidate_source_pins','exception')},
        sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED' else 1)
