"""New isolated desktop materialization and HIA authoring only; no native run."""
from pathlib import Path
from hashlib import sha1,sha256
import ast,json,os,stat,subprocess,sys,time,traceback,urllib.request
root=Path(sys.argv[1])
request=json.loads((root/'request.json').read_bytes())
source=root/'source'
original=Path(request['original_source'])
report={'schema':'hia.machine-instructions-remote-authoring.v1','status':'HOLD',
 'scope':'ISOLATED_SOURCE_MATERIALIZATION_AND_AUTHORING_ONLY',
 'native_compilation_executed':False,'product_tests_executed':False,
 'matching_current_cold':False,'whole_native_delivery':False,
 'commands':[],'downloads':[],'python':sys.version,'executable':sys.executable,
 'base_product_commit':request['base_product_commit'],
 'prototype_commit':request['prototype_commit']}
started=time.monotonic()
env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
 'PYTHONDONTWRITEBYTECODE':'1','GIT_CONFIG_NOSYSTEM':'1',
 'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0'}
def blob(raw):
    return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(name,value):
    (root/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def run(label,command,cwd,timeout=120):
    at=time.monotonic()
    done=subprocess.run(command,cwd=cwd,env=env,capture_output=True,timeout=timeout)
    (root/(label+'.stdout')).write_bytes(done.stdout)
    (root/(label+'.stderr')).write_bytes(done.stderr)
    report['commands'].append({'label':label,'argv':command,'returncode':done.returncode,
      'seconds':time.monotonic()-at,'stdout_sha256':sha256(done.stdout).hexdigest(),
      'stderr_sha256':sha256(done.stderr).hexdigest()})
    save('report.json',report)
    if done.returncode:raise RuntimeError(label+' returned '+str(done.returncode))
    return done.stdout
def git(*args,cwd):
    return subprocess.check_output(['/usr/bin/git',*args],cwd=cwd,env=env).decode().strip()
def original_state():
    return {'head':git('rev-parse','HEAD',cwd=original),
      'tree':git('rev-parse','HEAD^{tree}',cwd=original),
      'tracked_status':git('status','--porcelain','--untracked-files=no',cwd=original),
      'owner_sha256':sha256((original/'tools/hia_selfhost_process_owner.py').read_bytes()).hexdigest()}
def fetch(url,expected_blob,expected_bytes,expected_sha256=None):
    if not url.startswith('https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/'):
        raise ValueError('unexpected source URL')
    with urllib.request.urlopen(url,timeout=20) as response:
        raw=response.read(2*1024*1024+1)
    if len(raw)!=expected_bytes or blob(raw)!=expected_blob:
        raise ValueError('immutable Git source bytes differ: '+url)
    if expected_sha256 and sha256(raw).hexdigest()!=expected_sha256:
        raise ValueError('SHA256 differs: '+url)
    report['downloads'].append({'url':url,'bytes':len(raw),'git_blob':blob(raw),
                               'sha256':sha256(raw).hexdigest()})
    return raw
try:
    before=original_state()
    report['original_before']=before
    assert before['head']==request['original_commit']
    assert before['tree']==request['original_tree'] and before['tracked_status']==''
    assert before['owner_sha256']==request['owner_sha256']
    binary=Path(sys.executable).resolve()
    assert sha256(binary.read_bytes()).hexdigest()==request['python_binary_sha256']
    fs=os.statvfs(root)
    report['actual_storage_before']={'device':root.stat().st_dev,
      'available_bytes':fs.f_bavail*fs.f_frsize,'available_inodes':fs.f_favail}
    assert report['actual_storage_before']['available_bytes']>2*1024*1024*1024
    run('clone',['/usr/bin/git','clone','--no-local','--no-hardlinks','--',
                 str(original),str(source)],root)
    assert git('rev-parse','HEAD',cwd=source)==request['original_commit']
    assert git('rev-parse','HEAD^{tree}',cwd=source)==request['original_tree']
    delta_raw=fetch(request['state_delta_url'],request['state_delta_blob'],
                    request['state_delta_bytes'])
    (root/'original-state-delta.json').write_bytes(delta_raw)
    delta=json.loads(delta_raw)
    assert delta['source_commit']==request['base_product_commit']
    assert delta['source_tree']==request['base_product_tree'] and delta['count']==15
    for row in delta['files']:
        relative=Path(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        raw=fetch(request['raw_prefix']+request['base_product_commit']+'/'+row['path'],
                  row['sha'],row['bytes'],row['sha256'])
        target=source/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
    run('stage-state',['/usr/bin/git','add','--',*[r['path'] for r in delta['files']]],source)
    assert git('write-tree',cwd=source)==request['base_product_tree']
    report['actual_checkout_head']=git('rev-parse','HEAD',cwd=source)
    report['state_materialized_index_tree']=git('write-tree',cwd=source)
    for row in request['prototype_files']:
        relative=Path(row['target'])
        assert not relative.is_absolute() and '..' not in relative.parts
        raw=fetch(request['raw_prefix']+request['prototype_commit']+'/'+row['path'],
                  row['sha'],row['bytes'])
        target=source/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
        ast.parse(raw)
    original_image=Path(request['compiler_path'])
    image=original_image.read_bytes()
    assert len(image)==request['compiler_bytes']
    assert sha256(image).hexdigest()==request['compiler_sha256']
    inputs=root/'inputs';inputs.mkdir(mode=0o700)
    (inputs/'B3.image.bin').write_bytes(image);(inputs/'B3.image.bin').chmod(0o400)
    report['development_compiler']={'original_path':str(original_image),
        'bytes':len(image),'sha256':sha256(image).hexdigest(),
        'producer_scope':'FAILED_608_COLD_RUN_COMPLETED_B3_GENERATION_ONLY',
        'matching_source_cold':False}
    run('generate-instructions',[sys.executable,'-B','-m',
                                  'tools.generate_hia_machine_instructions'],source)
    sys.path.insert(0,str(source))
    from tools.generate_hia_machine_instructions import document,MODES
    from hepta.hia_agent_assembly import assemble_program
    generated=source/'examples/hia_bootstrap/machine_instructions.hiaasm'
    raw=generated.read_bytes()
    value=document()
    assert assemble_program(raw).as_dict()==value
    functions=[]
    for f in value['functions']:
        values=list(f['params'])
        for block in f['blocks']:
            values.extend(block['params'])
            for operation in block['ops']:values.extend(operation['out'])
        functions.append({'name':f['name'],'blocks':len(f['blocks']),
          'ops':sum(len(b['ops']) for b in f['blocks']),
          'max_ssa_index':max(int(v['name'][1:]) for v in values)})
    measurements={'source_bytes':len(raw),'lines':len(raw.splitlines()),
      'functions':len(functions),'blocks':sum(f['blocks'] for f in functions),
      'max_blocks_per_function':max(f['blocks'] for f in functions),
      'ops':sum(f['ops'] for f in functions),
      'max_ssa_index':max(f['max_ssa_index'] for f in functions)}
    report['generated_source']={'path':str(generated),'sha256':sha256(raw).hexdigest(),
      'git_blob':blob(raw),'measurements':measurements,'functions':functions,
      'modes':list(MODES)}
    save('generated-source.json',report['generated_source'])
    limits={'source_bytes':1048576,'lines':16384,'functions':128,
            'blocks':1536,'max_blocks_per_function':256,'ops':8192,'max_ssa_index':2047}
    report['original_limits']=limits
    assert all(measurements[k]<=maximum for k,maximum in limits.items()), measurements
    assert len(MODES)==41
    assert original_image.read_bytes()==image
    report['status']='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
except BaseException:
    report['exception']=traceback.format_exc()
finally:
    try:
        report['original_after']=original_state()
        report['original_source_metadata_stable']=report.get('original_before')==report['original_after']
        if not report['original_source_metadata_stable']:report['status']='HOLD'
    except BaseException:
        report['original_after_error']=traceback.format_exc();report['status']='HOLD'
    report['seconds']=time.monotonic()-started
    save('report.json',report)
    print(json.dumps({k:report.get(k) for k in ('status','scope','seconds','exception',
      'generated_source','original_source_metadata_stable')},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED' else 1)
