"""Freeze an isolated complete Source6/derive8 context on the Actions host."""
from __future__ import annotations
import argparse,ast,hashlib,json,os,stat,sys
from pathlib import Path

def need(value,message):
    if not value: raise RuntimeError(message)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def blob(raw): return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def wire(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def ident(s):
    return dict(dev=s.st_dev,ino=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,
                nlink=s.st_nlink,size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def read(path):
    path=Path(path).absolute()
    need(path.resolve(strict=True)==path,'aliased input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid in (0,os.geteuid())
             and not stat.S_IMODE(a.st_mode)&0o022,'unsafe input')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read()
        need(ident(a)==ident(os.fstat(fd))==ident(path.lstat()),'changed input')
    finally: os.close(fd)
    return raw,dict(path=str(path),bytes=len(raw),sha256=digest(raw),identity=ident(a))
def put(path,raw,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    need(path.parent.resolve(strict=True)==path.parent.absolute(),'aliased output parent')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    rb,pin=read(path);need(rb==raw,'whole write readback');return pin
def tree_hash(rows):
    tree={}
    for row in rows:
        node=tree;parts=row['path'].split('/')
        for part in parts[:-1]: node=node.setdefault(part,{})
        need(parts[-1] not in node,'duplicate leaf');node[parts[-1]]=row
    def walk(node):
        entries=[]
        for name,item in sorted(node.items(),key=lambda x:(x[0]+('' if isinstance(x[1].get('sha'),str) else '/')).encode()):
            leaf=isinstance(item.get('sha'),str)
            entries.append((item['mode'] if leaf else '40000').encode()+b' '+name.encode()+b'\0'+bytes.fromhex(item['sha'] if leaf else walk(item)))
        raw=b''.join(entries)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return walk(tree)
def source_paths(root):
    answer=[]
    for path in root.rglob('*'):
        s=path.lstat();need(not stat.S_ISLNK(s.st_mode),'source symlink')
        if stat.S_ISDIR(s.st_mode): continue
        need(stat.S_ISREG(s.st_mode),'source special file');answer.append(path.relative_to(root).as_posix())
    return sorted(answer)
def emit(value):
    target=Path(os.environ['GITHUB_OUTPUT'])
    with target.open('a',encoding='utf-8') as stream:
        for key,text in value.items():
            need('\n' not in text and '\r' not in text,'multiline action output')
            stream.write(key+'='+text+'\n')
        stream.flush();os.fsync(stream.fileno())
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    args=parser.parse_args();os.umask(0o077)
    policy_raw,policy_pin=read(args.policy);need(digest(policy_raw)==args.sha256,'policy SHA')
    policy=json.loads(policy_raw);payload=args.policy.parent
    need(policy['schema']=='hia.core-zero-store-fixture.remote-source6-derive8.policy.v1','policy schema')
    need(os.environ.get('GITHUB_REPOSITORY')==policy['repository']
         and os.environ.get('GITHUB_EVENT_NAME')=='push'
         and os.environ.get('GITHUB_REF')=='refs/heads/'+policy['branch']
         and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','isolated event binding')
    run=os.environ['GITHUB_RUN_ID'];need(run.isascii() and run.isdecimal(),'run identity')
    head=os.environ['GITHUB_SHA'];need(len(head)==40 and all(c in '0123456789abcdef' for c in head),'head identity')
    checkout=Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    need(payload.resolve(strict=True)==checkout/policy['git_prefix'],'payload context')
    work=Path(os.environ['RUNNER_TEMP']).resolve(strict=True)/('hia-core-fixture-source6-derive8-'+run+'-1')
    need(not work.exists(),'fresh remote qualification namespace')
    v=os.statvfs(work.parent)
    need(v.f_bavail*v.f_frsize>=2147483648 and v.f_favail>=16384,'original metadata copy capacity')
    work.mkdir(mode=0o700);meta=work/'metadata';meta.mkdir(mode=0o700)
    put(meta/'METADATA-INTENT.json',wire(dict(status='METADATA_PREPARATION_ONLY',run_id=run,attempt=1,
        workflow_head=head,policy=policy_pin,original_ai395_metadata_unknown=policy['ai395_unknown'],
        source6_executed=False,derive8_executed=False,native_executed=False)))
    files={}
    for row in policy['payload_files']:
        raw,pin=read(payload/row['path'])
        need(len(raw)==row['bytes'] and digest(raw)==row['sha256'] and blob(raw)==row['git_blob_sha1'],'payload '+row['path'])
        files[row['path']]=(raw,pin)
    rows=json.loads(files['BASE-TREE.json'][0])['files']
    names=[r['path'] for r in rows]
    need(names==sorted(set(names)) and len(rows)==4132 and sum(r['size'] for r in rows)==412300821
         and tree_hash(rows)==policy['base_tree'],'whole pure base tree')
    helper=files['candidate/tests/hia_core_pc_expected.py'][0]
    original_workflow=files['reference/hia-core.original.yml'][0]
    source=work/'source';source.mkdir(mode=0o700);controls=work/'control';controls.mkdir(mode=0o700)
    inputs=[]
    # The five old source/owner controls are reused byte-for-byte.
    for name in policy['runtime_controls']:
        raw,_=files['control/'+name];inputs.append(put(controls/name,raw));ast.parse(raw,filename=name)
    inputs.append(put(meta/'POLICY.json',policy_raw))
    for rel,(raw,pin) in files.items(): inputs.append(put(meta/'payload'/rel,raw))
    material=[];changed=[];origin_pins=[];matches=[]
    tokens=[v.encode() for v in policy['consumer_search_terms']]
    for row in rows:
        rel=row['path']
        if rel=='.github/workflows/hia-core.yml':
            raw=original_workflow;origin=files['reference/hia-core.original.yml'][1]
        else: raw,origin=read(checkout/rel)
        need(row['type']=='blob' and len(raw)==row['size'] and blob(raw)==row['sha'],'base body '+rel)
        need(row['mode'] in ('100644','100755'),'base Git role')
        origin_pins.append(origin)
        found=[policy['consumer_search_terms'][i] for i,value in enumerate(tokens) if value in raw]
        if found:
            matches.append(dict(path=rel,bytes=len(raw),sha256=digest(raw),git_blob_sha1=blob(raw),
                                occurrences={value:raw.count(value.encode()) for value in found}))
        candidate=helper if rel=='tests/hia_core_pc_expected.py' else raw
        if candidate!=raw: changed.append(rel)
        observed=put(source/rel,candidate,0o700 if row['mode']=='100755' else 0o600)
        material.append(dict(path=rel,mode=row['mode'],
            baseline=dict(bytes=len(raw),sha256=digest(raw),git_blob_sha1=blob(raw)),
            candidate=dict(bytes=len(candidate),sha256=digest(candidate),git_blob_sha1=blob(candidate)),
            physical=observed['identity']))
    need(changed==['tests/hia_core_pc_expected.py'] and source_paths(source)==names,'one helper and full source set')
    for pin in origin_pins: need(ident(Path(pin['path']).lstat())==pin['identity'],'base physical identity changed')
    materialization=dict(schema='hia.core39.remote-source-materialization.v1',source_root=str(source),
        file_count=4132,bytes=sum(r['candidate']['bytes'] for r in material),base_commit=policy['base_commit'],
        base_tree=policy['base_tree'],files=material)
    material_pin=put(meta/'SOURCE-MATERIALIZATION.json',wire(materialization));inputs.append(material_pin)
    inputs.append(put(meta/'HELPER-CONSUMERS.json',wire(dict(full_files=4132,full_bytes=412300821,
        terms=policy['consumer_search_terms'],matches=matches,whole_byte_scan=True,project_imports=0))))
    # The original comparison class setup remains part of the six original methods.
    for name in policy['selected_ids']:
        module,cls,method=name.rsplit('.',2);body,_=read(source/(module.replace('.','/')+'.py'))
        parsed=ast.parse(body);classes=[n for n in parsed.body if isinstance(n,ast.ClassDef) and n.name==cls]
        need(len(classes)==1 and sum(isinstance(n,ast.FunctionDef) and n.name==method for n in classes[0].body)==1,'original method '+name)
    runtime_raw,runtime=read(Path(sys.executable).resolve(strict=True))
    need(tuple(sys.version_info[:3])==(3,14,4),'same original standard-CI Python version')
    inputs.append(put(meta/'RUNTIME-OBSERVATION.json',wire(dict(runtime=runtime,version=sys.version,
        executable_content_read=True,executable_body_in_artifact=False))))
    owner_raw,owner=read(source/'tools/hia_selfhost_process_owner.py')
    need(digest(owner_raw)==policy['owner_sha256'],'original owner369')
    inputs.append(owner)
    before={}
    for row in material:
        raw,pin=read(source/row['path'])
        need(len(raw)==row['candidate']['bytes'] and digest(raw)==row['candidate']['sha256']
             and blob(raw)==row['candidate']['git_blob_sha1'] and pin['identity']==row['physical'],'frozen source before')
        before[row['path']]=pin
    inputs.append(put(meta/'SOURCE-PREEXEC.json',wire(before)))
    public=work/'public'
    request=dict(schema='hia.core39.snapshot-revision.source6-derive8.v1',
        operation='exact-zero-store-fixture-original-source6-derive8-remote-r1',host='GitHub Actions fresh source-only runner',
        scope=policy['scope'],baseline_commit=policy['base_commit'],baseline_tree=policy['base_tree'],
        action_binding=dict(repository=policy['repository'],branch=policy['branch'],head=head,run_id=run,attempt=1,event='push'),
        runtime=runtime,runtime_version='3.14.4',owner_implementation=owner,qualification_seconds=180,cleanup_seconds=3,
        source_root=str(source),source_file_count=4132,source_bytes_before=materialization['bytes'],output_root=str(public),
        materialization=material_pin,inputs=inputs,environment=dict(PATH='',LANG='C.UTF-8',LC_ALL='C.UTF-8',
            PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',PYTHONNOUSERSITE='1',TMPDIR=str(public/'scratch')),
        commands=policy['commands'],expected_command_count=8,selected_ids=policy['selected_ids'],expected_source_method_count=6,
        generated_write_paths=policy['derived_documents'],expected_changed_documents=policy['expected_changed_documents'],
        unchanged_generated_paths=policy['preserved_Core40'],minimum_free_bytes=1073741824,minimum_free_inodes=4096,
        worker_command_template=[runtime['path'],'-I','-S','-B',str(controls/'derive_worker.py'),'--request',
            str(controls/'REQUEST.json'),'--sha256','<REQUEST-SHA256>'],
        current_matching_cold_exists=False,original_Core116=[15,51,50],original_UNPACK18=[4,6,8],
        ai395_metadata_unknown_untouched=True)
    for pin in inputs: need(read(pin['path'])[1]==pin,'fixed input changed')
    rp=put(controls/'REQUEST.json',wire(request))
    lp=put(meta/'LAUNCH.json',wire(dict(request=rp,argv=[runtime['path'],'-I','-S','-B',
        str(controls/'derive_launch.py'),'--request',rp['path'],'--sha256',rp['sha256']],
        cwd=str(controls),original_owner_seconds=180,cleanup_seconds=3,administrative_wait_seconds=240)))
    put(meta/'PREEXEC.json',wire(dict(status='FROZEN_UNEXECUTED',request=rp,launch=lp,source_files=4132,
        source_bytes=materialization['bytes'],overlay=changed,source_methods=6,commands=8,
        original_control_bodies_unchanged=True,helper_imports=0,project_execution=0)))
    emit(dict(runtime=runtime['path'],launcher=str(controls/'derive_launch.py'),request=rp['path'],
              request_sha256=rp['sha256'],work=str(work)))
    print(json.dumps(dict(status='FROZEN_UNEXECUTED',request=rp,launch=lp,source_files=4132,methods=6,commands=8),sort_keys=True))
if __name__=='__main__': main()
