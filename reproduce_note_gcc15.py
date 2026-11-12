#!/usr/bin/env python3
"""Reproduce a frozen historical reference from its exact C source and flags."""
from pathlib import Path
import hashlib,json,os,shutil,stat,struct,subprocess,sys,time,traceback

HEAD='7e9c5a796a29746d169f9db97392ec774f627c03'
TREE='79843bddc6df7306299f0be6475a2fcd187b4d97'
EXPECTED='e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61'
root=Path(os.environ['GITHUB_WORKSPACE'])/'source'
out=Path(os.environ['RUNNER_TEMP'])/'hia-reference-reproduction'
out.mkdir(mode=0o700)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def git(*args):return subprocess.check_output(['git','-C',str(root),*args])
def snapshot():
    result={}
    for record in git('ls-tree','-rz','--full-tree','HEAD').split(b'\0'):
        if not record:continue
        header,path=record.split(b'\t',1);mode,kind,blob=header.decode().split();path=path.decode()
        p=root/path;assert kind=='blob' and mode in ('100644','100755') and p.is_file() and not p.is_symlink()
        raw=p.read_bytes();actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        assert actual==blob and bool(p.stat().st_mode&0o111)==(mode=='100755')
        result[path]={'mode':mode,'bytes':len(raw),'blob':blob,'sha256':sha(raw)}
    return result
def command(directory,name,argv):
    intent={'argv':argv,'cwd':str(directory),'timeout_seconds':30}
    write(directory/(name+'.intent.json'),intent)
    start=time.monotonic()
    try:
        p=subprocess.run(argv,cwd=directory,capture_output=True,timeout=30,env=environment)
    except subprocess.TimeoutExpired as error:
        (directory/(name+'.stdout')).write_bytes(error.stdout or b'')
        (directory/(name+'.stderr')).write_bytes(error.stderr or b'')
        intent.update({'exit_code':None,'timed_out':True,'seconds':time.monotonic()-start})
        write(directory/(name+'.result.json'),intent);raise
    (directory/(name+'.stdout')).write_bytes(p.stdout);(directory/(name+'.stderr')).write_bytes(p.stderr)
    intent.update({'exit_code':p.returncode,'timed_out':False,'seconds':time.monotonic()-start,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
    write(directory/(name+'.result.json'),intent)
    return p
def image(raw):
    assert raw[:7]==b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<H',raw,16)[0]==2 and struct.unpack_from('<H',raw,18)[0]==62
    assert struct.unpack_from('<Q',raw,24)[0]==0
    offset=struct.unpack_from('<Q',raw,40)[0];size,count,strings=struct.unpack_from('<3H',raw,58)
    assert size==64 and offset+count*size<=len(raw) and 0<strings<count
    headers=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+i*size) for i in range(count)]
    s=headers[strings];names=raw[s[4]:s[4]+s[5]];allocated=[]
    for h in headers:
        if not h[2]&2 or not h[5]:continue
        end=names.find(b'\0',h[0]);assert end>=h[0]
        name=names[h[0]:end].decode()
        assert h[1]!=8 and h[4]+h[5]<=len(raw)
        allocated.append((name,h[3],raw[h[4]:h[4]+h[5]]))
    assert len(allocated)==1 and allocated[0][0:2]==('.text',0)
    return allocated[0][2]

environment=dict(os.environ)
removed=[]
for key in tuple(environment):
    if key.startswith('HEPTA_HIA_') or key in ('CFLAGS','CPPFLAGS','LDFLAGS','CPATH','C_INCLUDE_PATH','LIBRARY_PATH','GCC_EXEC_PREFIX','COMPILER_PATH'):
        removed.append(key);environment.pop(key)
assert git('rev-parse','HEAD').decode().strip()==HEAD
assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
assert git('status','--porcelain=v1','--untracked-files=all')==b''
before=snapshot();assert len(before)==3084
write(out/'source-before.json',before)
fixture=json.loads((root/'tests/fixtures/hia_normalization_retained_v70.json').read_bytes())
c=fixture['sources']['original_flat_note_r1.c']['text'].encode()
ldscript=fixture['sources']['original_flat_note_r1.ld']['text'].encode()
assert len(c)==1298 and sha(c)=='10c20175731313f652fa73fe7776b02076866ee11ce092ee5cd6a44ffa8863c4'
assert len(ldscript)==183 and sha(ldscript)=='d4b159bfc0145e93b0566ce70c1be3bfb02bf8b30a411761538639b5f7cb8c64'
(out/'original-note.c').write_bytes(c);(out/'original-note.ld').write_bytes(ldscript)
IMAGE='docker.io/library/gcc@sha256:c101370f78e4a30be178c11dd18aeee64c65d617908a98157db2392ca73ab04f'
DOCKER=['docker','--host=unix:///var/run/docker.sock']
directory=out/'gcc-15.2.0';directory.mkdir(mode=0o700)
report={'schema':'hia.frozen-reference-gcc15-reproduction.v1','scope':'NEW_COMPILATION_OF_FROZEN_ORIGINAL_REFERENCE_ONLY','source_head':HEAD,'source_tree':TREE,'expected_image_bytes':260,'expected_image_sha256':EXPECTED,'historical_toolchain_identity_claimed':False,'historical_file_provenance_recovered':False,'historical_original_execution_replayed':False,'production_source_changed':False,'old_test_or_limit_changed':False,'native_reference_executed':False,'removed_environment_names':removed,'declared_container_manifest':IMAGE,'status':'RUNNING'}
write(out/'REPORT.json',report)
failed=False
try:
    inspected=command(out,'container-image-inspect',DOCKER+['image','inspect',IMAGE]);assert inspected.returncode==0
    inspected_data=json.loads(inspected.stdout);assert len(inspected_data)==1
    record=inspected_data[0];assert record['Architecture']=='amd64' and record['Os']=='linux'
    assert any(x.endswith('@sha256:c101370f78e4a30be178c11dd18aeee64c65d617908a98157db2392ca73ab04f') for x in record['RepoDigests'])
    report['actual_container_image_id']=record['Id']
    harness=Path(os.environ['GITHUB_WORKSPACE'])/'harness'
    argv=DOCKER+['run','--rm','--pull=never','--platform=linux/amd64','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=512m','--cpus=2','--user',str(os.getuid())+':'+str(os.getgid()),'--tmpfs','/tmp:rw,nosuid,nodev,size=67108864','--mount','type=bind,src='+str(harness)+',dst=/hia-harness,readonly','--mount','type=bind,src='+str(out)+',dst=/hia-input,readonly','--mount','type=bind,src='+str(directory)+',dst=/hia-output',record['Id'],'/bin/bash','/hia-harness/container_compile.sh']
    compiled=command(directory,'complete-container-compile',argv);assert compiled.returncode==0
    assert (directory/'toolchain-before.sha256').read_bytes()==(directory/'toolchain-after.sha256').read_bytes()
    assert (directory/'gcc-version.txt').read_text().strip()=='15.2.0'
    raw=image((directory/'note.elf').read_bytes());(directory/'note.image.bin').write_bytes(raw)
    report['image']={'bytes':len(raw),'sha256':sha(raw)}
    report['expected_bytes_and_hash_match']=len(raw)==260 and sha(raw)==EXPECTED
    report['toolchain_manifest_sha256']=sha((directory/'toolchain-before.sha256').read_bytes())
    report['status']='MATCH' if report['expected_bytes_and_hash_match'] else 'DIFFERENT_BYTES'
except BaseException:
    report['status']='FAILED';failed=True
    (out/'failure.traceback.txt').write_text(traceback.format_exc())
finally:
    try:
        after=snapshot();write(out/'source-after.json',after)
        assert before==after
        assert git('status','--porcelain=v1','--untracked-files=all')==b''
        assert (out/'original-note.c').read_bytes()==c and (out/'original-note.ld').read_bytes()==ldscript
        report['source_unchanged']=True
    except BaseException:
        report['status']='FAILED';failed=True
        (out/'source-integrity-failure.traceback.txt').write_text(traceback.format_exc())
    write(out/'REPORT.json',report)
    print(json.dumps(report,sort_keys=True))
if failed:raise SystemExit(1)
