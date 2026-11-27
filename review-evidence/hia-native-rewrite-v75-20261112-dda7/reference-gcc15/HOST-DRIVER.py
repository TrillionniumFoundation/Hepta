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
prefix=Path(os.environ['RUNNER_TEMP'])/'hia-gcc15-host'
lookup=Path(os.environ['RUNNER_TEMP'])/'hia-gcc15-host-bin'
assert (lookup/'cc').is_symlink() and (lookup/'cc').resolve(strict=True)==(prefix/'bin/gcc').resolve(strict=True)
os.environ['PATH']=str(lookup)+':'+str(prefix/'bin')+':'+os.environ['PATH']
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
fixture_path=root/'tests/fixtures/hia_normalization_retained_v70.json'
fixture=json.loads(fixture_path.read_bytes())
c=fixture['sources']['original_flat_note_r1.c']['text'].encode()
ldscript=fixture['sources']['original_flat_note_r1.ld']['text'].encode()
assert len(c)==1298 and sha(c)=='10c20175731313f652fa73fe7776b02076866ee11ce092ee5cd6a44ffa8863c4'
assert len(ldscript)==183 and sha(ldscript)=='d4b159bfc0145e93b0566ce70c1be3bfb02bf8b30a411761538639b5f7cb8c64'
(out/'original-note.c').write_bytes(c);(out/'original-note.ld').write_bytes(ldscript)
names=['cc']
linker=Path(shutil.which('ld')).resolve(strict=True)
report={'schema':'hia.frozen-reference-host-gcc15-reproduction.v1','scope':'NEW_COMPILATIONS_OF_FROZEN_ORIGINAL_REFERENCE_ONLY','source_head':HEAD,'source_tree':TREE,'expected_image_bytes':260,'expected_image_sha256':EXPECTED,'historical_toolchain_identity_claimed':False,'historical_file_provenance_recovered':False,'historical_original_execution_replayed':False,'production_source_changed':False,'old_test_or_limit_changed':False,'removed_environment_names':removed,'linker':{'path':str(linker),'bytes':linker.stat().st_size,'sha256':sha(linker.read_bytes())},'cases':[],'status':'RUNNING'}
write(out/'REPORT.json',report)
command(out,'linker-version',[str(linker),'--version'])
for name in names:
    directory=out/name;directory.mkdir(mode=0o700)
    row={'compiler_name':name,'status':'STARTED'}
    try:
        location=shutil.which(name)
        if not location:raise RuntimeError('declared compiler missing: '+name)
        compiler=Path(location).resolve(strict=True)
        assert compiler==(prefix/'bin/gcc').resolve(strict=True)
        fullversion=command(directory,'gcc-fullversion',[str(compiler),'-dumpfullversion'])
        assert fullversion.returncode==0 and fullversion.stdout.strip()==b'15.2.0'
        row['compiler']={'path':str(compiler),'bytes':compiler.stat().st_size,'sha256':sha(compiler.read_bytes())}
        version=command(directory,'compiler-version',[str(compiler),'--version'])
        assert version.returncode==0
        raw=(out/'original-note.c').read_bytes();assert raw==c
        compile_args=[str(compiler),'-std=c11','-c','-Os','-fPIC','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-ident','-fcf-protection=none','-march=x86-64','-mtune=generic','-Wall','-Wextra',str(out/'original-note.c'),'-o',str(directory/'note.o')]
        compiled=command(directory,'compile',compile_args)
        assert compiled.returncode==0
        linked=command(directory,'link',[str(linker),'-nostdlib','-T',str(out/'original-note.ld'),'-o',str(directory/'note.elf'),str(directory/'note.o')])
        assert linked.returncode==0
        raw=image((directory/'note.elf').read_bytes());(directory/'note.image.bin').write_bytes(raw)
        row['image']={'bytes':len(raw),'sha256':sha(raw)}
        row['expected_bytes_and_hash_match']=len(raw)==260 and sha(raw)==EXPECTED
        disassembler=Path(shutil.which('objdump')).resolve(strict=True)
        disassembled=command(directory,'disassemble',[str(disassembler),'-d',str(directory/'note.elf')])
        assert disassembled.returncode==0
        assert sha(compiler.read_bytes())==row['compiler']['sha256']
        row['status']='MATCH' if row['expected_bytes_and_hash_match'] else 'DIFFERENT_BYTES'
    except BaseException:
        row['status']='FAILED'
        (directory/'failure.traceback.txt').write_text(traceback.format_exc())
    report['cases'].append(row);write(out/'REPORT.json',report)
after=snapshot();write(out/'source-after.json',after)
assert before==after
assert git('status','--porcelain=v1','--untracked-files=all')==b''
assert (out/'original-note.c').read_bytes()==c and (out/'original-note.ld').read_bytes()==ldscript
assert sha(linker.read_bytes())==report['linker']['sha256']
report['source_unchanged']=True
report['matched_compilers']=[r['compiler_name'] for r in report['cases'] if r['status']=='MATCH']
report['status']='MATCH_FOUND' if report['matched_compilers'] else 'NO_MATCH'
report['all_requested_compilers_observed']=len(report['cases'])==1
report['host_cc_resolves_to_real_extracted_gcc15']=Path(shutil.which('cc')).resolve(strict=True)==(prefix/'bin/gcc').resolve(strict=True)
resolution=json.loads((Path(os.environ['RUNNER_TEMP'])/'hia-reference-prerequisites/official-image-inspect.json').read_bytes())
assert len(resolution)==1 and resolution[0]['Architecture']=='amd64' and resolution[0]['Os']=='linux'
report['new_official_image_resolution']={'requested_tag':'docker.io/library/gcc:15.2.0-bookworm','id':resolution[0]['Id'],'repo_digests':resolution[0]['RepoDigests']}
report['upstream_tag_resolved_at_this_run']=True
report['all_toolchain_dependencies_qualified']=False
write(out/'REPORT.json',report)
print(json.dumps(report,sort_keys=True))
if any(r['status']=='FAILED' for r in report['cases']):raise SystemExit(1)
