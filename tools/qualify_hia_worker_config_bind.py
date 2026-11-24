"""Qualify the native Worker config owner with synthetic inputs and an installed fixture.

This is an independent test driver. The measured owner, JSON parser, subprocess
supervisor and installation entry execute as native HIA ELF images.
"""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

FILES=('worker.json','hia-agent-worker','evaluate-full-worker.json','evaluate-full-worker-capsule.bin')
FIELDS=('worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256','python_executable','native_helpers_manifest')

def roots_of(installation):
    data=(installation/'evaluate-full-worker-capsule.bin').read_bytes()
    _,version,count,dossier,base,docs,artifact=struct.unpack_from('<8s6Q',data)
    at=56+count*48+dossier+base+docs
    assert version==1 and at+artifact==len(data)
    payload,count=struct.unpack_from('<2Q',data,at+72)
    at+=88+payload
    roots=[]
    for _ in range(count):
        n=struct.unpack_from('<Q',data,at)[0];at+=8
        roots.append(os.fsdecode(data[at:at+n]));at+=n
    assert at==len(data)
    return roots

def vector(roots):
    items=[os.fsencode(Path(p)) for p in roots]
    return struct.pack('<Q',len(items))+b''.join(struct.pack('<Q',len(x))+x for x in items)

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'))

def digest_fd(fd,size):
    at=0;result=sha256()
    while at<size:
        chunk=os.pread(fd,min(65536,size-at),at)
        assert chunk
        at+=len(chunk);result.update(chunk)
    return result.digest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,required=True)
    parser.add_argument('--runner',type=Path,required=True)
    parser.add_argument('--installation',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--large-bytes',type=int,default=67108865)
    args=parser.parse_args()
    for key in ('elf','runner','installation','output'):
        setattr(args,key,getattr(args,key).absolute())
    args.output.mkdir(mode=0o700,exist_ok=False)
    assert args.large_bytes>67108864
    runner_bytes=args.runner.read_bytes()
    input_pins={str(p):sha256(p.read_bytes()).hexdigest() for p in
                (args.elf,args.runner,*(args.installation/n for n in FILES))}
    roots=roots_of(args.installation)
    cases=[]
    def run(name,*,mode=1,roots_value=(),host='r',hosts=None,raw=None,explicit=(),
            output_fd=False,mutation=None,expect=True,trace=False,extra=None):
        folder=args.output/name;folder.mkdir(mode=0o700)
        installed=folder/'installation'
        if mode==2:
            installed.mkdir(mode=0o700)
            for n in FILES:shutil.copy2(args.installation/n,installed/n)
        selected={'host':host,'artifact_roots':list(roots_value)}
        if mode==2:
            selected.update(worker_sha256={'old':'overwritten'},native_helpers_manifest='old')
        config={'hosts':{'r':{}} if hosts is None else hosts,'hia_worker':selected,
                'unrelated':{'unicode':'测验','quote':'a"b','values':[1,None,False]}}
        if extra:extra(config)
        if raw is None:raw=json.dumps(config,ensure_ascii=True,separators=(',',':')).encode()
        with ExitStack() as stack:
            def owned(fd):
                stack.callback(os.close,fd);return fd
            def memfd(label,data,seal=True,mode=0o400):
                fd=owned(os.memfd_create(label,2))
                at=0
                while at<len(data):at+=os.write(fd,data[at:at+1048576])
                os.fchmod(fd,mode)
                if seal:fcntl.fcntl(fd,1033,15)
                os.lseek(fd,0,0);return fd
            config_fd=memfd('synthetic-config',raw,mutation!='unsealed-config')
            roots_fd=memfd('explicit-roots',vector(explicit),mutation!='unsealed-roots')
            out_fd=memfd('roots-output',b'',False,0o600) if output_fd else 0
            install_fd=owned(os.open(installed,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)) if mode==2 else 0
            runner_fd=memfd('native-runner',runner_bytes,mutation!='unsealed-runner',0o500) if mode==2 else 0
            config_pin=sha256(raw).digest();runner_pin=sha256(runner_bytes).digest() if mode==2 else bytes(32)
            deadline=time.monotonic_ns()+120000000000
            reserved=[out_fd,0,0,0,0,0,0,0]
            if mutation=='wrong-config-pin':config_pin=bytes(32)
            if mutation=='wrong-runner-pin':runner_pin=bytes(32)
            if mutation=='deadline':deadline=1
            if mutation=='reserved':reserved[1]=1
            if mutation=='alias-output':reserved[0]=config_fd
            if mutation=='output-nonempty':os.write(out_fd,b'x')
            if mutation=='output-sealed':fcntl.fcntl(out_fd,1033,15)
            if mutation=='existing-output':(installed/'runtime-config.json').write_bytes(b'keep-existing')
            if mutation=='existing-temp':(installed/'.hia-runtime-config.tmp').write_bytes(b'keep-temp')
            if mutation in ('profile-drift','capsule-drift','descriptor-drift'):
                n={'profile-drift':'worker.json','capsule-drift':'evaluate-full-worker-capsule.bin','descriptor-drift':'evaluate-full-worker.json'}[mutation]
                p=installed/n;p.chmod(0o600);data=p.read_bytes()
                p.write_bytes(data+b' ' if mutation!='capsule-drift' else data[:-1]+bytes([data[-1]^1]))
            if mutation=='entry-symlink':
                (installed/'hia-agent-worker').unlink()
                (installed/'hia-agent-worker').symlink_to(args.installation/'hia-agent-worker')
            if mutation=='directory-mode':installed.chmod(0o755)
            wire=struct.pack('<8s15Q',b'HIAWCB01',mode,0,deadline,config_fd,roots_fd,install_fd,runner_fd,*reserved)+config_pin+runner_pin
            request=memfd('request',wire,mutation!='unsealed-request')
            passed=tuple(fd for fd in (config_fd,roots_fd,out_fd,install_fd,runner_fd) if fd)
            command=[str(args.elf)]
            if trace:command=['/usr/bin/strace','-f','-qq','-o',str(folder/'trace'),*command]
            began=time.monotonic()
            result=subprocess.run(command,stdin=request,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  pass_fds=passed,env={'PATH':''},timeout=125)
            record={'name':name,'mode':mode,'expected_success':expect,'returncode':result.returncode,
                    'elapsed_seconds':time.monotonic()-began,'stdout_bytes':len(result.stdout),'stderr_bytes':len(result.stderr)}
            (folder/'stdout').write_bytes(result.stdout);(folder/'stderr').write_bytes(result.stderr)
            assert not result.stderr,(name,'unexpected stderr')
            if not expect:
                assert result.returncode in (65,74) and not result.stdout,(name,record)
                if mode==2:
                    if mutation=='existing-output':assert (installed/'runtime-config.json').read_bytes()==b'keep-existing'
                    else:assert not (installed/'runtime-config.json').exists()
                    if mutation=='existing-temp':assert (installed/'.hia-runtime-config.tmp').read_bytes()==b'keep-temp'
                    else:assert not (installed/'.hia-runtime-config.tmp').exists()
            else:
                assert result.returncode==0,(name,record)
                if mode==1:
                    expected=vector(json.loads(raw)['hia_worker'].get('artifact_roots',[]))
                    if output_fd:
                        magic,version,size,pin,zero=struct.unpack('<8sQQ32sQ',result.stdout)
                        assert (magic,version,size,pin,zero)==(b'HIAWCR01',1,len(expected),sha256(expected).digest(),0)
                        assert fcntl.fcntl(out_fd,1034)&15==15
                        assert os.fstat(out_fd).st_size==len(expected)
                        assert digest_fd(out_fd,len(expected))==pin
                        record.update(roots_bytes=size,roots_sha256=pin.hex())
                    else:assert result.stdout==expected,(name,'roots vector')
                else:
                    output=(installed/'runtime-config.json').read_bytes()
                    magic,version,size,pin,profile,zero=struct.unpack('<8sQQ32s32sQ',result.stdout)
                    assert (magic,version,size,pin,profile,zero)==(b'HIAWCO01',1,len(output),sha256(output).digest(),sha256((installed/'worker.json').read_bytes()).digest(),0)
                    query=subprocess.run([str(installed/'hia-agent-worker'),'-B','-E','-s','-m','hepta.hia_agent_worker',
                        '--installation-manifest','--native-helpers-manifest',str(installed/'worker.json'),
                        '--expected-native-helpers-sha256',profile.hex()],env={'PATH':''},capture_output=True,check=True)
                    assert not query.stderr
                    expected=json.loads(raw);expected['hia_worker'].update(json.loads(query.stdout),
                        python_executable=str(installed/'hia-agent-worker'),native_helpers_manifest=str(installed/'worker.json'))
                    assert canonical(json.loads(output))==canonical(expected),(name,'semantic mismatch')
                    assert (installed/'runtime-config.json').stat().st_mode&0o777==0o600
                    assert not (installed/'.hia-runtime-config.tmp').exists()
                    record.update(output_bytes=len(output),output_sha256=pin.hex(),semantic_match=True)
                if trace:
                    lines=(folder/'trace').read_text().splitlines()
                    executions=[x for x in lines if 'execve(' in x or 'execveat(' in x]
                    assert len(executions)==3 and all(not any(x in row for x in ('python','/bin/sh','/usr/bin/cc')) for row in executions)
                    record['native_exec_count']=len(executions)
            cases.append(record);print(json.dumps(record),flush=True)
    run('derive-empty')
    run('derive-path-normalization',roots_value=('/tmp//./x','//tmp///x'),explicit=('/tmp/x','//tmp/x'))
    run('derive-fd-output',roots_value=('/tmp/x',),output_fd=True)
    for host in (0,False,True,-1,-2):run('hosts-array-'+str(host),host=host,hosts=[{},{}])
    run('derive-utf16',raw=json.dumps({'hia_worker':{'host':'r','artifact_roots':[]},'hosts':{'r':{}},'text':'测试'}).encode('utf-16'))
    run('derive-surrogateescape',roots_value=('/tmp/\udc80',),output_fd=True)
    run('derive-nul-lexical',roots_value=('/tmp/a\0b',),output_fd=True)
    run('derive-long-lexical',roots_value=('/tmp/'+('a/../'*1000)+'x',),output_fd=True)
    for mutation in ('unsealed-config','unsealed-roots','unsealed-request','wrong-config-pin','deadline','reserved'):
        run('reject-'+mutation,mutation=mutation,expect=False)
    for mutation in ('alias-output','output-nonempty','output-sealed'):
        run('reject-'+mutation,mutation=mutation,output_fd=True,expect=False)
    run('reject-explicit-conflict',roots_value=('/tmp/a',),explicit=('/tmp/b',),expect=False)
    run('reject-decoded-duplicate',raw=b'{"hosts":{"r":{}},"hia_worker":{"host":"r"},"other":{"x":1,"\\u0078":2}}',expect=False)
    run('bind-query-and-preserve',mode=2,roots_value=roots,trace=True)
    run('bind-overwritten-surrogates',mode=2,roots_value=roots,
        extra=lambda c:c['hia_worker'].update({k:'\ud800' for k in FIELDS}))
    for mutation in ('unsealed-runner','wrong-runner-pin','existing-output','existing-temp','profile-drift','capsule-drift','entry-symlink','directory-mode'):
        run('bind-reject-'+mutation,mode=2,roots_value=roots,mutation=mutation,expect=False)
    run('bind-reject-roots-mismatch',mode=2,roots_value=('/different',),expect=False)
    run('bind-reject-unknown-surrogate',mode=2,roots_value=roots,extra=lambda c:c.update(unknown='\ud800'),expect=False)
    run('derive-large-roots-fd',roots_value=('/'+('a'*args.large_bytes),),output_fd=True)
    run('bind-large-preserved-config',mode=2,roots_value=roots,extra=lambda c:c.update(large='x'*args.large_bytes))
    for path,pin in input_pins.items():assert sha256(Path(path).read_bytes()).hexdigest()==pin
    report={'scope':'NATIVE_WORKER_CONFIG_OWNER_COMPONENT','passed':True,'cases':cases,'count':len(cases),
            'input_pins':input_pins,'large_bytes':args.large_bytes,'whole_worker_installation_qualified':False}
    (args.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'count':len(cases),'qualification':str(args.output/'qualification.json')}),flush=True)
if __name__=='__main__':main()
