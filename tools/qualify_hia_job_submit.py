"""Fresh original/native remote START qualification, outside the product."""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import time

FLAGS = ('terminal_supervisor','owner_publication','workdir_authority','loop_authority',
         'group_authority','child_publication','original_child_wait','native_output_capture',
         'workload_spawn','supervisor_identity','owner_lock_admission','owner_record_encoding',
         'owner_file_lock','owner_marker_observation','owner_custody','native_job_owner')


def main():
    parser = argparse.ArgumentParser()
    for name in ('executable','launcher','runtime-source','encoder','writer','supervisor','output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--stage', choices=('detached','full'), default='detached')
    parser.add_argument('--entry', type=Path, help='Fixed trusted native entry used by deferred systemd execution')
    parser.add_argument('--only',help='Run only these comma-separated case names during development')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(mode=0o700, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    runtime = args.runtime_source.read_text()
    def constant(name):
        prefix = 'const '+name+': &str = r#"'
        at = runtime.index(prefix)+len(prefix)
        return runtime[at:runtime.index('"#;',at)]
    private = constant('PRIVATE_DIRECTORY_CODE')
    reference = 'REMOTE_DIRECTORY_SOURCE = '+repr(private)+'\n'+private+'\n'+constant('START_CODE')
    tree = ast.parse((root/'tests/test_hia_subprocess.py').read_text())
    source = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id=='FIXTURE' for t in n.targets))
    (out/'fixture.S').write_text(source)
    subprocess.run(['/usr/bin/as','--64',str(out/'fixture.S'),'-o',str(out/'fixture.o')],check=True,capture_output=True)
    subprocess.run(['/usr/bin/ld','-nostdlib',str(out/'fixture.o'),'-o',str(out/'fixture')],check=True,capture_output=True)
    fixture = out/'fixture'; fixture.chmod(0o500)
    images = {k:getattr(args,k).read_bytes() for k in ('encoder','writer','supervisor','launcher')}
    pins = {k:sha256(v).hexdigest() for k,v in images.items()}
    rows = []
    frames = []

    def fake_systemd(name, message, code=37, invalid=False):
        area=out/('systemd-'+name);area.mkdir(mode=0o700)
        target=area/'systemd-run'
        if invalid:
            target.write_bytes(b'not-an-executable\n');target.chmod(0o500)
            return str(area)
        source='''.intel_syntax noprefix
.global _start
.text
_start:
    mov eax,1
    mov edi,2
    lea rsi,[rip+message]
    mov edx,MESSAGE_SIZE
    syscall
    mov eax,60
    mov edi,EXIT_CODE
    syscall
message:
    .byte MESSAGE_BYTES
'''.replace('MESSAGE_SIZE',str(len(message))).replace('EXIT_CODE',str(code)).replace('MESSAGE_BYTES',','.join(map(str,message)) or '0')
        (area/'fixture.S').write_text(source)
        subprocess.run(['/usr/bin/as','--64',str(area/'fixture.S'),'-o',str(area/'fixture.o')],check=True,capture_output=True)
        subprocess.run(['/usr/bin/ld','-nostdlib',str(area/'fixture.o'),'-o',str(target)],check=True,capture_output=True)
        target.chmod(0o500)
        return str(area)

    def run(name, native, mutate=None, setup=None, replay=None, environ=None):
        label = name+('-native' if native else '-reference')
        area = out/label;area.mkdir(mode=0o700)
        state = area/'state';jobs=state/'jobs';job=jobs/'job'
        digest = sha256(label.encode()).hexdigest()
        req = dict(job_id='job',job_dir=str(job),unit='hepta-submit-test-'+str(os.getpid()),
                   request_fingerprint=digest,request_digest=digest,executable=str(fixture),
                   args=['s'],cwd=str(area),allowed_cwd_prefixes=[str(area)],env={},
                   timeout_seconds=3,nice=0,allow_detached_fallback=True,
                   platform='linux',execution_mode='operator',allow_job_network=True,
                   **{'hia_'+key:True for key in FLAGS})
        if args.entry:req['hia_job_entry_path']=str(args.entry)
        data = {k:bytes(v) for k,v in images.items()}
        if mutate:mutate(req,data,job,area)
        if setup:
            state.mkdir(mode=0o700);jobs.mkdir(mode=0o700);job.mkdir(mode=0o700)
            setup(req,data,job,area)
        environment={'PATH':'','LANG':'C.UTF-8',**(environ or {})}
        def invoke(request, suffix):
            if native:
                metadata=dict(request)
                stdin=metadata.pop('stdin',None)
                metadata['hia_terminal_publisher']={k:pins[k] for k in ('encoder','writer','supervisor')}
                metadata['hia_job_launcher_sha256']=pins['launcher']
                encoded=json.dumps(metadata,sort_keys=True).encode()
                stdin_bytes=b'' if stdin is None else stdin.encode('utf8')
                frame=struct.pack('<8s7Q',b'HIAJSB01',len(encoded),(1<<64)-1 if stdin is None else len(stdin_bytes),
                                  *(len(data[k]) for k in ('encoder','writer','supervisor','launcher')),0)
                payload=frame+encoded+b''.join(data[k] for k in ('encoder','writer','supervisor','launcher'))+stdin_bytes
                command=[str(args.executable)]
                trace=area/('exec-'+suffix+'.trace')
                command=['/usr/bin/strace','-f','-qq','-s','160','-e','trace=execve,execveat','-o',str(trace),*command]
            else:
                metadata=dict(request)
                metadata['hia_terminal_publication_artifacts']={k:{'sha256':pins[k],'hex':data[k].hex()} for k in ('encoder','writer','supervisor')}
                payload=json.dumps(metadata,sort_keys=True).encode()
                command=['/usr/bin/python3','-I','-S','-c',reference]
            begun=time.monotonic()
            result=subprocess.run(command,input=payload,cwd=area,env=environment,capture_output=True,timeout=30)
            if native:
                text=trace.read_text()
                assert 'python' not in text.lower() and '/bin/sh' not in text,(name,text)
            wire=None
            if result.stdout:
                try:wire=json.loads(result.stdout)
                except ValueError:pass
            return {'returncode':result.returncode,'wire':wire,'wire_stdout':result.stdout.decode('utf8','replace'),
                    'wire_stderr':result.stderr.decode('utf8','replace'),'seconds':time.monotonic()-begun}
        row=invoke(req,'initial');row.update(name=name,native=native,job=str(job))
        if row['returncode']==0 and not replay:
            until=time.monotonic()+6
            while not (job/'exit.witness.json').exists() and time.monotonic()<until:time.sleep(.01)
        row['child_started']=(job/'child.json').exists()
        row['terminal']=None
        if (job/'exit.json').exists():
            try:row['terminal']=json.loads((job/'exit.json').read_bytes())
            except ValueError:row['terminal_parse_error']=True
        if row['terminal'] and (job/'request.json').exists():
            persisted=json.loads((job/'request.json').read_bytes())
            if 'launch_nonce' in persisted:
                nonce=persisted['launch_nonce']
                assert len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce)
                assert row['terminal']['launch_nonce']==nonce
                witness=json.loads((job/'exit.witness.json').read_bytes())
                assert witness['launch_nonce']==nonce
                assert witness['exit_sha256']==sha256((job/'exit.json').read_bytes()).hexdigest()
        streams=[(job/k).read_bytes() if (job/k).exists() else b'' for k in ('stdout.log','stderr.log')]
        if replay:
            before={p.name:sha256(p.read_bytes()).hexdigest() for p in job.iterdir() if p.is_file()}
            replay(req,data,job,area)
            row['replay']=invoke(req,'replay')
            after={p.name:sha256(p.read_bytes()).hexdigest() for p in job.iterdir() if p.is_file()}
            row['unchanged_on_replay']=before==after
        row['files']={p.name:{'mode':p.stat().st_mode&0o7777,'size':p.stat().st_size} for p in job.iterdir() if p.is_file()} if job.exists() else {}
        rows.append(row);(out/'partial.json').write_text(json.dumps(rows,indent=2)+'\n')
        return row,streams

    def compare(name, mutate=None, setup=None, expected=True, admitted=True, replay=None, replay_ok=True, normalize=None, **kw):
        if args.only and name not in args.only.split(','):return
        old,os_=run(name,False,mutate,setup,replay,**kw)
        new,ns_=run(name,True,mutate,setup,replay,**kw)
        assert (old['returncode']==0)==expected,(name,'reference',old)
        assert (new['returncode']==0)==expected,(name,'native',new)
        if expected and replay is None:
            assert old['child_started']==new['child_started'],(name,old,new)
            if admitted is not None:assert old['child_started']==admitted,(name,'admission',old,new)
            a=dict(old['wire']);b=dict(new['wire']);a.pop('launcher_pid',None);b.pop('launcher_pid',None)
            assert a==b,(name,'reply',a,b)
            if normalize:os_,ns_=normalize(os_),normalize(ns_)
            assert os_==ns_,(name,'streams',os_,ns_)
            if old['child_started']:
                a=dict(old['terminal']);b=dict(new['terminal'])
                for key in ('at_unix_ms','launch_nonce'):a.pop(key,None);b.pop(key,None)
                assert a==b,(name,'terminal',a,b)
        if replay:
            assert (old['replay']['returncode']==0)==(new['replay']['returncode']==0)==replay_ok,(name,old,new)
            assert old['unchanged_on_replay'] and new['unchanged_on_replay'],(name,'replay mutation',old,new)
            if replay_ok:assert old['replay']['wire']==new['replay']['wire'],(name,'replay wire',old,new)
        if not expected and setup is None and 'launch.json' in old['files'] and 'launch.json' in new['files']:
            a=json.loads((Path(old['job'])/'launch.json').read_bytes())
            b=json.loads((Path(new['job'])/'launch.json').read_bytes())
            assert a==b,(name,'durable launch failure',a,b)
            assert old['returncode']==new['returncode'],(name,'launch failure return',old,new)
            assert old['wire_stderr']==new['wire_stderr'],(name,'launch failure stderr',old,new)
        print(name,'PASS',round(new['seconds'],3),flush=True)

    def setreq(**kw):return lambda r,d,j,a:r.update(kw)
    def env_output(streams):
        return [b'\n'.join(x for x in streams[0].splitlines() if not x.startswith(b'HEPTA_RUNTIME_WORKER_ENTRY_FD=')),streams[1]]
    compare('fresh-private-directories')
    compare('existing-private-directories',setup=lambda r,d,j,a:None)
    compare('stdin-empty',setreq(stdin='',args=['c']))
    compare('stdin-unicode',setreq(stdin='hello\nα🙂\x00tail',args=['c']))
    compare('stdin-multiple-chunks',setreq(stdin='x'*180000,args=['c']))
    compare('arguments',setreq(args=['a','α🙂','quote"\\']))
    compare('environment',setreq(args=['e'],env={'Q':'value','LANG':'override'}),normalize=env_output)
    compare('nice',setreq(nice=1))
    compare('deadline',setreq(args=['w'],timeout_seconds=1))
    compare('cwd-outside',setreq(cwd='/tmp'),admitted=False)
    compare('bad-image',lambda r,d,j,a:d.update(encoder=b'x'*len(d['encoder'])),expected=False)
    compare('empty-image',lambda r,d,j,a:d.update(encoder=b''),expected=False)
    compare('flag-invalid',setreq(hia_native_job_owner=1),expected=False)
    compare('cpu-fallback-refused',setreq(cpu_quota_percent=50),expected=False)
    compare('memory-fallback-refused',setreq(memory_max_bytes=4096),expected=False)
    for name in ('stdin.bin','runner.py','owner-intent.json','started.json','child.json','launch.json','exit.json','exit.witness.json','exit.witness.json.tmp','stdout.log','stderr.log','native-exit.bin','hia-terminal-encoder','hia-terminal-writer','hia-terminal-supervisor'):
        compare('tombstone-'+name,setup=lambda r,d,j,a,name=name:(j/name).touch(mode=0o600),expected=False)
    compare('private-mode',setup=lambda r,d,j,a:j.chmod(0o755),expected=False)
    compare('launch-lock-mode',setup=lambda r,d,j,a:((j/'launch.lock').touch(mode=0o644),(j/'launch.lock').chmod(0o644)),expected=False)
    def replay_state(backend='detached',exit_only=False,ambiguous=False):
        def setup(r,d,j,a):
            (j/'request.json').write_text(json.dumps(r));(j/'request.json').chmod(0o600)
            if not ambiguous:
                p=j/('exit.json' if exit_only else 'launch.json')
                p.write_text(json.dumps({'exit_code':0} if exit_only else {'backend':backend,'unit':'replay','launcher_pid':123}));p.chmod(0o600)
        return setup
    compare('replay-completed',setup=replay_state(exit_only=True),replay=lambda r,d,j,a:None)
    compare('replay-detached',setup=replay_state(),replay=lambda r,d,j,a:None)
    compare('replay-systemd',setup=replay_state(backend='systemd'),replay=lambda r,d,j,a:None)
    compare('replay-ambiguous',setup=replay_state(ambiguous=True),expected=False)
    compare('replay-launch-failed',setup=replay_state(backend='launch_failed'),expected=False)
    compare('replay-changed-digest',setup=replay_state(),replay=lambda r,d,j,a:r.update(request_digest='b'*64),replay_ok=False)
    compare('replay-changed-roots',setup=replay_state(),replay=lambda r,d,j,a:r.update(allowed_cwd_prefixes=[]),replay_ok=False)
    compare('replay-invalid-fresh-artifacts',setup=replay_state(),replay=lambda r,d,j,a:(d.update(encoder=b''),r.update(hia_native_job_owner=False)))
    if args.stage=='full':
        compare('no-fallback-unavailable',setreq(allow_detached_fallback=False),expected=False)
        compare('nonlinux-platform',setreq(platform='darwin'),environ={'PATH':'/usr/bin:/bin'})
        failing=fake_systemd('failure',' \t\u2003failed α\r\nsecond\rthird\u3000 \r\n'.encode())
        compare('systemd-failure-fallback',environ={'PATH':failing})
        compare('systemd-failure-no-fallback',setreq(allow_detached_fallback=False),environ={'PATH':failing},expected=False)
        compare('systemd-cpu-fallback-refused',setreq(cpu_quota_percent=50),environ={'PATH':failing},expected=False)
        compare('systemd-memory-fallback-refused',setreq(memory_max_bytes=4096),environ={'PATH':failing},expected=False)
        empty=fake_systemd('empty',b'')
        compare('systemd-empty-error',environ={'PATH':empty})
        broken=fake_systemd('exec-format',b'',invalid=True)
        compare('systemd-exec-error',environ={'PATH':broken},expected=False)
        invalid=fake_systemd('invalid-utf8',b'bad\xff')
        compare('systemd-error-invalid-utf8',environ={'PATH':invalid},expected=False)
        compare('systemd-search-fallthrough',environ={'PATH':str(out/'absent')+':'+failing})
        compare('actual-systemd',setreq(allow_detached_fallback=False),environ={'PATH':'/usr/bin:/bin'})
        compare('actual-systemd-properties',setreq(allow_detached_fallback=False,cpu_quota_percent=80,memory_max_bytes=268435456,nice=1),environ={'PATH':'/usr/bin:/bin'})
        compare('actual-systemd-isolated',setreq(execution_mode='isolated'),environ={'PATH':'/usr/bin:/bin'},admitted=None)
        compare('actual-systemd-network-isolated',setreq(execution_mode='isolated',allow_job_network=False),environ={'PATH':'/usr/bin:/bin'},admitted=None)
    if not args.only:
        area=out/'invalid-frames';area.mkdir(mode=0o700)
        job=area/'state/jobs/job'
        metadata=dict(job_id='job',job_dir=str(job),unit='unit',request_fingerprint='a'*64,
                      request_digest='a'*64,allowed_cwd_prefixes=[],executable=str(fixture),args=['s'],
                      hia_terminal_publisher={k:pins[k] for k in ('encoder','writer','supervisor')},
                      hia_job_launcher_sha256=pins['launcher'],**{'hia_'+k:True for k in FLAGS})
        encoded=json.dumps(metadata).encode()
        lengths=[len(encoded),(1<<64)-1,*(len(images[k]) for k in ('encoder','writer','supervisor','launcher')),0]
        header=struct.pack('<8s7Q',b'HIAJSB01',*lengths)
        body=encoded+b''.join(images[k] for k in ('encoder','writer','supervisor','launcher'))
        bad=[('short-header',header[:-1]),('bad-magic',b'X'+header[1:]),
             ('truncated-metadata',header+encoded[:-1]),('truncated-images',header+body[:-1]),
             ('trailing-byte',header+body+b'x')]
        for name,index,value in [('empty-metadata',0,0),('metadata-over-limit',0,4194305),
                                 ('stdin-over-limit',1,536870913),('encoder-over-limit',2,1048577),
                                 ('writer-over-limit',3,1048577),('supervisor-over-limit',4,1048577),
                                 ('launcher-over-limit',5,1048577),('reserved',6,1)]:
            changed=list(lengths);changed[index]=value
            bad.append((name,struct.pack('<8s7Q',b'HIAJSB01',*changed)))
        changed=list(lengths);changed[1]=1
        bad.append(('truncated-stdin',struct.pack('<8s7Q',b'HIAJSB01',*changed)+body))
        for name,raw in [('invalid-json',b'{'),('invalid-utf8',b'{"x":"\xff"}'),('array-root',b'[]'),('multiple-json',encoded+b'{}')]:
            changed=list(lengths);changed[0]=len(raw)
            bad.append((name,struct.pack('<8s7Q',b'HIAJSB01',*changed)+raw))
        for name,payload in bad:
            result=subprocess.run([args.executable],input=payload,cwd=area,env={'PATH':''},capture_output=True,timeout=15)
            assert result.returncode!=0 and not result.stdout and not (area/'state').exists(),(name,result)
            frames.append({'name':name,'returncode':result.returncode,'no_directory_effect':True})
        result=subprocess.run([args.executable,'extra'],input=b'',cwd=area,env={'PATH':''},capture_output=True,timeout=15)
        assert result.returncode!=0 and not result.stdout and not (area/'state').exists()
        frames.append({'name':'extra-argv','returncode':result.returncode,'no_directory_effect':True})
        print('PASS',len(frames),'invalid frame/argv controls without directory effects',flush=True)
    assert rows,'No selected case ran'
    report=dict(schema='hia.job-submit.original-native-qualification.v1',passed=True,selection=args.only,
                scope=args.stage,pairs=len(rows)//2,executable_sha256=sha256(args.executable.read_bytes()).hexdigest(),
                launcher_sha256=pins['launcher'],runtime_source_sha256=sha256(args.runtime_source.read_bytes()).hexdigest(),rows=rows,invalid_frames=frames)
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',report['pairs'],'original/native pairs',flush=True)


if __name__=='__main__':main()
