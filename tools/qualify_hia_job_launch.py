"""Compare the bound native launcher with the unmodified v25 Python runner.

All fixture authors and comparison code run outside the product process. Native
cases execute with an empty PATH and may execute only the launcher, supervisor,
and the original static subprocess test payload.
"""
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
import traceback

FLAGS = ('terminal_supervisor','owner_publication','workdir_authority','loop_authority',
         'group_authority','child_publication','original_child_wait','native_output_capture',
         'workload_spawn','supervisor_identity','owner_lock_admission','owner_record_encoding',
         'owner_file_lock','owner_marker_observation','owner_custody','native_job_owner')


def main():
    parser=argparse.ArgumentParser()
    for name in ('executable','runtime-source','encoder','writer','supervisor','output'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--large',action='store_true')
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(mode=0o700,parents=False,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    runtime=args.runtime_source.read_text()
    def constant(name):
        prefix='const '+name+': &str = r#"'
        at=runtime.index(prefix)+len(prefix)
        return runtime[at:runtime.index('"#;',at)]
    start=ast.parse(constant('START_CODE'))
    runner=next(ast.literal_eval(n.value) for n in start.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='runner' for t in n.targets)
                and isinstance(n.value,ast.Constant))
    reference=constant('PRIVATE_DIRECTORY_CODE')+'\n'+runner
    fixture_tree=ast.parse((root/'tests/test_hia_subprocess.py').read_text())
    fixture_source=next(ast.literal_eval(n.value) for n in fixture_tree.body if isinstance(n,ast.Assign)
                        and any(isinstance(t,ast.Name) and t.id=='FIXTURE' for t in n.targets))
    (out/'fixture.S').write_text(fixture_source)
    subprocess.run(['/usr/bin/as','--64',str(out/'fixture.S'),'-o',str(out/'fixture.o')],check=True,capture_output=True)
    subprocess.run(['/usr/bin/ld','-nostdlib',str(out/'fixture.o'),'-o',str(out/'fixture')],check=True,capture_output=True)
    fixture=out/'fixture';fixture.chmod(0o500)
    images={name:getattr(args,name).read_bytes() for name in ('encoder','writer','supervisor')}
    pins={name:sha256(data).hexdigest() for name,data in images.items()}
    rows=[]

    def run(name,native,mutate=None,after=None,environ=None,backend='detached',cancel=False):
        label=name+('-native' if native else '-reference')
        area=out/label;area.mkdir(mode=0o700)
        state=area/'state';state.mkdir(mode=0o700)
        jobs=state/'jobs';jobs.mkdir(mode=0o700)
        job=jobs/'job';job.mkdir(mode=0o700)
        digest=sha256(label.encode()).hexdigest()
        req={'job_id':'job','job_dir':str(job),'unit':'hepta-native-launch-test',
             'request_fingerprint':digest,'request_digest':digest,'launch_nonce':'a'*32,
             'hia_terminal_publisher':dict(pins),'executable':str(fixture),
             'args':['s'],'cwd':str(area),'default_cwd':str(area),
             'allowed_cwd_prefixes':[str(area)],'env':{},'timeout_seconds':3,'nice':0,
             **{'hia_'+key:True for key in FLAGS}}
        for role,data in images.items():
            path=job/('hia-terminal-'+role);path.write_bytes(data);path.chmod(0o600)
        info=job.stat()
        binding={'device':info.st_dev,'inode':info.st_ino,'job_id':'job',
                 'launch_nonce':req['launch_nonce'],'request_fingerprint':digest,
                 'hia_terminal_publisher':dict(pins),**{'hia_'+key:True for key in FLAGS}}
        if mutate:mutate(req,binding,job,area)
        (job/'request.json').write_text(json.dumps(req,sort_keys=True)+'\n')
        (job/'request.json').chmod(0o600)
        if after:after(req,binding,job,area)
        command=([str(args.executable)] if native else ['/usr/bin/python3','-I','-S','-c',reference])
        command += [str(job),json.dumps(binding,sort_keys=True)]
        if backend is not None:command.append(backend)
        trace=area/'exec.trace'
        if native:command=['/usr/bin/strace','-f','-qq','-s','160','-e','trace=execve,execveat','-o',str(trace),*command]
        environment={'PATH':'','LANG':'C.UTF-8',**(environ or {})}
        started=time.monotonic()
        process=subprocess.Popen(command,cwd=area,env=environment,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if cancel:
            deadline=time.monotonic()+5
            while not (job/'child.json').is_file() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.01)
            if (job/'started.json').is_file():
                pid=json.loads((job/'started.json').read_bytes())['supervisor_pid']
                os.kill(pid,signal.SIGTERM)
        wireout,wireerr=process.communicate(timeout=30)
        terminal=json.loads((job/'exit.json').read_bytes()) if (job/'exit.json').is_file() else None
        stdout=(job/'stdout.log').read_bytes() if (job/'stdout.log').is_file() else b''
        stderr=(job/'stderr.log').read_bytes() if (job/'stderr.log').is_file() else b''
        child=(job/'child.json').is_file()
        if terminal:
            witness=json.loads((job/'exit.witness.json').read_bytes())
            assert witness['exit_sha256']==sha256((job/'exit.json').read_bytes()).hexdigest()
            assert len((job/'native-exit.bin').read_bytes())==128
        if native:
            text=trace.read_text()
            assert 'python' not in text.lower() and '/bin/sh' not in text
        row={'name':name,'native':native,'returncode':process.returncode,'child_started':child,
             'seconds':round(time.monotonic()-started,6),'stdout_sha256':sha256(stdout).hexdigest(),
             'stdout_bytes':len(stdout),'stderr_sha256':sha256(stderr).hexdigest(),'stderr_bytes':len(stderr),
             'wire_stdout':wireout.decode('utf8','replace'),'wire_stderr':wireerr.decode('utf8','replace'),
             'terminal':terminal,'job':str(job)}
        rows.append(row)
        (out/'partial.json').write_text(json.dumps(rows,indent=2)+'\n')
        return row,stdout,stderr

    def compare(name,mutate=None,after=None,expected=True,normalize=None,**kw):
        old=run(name,False,mutate,after,**kw)
        new=run(name,True,mutate,after,**kw)
        assert old[0]['child_started']==expected,(name,'oracle',old[0])
        assert new[0]['child_started']==expected,(name,'native',new[0])
        if expected:
            assert old[0]['returncode']==new[0]['returncode'],(name,old[0],new[0])
            left,right=old[1:],new[1:]
            if normalize:left,right=normalize(left),normalize(right)
            assert left==right,(name,'streams',left,right)
            a=dict(old[0]['terminal']);b=dict(new[0]['terminal'])
            for field in ('at_unix_ms',):a.pop(field,None);b.pop(field,None)
            assert a==b,(name,'terminal',a,b)
        else:
            assert old[0]['returncode']!=0 and new[0]['returncode']!=0,(name,old[0],new[0])
        print(name,'PASS',round(new[0]['seconds'],3),flush=True)

    def setreq(**values):
        return lambda r,b,j,a:r.update(values)
    def input_bytes(data):
        def apply(r,b,j,a):
            path=j/'stdin.bin';path.write_bytes(data);path.chmod(0o600)
            r.update(args=['c'],stdin_path=str(path))
        return apply
    def env_output(streams):
        lines=streams[0].splitlines()
        lines=[line for line in lines if not line.startswith(b'HEPTA_RUNTIME_WORKER_ENTRY_FD=')]
        return (b'\n'.join(lines),streams[1])
    def cwd_output(streams):
        return (streams[0].split(b'/state/',1)[0].replace(b'-reference',b'-native'),streams[1])
    try:
        compare('streams')
        compare('default-detached',backend=None)
        compare('systemd-marker',backend='systemd')
        compare('invalid-backend',backend='invalid',expected=False)
        for name,data in [('empty',b''),('binary',bytes(range(256))*4),('multiple-chunks',bytes(range(256))*512)]:
            compare('stdin-'+name,input_bytes(data))
        compare('arguments-unicode',setreq(args=['a','α🙂','é\\quoted']))
        compare('arguments-surrogateescape',setreq(args=['a','\udc80','\udcff']))
        compare('arguments-long',setreq(args=['a','x'*8192,'y'*8192]))
        compare('arguments-too-long',setreq(args=['a','x'*8193,'y']),expected=False)
        compare('arguments-64',setreq(args=['s']+['x']*62))
        compare('arguments-65',setreq(args=['s']+['x']*63),expected=False)
        compare('arguments-nul',setreq(args=['a','a\0b','c']),expected=False)
        compare('arguments-invalid-surrogate',setreq(args=['a','\ud800','c']),expected=False)
        compare('environment',setreq(args=['e'],env={'Z':'last','A_':'underscore','A':'short','UNICODE':'✓','LANG':'override'}),normalize=env_output)
        compare('environment-surrogate-order',setreq(args=['e'],env={'\udc80':'raw','é':'valid','🙂':'high'}),expected=False)
        compare('environment-64',setreq(args=['e'],env={'K'+str(i):str(i) for i in range(60)}),normalize=env_output)
        compare('environment-65',setreq(args=['e'],env={'K'+str(i):str(i) for i in range(61)}),expected=False)
        compare('environment-nul',setreq(env={'X':'a\0b'}),expected=False)
        compare('environment-key-equals',setreq(args=['e'],env={'A=B':'c'}),normalize=env_output)
        compare('environment-key-collision',setreq(env={'A':'x','A=B':'c'}),expected=False)
        compare('environment-key-empty',setreq(env={'':'x'}),expected=False)
        compare('environment-surrogate-value',setreq(args=['e'],env={'VALUE':'\udc80\udcff'}),normalize=env_output)
        compare('environment-long',setreq(args=['e'],env={'K':'v'*8190}),normalize=env_output)
        compare('environment-too-long',setreq(env={'K':'v'*8191}),expected=False)
        compare('engine-env-removed',setreq(args=['e'],env={'HEPTA_RUNTIME_ENGINE_SCRATCH':'removed'}),normalize=env_output)
        compare('invocation-binding',setreq(env={'INVOCATION_ID':'b'*32}),environ={'INVOCATION_ID':'c'*32})
        compare('nice-detached',setreq(nice=1))
        compare('deadline',setreq(args=['w'],timeout_seconds=1))
        compare('cancel',setreq(args=['w'],timeout_seconds=5),cancel=True)
        compare('outside-cwd',setreq(cwd='/tmp'),expected=False)
        compare('cwd-required',lambda r,b,j,a:r.pop('cwd'),expected=False)
        compare('cwd-unrestricted',setreq(allowed_cwd_prefixes=[]))
        compare('root-relative',setreq(allowed_cwd_prefixes=['.']),expected=False)
        compare('root-wrong-type',setreq(allowed_cwd_prefixes=[1]),expected=False)
        compare('root-parent',lambda r,b,j,a:r.update(allowed_cwd_prefixes=[str(a.parent)]))
        compare('root-filesystem',setreq(allowed_cwd_prefixes=['/']))
        compare('root-missing-dotdot',lambda r,b,j,a:r.update(allowed_cwd_prefixes=[str(a/'absent/..')]))
        def symlink_root(r,b,j,a):
            (a/'link').symlink_to(a,target_is_directory=True)
            r['allowed_cwd_prefixes']=[str(a/'link/absent/..')]
        compare('root-symlink-missing-dotdot',symlink_root)
        def repeated_link(r,b,j,a):
            child=a/'child';child.mkdir()
            (a/'link').symlink_to('child',target_is_directory=True)
            r.update(cwd=str(child),allowed_cwd_prefixes=[str(a/'link/../link')])
        compare('root-repeated-link',repeated_link)
        def chain(r,b,j,a):
            for i in range(48):(a/('l'+str(i))).symlink_to('l'+str(i+1) if i<47 else '.',target_is_directory=True)
            r['allowed_cwd_prefixes']=[str(a/'l0')]
        compare('root-48-links',chain)
        def loop(r,b,j,a):
            (a/'loop').symlink_to('loop')
            r['allowed_cwd_prefixes']=[str(a/'loop/..')]
        compare('root-link-cycle-dotdot',loop)
        compare('multiple-roots',lambda r,b,j,a:r.update(allowed_cwd_prefixes=['/absent',str(a),'/tmp']))
        for flag in FLAGS:
            compare('flag-false-'+flag,setreq(**{'hia_'+flag:False}),expected=False)
        for name,mutate in (
            ('wrong-job',lambda r,b,j,a:b.update(job_id='other')),
            ('wrong-inode',lambda r,b,j,a:b.update(inode=b['inode']+1)),
            ('wrong-device',lambda r,b,j,a:b.update(device=b['device']+1)),
            ('wrong-nonce',lambda r,b,j,a:b.update(launch_nonce='b'*32)),
            ('wrong-fingerprint',lambda r,b,j,a:b.update(request_fingerprint='f'*64)),
            ('wrong-pin-binding',lambda r,b,j,a:r['hia_terminal_publisher'].update(supervisor='0'*64)),
            ('extra-role',lambda r,b,j,a:r['hia_terminal_publisher'].update(other='0'*64)),
            ('engine-scratch',setreq(engine_scratch_protocol=True)),
            ('flag-integer',setreq(hia_native_job_owner=1)),
            ('terminal-missing',lambda r,b,j,a:(j/'hia-terminal-encoder').unlink()),
            ('terminal-writable',lambda r,b,j,a:(j/'hia-terminal-supervisor').chmod(0o666)),
            ('terminal-readable',lambda r,b,j,a:(j/'hia-terminal-writer').chmod(0o640)),
            ('terminal-content',lambda r,b,j,a:(j/'hia-terminal-supervisor').write_bytes(b'x'*64)),
            ('terminal-hardlink',lambda r,b,j,a:os.link(j/'hia-terminal-encoder',a/'linked')),
            ('workload-symlink',lambda r,b,j,a:((a/'alias').symlink_to(fixture),r.update(executable=str(a/'alias')))),
            ('private-mode',lambda r,b,j,a:j.chmod(0o755)),
        ):
            compare(name,mutate,expected=False)
        compare('request-writable',after=lambda r,b,j,a:(j/'request.json').chmod(0o666),expected=False)
        compare('request-hardlink',after=lambda r,b,j,a:os.link(j/'request.json',a/'linked'),expected=False)
        def duplicate(r,b,j,a):
            path=j/'request.json';raw=path.read_bytes()
            path.write_bytes(b'{"job_id":"wrong",'+raw[1:])
        compare('metadata-last-key-wins',after=duplicate)
        def encoded_metadata(encoding):
            def apply(r,b,j,a):
                value=dict(r,opaque='BMP:é high:🙂 isolated:\ud800\udcff')
                (j/'request.json').write_bytes(json.dumps(value,ensure_ascii=False).encode(encoding,'surrogatepass'))
            return apply
        for encoding in ('utf-8','utf-8-sig','utf-16','utf-16-le','utf-16-be','utf-32','utf-32-le','utf-32-be'):
            compare('metadata-'+encoding,after=encoded_metadata(encoding))
        compare('metadata-nonfinite-unknown',setreq(opaque=[float('nan'),float('inf'),-float('inf')]))
        def large_metadata(r,b,j,a):
            path=j/'request.json';raw=path.read_bytes().rstrip()
            padding=4194304-len(raw)-7
            path.write_bytes(raw[:-1]+b',"x":"'+b'x'*padding+b'"}')
            assert path.stat().st_size==4194304
        compare('metadata-exact-limit',after=large_metadata)
        def excess_metadata(r,b,j,a):
            large_metadata(r,b,j,a)
            with (j/'request.json').open('ab') as stream:stream.write(b' ')
        compare('metadata-over-limit',after=excess_metadata,expected=False)
        if args.large:
            def large_input(size):
                def apply(r,b,j,a):
                    path=j/'stdin.bin'
                    with path.open('wb') as stream:stream.truncate(size)
                    path.chmod(0o600);r['stdin_path']=str(path)
                return apply
            compare('stdin-512MiB',large_input(512<<20))
            compare('stdin-over-512MiB',large_input((512<<20)+1),expected=False)
            def large_executable(size):
                def apply(r,b,j,a):
                    path=a/'payload';path.write_bytes(fixture.read_bytes())
                    with path.open('ab') as stream:stream.truncate(size)
                    path.chmod(0o500);r['executable']=str(path)
                return apply
            compare('workload-64MiB',large_executable(64<<20))
            compare('workload-over-64MiB',large_executable((64<<20)+1),expected=False)
        report={'schema':'hepta.hia.job-launch-qualification.v1','success':True,
                'runtime_source_sha256':sha256(runtime.encode()).hexdigest(),
                'oracle_sha256':sha256(reference.encode()).hexdigest(),
                'executable_sha256':sha256(args.executable.read_bytes()).hexdigest(),
                'images':pins,'cases':len(rows)//2,'rows':rows}
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print('PASS',report['cases'],'original/native pairs',flush=True)
    except BaseException:
        (out/'failure.json').write_text(json.dumps({'error':traceback.format_exc(),'rows':rows},indent=2)+'\n')
        raise


if __name__=='__main__':
    main()
