"""Exercise complete native managed-Worker admission and preserve default START.
Run as root in a private mount namespace. Fixed external systemd tools are fixtures;
no fixture substitutes for the separate actual systemd/Worker lifecycle gate.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,json,os,shutil,stat,struct,subprocess,time,traceback

def state_root(workspace,principal,identity):
    raw=os.fsencode(workspace)
    domain=b'HIAWS001'+struct.pack('<Q',len(raw))+raw+struct.pack('<Q',principal)+bytes.fromhex(identity)
    return '/var/lib/private/hepta-hia-worker-'+sha256(domain).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['candidate','worker','fixture','output']:p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    assert os.geteuid()==0 and os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    source={n:getattr(a,n).read_bytes() for n in ['candidate','worker','fixture']}
    D=a.output.absolute();D.mkdir(mode=0o700)
    os.umask(0o022)
    for target,name in [('/var/lib','hia-worker-profile-varlib'),('/etc','hia-worker-profile-etc')]:
        subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','mode=0755',name,target],check=True)
    probe=Path('/var/lib/qa-probes');probe.mkdir(mode=0o755)
    for name in source:
        path=probe/name;path.write_bytes(source[name]);path.chmod(0o555)
    for target in ['/usr/bin/systemd-run','/usr/bin/systemctl']:
        subprocess.run(['/usr/bin/mount','--bind',str(probe/'fixture'),target],check=True)
    W=Path('/var/lib/hepta-runtime/workspaces/qa');W.mkdir(parents=True)
    other=W.parent/'other';other.mkdir()
    protected=probe/'protected';protected.mkdir(mode=0o755)
    inner=protected/'release';inner.mkdir(mode=0o555)
    worker=inner/'hia-agent-worker';worker.write_bytes(source['worker']);worker.chmod(0o555)
    identity='1a'*32
    profile={'executable':str(worker),'sha256':sha256(source['worker']).hexdigest(),'principal_uid':1000,'state_identity':identity}
    policy={'workspace':str(W),'native_worker':profile}
    policy_path=Path('/etc/hepta-runtime/job-policy.json');policy_path.parent.mkdir()
    registry=Path('/var/lib/hepta-runtime-jobctl')
    baseline={'op':'start','job_id':'managed-profile-qa','executable':str(worker),'args':['--state-root',state_root(W,1000,identity)],'cwd':str(W)}
    report={'schema':'hia.system-jobctl-managed-worker-admission.v1','status':'running',
        'scope':'actual native complete control with private external systemd command fixtures',
        'actual_systemd_lifecycle_qualified':False,
        'pins':{n:sha256(raw).hexdigest() for n,raw in source.items()},'cases':[]}
    def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    cases=[]
    def case(name,passed=False,**kw):cases.append({'name':name,'accepted':passed,**kw})
    case('managed-profile',True)
    case('default-other-executable',True,request={'executable':'/usr/bin/true','args':[]},managed=False)
    case('original-no-profile',True,omit=True,managed=False)
    case('authenticated-process-principal-over-request-env',True,request={'env':{'SUDO_UID':'999'}})
    case('principal-zero-root-direct',True,profile={'principal_uid':0},environment={},correct_state=True)
    case('other-workspace-new-domain',True,policy={'workspace':str(other)},request={'cwd':str(other)},correct_state=True)
    case('other-identity-new-domain',True,profile={'state_identity':'2b'*32},correct_state=True)
    case('missing-sudo-principal',environment={})
    case('other-sudo-principal',environment={'SUDO_UID':'1001'})
    case('leading-zero-principal',environment={'SUDO_UID':'01000'})
    case('invalid-principal',environment={'SUDO_UID':'1000x'})
    case('wrong-state-root',request={'args':['--state-root','/var/lib/private/other']})
    case('public-symlink-state-path',request={'args':['--state-root',state_root(W,1000,identity).replace('/var/lib/private/','/var/lib/')]})
    case('missing-state-root',request={'args':[]})
    case('duplicate-state-root',request={'args':baseline['args']+baseline['args']})
    case('state-prefix',request={'args':['--state-root',state_root(W,1000,identity)+'/child']})
    case('state-from-other-principal',request={'args':['--state-root',state_root(W,1001,identity)]})
    case('workspace-old-state',policy={'workspace':str(other)},request={'cwd':str(other)})
    case('config-identity-old-state',profile={'state_identity':'2b'*32})
    case('interactive-profile',request={'op':'pty'})
    case('worker-pin-replaced',profile={'sha256':'0'*64})
    case('worker-replaced-after-policy',mutation='bytes')
    case('worker-untrusted-elf-with-matching-pin',mutation='header',replace_pin=True)
    case('worker-writable',mutation='leaf-writable')
    case('worker-group-writable',mutation='leaf-group-writable')
    case('worker-other-owner',mutation='leaf-owner')
    case('worker-hardlink',mutation='hardlink')
    case('worker-symlink',mutation='symlink')
    case('worker-directory',mutation='directory')
    case('release-group-writable',mutation='release-writable')
    case('release-other-owner',mutation='release-owner')
    case('renameable-release-ancestor',mutation='ancestor-writable')
    case('foreign-release-ancestor',mutation='ancestor-owner')
    case('symlink-release-ancestor',mutation='ancestor-symlink')
    case('profile-extra-key',profile={'other':1})
    case('profile-negative-principal',profile={'principal_uid':-1})
    case('profile-overflow-principal',profile={'principal_uid':4294967295})
    case('profile-floating-principal',profile={'principal_uid':1000.0})
    case('profile-uppercase-pin',profile={'sha256':profile['sha256'].upper()})
    case('profile-dot-component',profile={'executable':str(inner)+'/./hia-agent-worker'})
    case('profile-dotdot-component',profile={'executable':str(inner)+'/../release/hia-agent-worker'})
    case('profile-empty-component',profile={'executable':str(inner)+'//hia-agent-worker'})
    case('profile-relative',profile={'executable':'hia-agent-worker'})
    case('profile-null',null=True)
    try:
        for item in cases:
            if registry.exists():shutil.rmtree(registry)
            for n in ['launch-count','show-count','stop-count','launch-argv']:
                path=probe/n
                if path.exists():path.unlink()
            pol=copy.deepcopy(policy);pol.update(item.get('policy',{}));pol['native_worker'].update(item.get('profile',{}))
            q=copy.deepcopy(baseline);q.update(item.get('request',{}))
            if item.get('correct_state'):
                q['args']=['--state-root',state_root(pol['workspace'],pol['native_worker']['principal_uid'],pol['native_worker']['state_identity'])]
            undo=[]
            mutation=item.get('mutation')
            if mutation in ['bytes','header']:
                raw=bytearray(source['worker']);raw[-1 if mutation=='bytes' else 0]^=1
                worker.chmod(0o600);worker.write_bytes(raw);worker.chmod(0o555)
                if item.get('replace_pin'):pol['native_worker']['sha256']=sha256(raw).hexdigest()
                undo.append(lambda: (worker.chmod(0o600),worker.write_bytes(source['worker']),worker.chmod(0o555)))
            if mutation in ['leaf-writable','leaf-group-writable']:
                worker.chmod(0o755 if mutation=='leaf-writable' else 0o575);undo.append(lambda:worker.chmod(0o555))
            if mutation=='leaf-owner':
                os.chown(worker,1000,0);undo.append(lambda:os.chown(worker,0,0))
            if mutation=='hardlink':
                link=inner/'extra';os.link(worker,link);undo.append(link.unlink)
            if mutation in ['symlink','directory']:
                original=inner/'saved';worker.rename(original)
                if mutation=='symlink':worker.symlink_to(original.name)
                else:worker.mkdir(mode=0o555)
                def restore():
                    worker.unlink() if worker.is_symlink() else worker.rmdir()
                    original.rename(worker)
                undo.append(restore)
            if mutation in ['release-writable','release-owner','ancestor-writable','ancestor-owner']:
                path=inner if mutation.startswith('release') else protected
                if mutation.endswith('writable'):path.chmod(0o777);undo.append(lambda p=path:p.chmod(0o555 if p==inner else 0o755))
                else:os.chown(path,1000,0);undo.append(lambda p=path:os.chown(p,0,0))
            if mutation=='ancestor-symlink':
                original=probe/'saved-protected';protected.rename(original);protected.symlink_to(original.name)
                def restore_parent():protected.unlink();original.rename(protected)
                undo.append(restore_parent)
            if item.get('omit'):pol.pop('native_worker')
            if item.get('null'):pol['native_worker']=None
            policy_path.write_text(json.dumps(pol,separators=(',',':'))+'\n');policy_path.chmod(0o600)
            try:
                result=subprocess.run([str(probe/'candidate')],input=json.dumps(q).encode()+b'\n',
                    capture_output=True,timeout=15,cwd=W,env={'PATH':'',**item.get('environment',{'SUDO_UID':'1000'})})
            finally:
                for action in reversed(undo):action()
            argv=(probe/'launch-argv').read_bytes().split(b'\0') if (probe/'launch-argv').exists() else []
            counts={n:(probe/(n+'-count')).stat().st_size if (probe/(n+'-count')).exists() else 0 for n in ['launch','show','stop']}
            row={'case':item['name'],'expected_accepted':item['accepted'],'rc':result.returncode,'stdout':result.stdout.decode(errors='replace'),
                'stderr':result.stderr.decode(errors='replace'),'launch_counts':counts,'registry_created':registry.exists(),'argv':[x.decode(errors='replace') for x in argv]}
            if item['accepted']:
                response=json.loads(result.stdout)
                assert result.returncode==0 and not result.stderr and response['ok'] is True,(item,row)
                assert counts['launch']==1,(item,row)
                props=[x.decode() for x in argv if x.startswith(b'StateDirectory=') or x.startswith(b'Environment=STATE_DIRECTORY=')]
                if item.get('managed',True):
                    basename=Path(q['args'][1]).name
                    assert props==['StateDirectory=hepta-job-managed-profile-qa '+basename,'Environment=STATE_DIRECTORY=/var/lib/hepta-job-managed-profile-qa'],(item,props)
                else:assert props==['StateDirectory=hepta-job-managed-profile-qa'],(item,props)
            else:
                assert result.returncode!=0 and counts['launch']==0 and not registry.exists(),(item,row)
            row['passed']=True;report['cases'].append(row);save()
        report['status']='passed';save();print(json.dumps({'status':'passed','cases':len(report['cases']),'output':str(D)}),flush=True)
    except BaseException:
        report['status']='failed';report['failure']=traceback.format_exc();save();raise
if __name__=='__main__':main()
