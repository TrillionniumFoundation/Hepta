"""Frozen source and owner custody for two CPython author invocations only.

No B3, GAS, VM, HIA entry, SQL, IPC, or Pager transaction is run by this stage.
The full source and selected system maps are fresh request inputs; historical
native or reference-runtime qualification is not inherited.
"""
from pathlib import Path
import hashlib,importlib.util,json,os,platform,stat,sys
import pager_common_r1 as common
ROOT=Path(__file__).resolve().parent.parent

def _walk_error(error):
    raise error

def read_json(path,maximum=64<<20):
    pin,raw=common.read(path,maximum);return pin,json.loads(raw)

def system_read(path):
    path=Path(path)
    with common.held_parent(path) as (parent,name):
        s=os.stat(name,dir_fd=parent,follow_symlinks=False)
        common.require(stat.S_ISREG(s.st_mode) and s.st_nlink>=1 and s.st_uid==0
            and not s.st_mode&0o022 and s.st_size<=128<<20,'frozen root-owned regular system role')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            common.require(common.identity(os.fstat(fd))==common.identity(s),'system fd identity')
            sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0');count=0
            while True:
                b=os.read(fd,1<<20)
                if not b:break
                count+=len(b);sha.update(b);git.update(b)
                common.require(count<=s.st_size,'system body grew')
            common.require(count==s.st_size and common.identity(os.fstat(fd))==common.identity(s)
                ==common.identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                'system whole read identity changed')
        finally:os.close(fd)
    return {'path':str(path),'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),'identity':common.identity(s)}

def runtime(request):
    actual=system_read(Path(sys.executable).resolve())
    common.require(actual==request['runtime'] and sys.version==request['python_version']
        and sys.version_info[:3]==(3,14,4) and sys.platform=='linux' and platform.machine()=='x86_64'
        and sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==request['boot_id'],
        'new ai395 runtime, flags or boot differs')
    return actual

def input_records(request):
    rows=common.input_records(ROOT,request)
    for name,pin in rows.items():
        common.require(pin==request['inputs'][name],
                       'complete frozen input pin changed: '+name)
    control=set()
    for path in (ROOT/'qualification').iterdir():
        common.require(stat.S_ISREG(path.lstat().st_mode),
                       'qualification namespace special entry')
        control.add(str(path.relative_to(ROOT)))
    common.require(control==set(request['qualification_namespace']),
                   'exact declared qualification namespace differs')
    return rows

def source_records(request):
    _,manifest=read_json(ROOT/'SOURCE-BASE.json',4<<20)
    common.require(manifest['source_commit']==request['source_commit']
        and manifest['source_tree']==request['source_tree']=='a5d9ce2d6fdff616bf91611c650e0fd3dc1786f2'
        and manifest['source_root']==str(Path(request['source_root']))
        and manifest['input_count']==request['source_count']==4136
        and manifest['bytes']==request['source_bytes']==412713085
        and len(manifest['files'])==4136,'complete current physical source set')
    rows={};total=0
    for item in manifest['files']:
        name=item['path']
        common.require(type(name)is str and name and not name.startswith('/')
            and str(Path(name))==name and '..' not in Path(name).parts,
            'source relative path')
        expected={'path':str(Path(request['source_root'])/name),
            **{key:item[key] for key in ('bytes','sha256','git_blob','identity')}}
        common.require(type(expected['identity'])is list and len(expected['identity'])==9
            and all(type(value)is int for value in expected['identity']),
            'source exact nine integer identity fields')
        pin,_=common.read(expected['path'])
        common.require(pin==expected,'current source complete pin: '+name)
        common.require(name not in rows,'duplicate source entry')
        rows[name]=pin;total+=pin['bytes']
    common.require(total==412713085,'complete current source byte population')
    found=set()
    for base,dirs,names in os.walk(Path(request['source_root']),onerror=_walk_error,followlinks=False):
        for d in dirs:common.require(stat.S_ISDIR((Path(base)/d).lstat().st_mode),'source directory link')
        for n in names:
            p=Path(base)/n;common.require(stat.S_ISREG(p.lstat().st_mode),'source special')
            found.add(str(p.relative_to(Path(request['source_root']))))
    common.require(found==set(rows),'source namespace exact')
    map_pin,map_raw=common.read(ROOT/'SOURCE-MAP.json',1<<20)
    common.require(map_pin==request['inputs']['SOURCE-MAP.json']
        and len(map_raw)==98339
        and hashlib.sha256(map_raw).hexdigest()==
            '28348495a949b9c94ffafcfb14a79b93f4bf7e1e4a8dbb435d0da376ee73c843',
        'exact current canonical cold source map bytes')
    cold=json.loads(map_raw)
    common.require(type(cold)is dict and len(cold)==901
        and all(type(name)is str and type(digest)is str
                and name in rows and rows[name]['sha256']==digest
                for name,digest in cold.items()),
        'all 901 cold entries join the 4136-file source')
    common.require(rows['tools/generate_hia_elf_linker.py']['sha256']==
        'cc57ae400052a47aa9861606eb9681e585d20b19a9b1f0a29fbc30b849a4071d',
        'unchanged original ELF author required by the fixed adapter')
    return rows

def system_records(request):
    map_pin,doc=read_json(ROOT/request['system_map'],4<<20)
    common.require(map_pin==request['inputs'][request['system_map']]
        and doc['count']==request['system_count']
        and len(doc['files'])==request['system_count']
        and doc['bytes']==request['system_bytes']
        and doc['runtime']==request['runtime'],
        'complete independently frozen current system profile')
    common.require(not Path('/etc/ld.so.preload').exists(),
                   'frozen profile: ld.so.preload absent before system read')
    rows={}
    for item in doc['files']:
        common.require(set(item)=={'path','bytes','sha256','git_blob','identity'}
            and type(item['identity'])is list and len(item['identity'])==9
            and all(type(value)is int for value in item['identity']),
            'exact complete system pin')
        p=system_read(item['path'])
        common.require(p==item,'fresh system input mismatch: '+item['path'])
        common.require(p['path'] not in rows,'duplicate system source');rows[p['path']]=p
    common.require(sum(item['bytes'] for item in rows.values())==doc['bytes'],
                   'complete declared system byte population')
    for alias,target in doc['aliases'].items():
        common.require(str(Path(alias).resolve(strict=True))==target,'system alias target changed')
    for label in ('directory_aliases','executable_aliases'):
        for alias in doc[label]:
            observed=os.lstat(alias['path'])
            common.require(type(alias['identity'])is list and len(alias['identity'])==9
                and all(type(value)is int for value in alias['identity'])
                and common.identity(observed)==alias['identity']
                and str(Path(alias['path']).resolve(strict=True))==alias['target'],
                'full original directory/executable alias identity and target')
            if label=='directory_aliases':
                common.require(stat.S_ISLNK(observed.st_mode) and Path(alias['target']).is_dir(),
                               'original declared directory alias')
    common.require(not Path('/etc/ld.so.preload').exists(),
                   'frozen profile: ld.so.preload absent after system read')
    return rows

def current_imports(request,source_rows):
    source={str(Path(request['source_root'])/r):p for r,p in source_rows.items()}
    source.update({str(ROOT/n):p for n,p in request['inputs'].items() if n.endswith('.py')})
    rows=[]
    for name,module in sorted(sys.modules.items()):
        if not (name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')
                or name=='tests' or name.startswith('tests.')):continue
        f=getattr(module,'__file__',None)
        if f is None:
            common.require(name=='tools','unknown project namespace');continue
        p=str(Path(f).resolve())
        common.require(p in source,'project import outside frozen source: '+name)
        observed,_=common.read(p)
        common.require(observed==source[p],'complete project import pin changed')
        rows.append({'module':name,'source':observed})
    return rows

def capacity(path,initial=False):
    v=os.statvfs(path);r={'path':str(path),'free_bytes':v.f_bavail*v.f_frsize,
        'free_inodes':v.f_favail,'device':Path(path).stat().st_dev}
    common.require(r['free_bytes']>=(1<<30 if initial else 512<<20) and r['free_inodes']>=4096,
                   'finite-native original capacity/inode gate')
    return r

def command(request,sha):
    q=request['command']
    common.require(q.count('@REQUEST_SHA256@')==1,'exact request hash slot')
    return [sha if v=='@REQUEST_SHA256@' else v for v in q]

def natural_owner(returned,life,parent_request,request,request_sha,life_pin,parent_pin):
    result=dict(returned);rc=result.pop('supervisor_returncode',None);seal=result.pop('receipt_sha256',None)
    common.require(result==life and type(rc)is int and seal==life_pin['sha256']
        and life.get('schema')=='hepta.hia.selfhost-process-owner.v1'
        and life.get('implementation_sha256')==request['inputs']['qualification/process_owner_impl.py']['sha256']
        and life.get('request_sha256')==parent_pin['sha256']
        and parent_request['implementation_sha256']==life['implementation_sha256']
        and parent_request['command']==command(request,request_sha)
        and parent_request['env']==request['environment'] and parent_request['cwd']==str(ROOT)
        and parent_request['qualification_seconds']==life.get('qualification_seconds')==180
        and parent_request['cleanup_seconds']==life.get('cleanup_seconds')==3
        and parent_request['deadline_ns']-parent_request['started_ns']==180000000000
        and life['parent_pid']==parent_request['parent_pid']
        and parent_request['stdout_path']==str(Path(request['output'])/'stdout.log')
        and parent_request['stderr_path']==str(Path(request['output'])/'stderr.log')
        and parent_request['receipt_path']==str(Path(request['output'])/'lifecycle.json'),
        'whole bound owner request/wrapper/implementation mismatch')
    cleanup=life.get('cleanup',{})
    closed=(life.get('subreaper_enabled') is True and life.get('event_overflow') is False
        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children')==[]
        and cleanup.get('errors')==[] and cleanup.get('deadline_exceeded') is False)
    common.require(closed,'owner closure unknown: do not enumerate/read child output')
    events=life.get('events',[])
    natural=(rc==0 and life.get('status')=='OWNED_PROCESS_COMPLETED' and life.get('returncode')==0
        and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True
        and life.get('owner_error') is None and life.get('interrupted_signals')==[]
        and [e.get('kind') for e in events]==['qualification_started','owned_child_observed',
             'qualification_exit_observed','owned_child_reaped']
        and all(e.get('pid')==life.get('qualification_pid') for e in events))
    return closed,natural

def catalog(output,skip=()):
    output=Path(output);rows=[];total=0
    for base,dirs,names in os.walk(output,onerror=_walk_error,followlinks=False):
        for d in dirs:common.require(stat.S_ISDIR((Path(base)/d).lstat().st_mode),'closed special directory')
        for n in sorted(names):
            p=Path(base)/n;name=str(p.relative_to(output))
            if name in skip:continue
            pin,_=common.read(p,4<<20);total+=pin['bytes'];rows.append({'relative_path':name,**pin})
            common.require(total<=384<<20 and len(rows)<=192,'closed full output original quota')
    return {'files':rows,'file_count':len(rows),'bytes':total,'all_bodies_read':True}

