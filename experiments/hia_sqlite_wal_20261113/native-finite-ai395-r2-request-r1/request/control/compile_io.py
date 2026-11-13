"""Exact fixed GCC command and complete depfile/link-map joins, no oracle call."""
from pathlib import Path
import json,shlex
import common,support
ROOT=support.ROOT
def child_request(request,version,directory):
    directory=Path(directory)
    adapter=ROOT/'candidate/native-oracles'/('sqlite-'+version)/'adapter.c'
    inputs=[adapter,*(adapter.with_name(n) for n in ('checksum.inc','decode-frame.inc','header-checks.inc'))]
    gcc=request['system_binaries']['gcc']
    argv=[gcc,'-std=c11','-O2','-fPIC','-shared','-fno-lto','-fno-common','-g0','-save-temps=obj',
          '-Wl,-Bsymbolic','-Wl,-z,defs','-MD','-MF',str(directory/'oracle.d'),
          '-MT',str(directory/'oracle.so'),'-Wl,-Map,'+str(directory/'oracle.map'),
          '-o',str(directory/'oracle.so'),str(adapter)]
    return {'schema':'hia.sqlite.wal.C-compile-request.v1','version':version,
            'output':str(directory),'cwd':str(directory),'argv':argv,
            'environment':{'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','TMPDIR':str(directory/'tmp')},
            'source_inputs':{str(p):common.read(p)[0] for p in inputs},
            'wall_seconds':20,'cpu_seconds':10,'max_image_bytes':1<<20}
def inspect(request,version,directory):
    directory=Path(directory)
    reqpin,q=support.read_json(directory/'REQUEST.json',1<<20)
    common.require(q==child_request(request,version,directory),'fixed C command/cwd/environment changed')
    pin,r=support.read_json(directory/'COMPILE.json',1<<20)
    common.require(r['request']==reqpin and r['argv']==q['argv'] and r['cwd']==q['cwd']
        and r['environment']==q['environment'] and r['status']=='C_ORIGINAL_ALGORITHMS_COMPILED_ONLY'
        and r['attempted'] is True and type(r['returncode'])is int and r['returncode']==0
        and r['timed_out'] is False and r['exception'] is None and r['secondary_errors']==[]
        and type(r['elapsed_ns'])is int and 0<=r['elapsed_ns']<=20000000000
        and r['inputs_after']==r['inputs_before']==q['source_inputs']
        and r['limits']=={'wall_seconds':20,'cpu_seconds':10,'address_bytes':256<<20,
            'stack_bytes':8<<20,'file_bytes':1<<20,'core_bytes':0},'complete successful C receipt')
    image_pin,image=common.read(directory/'oracle.so',1<<20)
    common.require(image_pin==r['image'] and image[:6]==b'\x7fELF\x02\x01'
        and int.from_bytes(image[16:18],'little')==3 and int.from_bytes(image[18:20],'little')==62,'new exact oracle image')
    _,system=support.read_json(ROOT/request['system_map'])
    allowed={p['path']:p for p in system['files']}
    allowed.update(q['source_inputs'])
    dp,raw=common.read(directory/'oracle.d',1<<20)
    text=raw.decode().replace('\\\n','')
    target,sep,names=text.partition(':')
    common.require(sep and target.strip()==str(directory/'oracle.so'),'explicit depfile target')
    dependencies=shlex.split(names);common.require(dependencies,'complete C dependency list empty')
    dep_rows=[]
    for name in dependencies:
        path=Path(name).resolve(strict=True);key=str(path)
        common.require(key in allowed,'C dependency missing from frozen closure: '+key)
        p=support.system_read(path) if key not in q['source_inputs'] else common.read(path)[0]
        common.require(all(p[k]==allowed[key][k] for k in ('bytes','sha256','git_blob','identity')),'C full dependency changed')
        dep_rows.append(p)
    mp,mraw=common.read(directory/'oracle.map',1<<20)
    load_names=[line[5:].strip() for line in mraw.decode().splitlines() if line.startswith('LOAD ')]
    common.require(load_names,'GNU linker map has no LOAD records')
    load_rows=[]
    for name in load_names:
        path=Path(name).resolve(strict=True);key=str(path)
        if path.is_relative_to(directory):
            p,_=common.read(path,1<<20)
        else:
            common.require(key in allowed,'link input missing from frozen closure: '+key)
            p=support.system_read(path)
            common.require(all(p[k]==allowed[key][k] for k in ('bytes','sha256','git_blob','identity')),'link input changed')
        load_rows.append(p)
    retained={}
    for p in directory.iterdir():
        if p.is_file():retained[p.name]=common.read(p,1<<20)[0]
        else:common.require(p.name=='tmp' and p.is_dir() and not list(p.iterdir()),'C temporary directory leftovers')
    common.require(any(n.endswith('.i') for n in retained) and any(n.endswith('.s') for n in retained)
        and any(n.endswith('.o') for n in retained),'whole preprocessed/assembly/object original not retained')
    return {'receipt':pin,'image':image_pin,'depfile':dp,'dependencies':dep_rows,
            'link_map':mp,'link_inputs':load_rows,'whole_case_files':retained}
