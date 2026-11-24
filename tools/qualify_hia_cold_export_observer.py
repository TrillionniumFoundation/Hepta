"""Build and compare a native scalar-export observer with the frozen old child.

This external component qualifier runs the original independent Core VM reference
before compiling its test targets. It is not the full cold B0/reference pipeline.
The final image contains HIA policy and a fixed Linux/libc/SysV adapter only.
"""
from __future__ import annotations
import argparse, ctypes, datetime, json, mmap, struct, subprocess, sys
from hashlib import sha256
from pathlib import Path

KINDS = ('void','unit','bool','u8','u16','u32','u64','usize','i8','i16','i32','i64','isize')
MAX_IMAGE=4<<20

def digest(raw):return sha256(raw).hexdigest()

def frame(image,calls):
    records=[]
    for row in calls:
        name=row['function'].encode('ascii');args=row['arguments'];kind=KINDS.index(row['return_type'])
        assert 1<=len(name)<=128 and len(args)<=16
        records.append(struct.pack('<4Q',len(name),len(args),kind,0)+name.ljust(128,b'\0')+
                       struct.pack('<16Q',*args,*([0]*(16-len(args)))))
    extent=64+288*len(calls)+len(image)
    return b'HIAEXQ01'+struct.pack('<7Q',len(image),len(calls),288*len(calls),0,0,0,extent)+b''.join(records)+image

def response(raw,calls):
    size=32+24*len(calls);begin=0
    while begin+size<=len(raw) and raw[begin] in b' \t\r\n':begin+=1
    assert raw[begin:begin+8]==b'HIAEXR01' and len(raw)>=begin+size
    assert all(v in b' \t\r\n' for v in raw[begin+size:])
    raw=raw[begin:begin+size];assert struct.unpack_from('<3Q',raw,8)==(len(calls),24*len(calls),0)
    observed=[]
    for i,row in enumerate(calls):
        index,kind,value=struct.unpack_from('<3Q',raw,32+24*i)
        assert index==i and kind==KINDS.index(row['return_type'])
        if kind==0:
            assert value==0;value=None
        elif kind>=8 and value>>63:value-=1<<64
        observed.append(dict(function=row['function'],value=value))
    return observed

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','seed','oracle-source','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--seed-sha256',required=True);a=p.parse_args()
    S=a.source.resolve(strict=True);F=a.oracle_source.resolve(strict=True);D=a.output.absolute();D.mkdir(mode=0o700)
    assert digest(a.seed.read_bytes())==a.seed_sha256
    sys.path.insert(0,str(S))
    from tools.generate_hia_cold_export_observer import reference_object,assembled_bridge,BRIDGE,BRIDGE_RELOCATIONS,POLICY_HOLE,START_SIZE
    from tools.build_hia_source_build import _named_source_request,_compiled_sources
    from tools.qualify_hia_selfhost_exports import independent_reference
    from tools.hia_selfhost_linked_observer import _runtime_interpreter
    for n in ('tools/qualify_hia_selfhost_exports.py','tools/hia_selfhost_exports_cases.py','tools/hia_selfhost_exports_child.py'):
        assert (S/n).read_bytes()==(F/n).read_bytes(),n
    names=('cold_export_observer.hepta','cold_export_packer.hepta')
    snapshots={n:(S/'examples/hia_bootstrap'/n).read_bytes() for n in names}
    report={'status':'running','started':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'seed':str(a.seed),'seed_sha256':a.seed_sha256,'source_sha256':{n:digest(v) for n,v in snapshots.items()},
        'oracle_source':str(F),'oracle_child_sha256':digest((F/'tools/hia_selfhost_exports_child.py').read_bytes()),
        'whole_cold_gate':False,'reference_before_this_component_compilation':True,'cases':[]}
    def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    # This is executed independently, not reconstructed from target outputs.
    ref=independent_reference();(D/'independent-reference.json').write_text(json.dumps(ref,indent=2)+'\n')
    report['independent_reference_sha256']=digest((D/'independent-reference.json').read_bytes())
    assert assembled_bridge()==(BRIDGE,BRIDGE_RELOCATIONS,POLICY_HOLE,START_SIZE)
    compiled=subprocess.run([str(a.seed),'sources'],input=_named_source_request(snapshots),capture_output=True,env={'PATH':''},timeout=120)
    (D/'compiler.stderr').write_bytes(compiled.stderr);assert compiled.returncode==0 and not compiled.stderr,(compiled.returncode,compiled.stderr)
    flats=_compiled_sources(compiled.stdout,snapshots)
    for n,b in flats.items():(D/(n+'.flat')).write_bytes(b)
    report['flats']={n:{'bytes':len(b),'sha256':digest(b)} for n,b in flats.items()}
    b=flats[names[1]];mapping=mmap.mmap(-1,len(b),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);mapping.write(b)
    prototype=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
    call=prototype(ctypes.addressof(ctypes.c_char.from_buffer(mapping)))
    def pack(raw,capacity=1<<20):
        inp=ctypes.create_string_buffer(raw);out=ctypes.create_string_buffer(b'\xa5'*capacity);work=ctypes.create_string_buffer(1)
        got=call(ctypes.addressof(inp),len(raw),ctypes.addressof(out),capacity,ctypes.addressof(work),0)
        return got,bytes(out)[:got] if got<=capacity else None
    policy=flats[names[0]];size,obj=pack(policy);assert obj==reference_object(policy) and size==len(obj)
    (D/'observer.o').write_bytes(obj)
    for raw in (b'',b'\xc3',bytes(range(256))*17):
        got,actual=pack(raw)
        if raw:assert actual==reference_object(raw)
        else:assert got==0xffffffff
    got,_=pack(policy,len(obj)-1);assert got==0xfffffffe
    report['packer_exact_object_controls']=5
    interpreter,runtime=_runtime_interpreter();image=D/'hia-cold-export-observer'
    link=subprocess.run(['/usr/bin/ld','-m','elf_x86_64','-pie','-e','_start','--dynamic-linker',str(interpreter),
        '-z','defs','-z','noexecstack','-z','relro','-z','now','--build-id=none',str(D/'observer.o'),'-ldl','-lc','-o',str(image)],capture_output=True)
    (D/'link.stderr').write_bytes(link.stderr);assert link.returncode==0,(link.returncode,link.stderr)
    image.chmod(0o500);report.update(native_sha256=digest(image.read_bytes()),native_bytes=image.stat().st_size,runtime_loader=runtime)
    targets={row['name']:row for row in ref['programs']}
    tasks=[]
    for label,row in targets.items():
        source=row['source'].encode();obj=D/(label+'.o');so=D/(label+'.so')
        r=subprocess.run([str(a.seed),'compile'],input=source,capture_output=True,env={'PATH':''},timeout=20)
        assert r.returncode==0 and not r.stderr,(label,r.returncode,r.stderr);obj.write_bytes(r.stdout)
        r=subprocess.run(['/usr/bin/cc','-nostartfiles','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now,--build-id=none',str(obj),'-o',str(so)],capture_output=True,timeout=20)
        assert r.returncode==0,(label,r.stderr)
        tasks.append((label,so,row['calls']))
    row=targets['scalar'];tasks.append(('1024-call-boundary',D/'scalar.so',(row['calls']*((1024+len(row['calls'])-1)//len(row['calls'])))[:1024]))
    before_image=image.read_bytes();count=0
    for label,so,calls in tasks:
        t=D/label;t.mkdir();complete=so.read_bytes();assert len(complete)<=MAX_IMAGE
        request={'schema':'hepta.hia.scalar-export-observation.v1','image':str(so),'image_sha256':digest(complete),
            'calls':[{k:v[k] for k in ('function','arguments','return_type')} for v in calls]}
        raw=json.dumps(request,sort_keys=True).encode();rp=t/'original-request.json';rp.write_bytes(raw)
        old=subprocess.run([sys.executable,'-I','-S','-B',str(F/'tools/hia_selfhost_exports_child.py'),'--request',str(rp),'--sha256',digest(raw)],capture_output=True,timeout=15)
        (t/'original.stdout').write_bytes(old.stdout);(t/'original.stderr').write_bytes(old.stderr)
        assert old.returncode==0 and not old.stderr,(label,old.returncode,old.stderr)
        original=json.loads(old.stdout);wire=frame(complete,calls);(t/'native-request.bin').write_bytes(wire)
        fd=__import__('os').memfd_create('hia-cold-export-component',__import__('os').MFD_ALLOW_SEALING)
        try:
            __import__('os').write(fd,before_image);__import__('fcntl').fcntl(fd,1033,15)
            new=subprocess.run(['/proc/self/fd/'+str(fd)],input=wire,capture_output=True,timeout=15,pass_fds=(fd,),env={'PATH':''})
        finally:__import__('os').close(fd)
        (t/'native.stdout').write_bytes(new.stdout);(t/'native.stderr').write_bytes(new.stderr)
        assert new.returncode==0 and not new.stderr,(label,new.returncode,new.stderr)
        actual=response(new.stdout,calls);expected=[{'function':v['function'],'value':v['expected']} for v in calls]
        assert actual==original['observations']==expected,label
        assert original['forbidden_compiler_modules_loaded']==[] and so.read_bytes()==complete
        count+=len(calls);report['cases'].append(dict(case=label,calls=len(calls),passed=True,source_sha256=targets.get(label,targets['scalar'])['source_sha256'],target_sha256=digest(complete),request_sha256=digest(wire),response_sha256=digest(new.stdout)))
        save();print('EXPORT',label,len(calls),'PASS',flush=True)
    first=tasks[0];valid=frame(first[1].read_bytes(),first[2]);negative=[]
    for extent in (0,1,7,8,63,64,64+287,len(valid)-1):negative.append(('truncated-'+str(extent),valid[:extent],2))
    negative += [('trailing',valid+b'x',2),('magic',b'BADREQ01'+valid[8:],2)]
    for offset,values in [(8,(0,MAX_IMAGE+1)),(16,(0,1025)),(24,(0,288)),(32,(1,)),(40,(1,)),(48,(1,)),(56,(0,)),(64,(0,129)),(72,(17,)),(80,(13,)),(88,(1,))]:
        for value in values:
            bad=bytearray(valid);struct.pack_into('<Q',bad,offset,value);negative.append((f'field-{offset}-{value}',bytes(bad),2))
    for offset,value in [(96,ord('0')),(97,ord('-')),(96+127,1)]:
        bad=bytearray(valid);bad[offset]=value;negative.append((f'name-{offset}-{value}',bytes(bad),2))
    negative.append(('input-plus-one',bytes(4489281),3))
    for label,raw,want in negative:
        r=subprocess.run([str(image)],input=raw,capture_output=True,timeout=15,env={'PATH':''})
        assert r.returncode==want and not r.stdout and not r.stderr,(label,r.returncode,r.stdout[:64],r.stderr[:100])
        report['cases'].append(dict(case=label,passed=True,private_carrier_refusal=True))
    extra=subprocess.run([str(image),'unexpected'],input=b'',capture_output=True,timeout=15,env={'PATH':''})
    assert extra.returncode==64 and not extra.stdout and not extra.stderr
    report['cases'].append(dict(case='argv',passed=True,private_carrier_refusal=True))
    assert image.read_bytes()==before_image and all((S/'examples/hia_bootstrap'/n).read_bytes()==b for n,b in snapshots.items())
    report.update(status='passed',actual_scalar_calls=count,case_count=len(report['cases']),source_unchanged=True,finished=datetime.datetime.now(datetime.timezone.utc).isoformat());save()
    print(json.dumps({k:report[k] for k in ('status','case_count','actual_scalar_calls','native_sha256','native_bytes')}),flush=True)

if __name__=='__main__':main()
