"""Compile every Jobctl owner and exercise the native twenty-part ELF packer."""
from __future__ import annotations
import argparse,ctypes,datetime,json,mmap,struct,subprocess,sys
from hashlib import sha256
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--seed',type=Path,required=True)
    parser.add_argument('--seed-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    source=args.source.resolve(strict=True);seed=args.seed.resolve(strict=True)
    output=args.output.absolute();output.mkdir(mode=0o700,exist_ok=False)
    assert sha256(seed.read_bytes()).hexdigest()==args.seed_sha256
    sys.path.insert(0,str(source))
    from tools.generate_hia_system_jobctl_packer import MAGIC,MODULES,MAXIMUM_IMAGE,template
    from tools.build_hia_source_build import _named_source_request,_compiled_sources
    names=[module+'.hepta' for _,module in MODULES]+['system_jobctl_packer.hepta']
    snapshots={name:(source/'examples/hia_bootstrap'/name).read_bytes() for name in names}
    report={'phase':'compiling','started':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source':str(source),'seed':str(seed),'seed_sha256':args.seed_sha256,
        'sources':{name:sha256(raw).hexdigest() for name,raw in snapshots.items()},'cases':[]}
    def save():(output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    result=subprocess.run([str(seed),'sources'],input=_named_source_request(snapshots),capture_output=True,env={'PATH':''},timeout=120)
    (output/'compiler.stderr').write_bytes(result.stderr)
    assert result.returncode==0 and not result.stderr,(result.returncode,result.stderr)
    flats=_compiled_sources(result.stdout,snapshots)
    for name,raw in flats.items():(output/(name+'.flat')).write_bytes(raw)
    report['flats']={name:{'sha256':sha256(raw).hexdigest(),'bytes':len(raw)} for name,raw in flats.items()}
    raw=flats['system_jobctl_packer.hepta']
    code=mmap.mmap(-1,len(raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);code.write(raw)
    prototype=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
    pack=prototype(ctypes.addressof(ctypes.c_char.from_buffer(code)))
    def invoke(wire,capacity=MAXIMUM_IMAGE,workspace=160):
        inp=ctypes.create_string_buffer(wire);out=ctypes.create_string_buffer(capacity);work=ctypes.create_string_buffer(max(workspace,1))
        got=pack(ctypes.addressof(inp),len(wire),ctypes.addressof(out),capacity,ctypes.addressof(work),workspace)
        return got,bytes(out[:got]) if got<=capacity else None
    parts=[flats[module+'.hepta'] for _,module in MODULES]
    sizes=list(map(len,parts));header=8+8*len(parts)
    wire=MAGIC+struct.pack('<20Q',*sizes)+b''.join(parts)
    got,image=invoke(wire)
    prefix,holes=template();expected=bytearray(prefix);total=len(prefix)+sum(sizes)
    struct.pack_into('<QQ',expected,96,total,total)
    offset=len(prefix)
    for (alias,_),part in zip(MODULES,parts):
        struct.pack_into('<i',expected,holes[alias],offset-holes[alias]-4);offset+=len(part)
    expected.extend(b''.join(parts))
    assert got==total and image==expected
    program=output/'jobctl-native';program.write_bytes(image);program.chmod(0o500)
    report['cases'].append({'case':'twenty-real-owners','result':'passed'})
    report.update(native_bytes=len(image),native_sha256=sha256(image).hexdigest(),adapter_sha256=sha256((source/'tools/hia_system_jobctl_syscalls.S').read_bytes()).hexdigest())
    negatives=[('empty',b'',4294967295),('magic',b'BADJCT01'+wire[8:],4294967295),('trailing',wire+b'x',4294967295)]
    for length in [1,7,8,15,header-1,header,header+1,len(wire)-1]:negatives.append(('truncated-'+str(length),wire[:length],4294967295))
    for index in range(20):
        for size in [0,1048577,(1<<64)-1]:
            bad=bytearray(wire);struct.pack_into('<Q',bad,8+index*8,size);negatives.append((f'component-{index}-size-{size}',bytes(bad),4294967295))
    for name,bad,want in negatives:
        actual,_=invoke(bad);assert actual==want,(name,actual,want)
        report['cases'].append({'case':name,'result':'passed'})
    actual,_=invoke(wire,capacity=len(image)-1);assert actual==4294967294
    report['cases'].append({'case':'short-output','result':'passed'})
    actual,_=invoke(wire,workspace=159);assert actual==4294967294
    report['cases'].append({'case':'short-workspace','result':'passed'})
    remaining=MAXIMUM_IMAGE-len(image);assert remaining>0 and sizes[-1]+remaining<=1048576
    boundary=parts.copy();boundary[-1]+=bytes(remaining)
    at_limit=MAGIC+struct.pack('<20Q',*map(len,boundary))+b''.join(boundary)
    actual,maximum=invoke(at_limit);assert actual==MAXIMUM_IMAGE and maximum is not None
    report['cases'].append({'case':'exact-four-MiB-image','result':'passed'})
    boundary[-1]+=b'x';over=MAGIC+struct.pack('<20Q',*map(len,boundary))+b''.join(boundary)
    actual,_=invoke(over);assert actual==4294967294
    report['cases'].append({'case':'four-MiB-plus-one-image','result':'passed'})
    assert all((source/'examples/hia_bootstrap'/name).read_bytes()==raw for name,raw in snapshots.items())
    report.update(phase='passed',case_count=len(report['cases']),source_unchanged=True,finished=datetime.datetime.now(datetime.timezone.utc).isoformat());save()
    print(json.dumps({'phase':'passed','cases':len(report['cases']),'native_sha256':report['native_sha256'],'bytes':len(image)}),flush=True)

if __name__=='__main__':main()
