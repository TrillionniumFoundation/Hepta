"""Original native packet bounds and every fixed import of the Runtime/BG root."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib.abc,importlib.machinery,json,struct,sys

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--build',type=Path,required=True)
    a.add_argument('--output',type=Path,required=True)
    a.add_argument('--reference-root',type=Path,required=True)
    a.add_argument('--runtime-checkpoint',type=Path,required=True)
    a.add_argument('--runtime-tools-root',type=Path,required=True)
    args=a.parse_args();root=Path(__file__).resolve().parents[1]
    sys.path[:0]=[str(root),str(args.reference_root),str(args.runtime_tools_root)]
    paths=[str(args.runtime_checkpoint/'source/tools'),str(root/'tools'),str(args.runtime_tools_root/'tools'),str(args.reference_root/'tools')]
    class Frozen(importlib.abc.MetaPathFinder):
        def find_spec(self,name,path=None,target=None):
            if name.startswith('tools.'):return importlib.machinery.PathFinder.find_spec(name,paths)
    sys.meta_path.insert(0,Frozen())
    from tools import generate_hia_generation_background_runtime_fusion_packer as spec
    from tools.qualify_hia_multiversion_components import Image
    pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    build=json.loads((args.build/'build.json').read_text())
    source=json.loads(Path(build['source_build']['path']).read_text())
    assert pin((root/'tools/generate_hia_generation_background_runtime_fusion_packer.py').read_bytes())=={k:source['author'][k]for k in ('bytes','sha256')}
    rows=build['role_inputs'];assert tuple(r['role']for r in rows)==spec.ROLES
    parts=[]
    for row in rows:
        raw=Path(row['path']).read_bytes();assert pin(raw)=={k:row[k]for k in ('bytes','sha256')};parts.append(raw)
    packer=Path(build['packer']['path']);assert pin(packer.read_bytes())=={k:build['packer'][k]for k in ('bytes','sha256')}
    actual=(args.build/'component.o').read_bytes()
    assert actual==spec.reference_object(parts)
    wire=struct.pack('<'+'Q'*(len(parts)+2),spec.MAGIC,len(parts),*map(len,parts))+b''.join(parts)
    im=Image(packer);results=[];args.output.mkdir(exist_ok=False,parents=True)
    def check(name,raw,want,workspace=8192):
        out=C.create_string_buffer(b'\xa5'*8192,8192);work=C.create_string_buffer(workspace)
        before=hashlib.sha256(raw).hexdigest();rc=im(raw,out,work)
        assert rc==want and out.raw==b'\xa5'*8192,(name,rc,want)
        assert hashlib.sha256(raw).hexdigest()==before
        results.append(dict(case=name,rc=rc,output_unchanged=True))
    check('exact valid frame with short output',wire,4294967294)
    check('short workspace',wire,4294967294,2047)
    for n in (0,7,15,399):check('truncated header '+str(n),wire[:n],4294967295)
    for at,value,name in ((0,0,'bad magic'),(8,47,'previous role count'),(8,49,'extra role count')):
        frame=bytearray(wire);struct.pack_into('<Q',frame,at,value);check(name,bytes(frame),4294967295)
    check('missing final byte',wire[:-1],4294967295);check('unexpected trailing byte',wire+b'\0',4294967295)
    for i,role in enumerate(spec.ROLES):
        for size in (0,4194305):
            frame=bytearray(wire);struct.pack_into('<Q',frame,16+8*i,size)
            check(role+' length '+str(size),bytes(frame),4294967295)
    starts={};at=16+8*len(parts)
    for role,part in zip(spec.ROLES,parts):starts[role]=at;at+=len(part)
    holes=[]
    for off,_ in spec.owner.provider.RELOCATIONS:holes.append(('provider_capsule',off))
    for offsets in spec.owner.sidecar.OUTER_HOLES.values():
        holes.extend(('sidecar_capsule',off)for off in offsets)
    holes.extend(('sidecar_capsule',off)for off,_ in spec.base.sidecar.RELOCATIONS)
    temp=spec.owner.sidecar_tempdir_offset(parts[spec.ROLES.index('sidecar_capsule')])
    holes.extend(('sidecar_capsule',temp+off)for off,_ in spec.owner.tempdir.RELOCATIONS)
    for role,unit in (('global_capsule',spec.global_capsule),('frontend_capsule',spec.frontend),('runtime_borrow',spec.borrow),('background_bind_capsule',spec.bg_capsule)):
        offsets={off for group in unit.FIXED_HOLES.values()for off in group}|{off for off,_ in getattr(unit,'DYNAMIC_RELOCATIONS',())}
        holes.extend((role,off)for off in sorted(offsets))
    assert len(holes)==len(set(holes))
    for role,off in holes:
        frame=bytearray(wire);site=starts[role]+off;assert frame[site:site+4]==bytes(4);frame[site]=1
        check('unresolved '+role+' at '+str(off),bytes(frame),4294967295)
    for at in (881,temp+458):
        frame=bytearray(wire);struct.pack_into('<I',frame,starts['sidecar_capsule']+at,4294967295)
        check('bounded sidecar target '+str(at),bytes(frame),4294967295)
    result=dict(schema='hia.BG.Runtime48.packer-controls.v1',passed=True,groups=len(results),controls=results,
        every_actual_fixed_import_checked=len(holes),independent_object_bytes_equal=True,original_budgets_unchanged=True,
        root=build['root'],packer=build['packer'],qualifier=pin(Path(__file__).read_bytes()),whole_background_closed=False)
    (args.output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    print('ACTUAL_RUNTIME48_NATIVE_PACKER_CONTROLS_PASS',len(results),len(holes),flush=True)
if __name__=='__main__':main()
