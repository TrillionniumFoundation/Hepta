"""Construct the fixed 64-role sidecar/Future image with one Value body.

Existing role receipts are verified; changed Future policy is recompiled twice.
No constructor, callable body, continuation, or finalizer is implemented here.
"""
from pathlib import Path
import argparse,ctypes as C,fcntl,hashlib,importlib,json,mmap,os,struct,subprocess,sys,time,traceback
import tools
ROOT=Path(__file__).resolve().parents[1]
SHARED=Path('/home/qian-qi/hia-native-followthrough-20261126-620a')
if str(SHARED/'tools')not in tools.__path__:tools.__path__.append(str(SHARED/'tools'))
from tools import generate_hia_generation_future_sidecar_fusion_packer as spec
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_publication_cancellation import address

COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
FUTURE_NAMES=('background_optimizer_future_public_owner','background_optimizer_future_public_carrier',
 'background_optimizer_future_public_timeout','background_optimizer_future_public_log',
 'multiversion_background_future_cell','multiversion_future',None,'background_optimizer_future_public_cleanup')

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,d):p.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
def evidence(p):return dict(path=str(p),**pin(p.read_bytes()))

def controls(packer,wire,obj,parts):
    native=Image(packer);invalid=[('short-header',wire[:15]),('truncated-role',wire[:-1]),('trailing-data',wire+b'x')]
    for name,at,value in [('magic',0,0),('count-low',8,63),('count-high',8,65)]:
        r=bytearray(wire);struct.pack_into('<Q',r,at,value);invalid.append((name,bytes(r)))
    for i,role in enumerate(spec.ROLES):
        for name,value in [('empty',0),('oversize',4194305)]:
            r=bytearray(wire);struct.pack_into('<Q',r,16+i*8,value);invalid.append((role+'-'+name,bytes(r)))
    pi=spec.ROLES.index('provider_capsule');si=spec.ROLES.index('sidecar_capsule')
    offsets=[16+8*len(parts)+sum(map(len,parts[:i]))for i in range(len(parts))]
    holes=[('provider',offsets[pi]+off)for off,_ in spec.owner.provider.RELOCATIONS]
    holes += [('sidecar',offsets[si]+off)for group in spec.owner.sidecar.OUTER_HOLES.values()for off in group]
    temp=spec.owner.sidecar_tempdir_offset(parts[si])
    holes += [('tempdir',offsets[si]+temp+off)for off,_ in spec.owner.tempdir.RELOCATIONS]
    for label,at in holes:
        r=bytearray(wire);struct.pack_into('<I',r,at,1);invalid.append((label+'-fixed-hole-'+str(at),bytes(r)))
    rows=[]
    with mmap.mmap(-1,32<<20)as output,mmap.mmap(-1,1<<20)as work:
        for name,raw in invalid:
            source=C.create_string_buffer(raw);output[:128]=b'\xa5'*128
            rc=native.entry(source,len(raw),address(output),len(output),address(work),len(work))
            assert rc==0xffffffff and output[:128]==b'\xa5'*128,(name,rc)
            assert source.raw==raw+b'\0';rows.append(name)
        source=C.create_string_buffer(wire)
        for name,on,wn in [('short-output',len(obj)-1,len(work)),('short-workspace',len(output),2047)]:
            output[:128]=b'\xa5'*128
            rc=native.entry(source,len(wire),address(output),on,address(work),wn)
            assert rc==0xfffffffe and output[:128]==b'\xa5'*128,(name,rc)
            rows.append(name)
    return rows

def build(compiler,owner_build,future_build,value_qualification,output):
    output.mkdir(parents=True,exist_ok=False)
    seed=compiler.read_bytes();assert pin(seed)==dict(bytes=813129,sha256=COMPILER_SHA)
    raw_receipt=(owner_build/'frozen_role_inputs.json').read_bytes()
    owner_rows=json.loads(raw_receipt);assert len(owner_rows)==56
    future=json.loads((future_build/'build.json').read_bytes())
    vq=json.loads(value_qualification.read_bytes())
    assert vq['component_qualified']and vq['native_callable_and_boundmethod_qualified']
    assert vq['value_protocol']=='HIABVP08'and vq['original_six_campaigns_qualified']
    for name,expected in vq['construction']['source_files'].items():assert pin((ROOT/name).read_bytes())==expected,name
    expected_value={k:vq['construction']['products']['value-component.flat'][k]for k in('bytes','sha256')}
    inputs=output/'role-inputs';inputs.mkdir();parts=[];rows=[]
    captured={str(Path(__file__).resolve()):Path(__file__).read_bytes()}
    for name,module in tuple(sys.modules.items()):
        path=Path(getattr(module,'__file__','')or'')
        if name.startswith('tools.generate_')and path.is_file():captured[str(path.resolve())]=path.read_bytes()

    record=dict(schema='hia.generation-future-sidecar-fusion.build.v1',passed=False,
      compiler=pin(seed),owner_manifest=evidence(owner_build/'frozen_role_inputs.json'),
      future_checkpoint=evidence(future_build/'build.json'),value_qualification=evidence(value_qualification),
      compile=[],products={},source_files={},whole_public_runtime_qualified=False,
      managed_future_resource_provider_qualified=False)
    fd=os.memfd_create('hia-fusion64-compiler',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        done=0
        while done<len(seed):n=os.write(fd,seed[done:]);assert n>0;done+=n
        os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15
        for i,row in enumerate(owner_rows):
            assert row['index']==i
            raw=Path(row['path']).read_bytes();assert pin(raw)=={k:row[k]for k in('bytes','sha256')}
            if i==2:assert pin(raw)==expected_value
            target=inputs/(str(i).zfill(2)+'-'+spec.ROLES[i]+'.flat');target.write_bytes(raw)
            rows.append(dict(role=spec.ROLES[i],path=str(target),**pin(raw)));parts.append(raw)
        def compile_one(name):
            rel='examples/hia_bootstrap/'+name+'.hepta';source=(ROOT/rel).read_bytes();captured[rel]=source;outputs=[]
            for i in range(2):
                p=subprocess.run(['/proc/self/fd/'+str(fd),'compile'],input=source,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=30)
                (output/(name+'.'+str(i)+'.stderr')).write_bytes(p.stderr)
                if p.returncode:(output/(name+'.'+str(i)+'.stdout')).write_bytes(p.stdout)
                assert p.returncode==0 and p.stdout and not p.stderr,(name,i,p.returncode,p.stderr)
                outputs.append(p.stdout)
            assert outputs[0]==outputs[1]and len(outputs[0])<=4194304
            target=output/(name+'.flat');target.write_bytes(outputs[0])
            record['compile'].append(dict(source_path=rel,source=pin(source),flat=pin(outputs[0]),two_compile_byteequal=True))
            print('FUSION64_NATIVE_COMPILE',name,len(outputs[0]),flush=True)
            return outputs[0]
        for i,name in enumerate(FUTURE_NAMES,56):
            if name is None:
                p=future_build/'hia-future-notify.core.bin';raw=p.read_bytes()
                assert pin(raw)==future['products'][p.name]
            else:raw=compile_one(name)
            target=inputs/(str(i).zfill(2)+'-'+spec.ROLES[i]+'.flat');target.write_bytes(raw)
            rows.append(dict(role=spec.ROLES[i],path=str(target),**pin(raw)));parts.append(raw)
        assert len(parts)==64 and len(set(spec.ROLES))==64
        packer=compile_one('generation_future_sidecar_fusion_packer')
        wire=struct.pack('<66Q',spec.MAGIC,64,*map(len,parts))+b''.join(parts)
        expected=spec.reference_object(parts)
        obj=q.old.run_packer(packer,wire);assert obj==expected
        linker_path=Path('/home/qian-qi/.local/state/hia-native-followthrough-20261126-620a-generation-lease/owner-bound-value13-v2/multiversion_runtime_linker.flat')
        linker=linker_path.read_bytes();assert pin(linker)==dict(bytes=126116,sha256='f3c4657b0c22dc44388cf1fcc932c26c1e5f9fd741d77b2356faad363d75d8fb')
        linked=q.old.run_packer(linker,obj)
        value=parts[spec.ROLES.index('values')]
        assert obj.count(value)==linked.count(value)==1
        sh=struct.unpack_from('<Q',obj,40)[0]
        textsize=struct.unpack_from('<Q',obj,sh+64+32)[0]
        assert textsize<=16777216
        positions={};unique={}
        for role,body in zip(spec.ROLES,parts):
            hs=spec.HOLES[role]
            if hs:
                actual={64+h+4+struct.unpack_from('<i',obj,64+h)[0]for h in hs}
                assert len(actual)==1;at=actual.pop()
            else:
                sym=struct.unpack_from('<Q',obj,sh+3*64+24)[0]
                at=64+struct.unpack_from('<Q',obj,sym+4*24+8)[0]
                assert role=='sidecar_capsule'
            if body in unique:assert at==unique[body]
            else:unique[body]=at
            positions[role]=at-64
        outputs={'generation-future-sidecar-fusion.o':obj,'hia-generation-future-sidecar-fusion.so':linked,
                 'hia-generation-lease-values.core.bin':value}
        for name in('code-owner.flat','tempdir-component.flat'):outputs[name]=(owner_build/name).read_bytes()
        for name,raw in outputs.items():(output/name).write_bytes(raw);record['products'][name]=pin(raw)
        record['packer_controls']=controls(output/'generation_future_sidecar_fusion_packer.flat',wire,obj,parts)
        for name,raw in captured.items():
            path=Path(name)if name.startswith('/')else ROOT/name
            assert path.read_bytes()==raw
            record['source_files'][name]=pin(raw)
        record.update(passed=True,native_double_compile=True,native_pack=True,native_link=True,
          independent_object_byteequality=True,single_value_body=True,logical_roles=64,
          unique_bodies=len(unique),text_bytes=textsize,original_text_limit_bytes=16777216,
          original_role_limit_bytes=4194304,role_inputs=rows,role_offsets=positions,
          linker=evidence(linker_path),immutable_code_bytes_deduplicated=sum(map(len,parts))-sum(map(len,unique)))
        print('FUSION64_NATIVE_BUILD_PASS',json.dumps(record['products']),textsize,flush=True)
        return output/'hia-generation-future-sidecar-fusion.so'
    except BaseException as error:
        record['error']=repr(error);record['traceback']=traceback.format_exc();raise
    finally:
        os.close(fd);save(output/'build.json',record)

def basic(path,output):
    from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,echo_field,sweep,word
    from tools.qualify_hia_future_retirement import Public
    b=Bound(path);r=b.call(0);assert r['status']==0 and r['state']==2 and word(b.owner.context,680)==62
    v=Values(Engine(b))
    class FutureImage:
        def __init__(self):
            self.lib=b.owner.lib;self.entry=self.lib.hia_background_optimizer_future_public
            self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
    future=Public(v,FutureImage())
    assert word(future.ctx.raw,72)==b.value
    assert word(future.ctx.raw,112)==C.addressof(b.owner.context)+512 and word(future.ctx.raw,120)==256
    f=future.factory();item=future.make(f)
    fn=v.function(echo_field(3),name='actual code through Future')
    future.call(22,*item,value=fn,kind=1);v.drop(fn)
    got=v.keep(future.call(10,*item),72)
    result=v.invoke(got,v.tuple([v.scalar('shared'),v.scalar(73)]))
    assert v.python_value(result)==('shared',73)
    future.finish()
    sweep(v,b);b.close()
    row=dict(passed=True,three_actual_exports=True,single_value_entry=True,single_native_arena=True,
      actual_code_native_initialized=True,function_survives_external_drop_in_future=True,
      actual_native_invocation_after_future_result=True,actual_native_retirement=True,
      managed_future_resource_provider_qualified=False,whole_public_runtime_qualified=False)
    save(output/'binding.json',row);print('FUSION64_NATIVE_CODE_FUTURE_BINDING_PASS',flush=True)

def original_cases(path,output,tool_paths):
    from tools import qualify_hia_generation_lease_owner_resources as resources
    files=[];rows=[];entries=[]
    class FusionImage:
        def __init__(self,unused):
            self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_optimizer_future_public
            self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
    OriginalPublic=resources.Public
    class BoundPublic(OriginalPublic):
        def __init__(self,value,image):
            super().__init__(value,image);owner=value.engine.owner
            assert q.get(self.ctx,72)==q.get(owner.context,40)
            assert q.get(self.ctx,112)==C.addressof(owner.context)+512 and q.get(self.ctx,120)==256
            entries.append(dict(runtime_value_entry=q.get(owner.context,40),future_value_entry=q.get(self.ctx,72),
                                same_code_entry=True,same_native_arena=True))
    old_image=resources.Image;resources.Image=FusionImage;resources.Public=BoundPublic
    report=dict(schema='hia.generation-future-sidecar-fusion.original-cases.v1',passed=False,
      product=pin(path.read_bytes()),cases=rows,actual_entry_bindings=entries,
      whole_public_runtime_qualified=False,managed_future_resource_provider_qualified=False)
    try:
        for tool in tool_paths:
            raw=tool.read_bytes();files.append((q.old.sealed(raw),raw))
        cases=[('resource-lease-first',lambda p:resources.resource_case(path,files,p,False)),
          ('resource-runtime-first',lambda p:resources.resource_case(path,files,p,True)),
          ('resource-binding',lambda p:resources.binding_cases(path,files,p)),
          ('resource-concurrent',lambda p:resources.concurrent_last_refs(path,files,p)),
          ('pending-runtime',lambda p:resources.pending_case(path,files,p,False)),
          ('pending-lease',lambda p:resources.pending_case(path,files,p,True)),
          ('future-runtime-first',lambda p:resources.future_case(path,path,files,p,False)),
          ('future-lease-first',lambda p:resources.future_case(path,path,files,p,True)),
          ('lifecycle-lease-first',lambda p:q.lifecycle_case(path,files,p,False)),
          ('lifecycle-runtime-first',lambda p:q.lifecycle_case(path,files,p,True)),
          ('active-destroy',lambda p:q.active_destroy(path,files,p)),
          ('typed-calls',lambda p:q.typed_calls(path,files,p))]
        for name,fn in cases:
            parent=output/name;parent.mkdir(mode=0o700);start=time.monotonic()
            result=fn(parent);row=dict(name=name,seconds=time.monotonic()-start,result=result)
            rows.append(row);save(output/(name+'.json'),row);save(output/'original-report.json',report)
            print('FUSION64_ORIGINAL_CASE_PASS',name,flush=True)
        for name,fn in [('os-failure-retention',lambda:q.os_failure_retention(path,output)),
                         ('tool-bank-custody',lambda:q.tool_bank_custody(path,files))]:
            start=time.monotonic();result=fn();row=dict(name=name,seconds=time.monotonic()-start,result=result)
            rows.append(row);save(output/(name+'.json'),row);save(output/'original-report.json',report)
            print('FUSION64_ORIGINAL_CASE_PASS',name,flush=True)
        assert len(entries)==2 and len(rows)==14
        report.update(passed=True,original_resource_and_owner_assertions_preserved=True,
                      single_actual_value_entry_qualified=True,shared_native_value_arena_qualified=True)
        print('FUSION64_ORIGINAL_14_PASS',flush=True)
    except BaseException as error:
        report['error']=repr(error);report['traceback']=traceback.format_exc();raise
    finally:
        resources.Image=old_image;resources.Public=OriginalPublic
        save(output/'original-report.json',report)
        for fd,_ in files:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    for name in('compiler','owner-build','future-build','value-qualification','output','built-dir'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--build-only',action='store_true');a=p.parse_args()
    assert a.output
    if a.built_dir:
        path=a.built_dir/'hia-generation-future-sidecar-fusion.so';a.output.mkdir(parents=True,exist_ok=False)
    else:
        assert a.compiler and a.owner_build and a.future_build and a.value_qualification
        path=build(a.compiler,a.owner_build,a.future_build,a.value_qualification,a.output)
    if not a.build_only:
        basic(path,a.output)
        custody=Path('/home/qian-qi/hia-followthrough-evidence-20261126-620a/shared-custody')
        original_cases(path,a.output,[custody/'normalizer-84619bd.bin',custody/'proof-3fc158.bin',custody/'builder-539ce9.bin'])

if __name__=='__main__':main()
