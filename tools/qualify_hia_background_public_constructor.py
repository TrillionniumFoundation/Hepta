"""Native same-arena BackgroundOptimizer ordered public constructor qualification."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,os,struct,subprocess
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import qualify_hia_background_public_paths as paths
from tools.qualify_hia_generation_lease_owner_provider import Provider,ObjectImage,pin,libc,get
from tools.qualify_hia_multiversion_components import Image

ROOT=Path(__file__).resolve().parents[1]
EXTRA_PACKS=('background_optimizer_verify_program','background_optimizer_value_transport',
             'background_optimizer_value_freeze','multiversion_prepare_process')
EXTRA_BARE=('background_optimizer_value_structure','background_optimizer_json_capture',
            'background_optimizer_freeze','sha256_stream','background_optimizer_verify_raw')
ZERO=(0,0,0)
def put(buf,at,*values):struct.pack_into('<'+'Q'*len(values),buf,at,*values)
def ptr(entry):return C.cast(entry,C.c_void_p).value
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def names():
    return list(dict.fromkeys([n for name in paths.SINGLE+EXTRA_PACKS for n in(name,name+'_packer')]
        +[n for name,roles in paths.PAIRS.items()for n in(*roles,name+'_packer')]
        +list(paths.BARE)+[paths.CHECKS]+list(EXTRA_BARE)))
def build(compiler,out):
    assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=paths.COMPILER_SHA)
    captured={name:(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()for name in names()}
    flats={};rows=[]
    for name,source in captured.items():
        blobs=[]
        for _ in range(2):
            result=subprocess.run([str(compiler),'compile'],input=source,capture_output=True,timeout=30)
            assert result.returncode==0 and not result.stderr,(name,result.stderr.decode(errors='replace'))
            blobs.append(result.stdout)
        assert blobs[0]==blobs[1]
        flats[name]=blobs[0];(out/(name+'.flat')).write_bytes(blobs[0])
        rows.append(dict(source_path='examples/hia_bootstrap/'+name+'.hepta',source=pin(source),flat=pin(blobs[0]),double_compile_identical=True))
        print('PUBLIC_CONSTRUCTOR_NATIVE_COMPILE',name,len(blobs[0]),flush=True)
    products={}
    for name in paths.SINGLE+tuple(paths.PAIRS)+EXTRA_PACKS:
        spec=importlib.import_module('tools.generate_hia_'+name+'_packer')
        roles=(name,paths.CHECKS)if name=='background_optimizer_constructor_binding'else paths.PAIRS.get(name,(name,))
        parts=[flats[x]for x in roles]
        if name in paths.PAIRS:
            magic=b'HIANPP01'if name=='native_path_value'else b'HIANXP01'
            wire=magic+struct.pack('<4Q',2,*map(len,parts),0)+b''.join(parts)
        else:
            wire=struct.pack('<'+'Q'*(2+len(parts)),spec.MAGIC,len(parts),*map(len,parts))+b''.join(parts)
        native=q.old.run_packer(flats[name+'_packer'],wire);assert native==spec.reference_object(parts)
        (out/(name+'.o')).write_bytes(native)
        products[name]=dict(object=pin(native),independent_native_pack_comparison=True)
        print('PUBLIC_CONSTRUCTOR_NATIVE_PACK',name,len(native),flush=True)
    assert all((ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()==source for name,source in captured.items())
    result=dict(compiler=pin(compiler.read_bytes()),modules=rows,products=products,
                native_construction=True,whole_public_background_closed=False)
    save(out/'build.json',result);return result

def make(v,value):
    if type(value)is list:return v.lst([make(v,x)for x in value])
    if type(value)is dict:
        cap=v.keep(v.raw(4))
        for key,item in value.items():v.raw(10,a=cap,b=make(v,key),c=make(v,item))
        return cap
    return v.scalar(value)

class Constructor:
    def __init__(self,owner,provider,build_dir,normalizer_fd):
        self.owner=owner;self.provider=provider;self.images={}
        imports={name:C.cast(getattr(libc,name),C.c_void_p).value for name in('malloc','free')}
        for name in paths.SINGLE+tuple(paths.PAIRS)+EXTRA_PACKS:
            self.images[name]=ObjectImage((build_dir/(name+'.o')).read_bytes(),imports)
        for name in paths.BARE+EXTRA_BARE:
            self.images[name]=Image(build_dir/(name+'.flat'))
        self.entry=self.images['background_optimizer_public_constructor'].entry
        threshold=(ROOT/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes()
        self.threshold=C.create_string_buffer(threshold,len(threshold))
        self.fd=normalizer_fd
    def ep(self,name):return ptr(self.images[name].entry)
    def context(self):
        w=C.create_string_buffer(294912)
        fields={0:int.from_bytes(b'HIABPCC1','little'),8:get(self.owner.context,40),
          16:C.addressof(self.owner.context)+512,24:256,
          32:self.ep('background_optimizer_constructor_options'),40:self.ep('background_optimizer_bridge_paths'),
          48:self.ep('background_optimizer_constructor_binding'),56:self.ep('native_path_value'),
          64:self.ep('native_path_resolve'),72:self.ep('ndu_rank_native_owner_error'),80:self.ep('native_path_string_codec'),
          88:self.ep('background_optimizer_verify_program'),96:get(self.provider.context,104),
          104:get(self.provider.context,112),112:256,120:ptr(self.provider.entry),
          128:C.addressof(self.provider.context),136:768,144:self.ep('background_optimizer_json_capture'),
          152:self.ep('sha256_stream'),160:self.fd,168:C.addressof(self.threshold),176:len(self.threshold),
          184:self.ep('background_optimizer_value_transport'),192:self.ep('background_optimizer_freeze'),
          200:self.ep('background_optimizer_value_structure'),208:self.ep('background_optimizer_value_freeze'),
          216:self.ep('multiversion_prepare_process'),224:self.ep('background_optimizer_verify_raw'),232:4300,240:os.getpid(),
          264:self.ep('native_posix_path_factory')}
        for at,value in fields.items():put(w,at,value)
        return w
    def call(self,caps,context=None,op=0):
        context=context if context is not None else self.context()
        packet=bytearray(192);packet[:8]=b'HIABPCQ1';put(packet,8,op)
        if op==0:
            assert len(caps)==7
            for i,cap in enumerate(caps):put(packet,24+i*24,*cap)
        source=C.create_string_buffer(bytes(packet));out=C.create_string_buffer(524288)
        rc=self.entry(source,len(packet),out,len(out),context,len(context))
        assert rc==0 and out.raw[:8]==b'HIABPCR1',(rc,out.raw[:256].hex())
        assert source.raw==bytes(packet)+b'\0'
        self.last_output=out.raw;self.last_context=context.raw
        if get(out,8)>2:
            print('CONSTRUCTOR_DIAGNOSTIC',json.dumps(dict(status=get(out,8),detail=get(out,248),state=[get(out,i)for i in range(256,400,8)],child=[get(out,262144+i)for i in range(0,256,8)],binding=[get(context,270336+i)for i in range(192,256,8)])),flush=True)
        return out.raw[:256],context
    def payload(self,cap):
        raw=bytearray(128);raw[:8]=b'HIABPY01';put(raw,8,6);put(raw,24,*cap)
        source=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(512)
        from tools.qualify_hia_generation_lease_owner_provider import ENTRY
        entry=ENTRY(get(self.provider.context,104))
        rc=entry(source,128,out,512,get(self.provider.context,112),256)
        assert rc==0 and out.raw[:8]==b'HIABPYR1'and get(out,8)==0
        return C.string_at(get(out,64),get(out,40))

def path_values(v,root):
    n=get(v.raw(7,a=root),48);out=v.raw(23,a=root,arg1=n,on=max(16384,8192+n*64))
    expected=v.builtin(18);result={}
    for i in range(n):
        key=v.keep(out,8192+i*64+16);value=v.keep(out,8192+i*64+40)
        actual=v.keep(v.raw(36,a=value));assert v.same(actual,expected)
        descriptor=v.raw(26,a=value);assert get(descriptor,8200)==14
        children=[v.keep(descriptor,8224+j*24)for j in range(3)]
        assert get(v.raw(7,a=children[1]),16)==5
        raw=v.python_value(children[1]);assert len(raw)==1 and type(raw[0])is str
        result[v.python_value(key)]=raw[0]
        for cap in children+[key,value,actual]:v.drop(cap)
    v.drop(expected);return result

def decode(ctor,v,reply):
    status=get(reply,8)
    assert get(reply,240)==0,('pending constructor custody',reply.hex())
    if status==0:
        return dict(status='ok',max_pending=get(reply,144),timeout_ms=get(reply,152),
                    bridge_timeout=struct.unpack_from('<d',reply,160)[0]if get(reply,168)==0 else get(reply,160))
    if get(reply,16):
        descriptor=json.loads(ctor.payload(struct.unpack_from('<3Q',reply,16)))
        if get(reply,48)==1:
            assert descriptor['status']=='error'and descriptor['ok']is False
            diagnostics=descriptor['diagnostics'];assert len(diagnostics)==1
            # This segment returns the native normalizer diagnostic wire. The
            # final public exception owner consumes its explicitly tagged domain.
            return dict(status='error',descriptor=dict(class_name='HIAProgramRejected',message=diagnostics[0]['message']),
                        format=1,native_normalizer_wire=descriptor)
        return dict(status='error',descriptor=descriptor,format=get(reply,48))
    if get(reply,72):
        error=v.keep(reply,72);descriptor=v.python_value(error);v.drop(error)
        return dict(status='error',descriptor=descriptor,format=get(reply,48),value_consumed=True)
    raise AssertionError(('constructor failure without descriptor',status,reply.hex()))

def run(a,build_dir,out):
    owner,c,v=resources.setup(a.owner)
    provider=Provider(owner,(a.provider/'build/provider.o').read_bytes())
    files=[]
    for key in('normalizer','proof','builder'):
        raw=getattr(a,key).read_bytes();files.append((q.old.sealed(raw),raw))
    before=set(os.listdir('/proc/self/fd'));parent=out/'native-runtime';parent.mkdir(mode=0o700)
    raw=q.old.create(c,files,parent);runtime=resources.capture(owner,v,1,raw)
    ctor=Constructor(owner,provider,build_dir,files[0][0])
    baseline=q.old.scalar_program(None)
    bridge={'binary':str(a.builder),'build_receipt':str(ROOT/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    cases=[];reference_runtime=None
    try:
        inputs=[runtime,make(v,baseline),make(v,'calculate'),make(v,bridge),make(v,8),make(v,2000),make(v,10.0)]
        reply,context=ctor.call(inputs);decoded=decode(ctor,v,reply)
        assert decoded==dict(status='ok',max_pending=8,timeout_ms=2000,bridge_timeout=10.0),decoded
        baseline_out=struct.unpack_from('<3Q',reply,16);runtime_out=struct.unpack_from('<3Q',reply,48)
        function_out=v.keep(reply,72);bridge_out=v.keep(reply,96);runtime_value_out=v.keep(reply,120)
        assert v.same(runtime_value_out,runtime)and v.same(function_out,inputs[2])
        expected_paths={key:str(Path(value).resolve())for key,value in bridge.items()}
        assert path_values(v,bridge_out)==expected_paths
        from hepta.hia_program import verify_program
        verified=verify_program(baseline)
        assert reply[176:208].hex()==verified.sha256 and reply[208:240].hex()==verified.input_sha256
        assert ctor.payload(baseline_out)[:8]==b'HIAVCF01'
        provider.drop(runtime_out);provider.drop_payload({'cap':baseline_out})
        for cap in(function_out,bridge_out,runtime_value_out):v.drop(cap)
        cleaned,_=ctor.call([],context,op=1);assert get(cleaned,8)==get(cleaned,240)==0
        cases.append(dict(case='actual-full-ordered-native-construction',**decoded,actual_same_runtime_value=True,
                          actual_path_class=18,baseline_hashes_match_original=True,cleanup_completed=True))
        save(out/'cases.json',cases);print('PUBLIC_CONSTRUCTOR_GATE',cases[-1]['case'],flush=True)
        # The pre-verification rejection matrix compares the unchanged original
        # Python method. Later native-only success is independently checked above.
        from hepta.hia_background_optimizer import BackgroundOptimizer
        original=BackgroundOptimizer.__init__
        variants=[
          ('runtime-first',None,None,None,{},False,False,float('nan')),
          ('max-pending-exact-bool','runtime',None,None,{},True,0,0),
          ('max-pending-low','runtime',None,None,{},0,0,0),
          ('timeout-exact-bool','runtime',None,None,{},8,True,0),
          ('timeout-high','runtime',None,None,{},8,5001,0),
          ('bridge-timeout-nan','runtime',None,None,{},8,2000,float('nan')),
          ('bridge-timeout-zero','runtime',None,None,{},8,2000,0),
          ('bridge-keys','runtime',None,None,{},8,2000,10.0),
          ('bridge-extra-key','runtime',None,None,dict(bridge,extra='x'),8,2000,10.0)]
        from hepta.hia_multiversion import ScalarMultiversionRuntime
        reference_parent=out/'original-runtime';reference_parent.mkdir(mode=0o700)
        reference_runtime=ScalarMultiversionRuntime(baseline,reference_parent)
        reference_bg=BackgroundOptimizer(reference_runtime,baseline,function='calculate',bridge=bridge)
        assert not reference_bg.snapshot()['closed']
        reference_bg.shutdown()
        assert reference_bg.snapshot()['closed']and not reference_runtime.snapshot()['closed']
        cases[0]['original_runtime_and_background_actually_constructed']=True
        cases[0]['original_shutdown_preserves_runtime']=True
        variants.extend([
          ('function-exact-int','runtime',baseline,1,bridge,8,2000,10.0),
          ('function-nonpublic','runtime',baseline,'missing',bridge,8,2000,10.0),
          ('invalid-program-before-function','runtime',None,1,bridge,8,2000,10.0),
          ('different-immutable-baseline','runtime',q.old.scalar_program('bit.xor'),'calculate',bridge,8,2000,10.0)])
        for name,rt,program,function,paths_arg,maxp,timeout,btime in variants:
            oracle_runtime=reference_runtime if rt=='runtime'else None
            try:
                original(object.__new__(BackgroundOptimizer),oracle_runtime,program,function=function,bridge=paths_arg,
                         max_pending=maxp,timeout_ms=timeout,bridge_timeout_s=btime)
                raise AssertionError('reference rejection was not reached')
            except BaseException as exc:
                reference=dict(class_name=type(exc).__name__,message=str(exc))
            native_caps=[runtime if rt=='runtime'else make(v,None),make(v,program),make(v,function),make(v,paths_arg),
                         make(v,maxp),make(v,timeout),make(v,btime)]
            reply,context=ctor.call(native_caps);decoded=decode(ctor,v,reply)
            assert decoded['status']=='error',decoded
            descriptor=decoded['descriptor']
            assert descriptor.get('class',descriptor.get('type',descriptor.get('class_name')))==reference['class_name']and descriptor['message']==reference['message'],(name,descriptor,reference)
            if get(reply,16):provider.drop_payload({'cap':struct.unpack_from('<3Q',reply,16)})
            cleaned,_=ctor.call([],context,op=1);assert get(cleaned,8)==get(cleaned,240)==0
            cases.append(dict(case=name,oracle=reference,native_descriptor=descriptor,wire_format=decoded['format'],paired=True,
                              native_normalizer_wire=decoded.get('native_normalizer_wire')))
            save(out/'cases.json',cases);print('PUBLIC_CONSTRUCTOR_GATE',name,flush=True)
        # Exercise real selection and closed-runtime rejection after all
        # immutable-baseline controls. Neither side receives a fabricated snapshot.
        from tools.qualify_hia_generation_lease_owner_provider import Token
        imports={name:C.cast(getattr(libc,name),C.c_void_p).value for name in('malloc','free')}
        token=Token(ObjectImage((a.provider/'build/token.o').read_bytes(),imports))
        candidate=q.old.scalar_program('bit.xor')
        reference_runtime.publish(candidate)
        published=provider.q(2,raw,token=token.address,gen=b'0',epoch=b'0',raw=q.old.rawdoc(candidate))
        assert get(published['header'],64)==1 and get(token.context,64)==2
        provider.drop_payload(published);token.q(10)
        for name in('untracked-current-native-source','actual-closed-runtime'):
            if name=='actual-closed-runtime':
                reference_runtime.close()
                c.q(4,raw,q.old.public_request(8),child=0)
            try:
                original(object.__new__(BackgroundOptimizer),reference_runtime,baseline,function='calculate',bridge=bridge)
                raise AssertionError('reference rejection was not reached')
            except BaseException as exc:
                reference=dict(class_name=type(exc).__name__,message=str(exc))
            reply,context=ctor.call(inputs);decoded=decode(ctor,v,reply)
            assert decoded['status']=='error',decoded
            descriptor=decoded['descriptor']
            assert descriptor.get('class',descriptor.get('type',descriptor.get('class_name')))==reference['class_name']and descriptor['message']==reference['message'],(name,descriptor,reference)
            if get(reply,16):provider.drop_payload({'cap':struct.unpack_from('<3Q',reply,16)})
            cleaned,_=ctor.call([],context,op=1);assert get(cleaned,8)==get(cleaned,240)==0
            cases.append(dict(case=name,oracle=reference,native_descriptor=descriptor,paired=True,actual_runtime_operation=True))
            save(out/'cases.json',cases);print('PUBLIC_CONSTRUCTOR_GATE',name,flush=True)
        reference_runtime.close()
        assert not list(reference_parent.iterdir())
        for cap in list(v.held):
            if cap!=runtime:v.drop(cap)
        v.drop(runtime);c.q(3,raw)
        assert not list(parent.iterdir())
        provider.close()
        closed=owner.call(3);assert closed['status']==0 and closed['state']==3
        assert set(os.listdir('/proc/self/fd'))==before
        return cases
    finally:
        if reference_runtime is not None:reference_runtime.close()
        for fd,_ in files:os.close(fd)

def main():
    ap=argparse.ArgumentParser()
    for key in('compiler','owner','provider','normalizer','proof','builder','output'):ap.add_argument('--'+key,type=Path,required=True)
    ap.add_argument('--reuse-build',action='store_true');a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=a.reuse_build);bd=a.output/'build';bd.mkdir(exist_ok=a.reuse_build)
    built=json.loads((bd/'build.json').read_bytes())if a.reuse_build else build(a.compiler,bd)
    for row in built['modules']:assert pin((ROOT/row['source_path']).read_bytes())==row['source']
    provider_report=json.loads((a.provider/'report.json').read_bytes())
    assert provider_report['component_qualified']and provider_report['owner']==pin(a.owner.read_bytes())
    assert pin((a.provider/'build/provider.o').read_bytes())==provider_report['build']['products']['provider']
    cases=run(a,bd,a.output)
    import z3
    oracle_sources=['hepta/hia_background_optimizer.py','hepta/hia_multiversion.py',
                    'hepta/hia_program.py','hepta/hia_translation_validation.py']
    source_files=['tools/generate_hia_background_optimizer_public_constructor.py',
        'examples/hia_bootstrap/background_optimizer_public_constructor.hepta',
        'tools/generate_hia_background_optimizer_constructor_binding.py',
        'examples/hia_bootstrap/background_optimizer_constructor_binding.hepta',
        'tools/hia_background_provider_retirement_source.py',
        'tools/probe_hia_background_constructor_binding.py',
        'tools/qualify_hia_background_public_constructor.py']
    report=dict(schema='hepta.hia.background-public-constructor-qualification.v1',
        component_qualified=True,whole_public_background_closed=False,trusted_enclosing_bootstrap_qualified=False,
        actual_background_resource_and_worker_qualified=False,
        scope='ordered constructor segment returning retained native Runtime/Value/payload capabilities',
        owner=pin(a.owner.read_bytes()),value=provider_report['value'],provider=provider_report['build']['products']['provider'],
        compiler=pin(a.compiler.read_bytes()),build=built,cases=cases,paired=len(cases)-1,
        successful_native_constructor=True,python_product_callbacks=False,
        source_files=[dict(path=name,**pin((ROOT/name).read_bytes()))for name in source_files],
        original_oracle=dict(actual_runtime_constructed=True,actual_background_thread_started_and_joined=True,
            actual_publication_and_close=True,z3_version=z3.get_version_string(),
            source_files=[dict(path=name,**pin((ROOT/name).read_bytes()))for name in oracle_sources]),
        native_tools={name:dict(path=str(getattr(a,name)),**pin(getattr(a,name).read_bytes()))for name in('normalizer','proof','builder')},
        error_wire_domains={'1':'native normalizer diagnostic mapped to original HIAProgramRejected by the QA decoder',
                            '2':'constructor rejection descriptor','4':'retained Value diagnostic descriptor',
                            '5':'retained Value exception data'},
        public_exception_object_integration_qualified=False)
    save(a.output/'report.json',report);print('PUBLIC_CONSTRUCTOR_PASS',len(cases),flush=True)
if __name__=='__main__':main()
