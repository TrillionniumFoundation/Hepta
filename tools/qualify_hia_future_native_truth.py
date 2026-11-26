"""Actual same-arena Future truth dispatch against the original CPython object model."""
from pathlib import Path
import argparse,ctypes as C,fcntl,hashlib,json,os,platform,struct,subprocess,sys,time,traceback
import tools
ROOT=Path(__file__).resolve().parents[1]
SHARED=Path('/home/qian-qi/hia-native-followthrough-20261126-620a')
if str(SHARED/'tools')not in tools.__path__:tools.__path__.append(str(SHARED/'tools'))
from tools import generate_hia_generation_future_sidecar_fusion_packer as fusion
from tools import generate_hia_background_optimizer_future_public_truth_packer as capsule
from tools import qualify_hia_generation_future_sidecar_fusion as previous
from tools import qualify_hia_generation_lease_owner as ownerqa
from tools.qualify_hia_result_value_invocations import Bound,Engine,Values,echo_field,sweep,word
from tools.qualify_hia_future_retirement import Public
from tools.qualify_hia_future_value_kinds import construct,CASES,original_call,identity
from hepta.hia_background_optimizer import _OptimizationFuture,PublicationCancellation

COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
NAMES=('background_optimizer_future_public_owner','background_optimizer_future_public_cleanup',
       'background_optimizer_future_public_truth','background_optimizer_future_public_truth_packer')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
def build(compiler,base,output,value_build=None):
    output.mkdir(parents=True,exist_ok=False)
    old=json.loads((base/'build.json').read_text());assert old['passed']and old['logical_roles']==64
    managed=old['schema']=='hia.generation-future-managed-fusion.build.v1'
    if managed:
        from tools import generate_hia_generation_future_managed_fusion_packer as fusion_spec
        pack_name='generation_future_managed_fusion_packer'
    else:
        assert old['schema']=='hia.generation-future-sidecar-fusion.build.v1',old['schema']
        fusion_spec=fusion;pack_name='generation_future_sidecar_fusion_packer'
    seed=compiler.read_bytes();assert pin(seed)==dict(bytes=813129,sha256=COMPILER_SHA)
    candidate=None
    if value_build is not None:
        value_build=value_build.resolve();candidate=json.loads(value_build.read_text())
        assert candidate['source_frozen'] and candidate['value_protocol']=='HIABVP08' and len(candidate['value_roles'])==15
        assert candidate['compiler']['sha256']==COMPILER_SHA and all(x['two_compile_byteequal']for x in candidate['roles'])
    captured={str(Path(__file__).resolve()):Path(__file__).read_bytes()}
    for mod in tuple(sys.modules.values()):
        path=Path(getattr(mod,'__file__','')or'')
        if path.is_file()and path.name.startswith('generate_hia_'):captured[str(path.resolve())]=path.read_bytes()
    bridge=ROOT/'tools/hia_background_optimizer_future_public_truth_bridge.S';captured[str(bridge)]=bridge.read_bytes()
    if candidate is not None:
        captured[str(value_build)]=value_build.read_bytes()
        for name,expected in candidate['source_files'].items():
            path=ROOT/name;raw=path.read_bytes();assert pin(raw)==expected,(name,pin(raw),expected)
            captured[str(path)]=raw
    record=dict(schema='hia.future.truth.native-build.v1',passed=False,compiler=pin(seed),
      frozen_parent=dict(path=str(base/'build.json'),**pin((base/'build.json').read_bytes())),
      native_double_compile=True,modules=[],source_files={},products={},whole_public_future_qualified=False)
    fd=os.memfd_create('hia-future-truth-compiler',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        n=0
        while n<len(seed):
            amount=os.write(fd,seed[n:]);assert amount>0;n+=amount
        os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15
        flats={}
        for name in NAMES:
            path=ROOT/'examples/hia_bootstrap'/ (name+'.hepta');source=path.read_bytes();captured[str(path)]=source;rounds=[]
            for i in range(2):
                p=subprocess.run(['/proc/self/fd/'+str(fd),'compile'],input=source,capture_output=True,
                    pass_fds=(fd,),env={'PATH':''},timeout=30)
                (output/(name+'.'+str(i)+'.stderr')).write_bytes(p.stderr)
                if p.returncode:(output/(name+'.'+str(i)+'.stdout')).write_bytes(p.stdout)
                assert p.returncode==0 and p.stdout and not p.stderr,(name,i,p.returncode,p.stderr)
                rounds.append(p.stdout)
            assert rounds[0]==rounds[1]and len(rounds[0])<=4194304
            flats[name]=rounds[0];(output/(name+'.flat')).write_bytes(rounds[0])
            record['modules'].append(dict(source_path=str(path),source=pin(source),flat=pin(rounds[0]),two_compile_byteequal=True))
            print('FUTURE_TRUTH_NATIVE_COMPILE',name,len(rounds[0]),flush=True)
        children=[flats[NAMES[1]],flats[NAMES[2]]]
        wire=struct.pack('<4Q',capsule.MAGIC,2,*map(len,children))+b''.join(children)
        combined=ownerqa.old.run_packer(flats[NAMES[3]],wire)
        assert combined==capsule.reference_flat(children)and len(combined)<=4194304
        parts=[]
        for i,row in enumerate(old['role_inputs']):
            body=Path(row['path']).read_bytes();assert pin(body)=={k:row[k]for k in ('bytes','sha256')}
            if i==2 and candidate is not None:
                entry=candidate['products']['value-component.flat'];body=Path(entry['path']).read_bytes()
                assert pin(body)=={k:entry[k]for k in ('bytes','sha256')}
            if i==56:body=flats[NAMES[0]]
            if i==63:body=combined
            parts.append(body)
        native_pack=(base/(pack_name+'.flat')).read_bytes()
        assert pin(native_pack)==next(x['flat']for x in old['compile']if x.get('source_path',x.get('source','')).endswith(pack_name+'.hepta'))
        frame=struct.pack('<66Q',fusion_spec.MAGIC,64,*map(len,parts))+b''.join(parts)
        obj=ownerqa.old.run_packer(native_pack,frame);assert obj==fusion_spec.reference_object(parts)
        linker=Path(old['linker']['path']).read_bytes();assert pin(linker)=={k:old['linker'][k]for k in('bytes','sha256')}
        linked=ownerqa.old.run_packer(linker,obj)
        assert obj.count(parts[2])==linked.count(parts[2])==1
        sh=struct.unpack_from('<Q',obj,40)[0];text=struct.unpack_from('<Q',obj,sh+64+32)[0];assert text<=16777216
        products={'future-truth-capsule.flat':combined,'generation-future-sidecar-fusion.o':obj,
          'hia-generation-future-sidecar-fusion.so':linked,'hia-generation-lease-values.core.bin':parts[2]}
        for name in('code-owner.flat','tempdir-component.flat'):products[name]=(base/name).read_bytes()
        inputs=output/'role-inputs';inputs.mkdir()
        record['role_inputs']=[]
        for i,(role,body)in enumerate(zip(fusion_spec.ROLES,parts)):
            path=inputs/(str(i).zfill(2)+'-'+role+'.flat');path.write_bytes(body)
            record['role_inputs'].append(dict(role=role,path=str(path),**pin(body)))
        for name,raw in products.items():(output/name).write_bytes(raw);record['products'][name]=pin(raw)
        for name,raw in captured.items():
            assert Path(name).read_bytes()==raw,name
            record['source_files'][name]=pin(raw)
        record.update(passed=True,logical_roles=64,physical_truth_subroles=2,source_before_after_identical=True,
          native_pack=True,independent_object_byteequal=True,single_value_body=True,text_bytes=text,
          original_role_limit_bytes=4194304,original_text_limit_bytes=16777216,
          inherited_code_binding_profile='mask190'if managed else 'mask62',managed_future_resource_provider_qualified=False,
          actual_native_future_binding_inherited=managed,fusion_protocol=fusion_spec.MAGIC,
          private_classified_invocation=97,value_candidate_construct=None if candidate is None else dict(path=str(value_build),**pin(value_build.read_bytes())))
        print('FUTURE_TRUTH_NATIVE_BUILD_PASS',record['products']['hia-generation-future-sidecar-fusion.so'],text,flush=True)
        return output/'hia-generation-future-sidecar-fusion.so'
    except BaseException as error:
        record['error']=repr(error);record['traceback']=traceback.format_exc();raise
    finally:
        os.close(fd);save(output/'build.json',record)

class Fixture:
    def __init__(self,path):
        self.bound=Bound(path);r=self.bound.call(0);assert r['status']==0 and r['state']==2
        self.v=Values(Engine(self.bound))
        class Image:
            def __init__(image):
                image.lib=self.bound.owner.lib;image.entry=image.lib.hia_background_optimizer_future_public
                image.entry.argtypes=[C.c_void_p,C.c_uint64]*3;image.entry.restype=C.c_uint32
        self.future=Public(self.v,Image())
        assert word(self.future.ctx.raw,72)==self.bound.value
        assert word(self.future.ctx.raw,112)==C.addressof(self.bound.owner.context)+512 and word(self.future.ctx.raw,120)==256
        self.factory=self.future.factory()
    def finish(self):
        self.future.finish();sweep(self.v,self.bound);self.bound.close()

class ManagedFixture:
    def __init__(self,path):
        from tools.qualify_hia_generation_future_managed_binding import Fixture as Actual
        self.actual=Actual(path);self.bound=self.actual.bound;self.v=self.actual.v
        outer=self
        class PublicFacade:
            def __getattr__(self,name):return getattr(outer.actual.public,name)
            def make(self,factory):
                resource,weak=outer.actual.resource(factory)
                strong,borrowed=outer.actual.acquire(resource)
                assert outer.v.isinst(resource,outer.v.builtin(37))
                return borrowed
        self.future=PublicFacade();self.factory=self.actual.public.factory()
    def finish(self):self.actual.finish()

def error(v,reply):
    assert word(reply,16)==200,reply[:128].hex()
    cap=v.keep(reply,72);kind=word(v.raw(7,a=cap),16)
    if kind==6:
        values={}
        for key in ('class','message'):
            k=v.scalar(key);field=v.keep(v.raw(9,a=cap,b=k));values[key]=v.python(field);v.drop(field);v.drop(k)
    else:
        assert kind==8 and v.isinst(cap,v.builtin(21))
        namespace,args,name=v.parts(cap);arguments=v.python_value(args)
        assert type(arguments)is tuple
        values=dict(class_=v.python(name),message=''if not arguments else str(arguments[0])if len(arguments)==1 else str(arguments))
        values['class']=values.pop('class_')
        for item in (namespace,args,name):v.drop(item)
    v.drop(cap);return values

def defaults(path,output,fixture=Fixture):
    rows=[]
    extra=[('IntAlias',3,int,x)for x in(0,1,-1,10**100)]
    extra += [('FloatAlias',5,float,x)for x in(0.0,-0.0,0.5,float('nan'))]
    extra += [('ListAlias',8,list,x)for x in([], [0])]
    extra += [('DictAlias',9,dict,x)for x in({}, {'x':0})]
    extra += [('TupleAlias',28,tuple,x)for x in((), (0,))]
    for number,(name,index,typ,original)in enumerate(extra):
        f=fixture(path);v=f.v;p=f.future;item=p.make(f.factory)
        cls=v.cls(name,[v.builtin(index)]);pycls=type(name,(typ,),{});py=pycls(original)
        if typ is list:base=v.lst([v.scalar(x)for x in original])
        elif typ is dict:base=v.dictionary(list(original.items()))
        elif typ is tuple:base=v.tuple([v.scalar(x)for x in original])
        else:base=v.scalar(original)
        native=v.inherited(cls,base);empty=v.scalar(None);oracle=_OptimizationFuture(PublicationCancellation());oracle.set_exception(py)
        p.call(23,*item,value=native,kind=1)
        actual_id=word(p.call(21,*item),96)
        want=original_call(oracle,'set_result',None)
        want['error']['message']=want['error']['message'].replace(hex(id(oracle)),hex(actual_id))
        got=p.call(22,*item,value=empty,kind=1,status=want['status'])
        assert error(v,got)==want['error'],(name,original,want,got[:128].hex())
        f.finish();rows.append(dict(case='actual-default-builtin-subclass',name=name,ordinal=number,python_truth=bool(py),passed=True))
        print('FUTURE_TRUTH_DEFAULT_PASS',name,repr(original),flush=True)
    save(output/'default-report.json',dict(passed=True,oracle=platform.python_version(),groups=rows))
    return rows

def custom(path,output,fixture=Fixture):
    rows=[]
    scenarios=[]
    for method,values in [('__bool__',[False,True,0,1,'x',None]),('__len__',[0,3,-1,2**63,-(2**63)-1,1.5,None,True])]:
        for result in values:scenarios.append((method,result,None,None))
    for result in(0,3,-1,2**63,1.5,None,True):scenarios.append(('__len__',result,'index',None))
    for method in('__bool__','__len__'):
        for exception in(ValueError('truth failure'),BaseException('base truth failure')):
            scenarios.append((method,None,'raise',exception))
        scenarios.append((method,None,'missing-callable',None))
    scenarios += [('__bool__',None,'long-name',None),('__len__',None,'long-name',None)]
    for ordinal,(method,result,mode,raised)in enumerate(scenarios):
        f=fixture(path);v=f.v;p=f.future;item=p.make(f.factory)
        name='TruthObject';cls=v.cls(name,[])
        if mode=='raise':
            native_result=v.exception(v.builtin(24 if isinstance(raised,ValueError)else 21),v.tuple([v.scalar(str(raised))]))
            fn=v.function(echo_field(1,2),env=native_result)
            def py_method(self,_error=raised):raise _error
        elif mode=='missing-callable':
            fn=v.scalar(None);py_method=None
        elif mode=='index':
            indexcls=v.cls('IndexReturn',[]);returncap=v.scalar(result)
            indexfn=v.function(echo_field(1),env=returncap);v.attr(indexcls,'__index__',indexfn)
            indexobject=v.instance(indexcls)
            native_result=indexobject;fn=v.function(echo_field(1),env=indexobject)
            pyindex=type('IndexReturn',(),{'__index__':lambda self,value=result:value})()
            py_method=lambda self,value=pyindex:value
        elif mode=='long-name':
            long_name='Return_'+('é'*10000);longcls=v.cls(long_name,[]);native_result=v.instance(longcls)
            fn=v.function(echo_field(1),env=native_result)
            pyreturn=type(long_name,(),{})()
            py_method=lambda self,value=pyreturn:value
        else:
            native_result=v.scalar(result);fn=v.function(echo_field(1),env=native_result)
            py_method=lambda self,value=result:value
        v.attr(cls,method,fn);native=v.instance(cls)
        pycls=type(name,(),{method:py_method});py=pycls()
        oracle=_OptimizationFuture(PublicationCancellation());oracle.set_exception(py)
        empty=v.scalar(None);p.call(23,*item,value=native,kind=1)
        actual_id=word(p.call(21,*item),96)
        want=original_call(oracle,'set_result',None)
        want['error']['message']=want['error']['message'].replace(hex(id(oracle)),hex(actual_id))
        got=p.call(22,*item,value=empty,kind=1,status=want['status'])
        observed=error(v,got);assert observed==want['error'],(ordinal,method,repr(result),mode,observed,want['error'])
        f.finish();rows.append(dict(case='actual-special-method-native-dispatch',ordinal=ordinal,method=method,
          return_repr=repr(result),mode=mode,error=observed,status=want['status'],passed=True))
        print('FUTURE_TRUTH_CUSTOM_PASS',ordinal,method,repr(result),mode,flush=True)
    save(output/'custom-report.json',dict(passed=True,oracle=platform.python_version(),groups=rows))
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--compiler',type=Path);p.add_argument('--base',type=Path)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--built',type=Path);p.add_argument('--build-only',action='store_true');p.add_argument('--value-build',type=Path);p.add_argument('--managed',action='store_true')
    a=p.parse_args();assert platform.python_version()=='3.14.4'
    if a.built:a.output.mkdir(parents=True,exist_ok=False);path=a.built
    else:path=build(a.compiler,a.base,a.output,a.value_build)
    if a.build_only:return
    report=dict(schema='hia.future.truth.actual-behavior.v1',passed=False,whole_public_future_qualified=False,
      managed_future_provider_qualified=False,actual_native_managed_binding=a.managed,product=pin(path.read_bytes()))
    try:
        factory=ManagedFixture if a.managed else Fixture
        report['defaults']=defaults(path,a.output,factory);report['custom']=custom(path,a.output,factory)
        report['passed']=True
    except BaseException as exc:
        report['error']=repr(exc);report['traceback']=traceback.format_exc();raise
    finally:save(a.output/'report.json',report)
if __name__=='__main__':main()
