"""Actual class-graph transitions with an independent interpreter class oracle.

Author mode is development evidence only. The native route requires the new
complete value image, not a Python implementation of the class transitions.
"""
from pathlib import Path
import argparse, ctypes as C, hashlib, importlib, json, mmap, os, platform, random, struct, sys, traceback

HERE = Path(__file__).resolve().parents[1]
FALLBACK = HERE.parents[1]/'root_native_recovery'
PATHROOT = HERE.parent/'native_path_value_source'
sys.path[:0] = [str(HERE), str(FALLBACK)]
import tools
tools.__path__ = [str(HERE/'tools'), str(PATHROOT/'tools'), str(HERE.parent/'native_value_extension/candidate'), str(FALLBACK/'tools')]
from tools.qualify_hia_result_value_dict_iterator import AuthorEngine as OldAuthor, NativeEngine, Values as OldValues, word, put, wire, ZERO
from tools import generate_hia_native_class_mro as mro_author


def frame(op, **kw):
    value = bytearray(wire(op, **kw))
    if 32 <= op <= 39:
        value[:8] = b'HIABVQ03'
    return bytes(value)


class AuthorEngine(OldAuthor):
    def __init__(self, unused=None):
        common = importlib.import_module('tools.generate_hia_result_value_common')
        core = importlib.import_module('tools.generate_hia_result_value_core')
        iterator = importlib.import_module('tools.generate_hia_result_value_dict_iterator')
        owner = importlib.import_module('tools.generate_hia_result_value_owner')
        classes = importlib.import_module('tools.generate_hia_result_value_classes')
        self.ns = dict(common.C)
        self.ns.update(length=len, byte=lambda b,i:b[i], store=self.store)
        source = core.SOURCE+'\n'+iterator.SOURCE+'\n'+owner.SOURCE+'\n'+classes.SOURCE+'\n'+classes.catalog_source()+'\n'+common.SOURCE
        exec(compile('from __future__ import annotations\n'+source, '<exact-class-value-authors>', 'exec'), self.ns)
        # HIA u64 multiplication wraps at every step. Python's unbounded
        # temporary integer otherwise makes a long, valid string quadratic.
        # The low 64 bits are identical; this is interpreter arithmetic, not
        # a replacement for any class/GC/namespace policy.
        def bytes_hash(buffer,at,count):
            result=14695981039346656037
            for i in range(count):result=((result^buffer[at+i])*1099511628211)&((1<<64)-1)
            return result
        self.ns['bytes_hash']=bytes_hash
        self.mro = dict(length=len, word_load=word, word_store=put)
        exec('from __future__ import annotations\n'+mro_author.source_program(), self.mro)
        self.w=bytearray(65536);self.calls=0;self.growth_failures=0
        self.allocation_fault=None;self.allocation_attempts=0
        self.real_allocate=self.ns['allocate'];self.ns['allocate']=self.allocate
        out=bytearray(16384)
        put(out, common.C['G_PHASE'], 90)
        put(out, common.C['G_TAG0'], 18446744073709551557)
        put(out, common.C['G_INPUT'], 4300)
        assert self.ns['result_value_core'](b'',out,self.w)==0

    def call(self, request, on=16384):
        if word(request,8)<32:
            return super().call(request,on)
        self.calls+=1;out=bytearray(on);n=self.ns
        # The real public owner performs this check before touching the arena.
        if request[:8]!=b'HIABVQ03' or len(request)!=128 or word(request,16) or word(request,120) or not n['class_request_valid'](request):
            return 0xfffffffd,bytes(out)
        for _ in range(256):
            action=n['result_value_classes'](request,out,self.w)
            if action==0:
                n['finish'](request,out,word(out,n['P_ERROR']))
                return 0,bytes(out)
            if action==10:
                continue
            if action==1:
                if self.allocation_fault is not None:
                    self.growth_failures+=1;put(out,n['G_ALLOC_FAILED'],1);continue
                old=len(self.w);wanted=word(out,n['G_WANT'])
                assert wanted>old and wanted&(wanted-1)==0
                self.w.extend(bytes(wanted-old));n['arena_extend'](self.w,old);put(out,n['G_ALLOC_FAILED'],0);continue
            if action==5:
                at=word(out,n['G_RANDOM'])+word(out,n['G_RUSED']);count=word(out,n['G_RN'])-word(out,n['G_RUSED'])
                self.w[at:at+count]=os.urandom(count);put(out,n['G_FEEDBACK'],count);continue
            if action==4 and word(out,n['P_ROLE'])==10:
                args=struct.unpack_from('<6Q',out,n['P_ARG'])
                a,an,b,bn,c,cn=args
                view=memoryview(self.w)
                result=self.mro['native_class_mro'](view[a:a+an],view[b:b+bn],view[c:c+cn])
                del view
                put(out,n['G_FEEDBACK'],result);continue
            raise AssertionError(('unhandled class action',word(request,8),action,word(out,n['G_PHASE'])))
        raise AssertionError(('unbounded class continuation',word(request,8),word(out,n['G_PHASE'])))

    def finish(self):
        assert word(self.w,88)==0,('live caps',word(self.w,88))
        self.ns['collect'](self.w)
        expected=3+word(self.w,152)*3
        assert word(self.w,104)==expected,('unreachable graph survived',word(self.w,104),expected)
        # Complete catalog graph remains actual and internally consistent.
        for i in range(word(self.w,152)):
            obj=word(self.w,160+i*8);assert word(self.w,obj+8)==10
            data=word(self.w,obj+24);assert word(self.w,data+40)==i+1


class MechanicalEngine:
    """Real machine capsule/syscalls/locks, with explicitly interpreted HIA roles."""
    scope='actual-x86-effects-and-exact-development-authors'

    def __init__(self):
        from tools import generate_hia_result_value_class_packer as pack
        author=AuthorEngine()
        self.ns=author.ns;self.mro=author.mro;self.errors=[];self.calls=0
        self.context=C.create_string_buffer(256)
        sig=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
        def view(ptr,n):return memoryview((C.c_ubyte*n).from_address(ptr or 0)).cast('B')
        def dispatch(name):
            def invoke(s,sn,o,on,w,wn):
                try:
                    if name=='class_mro':return self.mro['native_class_mro'](view(s,sn),view(o,on),view(w,wn))
                    if name=='format':
                        value=struct.unpack('<d',C.string_at(s,sn))[0];raw=repr(value).encode()
                        assert len(raw)<=on;C.memmove(o,raw,len(raw));return len(raw)
                    return self.ns['result_value_'+name](view(s,sn),view(o,on),view(w,wn))
                except BaseException:
                    self.errors.append(traceback.format_exc());return 0xfffffffd
            return sig(invoke)
        self.functions=[dispatch(role)for role in pack.ROLES]
        flats=[b'\x48\xb8'+struct.pack('<Q',C.cast(f,C.c_void_p).value)+b'\xff\xe0' for f in self.functions]
        image=pack.reference_flat(flats)
        self.mapping=mmap.mmap(-1,len(image),prot=7);self.mapping.write(image)
        self.buffer=(C.c_ubyte*len(image)).from_buffer(self.mapping)
        self.callable=sig(C.addressof(self.buffer))
        rc,out=self.call(frame(0,arg0=4300));assert rc==0 and word(out,8)==0

    def call(self,request,on=16384):
        self.calls+=1;s=C.create_string_buffer(request);out=C.create_string_buffer(b'\xa5'*(on+32))
        rc=int(self.callable(s,len(request),out,on,self.context,len(self.context)))
        assert not self.errors,self.errors
        assert s.raw==request+b'\0'and out.raw[on:]==b'\xa5'*32+b'\0'
        return rc,out.raw[:on]

    def finish(self):
        rc,out=self.call(frame(30));assert rc==0
        assert (word(out,8),word(out,80),word(out,88),word(out,96))==(0,0,1,1),out[:128].hex()
        assert word(self.context.raw,16)==0 and word(self.context.raw,40)==0


class Values(OldValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        rc,out=self.engine.call(frame(op,**kw),on=on)
        assert rc==0 and out[:8]==(b'HIABVR02' if 29<=op<=31 else b'HIABVR01'),(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want)
        return out

    def builtin(self,index):return self.keep(self.raw(32,arg0=index))
    def lst(self,items):
        cap=self.keep(self.raw(3))
        for item in items:self.raw(16,a=cap,b=item)
        return cap
    def copy_caps(self,cap):
        n=word(self.raw(17,a=cap),48)
        out=self.raw(23,a=cap,arg1=n,on=max(16384,8192+n*64))
        return [self.keep(out,8192+i*64+40) for i in range(n)]
    def same(self,a,b):return bool(word(self.raw(8,a=a,b=b),48))
    def cls(self,name,bases,namespace=None,want=0):
        a=self.scalar(name);b=self.lst(bases);c=self.dictionary([]) if namespace is None else self.keep(self.raw(5,a=namespace))
        out=self.raw(33,a=a,b=b,c=c,want=want)
        for item in (a,b,c):self.drop(item)
        return self.keep(out) if want==0 else None
    def instance(self,cls,base=ZERO,env=None):
        e=self.scalar(None) if env is None else self.keep(self.raw(5,a=env))
        result=self.keep(self.raw(35,a=cls,b=e,c=base));self.drop(e);return result
    def isinst(self,obj,cls):return bool(word(self.raw(37,a=obj,b=cls),48))
    def attr(self,cls,name,value=None,delete=False):
        k=self.scalar(name)
        self.raw(34,a=cls,b=k,c=ZERO if delete else value,arg0=int(delete));self.drop(k)
    def lookup(self,obj,name,want=0):
        k=self.scalar(name);out=self.raw(39,a=obj,b=k,want=want);self.drop(k)
        return self.keep(out) if want==0 else None


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image');ap.add_argument('--mechanical',action='store_true');ap.add_argument('--output',required=True);args=ap.parse_args()
    if args.image and args.mechanical:ap.error('native and author/mechanical modes are separate')
    output=Path(args.output);output.mkdir(parents=True,exist_ok=False)
    factory=lambda:NativeEngine(args.image) if args.image else MechanicalEngine() if args.mechanical else AuthorEngine()
    rows=[]
    from pathlib import PurePath,PurePosixPath,PureWindowsPath,Path as ActualPath,PosixPath,WindowsPath
    original=[object,type,int,bool,float,str,bytes,list,dict,type(None),type(iter({})),type(iter({}.items())),type(iter({}.values())),PurePath,PurePosixPath,PureWindowsPath,ActualPath,PosixPath,WindowsPath]
    v=Values(factory());known={original[0]:v.builtin(1)}
    for index,cls in enumerate(original,1):
        cap=v.builtin(index);known[cls]=cap
        name=v.keep(v.raw(38,a=cap,arg0=0));assert v.python(name)==cls.__name__;v.drop(name)
        mro=v.keep(v.raw(38,a=cap,arg0=2));items=v.copy_caps(mro)
        assert len(items)==len(cls.__mro__),(cls,len(items),cls.__mro__)
        for item,base in zip(items,cls.__mro__):
            # Every actual base is already constructed by catalog dependency order.
            expected=known.get(base)
            if expected is None:expected=v.builtin(original.index(base)+1);known[base]=expected
            assert v.same(item,expected),(cls,base)
            v.drop(item)
        v.drop(mro);rows.append(dict(case='catalog-'+cls.__name__))
    # Same name and namespace never grant the fixed class identity.
    fake=v.cls('ScalarMultiversionRuntime',[]);runtime=v.builtin(20)
    fakeobj=v.instance(fake);realobj=v.instance(runtime)
    assert not v.isinst(fakeobj,runtime) and v.isinst(realobj,runtime)
    child=v.cls('DerivedRuntime',[runtime]);childobj=v.instance(child);assert v.isinst(childobj,runtime)
    rows.append(dict(case='actual-runtime-class-and-subclass-not-name'))
    # Build randomized real C3 hierarchies, retaining the actual native class edges.
    pool=[object];native={object:known[object]};rng=random.Random(77051)
    for i in range(250):
        bases=tuple(rng.choices(pool,k=rng.randrange(1,min(5,len(pool))+1)))
        try:cls=type('K'+str(i),bases,{})
        except TypeError as error:
            status=16 if str(error).startswith('duplicate base class ') else 17
            v.cls('K'+str(i),[native[b] for b in bases],want=status)
            rows.append(dict(case='c3-refusal',i=i,status=status));continue
        cap=v.cls(cls.__name__,[native[b] for b in bases]);native[cls]=cap;pool.append(cls)
        described=v.keep(v.raw(38,a=cap,arg0=2));members=v.copy_caps(described)
        assert len(members)==len(cls.__mro__)
        for member,want in zip(members,cls.__mro__):assert v.same(member,native[want]);v.drop(member)
        v.drop(described);obj=v.instance(cap)
        for base in rng.sample(pool,min(5,len(pool))):assert v.isinst(obj,native[base])==isinstance(cls(),base)
        v.drop(obj);rows.append(dict(case='c3-instance',i=i,bases=len(bases),mro=len(cls.__mro__)))
    # Class namespaces are copied and later mutations are read through the MRO.
    source=v.dictionary([('x',1)]);a=v.cls('A',[],source);b=v.cls('B',[a]);obj=v.instance(b)
    class OA:x=1
    class OB(OA):pass
    original_obj=OB()
    v.set(source,'x',2)
    picked=v.lookup(obj,'x');assert v.python(picked)==original_obj.x==1;v.drop(picked)
    for number in (7,11,99):
        value=v.scalar(number);v.attr(a,'x',value);v.drop(value);OA.x=number
        picked=v.lookup(obj,'x');assert v.python(picked)==original_obj.x;v.drop(picked)
    value=v.scalar(23);v.attr(b,'x',value);v.drop(value);OB.x=23
    picked=v.lookup(obj,'x');assert v.python(picked)==original_obj.x;v.drop(picked)
    v.attr(b,'x',delete=True);del OB.x
    picked=v.lookup(obj,'x');assert v.python(picked)==original_obj.x;v.drop(picked)
    newname=v.scalar('Renamed');v.attr(a,'__name__',newname);v.drop(newname);OA.__name__='Renamed'
    named=v.keep(v.raw(38,a=a));assert v.python(named)==OA.__name__;v.drop(named)
    rows.append(dict(case='namespace-copy-live-lookup-rename-and-fallback'))
    # Actual PurePath family identity is distinct from a spelling impostor;
    # construction captures a private list copy and retains its actual strings.
    posix=v.builtin(18);pure=v.builtin(14);segments=[v.scalar('/a'),v.scalar('../b')];raw=v.lst(segments)
    path=v.instance(posix,raw)
    assert v.isinst(path,pure) and v.isinst(path,posix)
    for cap in segments+[raw]:v.drop(cap)
    same_name=v.cls('PosixPath',[]);other=v.instance(same_name)
    assert not v.isinst(other,pure)
    rows.append(dict(case='purepath-family-real-identity-and-captured-parts'))
    # A class namespace may point back to an instance/class; shared collector
    # traces the class edge, namespace, bases and self-containing MRO.
    cycle=v.cls('Cycle',[]);cycleobj=v.instance(cycle);v.attr(cycle,'instance',cycleobj)
    v.drop(cycleobj);v.drop(cycle)
    v.finish();rows.append(dict(case='complete-cycle-collection'))
    # Growth failures preserve retry state, original graph and capability roots.
    faults=[]
    if not args.image and not args.mechanical:
        for after in range(1,13):
            engine=AuthorEngine();values=Values(engine);root=values.builtin(1)
            name=values.scalar('Fail');bases=values.lst([root]);namespace=values.dictionary([('x',3)])
            before=word(engine.w,88);engine.allocation_fault=engine.allocation_attempts+after
            rc,out=engine.call(frame(33,a=name,b=bases,c=namespace))
            status=word(out,8);assert status in (0,5),(after,status)
            if status==0:values.keep(out)
            else:assert word(engine.w,88)==before
            engine.allocation_fault=None;values.finish()
            faults.append(dict(after=after,status=status,growth_failures=engine.growth_failures))
    # The new owner request grammar does not make Q03 an alias of Q01/Q02.
    checks=[]
    if not args.image:
        e=AuthorEngine();n=e.ns
        for magic,ops in ((b'HIABVQ01',range(25,45)),(b'HIABVQ02',list(range(25))+list(range(32,45))),(b'HIABVQ03',list(range(32))+list(range(40,45)))):
            for op in ops:
                raw=bytearray(wire(op));raw[:8]=magic;o=bytearray(8192);w=bytearray(256)
                assert n['owner_begin'](bytes(raw),o,w)==0xfffffffd,(magic,op)
                checks.append((magic.decode(),op))
    report=dict(schema='hia.native-class-value.development.v1',native_qualified=bool(args.image),scope='actual-native-image'if args.image else'actual-x86-effects-and-exact-development-authors'if args.mechanical else'development-exact-authors',oracle=platform.python_version(),groups=rows,allocation_faults=faults,private_controls=len(checks),full_public_class_factory_closed=False,callable_custody_closed=False,purepath_methods_closed=False)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(groups=len(rows),allocation_faults=len(faults),private_controls=len(checks),native_qualified=bool(args.image))))


if __name__=='__main__':main()
