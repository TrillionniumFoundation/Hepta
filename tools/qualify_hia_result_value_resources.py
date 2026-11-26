"""Actual native extended-builtin construction and resource protocol boundaries.

This gate does not simulate a finalizer or claim resource ownership integration.
The sole owner gate supplies real carrier references and a fixed native finalizer.
"""
from pathlib import Path
import argparse, hashlib, json, platform, struct
from tools.qualify_hia_result_value_records import Values as RecordValues, NativeEngine, frame as record_frame, abi_frame, word, ZERO

def frame(op, **kw):
    data=bytearray(record_frame(op,**kw))
    if 48<=op<=59:data[:8]=b'HIABVQ05'
    return bytes(data)

class Values(RecordValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        rc,out=self.engine.call(frame(op,**kw),on=on)
        assert rc==0 and out[:8]==(b'HIABVR02'if 29<=op<=31 else b'HIABVR01'),(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want,out[:128].hex())
        return out
    def builtin(self,index):
        return self.keep(self.raw(57,arg0=index))if index>=31 else super().builtin(index)
    def inherited(self,cls,base=ZERO,env=ZERO):
        return self.keep(self.raw(50,a=cls,b=env,c=base))
    def inherited_parts(self,cap):
        raw=self.raw(26,a=cap)
        return word(raw,8200),[self.keep(raw,8224+i*24)for i in range(3)]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
    assert platform.python_version()=='3.14.4'
    target=Path(args.output);target.mkdir(parents=True,exist_ok=False)
    v=Values(NativeEngine(args.image));rows=[]
    for index,name in ((31,'GenerationLease'),(32,'function'),(33,'method'),(34,'builtin_function_or_method'),(35,'BackgroundOptimizer')):
        cls=v.builtin(index);text=v.keep(v.raw(38,a=cls));assert v.python(text)==name
        v.raw(50,a=cls,want=18)
        if index in(32,33,34):v.cls('Impossible',[cls],want=18)
        v.drop(text);v.drop(cls)
        rows.append(dict(case='actual-canonical-class',id=index,name=name))
    scenarios=[
        ('ObjectAlias',1,object,None,0),
        ('IntAlias',3,int,-(10**160),2),
        ('FloatAlias',5,float,-0.125,3),
        ('StringAlias',6,str,'a\ud800\U0001f600',4),
        ('BytesAlias',7,bytes,b'\x00\xff',7),
        ('ListAlias',8,list,[4,'x'],5),
        ('DictAlias',9,dict,{'z':4,'a':2},6),
        ('TupleAlias',28,tuple,(4,'x'),11)]
    for name,index,original_type,original,kind in scenarios:
        builtin=v.builtin(index);cls=v.cls(name,[builtin])
        oracle_type=type(name,(original_type,),{})
        oracle=oracle_type()if original is None else oracle_type(original)
        if original is None:base=ZERO
        elif type(original)is list:base=v.lst([v.scalar(x)for x in original])
        elif type(original)is tuple:base=v.tuple([v.scalar(x)for x in original])
        elif type(original)is dict:base=v.dictionary(list(original.items()))
        else:base=v.scalar(original)
        obj=v.inherited(cls,base)
        assert word(v.raw(7,a=obj),16)==8
        actual_type=v.keep(v.raw(36,a=obj));assert v.same(actual_type,cls)
        assert v.isinst(obj,builtin)and isinstance(oracle,original_type)
        got_kind,parts=v.inherited_parts(obj)
        env,stored,namecap=parts
        assert got_kind==kind and v.python(env)is None and v.python(namecap)==name
        if original is not None:
            assert v.python_value(stored)==original
            assert v.same(stored,base)==(kind not in (5,6))
            if kind==5:
                v.raw(16,a=base,b=v.scalar(99));assert v.python_value(stored)==list(oracle)
            elif kind==6:
                v.set(base,'other',99);assert v.python_value(stored)==dict(oracle)
            if kind in (4,5,6,7,11):assert word(v.raw(17,a=obj),48)==len(oracle)
            if kind==5:
                v.raw(16,a=stored,b=v.scalar(8))
                assert word(v.raw(17,a=obj),48)==len(oracle)+1
            elif kind==6:
                v.set(stored,'new',8)
                assert word(v.raw(17,a=obj),48)==len(oracle)+1
        else:assert v.python(stored)is None
        # Canonical builtin objects cannot be fabricated as kind-8 subclasses.
        v.raw(50,a=builtin,c=base,want=18)
        alias=v.keep(v.raw(5,a=obj))
        for cap in (obj,cls,builtin,actual_type,*parts):
            v.drop(cap)
        if base!=ZERO:v.drop(base)
        _,survivors=v.inherited_parts(alias)
        assert v.python(survivors[2])==type(oracle).__name__
        for cap in survivors+[alias]:v.drop(cap)
        rows.append(dict(case='real-inherited-object-capture-and-strong-edges',name=name,base_kind=kind,mutable_base_copied=kind in(5,6)))
    function=v.scalar('f');value=v.scalar(7);wire=abi_frame([('f',('i64',),'i64')])
    listcls=v.cls('ActualListSubclass',[v.builtin(8)]);listbase=v.lst([value]);listobj=v.inherited(listcls,listbase)
    tuplecls=v.cls('ActualTupleSubclass',[v.builtin(28)]);tuplebase=v.tuple([value]);tupleobj=v.inherited(tuplecls,tuplebase)
    intcls=v.cls('ActualIntSubclass',[v.builtin(3)]);intobj=v.inherited(intcls,value)
    strcls=v.cls('ActualStringSubclass',[v.builtin(6)]);strobj=v.inherited(strcls,function)
    for cap in (listobj,tupleobj):v.raw(45,a=function,b=cap,tail=wire,want=21)
    v.raw(45,a=function,b=v.lst([intobj]),tail=wire,want=22)
    v.raw(45,a=strobj,b=listobj,tail=wire,want=20)
    rows.append(dict(case='typed-call-rejects-real-builtin-subclasses-in-original-order'))
    # A subclass participates in the same collector as its mutable environment.
    cycle=v.lst([]);cycobj=v.inherited(listcls,v.lst([]),cycle);v.raw(16,a=cycle,b=cycobj)
    for cap in list(v.held):v.drop(cap)
    stats=v.raw(51);assert (word(stats,48),word(stats,56),word(stats,64))==(0,0,1)
    rows.append(dict(case='real-subclass-environment-cycle-collection'))
    # Missing fixed finalizer custody rejects capture, with an explicit fact.
    raw=v.raw(48,arg0=1,tail=struct.pack('<3Q',1,2,3),want=6)
    assert (word(raw,80),word(raw,88),word(raw,96))==(0,1,0)
    assert raw[16:80]==bytes(64) and raw[104:128]==bytes(24)
    for op in (49,52,53,54,55,56):
        kw=dict(arg0=1)if op in(54,55)else{}
        v.raw(op,want=6,**kw)
    rows.append(dict(case='unbound-resource-capture-explicit-unconsumed-custody'))
    before=v.engine.context.raw;controls=[]
    for op in (58,59,60,(1<<64)-1):
        raw=bytearray(frame(51));struct.pack_into('<Q',raw,8,op);controls.append(bytes(raw))
    for at in (16,24,32,40,48,56,64,72,80,88,96,104,112,120):
        raw=bytearray(frame(51));struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
    for raw in controls:
        rc,out=v.engine.call(raw);assert rc==0xfffffffd and v.engine.context.raw==before
    rows.append(dict(case='internal-claim-ack-and-malformed-controls-rejected',controls=len(controls)))
    v.finish()
    assert word(v.engine.context.raw,120)==0
    report=dict(schema='hia.native-resource-values.primitives.v1',actual_native_image=True,image_sha256=hashlib.sha256(Path(args.image).read_bytes()).hexdigest(),oracle=platform.python_version(),groups=rows,primitive_qualified=True,resource_finalizer_integration_qualified=False,whole_public_runtime_qualified=False)
    (target/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows),controls=len(controls))))
if __name__=='__main__':main()
