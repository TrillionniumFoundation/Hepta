"""Real immutable HIAProgramLLVM records preserve all original dataclass fields."""
from pathlib import Path
import argparse,ctypes as C,dataclasses,hashlib,json,math,platform,struct
from hepta.hia_program_llvm import HIAProgramLLVM, HIAProgramLLVMRejected
from hepta.hia_static_budget import HIAStaticBudgetRejected
from tools.qualify_hia_result_value_resources import Values as PriorValues, NativeEngine, frame, word, ZERO
from tools.qualify_hia_result_value_verified_program import make_value,objects
from tools.qualify_hia_result_value_records import equivalent

FIELDS=('text','sha256','core_sha256','implementation_sha256','exports','profile','target','input_sha256','layout')
class Values(PriorValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        if op not in (62,63,99,100):return super().raw(op,want=want,on=on,**kw)
        wire=bytearray(frame(op,**kw));wire[:8]=b'HIABVQ05'
        rc,out=self.engine.call(bytes(wire),on=on)
        assert rc==0 and out[:8]==b'HIABVR01',(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want,out[:128].hex())
        return out
    def builtin(self,index):
        if index>=46:return self.keep(self.raw(99,arg0=index))
        return super().builtin(index)
    def record(self,fields,cls=ZERO):
        seq=self.lst(fields)
        result=self.keep(self.raw(100,a=seq,b=cls));self.drop(seq)
        return result
    def equal(self,left,right):return bool(word(self.raw(62,a=left,b=right),48))
    def hashed(self,cap,want=0):
        out=self.raw(63,a=cap,want=want)
        return struct.unpack('<q',out[48:56])[0]

def field_values(v,original):return [make_value(v,getattr(original,name))for name in FIELDS]
def run(image,output):
    assert platform.python_version()=='3.14.4'
    assert tuple(HIAProgramLLVM.__dataclass_fields__)==FIELDS and HIAProgramLLVM.__dataclass_params__.frozen
    output.mkdir(parents=True,exist_ok=False);v=Values(NativeEngine(image));rows=[]
    canonical=v.builtin(46);budgetclass=v.builtin(47)
    for cls,name in ((canonical,'HIAProgramLLVM'),(budgetclass,'HIAStaticBudgetRejected')):
        actualname=v.keep(v.raw(38,a=cls));assert v.python(actualname)==name;v.drop(actualname)
    repeated=v.builtin(46);assert v.same(canonical,repeated);v.drop(repeated)
    fakeclass=v.cls('HIAProgramLLVM',[]);fake=v.instance(fakeclass)
    assert not v.isinst(fake,canonical)
    v.drop(fake);v.drop(fakeclass)
    budgetbases=v.keep(v.raw(38,a=budgetclass,arg0=2))
    for index,baseid in enumerate((47,24,22,21,1)):
        ix=v.scalar(index);item=v.keep(v.raw(12,a=budgetbases,b=ix));base=v.builtin(baseid)
        assert v.same(item,base)
        for cap in(item,base,ix):v.drop(cap)
    v.drop(budgetbases)
    rows.append(dict(case='canonical-real-record-and-budget-error-class-identity'))

    normal=HIAProgramLLVM('define i64 @f() { ret i64 1 }','a'*64,'b'*64,'c'*64,('f',))
    nodes=field_values(v,normal);record=v.record(nodes)
    actualtype=v.keep(v.raw(36,a=record));assert v.same(actualtype,canonical)and v.isinst(record,canonical)
    assert word(v.raw(7,a=record),16)==12 and word(v.raw(7,a=record),48)==9
    for index,node in enumerate(nodes):
        actual=v.field(record,index);assert v.same(actual,node)and equivalent(v.python_value(actual),getattr(normal,FIELDS[index]));v.drop(actual)
    v.raw(43,a=record,arg0=9,want=4)
    for op,kw in ((16,dict(a=record,b=nodes[0])),(13,dict(a=record,b=v.scalar(0),c=nodes[0]))):
        v.raw(op,want=2,**kw)
        if op==13:v.drop(kw['b'])
    for cap in [record,actualtype,*nodes]:v.drop(cap)
    rows.append(dict(case='all-nine-fields-defaults-actual-cap-identity-and-immutable-domain'))

    unusual=(None,False,10**160,-0.0,float('nan'),b'\xff\0','\ud800',[1,'x'],{'x':1},(1,'x'))
    for index,name in enumerate(FIELDS):
        for item in unusual:
            original=dataclasses.replace(normal,**{name:item})
            nodes=field_values(v,original);record=v.record(nodes)
            actual=v.field(record,index)
            assert v.same(actual,nodes[index])and equivalent(v.python_value(actual),getattr(original,name))
            for cap in [actual,record,*nodes]:v.drop(cap)
        rows.append(dict(case='annotations-do-not-validate-field',field=name,values=len(unusual)))

    cls=v.cls('LLVMSubclass',[canonical]);originalcls=type('LLVMSubclass',(HIAProgramLLVM,),{})
    nodes=field_values(v,normal);sub=v.record(nodes,cls);base=v.record(nodes)
    actualtype=v.keep(v.raw(36,a=sub));assert v.same(actualtype,cls)and v.isinst(sub,canonical)
    assert v.equal(sub,base)==(originalcls(**dataclasses.asdict(normal))==normal)==False
    other=v.record(nodes,cls);assert v.equal(sub,other)
    for cap in [actualtype,cls,*nodes,base,other,sub]:v.drop(cap)
    rows.append(dict(case='real-record-subclass-strong-class-edge-and-exact-class-equality'))

    cases=[tuple(range(9)),tuple([True,1,1.0,0,-0.0,False,2**150,-2**150,None])]
    for fields in cases:
        original=HIAProgramLLVM(*fields);nodes=[v.scalar(x)for x in fields];left=v.record(nodes);right=v.record(nodes)
        assert v.equal(left,right)==(original==HIAProgramLLVM(*fields))
        assert v.hashed(left)==hash(original),(v.hashed(left),hash(original))
        for cap in [left,right,*nodes]:v.drop(cap)
    nan=float('nan');fields=[nan,*range(8)];original=HIAProgramLLVM(*fields)
    nodes=[v.scalar(x)for x in fields];left=v.record(nodes);right=v.record(nodes)
    assert v.equal(left,left)==(original==original)
    assert v.equal(left,right)==(original==HIAProgramLLVM(*fields))
    for cap in [left,right,*nodes]:v.drop(cap)
    rows.append(dict(case='actual-record-equality-hash-numeric-and-nan-oracle'))

    nodes=[v.scalar(i)for i in range(8)];mutable=v.lst([]);record=v.record([mutable,*nodes])
    v.raw(16,a=mutable,b=nodes[0]);field=v.field(record,0)
    assert v.same(field,mutable)and v.python_value(field)==[0]
    v.hashed(record,want=2)
    v.drop(mutable);v.drop(record)
    assert v.python_value(field)==[0]
    for cap in [field,*nodes]:v.drop(cap)
    rows.append(dict(case='mutable-field-alias-strong-retention-and-unhashable-record'))

    nodes=[v.scalar(i)for i in range(9)];seq=v.lst(nodes);badclass=v.cls('HIAProgramLLVM',[])
    before=word(v.raw(47),48)
    for kw,want in ((dict(a=(1,1,1)),1),(dict(a=nodes[0]),2),(dict(a=seq,b=(1,1,1)),1),(dict(a=seq,b=nodes[0]),2),(dict(a=seq,b=badclass),2)):
        v.raw(100,want=want,**kw);assert word(v.raw(47),48)==before
    for count in (0,1,8,10):
        wrong=v.lst([nodes[i%9]for i in range(count)]);v.raw(100,a=wrong,want=7);v.drop(wrong)
    for cap in [badclass,seq,*nodes]:v.drop(cap)
    rows.append(dict(case='invalid-cap-class-shape-and-field-count-controls'))

    for cap in [canonical,budgetclass]:v.drop(cap)
    baseline=objects(v)
    nodes=[v.scalar(i)for i in range(8)];mutable=v.lst([]);record=v.record([mutable,*nodes]);v.raw(16,a=mutable,b=record)
    for cap in [mutable,record,*nodes]:v.drop(cap)
    assert word(v.raw(47),48)==0 and objects(v)==baseline,(word(v.raw(47),48),objects(v),baseline)
    rows.append(dict(case='actual-record-container-cycle-collection'))

    malformed=[]
    for op in(99,100):
        raw=bytearray(frame(op,arg0=46 if op==99 else 0));raw[:8]=b'HIABVQ05'
        for magic in(b'HIABVQ01',b'HIABVQ02',b'HIABVQ03',b'HIABVQ04',b'HIABVQ06',b'HIABVQ07',b'HIABVQ08'):
            bad=bytearray(raw);bad[:8]=magic;malformed.append(bytes(bad))
        for at in(16,96,112,120):
            bad=bytearray(raw);struct.pack_into('<Q',bad,at,1);malformed.append(bytes(bad))
        malformed.extend([bytes(raw[:-1]),bytes(raw)+b'\0'])
    for op,arg in((87,46),(98,46),(99,45),(99,48)):
        raw=bytearray(frame(op,arg0=arg));raw[:8]=b'HIABVQ05';malformed.append(bytes(raw))
    context=v.engine.context.raw
    for raw in malformed:
        rc,_=v.engine.call(raw);assert rc==0xfffffffd and v.engine.context.raw==context
    rows.append(dict(case='new-domain-and-old87-98-refusals-preserved',controls=len(malformed)))
    assert not v.held
    v.finish()
    report=dict(schema='hia.native-llvm-record.qualification.v1',passed=True,llvm_record_component_qualified=True,
      actual_native_image=True,image=dict(path=str(image),bytes=image.stat().st_size,sha256=hashlib.sha256(image.read_bytes()).hexdigest()),
      oracle=platform.python_version(),original_fields=FIELDS,groups=rows,
      constructor_does_not_validate_annotations=True,public_constructor_argument_binding_qualified=False,
      fresh_emit_origin_qualified=False,command_log_qualified=False,bounded_resource_limits_qualified=False,
      whole_public_runtime_qualified=False)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows))),flush=True)
    return report
def main():
    p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();run(a.image,a.output)
if __name__=='__main__':main()
