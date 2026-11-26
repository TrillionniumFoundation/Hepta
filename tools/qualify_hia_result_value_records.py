"""Execute actual immutable values and typed scalar preparation against original Python values."""
from pathlib import Path
import argparse, ctypes as C, json, math, platform, random, struct
from tools.qualify_hia_result_value_classes import Values as PriorValues, NativeEngine, frame as prior_frame, word, ZERO
from hepta.hia_program import scalar_value_valid, integer_range
from hepta.hia_multiversion import ScalarABI, GenerationInfo

TYPES=('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize')

def frame(op,**kw):
    raw=bytearray(prior_frame(op,**kw))
    if 40<=op<=47:raw[:8]=b'HIABVQ04'
    return bytes(raw)

class Values(PriorValues):
    def raw(self,op,*,want=0,on=16384,**kw):
        rc,out=self.engine.call(frame(op,**kw),on=on)
        assert rc==0 and out[:8]==(b'HIABVR02' if 29<=op<=31 else b'HIABVR01'),(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want)
        return out
    def tuple(self,items):
        original=self.lst(items)
        result=self.keep(self.raw(40,a=original));self.drop(original)
        return result
    def field(self,record,index):
        return self.keep(self.raw(43,a=record,arg0=index))
    def python_value(self,cap):
        kind=word(self.raw(7,a=cap),16)
        if kind in (5,11):
            members=self.copy_caps(cap)
            values=[self.python_value(x)for x in members]
            for item in members:self.drop(item)
            return tuple(values)if kind==11 else values
        if kind==6:
            n=word(self.raw(7,a=cap),48)
            out=self.raw(23,a=cap,arg1=n,on=max(16384,8192+n*64))
            result={}
            for i in range(n):
                key=self.keep(out,8192+i*64+16);value=self.keep(out,8192+i*64+40)
                result[self.python_value(key)]=self.python_value(value)
                self.drop(key);self.drop(value)
            return result
        if kind==3:
            raw=self.raw(19,a=cap,arg1=8)[8192:8200]
            return struct.unpack('<d',raw)[0]
        return self.python(cap)
    def builtin(self,index):
        return self.keep(self.raw(46,arg0=index)) if index>=28 else super().builtin(index)
    def finish(self):
        for item in list(self.held):self.drop(item)
        assert word(self.raw(47),48)==0
        self.engine.finish()
        assert word(self.engine.context.raw,16)==word(self.engine.context.raw,40)==0

def abi_frame(entries):
    raw=bytearray(5136);raw[:8]=b'HIAMVABI';struct.pack_into('<Q',raw,8,len(entries))
    for i,(name,parameters,result)in enumerate(entries):
        at=16+i*320;name=name.encode()
        assert len(name)<=128 and len(parameters)<=16
        struct.pack_into('<4Q',raw,at,i,len(name),len(parameters),TYPES.index(result)+1)
        raw[at+32:at+32+len(name)]=name
        for j,typ in enumerate(parameters):struct.pack_into('<Q',raw,at+160+j*8,TYPES.index(typ)+1)
    return bytes(raw)

def equivalent(a,b):
    if type(a)is float and type(b)is float and math.isnan(a)and math.isnan(b):return True
    if type(a)is not type(b):return False
    if type(a)is dict:return list(a)==list(b)and all(equivalent(a[k],b[k])for k in a)
    if type(a)in(list,tuple):return len(a)==len(b)and all(equivalent(x,y)for x,y in zip(a,b))
    return a==b

def qualify_asdict(v):
    rows=[]
    mapping_cases=[b'',b'null',b'{"x":[1,true,null,"\\u03bb","\\ud800"],"z":-0.0}',b'[-123456789012345678901234567890,0.25]',b'NaN',b'Infinity',b'-Infinity',json.dumps({'rows':[{'x':i,'tag':'\u03bb'*32}for i in range(2048)]},ensure_ascii=False).encode()]
    for mapping in mapping_cases:
        function=v.scalar('f');parameters=v.tuple([v.scalar('i64')]);result=v.scalar('i64')
        abi=v.keep(v.raw(41,a=function,b=parameters,c=result))
        py=GenerationInfo(10**200,'1'*64,'2'*64,'3'*64,4096,(ScalarABI('f',('i64',),'i64'),),1,2,True,'profile',0,mapping)
        fields=[v.scalar(py.generation),v.scalar(py.program_sha256),v.scalar(py.input_sha256),v.scalar(py.artifact_sha256),v.scalar(py.artifact_bytes),v.tuple([abi]),v.scalar(py.translation_proofs),v.scalar(py.native_probe_calls),v.scalar(py.baseline),v.scalar(py.admission_profile),v.scalar(py.totality_proofs),v.scalar(mapping)]
        packed=v.tuple(fields);info=v.keep(v.raw(42,a=packed));snapshot=v.keep(v.raw(44,a=info))
        assert equivalent(v.python_value(snapshot),py.as_dict())
        # Mutating the detached ABI list cannot change the immutable record.
        key=v.scalar('abi');outer=v.keep(v.raw(9,a=snapshot,b=key));index=v.scalar(0)
        row=v.keep(v.raw(12,a=outer,b=index));pkey=v.scalar('parameters');params=v.keep(v.raw(9,a=row,b=pkey));extra=v.scalar('u8')
        v.raw(16,a=params,b=extra)
        second=v.keep(v.raw(44,a=info));assert equivalent(v.python_value(second),py.as_dict())
        for cap in list(v.held):
            if cap!=second:v.drop(cap)
        assert equivalent(v.python_value(second),py.as_dict())
        v.drop(second);assert word(v.raw(47),48)==0
        rows.append(dict(case='generation-info-as-dict-detached-original-oracle',mapping_bytes=len(mapping)))
    for parameters in ('i\u03bb',b'\x00\x7f\xff',{'i64':1,'u8':2},['i64','u8']):
        function=v.scalar('f');result=v.scalar('i64')
        if type(parameters)is dict:p=v.dictionary(list(parameters.items()))
        elif type(parameters)is list:p=v.lst([v.scalar(x)for x in parameters])
        else:p=v.scalar(parameters)
        abi=v.keep(v.raw(41,a=function,b=p,c=result))
        py=GenerationInfo(0,'p','i','a',1,(ScalarABI('f',parameters,'i64'),),0,0,False)
        fields=[v.scalar(0),v.scalar('p'),v.scalar('i'),v.scalar('a'),v.scalar(1),v.tuple([abi]),v.scalar(0),v.scalar(0),v.scalar(False),v.scalar(py.admission_profile),v.scalar(0),v.scalar(b'')]
        info=v.keep(v.raw(42,a=v.tuple(fields)));snapshot=v.keep(v.raw(44,a=info))
        assert equivalent(v.python_value(snapshot),py.as_dict())
        for cap in list(v.held):v.drop(cap)
        rows.append(dict(case='dataclass-annotation-does-not-restrict-parameters',original_type=type(parameters).__name__))
    return rows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
    assert platform.python_version()=='3.14.4'
    target=Path(args.output);target.mkdir(parents=True,exist_ok=False)
    v=Values(NativeEngine(args.image));rows=[]
    assert word(v.raw(47),48)==0
    for index,original in ((28,tuple),(29,ScalarABI),(30,GenerationInfo)):
        cls=v.builtin(index);name=v.keep(v.raw(38,a=cls))
        assert v.python(name)==original.__name__;v.drop(name)
        fake=v.cls(original.__name__,[]);obj=v.instance(fake)
        assert not v.isinst(obj,cls)
        for cap in (obj,fake,cls):v.drop(cap)
        rows.append(dict(case='actual-class-identity',name=original.__name__))
    scalars=[v.scalar(x)for x in (None,False,True,0,-1,1.5,'x',b'y')]
    source=v.lst(scalars);t=v.keep(v.raw(40,a=source))
    alias=v.keep(v.raw(40,a=t));assert v.same(t,alias)
    changed=v.scalar(44);zero=v.scalar(0)
    v.raw(13,a=source,b=zero,c=changed)
    assert v.python_value(t)==(None,False,True,0,-1,1.5,'x',b'y')
    for op,kw in ((13,dict(b=zero,c=changed)),(14,dict(b=zero,c=changed)),(15,dict(b=zero)),(16,dict(b=changed))):
        v.raw(op,a=t,want=2,**kw)
    for index in range(-len(scalars)-2,len(scalars)+2):
        key=v.scalar(index)
        try:expected=(None,False,True,0,-1,1.5,'x',b'y')[index]
        except IndexError:v.raw(12,a=t,b=key,want=4)
        else:
            item=v.keep(v.raw(12,a=t,b=key));assert v.python_value(item)==expected;v.drop(item)
        v.drop(key)
    encoded=v.keep(v.raw(18,a=v.tuple([zero,changed])))
    assert v.python(encoded)==b'[0,44]';v.drop(encoded)
    empty=v.tuple([]);empty2=v.tuple([]);assert v.same(empty,empty2)
    rows.append(dict(case='immutable-shallow-tuple-identity-index-mutation-json'))
    for cap in list(v.held):v.drop(cap)
    a=v.scalar('f');p=v.tuple([v.scalar('i64')]);r=v.scalar('i64')
    scalar=v.keep(v.raw(41,a=a,b=p,c=r));cls=v.builtin(29);assert v.isinst(scalar,cls)
    for index,cap in enumerate((a,p,r)):
        field=v.field(scalar,index);assert v.same(field,cap);v.drop(field)
    # Dataclass annotations do not validate constructor values.
    arbitrary=v.scalar(123);odd=v.keep(v.raw(41,a=arbitrary,b=arbitrary,c=arbitrary))
    fields=[v.scalar(10**200),v.scalar('1'*64),v.scalar('2'*64),v.scalar('3'*64),v.scalar(4096),v.tuple([scalar]),v.scalar(1),v.scalar(2),v.scalar(True),v.scalar('profile'),v.scalar(0),v.scalar(b'')]
    packed=v.tuple(fields);info=v.keep(v.raw(42,a=packed))
    generation_class=v.builtin(30);assert v.isinst(info,generation_class)
    for cap in fields+[packed,a,p,r,scalar,cls,arbitrary,odd,generation_class]:v.drop(cap)
    g=v.field(info,0);assert v.python(g)==10**200;v.drop(g)
    signatures=v.field(info,5);copied=v.copy_caps(signatures);assert len(copied)==1
    fn=v.field(copied[0],0);assert v.python(fn)=='f'
    for cap in (fn,*copied,signatures,info):v.drop(cap)
    rows.append(dict(case='native-frozen-records-real-class-fields-and-retention'))
    for cap in list(v.held):v.drop(cap)
    # Cycles crossing a tuple and mutable list participate in the same collector.
    child=v.lst([]);cyclic=v.tuple([child]);v.raw(16,a=child,b=cyclic)
    v.drop(child);v.drop(cyclic);assert word(v.raw(47),48)==0
    rows.append(dict(case='tuple-list-cycle-collection-and-nonmutating-probe'))
    rows.extend(qualify_asdict(v))
    calls=0
    for typ in TYPES:
        if typ=='bool':values=[False,True,0,1,-1,None,0.0,'true',b'true']
        else:
            lo,hi=integer_range(typ);values=[lo-1,lo,lo+1,-1,0,1,hi-1,hi,hi+1,True,False,1.0,None,'1',b'1']
        wire=abi_frame([('first',(),typ),('f',(typ,),typ)])
        function=v.scalar('f')
        for value in values:
            scalar=v.scalar(value)
            for tuple_mode in (False,True):
                arguments=v.tuple([scalar])if tuple_mode else v.lst([scalar])
                valid=scalar_value_valid(value,typ)
                out=v.raw(45,a=function,b=arguments,tail=wire,want=0 if valid else 22)
                if valid:
                    assert word(out,56)==1 and word(out,64)==152
                    assert out[8192:8200]==b'HIAMVCAL' and word(out,8200)==1 and word(out,8208)==TYPES.index(typ)+1
                    expected=int(value)&((1<<64)-1);assert word(out,8216)==expected
                    assert out[8224:8344]==bytes(120)
                v.drop(arguments);calls+=1
            v.drop(scalar)
        v.drop(function)
        rows.append(dict(case='typed-exact-scalar-original-oracle',type=typ,comparisons=len(values)*2))
    wire=abi_frame([('f',('i64',),'i64')]);function=v.scalar('f');unknown=v.scalar('missing');bad=v.scalar(None)
    v.raw(45,a=unknown,b=bad,tail=wire,want=20)
    for value in (None,False,42,2.0,b'f'):
        f=v.scalar(value);v.raw(45,a=f,b=bad,tail=wire,want=20);v.drop(f)
    for cap in (bad,function,unknown,v.dictionary([])):
        v.raw(45,a=function,b=cap,tail=wire,want=21)
    cls=v.cls('tuple',[]);obj=v.instance(cls)
    v.raw(45,a=function,b=obj,tail=wire,want=21)
    strcls=v.cls('StringAlias',[v.builtin(6)]);alias=v.instance(strcls,function)
    v.raw(45,a=alias,b=bad,tail=wire,want=20)
    empty=v.tuple([]);v.raw(45,a=function,b=empty,tail=wire,want=22)
    rows.append(dict(case='type-impostors-and-original-validation-precedence'))
    before=v.engine.context.raw;controls=0
    valid=frame(47)
    invalid=[]
    for magic,ops in ((b'HIABVQ01',range(40,48)),(b'HIABVQ02',range(40,48)),(b'HIABVQ03',range(40,48)),(b'HIABVQ04',list(range(40))+[48,(1<<64)-1])):
        for op in ops:
            raw=bytearray(valid);raw[:8]=magic;struct.pack_into('<Q',raw,8,op);invalid.append(bytes(raw))
    for offset in range(16,128,8):
        raw=bytearray(valid);struct.pack_into('<Q',raw,offset,1);invalid.append(bytes(raw))
    invalid.extend([valid[:-1],valid+b'\0'])
    for raw in invalid:
        rc,out=v.engine.call(raw);assert rc==0xfffffffd and v.engine.context.raw==before
        controls+=1
    rows.append(dict(case='preserved-and-new-private-request-domains',controls=controls))
    v.finish()
    report=dict(schema='hia.native-record-values.qualification.v1',component_qualified=True,actual_native_image=True,oracle=platform.python_version(),groups=rows,typed_scalar_comparisons=calls,whole_public_runtime_qualified=False,generation_info_as_dict_captured_values_qualified=True,public_arbitrary_iterable_dataclass_protocol_closed=False,tuple_hash_equality_protocol_closed=False,typed_native_call_lock_integration_closed=False)
    (target/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows),typed_scalar_comparisons=calls,private_controls=controls)))
if __name__=='__main__':main()
