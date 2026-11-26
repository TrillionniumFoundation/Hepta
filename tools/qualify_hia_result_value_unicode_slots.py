"""Native Unicode exception descriptors retain real decoder facts and chains."""
from pathlib import Path
import argparse,errno,hashlib,json,os,platform,struct,traceback
from tools.qualify_hia_result_value_platform import Values,Bound,Engine,frame,word,ZERO,name,periodic_gc,objects,args_and_dict,thread_result,pending_function,deny_native,ip_at,values_pack,code_pack,sweep
from tools.qualify_hia_result_value_verified_program import make_value
from tools.qualify_hia_result_value_records import equivalent
FIELDS=('encoding','object','start','end','reason')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def raw_capture(v,fields,cls=ZERO,want=0):
    seq=v.tuple(fields);reply=v.raw(108,a=seq,b=cls,want=want)
    v.drop(seq);return reply
def capture(v,fields,cls=ZERO):
    r=raw_capture(v,fields,cls)
    assert tuple(word(r,i)for i in(64,80,88,96,104))==(1,0,1,1,0)
    return v.keep(r)
def field(v,obj,selector):
    r=v.raw(109,a=obj,arg0=selector)
    assert tuple(word(r,i)for i in(64,80,88,96,104))==(1,0,1,1,0)
    return v.keep(r)
def projection(value):
    if isinstance(value,tuple):return tuple(projection(x)for x in value)
    if isinstance(value,str):return str(value)
    if isinstance(value,bytes):return bytes(value)
    if isinstance(value,bool):return value
    if isinstance(value,int):return int(value)
    return value
def native_projection(v,cap):
    # The legacy dict-iterator oracle supports only its own str subclass.
    # Decode the actual native descriptor instead; class/alias assertions below
    # independently verify that the native object has not lost its true type.
    kind=word(v.raw(7,a=cap),16)
    if kind==8:
        result=v.raw(26,a=cap)
        assert word(result,8200)in(1,2,4,7)
        children=[v.keep(result,8224+i*24)for i in range(3)]
        try:return native_projection(v,children[1])
        finally:
            for child in children:v.drop(child)
    if kind==11:
        children=v.copy_caps(cap)
        try:return tuple(native_projection(v,x)for x in children)
        finally:
            for child in children:v.drop(child)
    return v.python_value(cap)
def compare(v,obj,expected):
    assert name(v,obj)==type(expected).__name__
    for i,attr in enumerate(FIELDS):
        value=field(v,obj,i)
        assert equivalent(native_projection(v,value),projection(getattr(expected,attr))),(attr,v.python_value(value),getattr(expected,attr))
        assert name(v,value)==type(getattr(expected,attr)).__name__
        if attr in('start','end'):assert name(v,value)=='int'
        v.drop(value)
    args=v.slot(obj,5);assert equivalent(native_projection(v,args),projection(expected.args))
    for i,item in enumerate(expected.args):
        index=v.scalar(i);cap=v.keep(v.raw(12,a=args,b=index))
        assert name(v,cap)==type(item).__name__
        v.drop(cap);v.drop(index)
    v.drop(args)
    ns,stored,typename=args_and_dict(v,obj)
    assert v.python_value(ns)=={}
    for cap in(ns,stored,typename):v.drop(cap)
def run(path,out):
    out.mkdir(parents=True,exist_ok=False);assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.native-unicode-exception-slots.component.v1',passed=False,product=pin(path.read_bytes()),
        public_unicode_constructor_qualified=False,custom_index_dispatch_qualified=False,
        mutable_unicode_descriptor_setters_qualified=False,unicode_exception_formatting_qualified=False,
        whole_public_runtime_qualified=False)
    before=set(os.listdir('/proc/self/fd'));rows=[]
    try:
        b=Bound(path);assert b.call(0)['status']==0;v=Values(Engine(b));decode=v.builtin(70);encode=v.builtin(44)
        specimens=[b'\xff',b'a\x80z',b'\xc0\xaf',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82',
                   b'\xf0\x9f',b'\xe2A',b'\xf0\x80\x80\xaf',b'abc\xfe\xff',b'\x80'*2048,b'abc\x00\xffdef']
        decodes=0
        for data in specimens:
            try:data.decode('utf-8')
            except UnicodeDecodeError as error:
                fields=[make_value(v,getattr(error,k))for k in FIELDS]
                obj=capture(v,fields);compare(v,obj,error)
                for cap in [obj,*fields]:v.drop(cap)
                decodes+=1
            else:raise AssertionError('fixture must cause an actual decoder failure')
        rows.append(dict(case='actual-CPython-UTF8-decoder-facts-as-native-slots',cases=decodes))
        print('UNICODE_SLOTS_PASS actual-decodes',flush=True)
        encodes=0
        for text in('\ud800','a\udcffz','\ud800\udfff','é\udc80\U0001f600'):
            for encoding in('utf-8','ascii'):
                try:text.encode(encoding)
                except UnicodeEncodeError as error:
                    fields=[make_value(v,getattr(error,k))for k in FIELDS]
                    obj=capture(v,fields,encode);compare(v,obj,error)
                    for cap in [obj,*fields]:v.drop(cap)
                    encodes+=1
                else:raise AssertionError('fixture must cause an actual encoder failure')
        rows.append(dict(case='actual-CPython-encoder-facts-and-original-args',cases=encodes))
        for pycls,cls,payload in((UnicodeDecodeError,decode,b'\xffa'),(UnicodeEncodeError,encode,'a\udcff')):
            for start,end in((0,1),(-5,99),(-(1<<63),(1<<63)-1),(True,False)):
                expected=pycls('utf-8',payload,start,end,'cause')
                fields=[make_value(v,x)for x in expected.args]
                obj=capture(v,fields,cls);compare(v,obj,expected)
                for cap in[obj,*fields]:v.drop(cap)
        rows.append(dict(case='full-signed-index-range-bool-normalization-and-unbounded-relative-positions',cases=8))
        print('UNICODE_SLOTS_PASS encode-and-indices',flush=True)
        class S(str):pass
        class B(bytes):pass
        class I(int):pass
        nativeclasses={base:v.cls(py.__name__,[v.builtin(base)])for base,py in((6,S),(7,B),(3,I))}
        def subclass(base,value):
            actual=v.scalar(value);ns=v.keep(v.raw(4))
            obj=v.keep(v.raw(50,a=nativeclasses[base],b=ns,c=actual))
            v.drop(actual);v.drop(ns);return obj
        for pycls,cls,payload,base in((UnicodeDecodeError,decode,B(b'\xffa'),7),(UnicodeEncodeError,encode,S('a\udcff'),6)):
            expected=pycls(S('utf-8'),payload,I(2),I(3),S('reason'))
            fields=[subclass(6,'utf-8'),subclass(base,bytes(payload)if base==7 else str(payload)),subclass(3,2),subclass(3,3),subclass(6,'reason')]
            obj=capture(v,fields,cls);compare(v,obj,expected)
            for i in(0,1,4):
                alias=field(v,obj,i);assert v.same(alias,fields[i]);v.drop(alias)
            for cap in[obj,*fields]:v.drop(cap)
        rows.append(dict(case='real-str-bytes-int-subclasses-and-slot-alias-identity',cases=2))
        for pybase,cls,payload in((UnicodeDecodeError,decode,b'\xff'),(UnicodeEncodeError,encode,'\udcff')):
            pycls=type('ActualUnicodeChild',(pybase,),{});actualclass=v.cls('ActualUnicodeChild',[cls])
            fields=[v.scalar('utf-8'),v.scalar(payload),v.scalar(0),v.scalar(1),v.scalar('why')]
            obj=capture(v,fields,actualclass);compare(v,obj,pycls('utf-8',payload,0,1,'why'))
            actualtype=v.keep(v.raw(36,a=obj));assert v.same(actualtype,actualclass);v.drop(actualtype)
            for cap in[obj,actualclass,*fields]:v.drop(cap)
        rows.append(dict(case='actual-Unicode-exception-subclasses'))
        print('UNICODE_SLOTS_PASS subclasses',flush=True)
        fields=[v.scalar('utf-8'),v.scalar(b'\xff\x00payload'),v.scalar(0),v.scalar(1),v.scalar('invalid start byte')]
        obj=capture(v,fields);expected=UnicodeDecodeError('utf-8',b'\xff\x00payload',0,1,'invalid start byte')
        other=v.exception(v.builtin(22),v.tuple([]))
        for selector in(0,1):
            result=v.keep(v.raw(106,a=obj,b=other,arg0=selector));v.drop(result)
        v.drop(other)
        cause=v.keep(v.raw(107,a=obj,arg0=0));context=v.keep(v.raw(107,a=obj,arg0=1));assert v.same(cause,context)
        for cap in fields:v.drop(cap)
        compare(v,obj,expected)
        for cap in(obj,cause,context):v.drop(cap)
        rows.append(dict(case='five-private-slots-survive-chain-replacement-and-original-caller-drop'))
        periodic_gc(v,decode);baseline=objects(v)
        fields=[v.scalar('utf-8'),v.scalar(b'\xff'*4096),v.scalar(0),v.scalar(1),v.scalar('invalid')]
        first=capture(v,fields);second=capture(v,fields)
        for a,c in((first,second),(second,first),(first,first)):
            result=v.keep(v.raw(106,a=a,b=c,arg0=0));v.drop(result)
        for cap in[first,second,*fields]:v.drop(cap)
        periodic_gc(v,decode);assert objects(v)==baseline,(objects(v),baseline)
        rows.append(dict(case='real-Unicode-slots-and-mutual-cause-cycle-collection'))
        print('UNICODE_SLOTS_PASS chain-and-GC',flush=True)
        fields=[v.scalar('utf-8'),v.scalar(b'\xff'),v.scalar(0),v.scalar(1),v.scalar('invalid')]
        args=v.tuple(fields)
        def denied_capture():
            deny_native(ip_at(b.value,values_pack),318,errno.EIO)
            return v.raw(108,a=args,b=decode,want=11)
        result=thread_result(denied_capture)
        assert result[24:48]==bytes(24)and tuple(word(result,i)for i in(80,88,96,104))==(0,1,0,11)
        obj=capture(v,fields);receipts=[]
        for op,kw in((108,dict(a=args,b=decode)),(109,dict(a=obj,arg0=1))):
            pending_function(v,b)
            def denied_cleanup():
                deny_native(ip_at(b.code,code_pack),11,errno.EIO)
                return v.raw(op,**kw,want=11)
            result=thread_result(denied_cleanup)
            assert tuple(word(result,i)for i in(64,80,88,96,104))==(1,1,1,1,11),result[:128].hex()
            cap=v.keep(result);receipts.append(dict(operation=op,reply=result[:128].hex()))
            v.raw(47);assert word(v.engine.context,176)==word(v.engine.context,184)==0
            v.drop(cap)
        rows.append(dict(case='actual-getrandom-and-two-postpublication-code-munmap-faults',receipts=receipts))
        for cap in[obj,args,*fields]:v.drop(cap)
        print('UNICODE_SLOTS_PASS real-faults',flush=True)
        normal=[v.scalar('utf-8'),v.scalar(b'\xff'),v.scalar(0),v.scalar(1),v.scalar('why')]
        wrongtypes=0
        for index in range(5):
            fields=normal.copy();fields[index]=v.scalar(None)
            failed=raw_capture(v,fields,decode,want=2);assert word(failed,88)==1 and word(failed,96)==0
            v.drop(fields[index]);wrongtypes+=1
        fields=normal.copy();fields[2]=v.scalar(1<<100)
        failed=raw_capture(v,fields,decode,want=4);assert word(failed,96)==0;v.drop(fields[2])
        fake=v.cls('UnicodeDecodeError',[]);failed=raw_capture(v,normal,fake,want=2);assert word(failed,96)==0;v.drop(fake)
        for cap in normal:v.drop(cap)
        controls=[]
        for op in(108,109):
            packet=bytearray(frame(op))
            for magic in(b'HIABVQ01',b'HIABVQ02',b'HIABVQ03',b'HIABVQ04',b'HIABVQ06',b'HIABVQ07',b'HIABVQ08',b'HIABVQ09',b'HIABVQ10'):
                raw=bytearray(packet);raw[:8]=magic;controls.append(bytes(raw))
            for at in(16,96,112,120):
                raw=bytearray(packet);struct.pack_into('<Q',raw,at,1);controls.append(bytes(raw))
            controls.extend((bytes(packet[:-1]),bytes(packet)+b'\0'))
        controls.append(frame(109,arg0=5));controls.append(frame(108,arg0=1))
        for raw in controls:
            beforectx=bytes(v.engine.context);rc,outcome=v.engine.call(raw)
            assert rc==0xfffffffd and bytes(v.engine.context)==beforectx
            expected=bytearray(b'\xa5'*len(outcome));expected[128:136]=bytes(8);assert outcome==expected
        rows.append(dict(case='original-type-boundary-and-exact-new-wire',type_cases=wrongtypes+2,controls=len(controls)))
        for cap in list(v.held):v.drop(cap)
        sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
        report.update(passed=True,groups=rows,source=pin(Path(__file__).read_bytes()))
        print('UNICODE_SLOTS_ALL_PASS',len(rows),flush=True)
    except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:save(out/'report.json',report)
    return report
def main():
    p=argparse.ArgumentParser()
    for name in('owner','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
