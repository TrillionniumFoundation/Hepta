"""Mechanical GraphLease capture and actual two-image test executor.

Capture preserves object representations and references only. It deliberately
does not perform a JSON size/admission/canonicalization decision. A complete
capture is not proof of the public incremental-capture resource boundary.
"""
from pathlib import Path
from hashlib import sha256
import ctypes, json, struct, sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
BASE=Path('/workspace/scratch/9acdfa9f5639/Hepta-agent-edit-native')
sys.path.insert(0,str(BASE))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program_tools import bounded_json_wire

MAGIC=lambda word:int.from_bytes(word,'little')
GRAPH=MAGIC(b'HIAGRF01');COMMAND=MAGIC(b'HIAGWC01');EVENT=MAGIC(b'HIAGWE01')
BAD=0xfffffffd
CANARY=b'\xb9'*32
ERRORS={
1:'invalid JSON output byte budget',
2:'JSON string exceeds byte budget before encoding',
3:'unpaired Unicode surrogate in UTF-8 JSON',
4:'JSON input exceeds nesting depth before encoding',
5:'JSON input exceeds node/byte budget',
6:'JSON container exceeds queued-node/byte budget',
7:'cyclic JSON container',
8:'unsupported JSON object key',
9:'JSON key exceeds numeric byte budget',
10:'nonfinite JSON object key',
11:'JSON key exceeds byte budget',
12:'JSON object key collision after JSON conversion',
13:'JSON integer exceeds byte budget',
14:'non-JSON in-process value',
15:'invalid bounded JSON',
16:'JSON encoding exceeds byte budget',
}

def capture(root,lease=19):
    objects=[];ids={}
    def add(value):
        key=id(value)
        if key not in ids:
            ids[key]=len(objects)+1
            objects.append(value)
        return ids[key]
    rootid=add(root)
    records=[];edges=[];pool=bytearray()
    position=0
    while position<len(objects):
        value=objects[position];kind=type(value)
        record=[0]*8
        raw=None
        if value is None:
            record[0]=0
        elif kind is bool:
            record[0]=1;record[6]=int(value)
        elif kind is int:
            record[0]=2;record[6]=int(value<0)
            magnitude=abs(value);raw=magnitude.to_bytes((magnitude.bit_length()+7)//8,'little')
        elif kind is float:
            record[0]=3;raw=struct.pack('<d',value)
        elif kind is str:
            record[0]=4;record[6]=len(value);raw=value.encode('utf-8','surrogatepass')
        elif kind in (list,dict,tuple):
            record[0]={list:5,dict:6,tuple:7}[kind]
            record[3]=len(edges);record[4]=len(value);record[5]=position+1
            if kind is dict:
                items=list(value.items())
                for key,child in items:
                    edges.extend((add(key),add(child)))
            else:
                for child in tuple(value):
                    edges.append(add(child))
        elif kind is bytes:
            record[0]=9;raw=value
        else:
            record[0]=8
        if raw is not None:
            record[1]=len(pool);record[2]=len(raw);pool.extend(raw)
        records.append(record);position+=1
    data=64+len(records)*64+len(edges)*8
    for record in records:
        if record[0] in (2,3,4,9):
            record[1]+=data
    header=(GRAPH,lease,len(records),rootid,len(edges),len(pool),data+len(pool),0)
    return (struct.pack('<8Q',*header)+b''.join(struct.pack('<8Q',*row) for row in records)
            +b''.join(struct.pack('<Q',value) for value in edges)+bytes(pool))


class Actual:
    def __init__(self,out,bundle=None):
        self.out=Path(out);self.pins={};self.entries={'scan':0,'emit':0}
        bundle=Path(bundle or ROOT/'development/compile-r3/bundle.json')
        def read(path):
            path=Path(path).resolve();raw=path.read_bytes()
            if path in self.pins:assert self.pins[path]==raw
            self.pins[path]=raw;return raw
        rows=json.loads(read(bundle))
        assert rows['status']=='PASS'
        assert rows['scope']=='SOURCE_BOUND_GRAPH_WIRE_DEVELOPMENT_NOT_PUBLIC_ADMISSION_OR_COLD'
        images={}
        for role,row in rows['components'].items():
            assert row['schema']=='hepta.hia.graph-json-wire-'+role+'-native.v1'
            assert row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
            source=read(row['source_path']);current=read(ROOT/('examples/hia_bootstrap/graph_json_wire_'+role+'.hiaasm'))
            image=read(row['image_path'])
            assert source==current and sha256(source).hexdigest()==row['source_sha256']
            assert sha256(image).hexdigest()==row['image_sha256']
            images[role]=(image,row['image_sha256'])
        self.readback()
        self.out.mkdir(parents=True,exist_ok=False)
        self.images={key:NativeHiaJsonImage(*value) for key,value in images.items()}
        self.log=(self.out/'entries.jsonl').open('w')
        self.sources=(self.out/'inputs');self.sources.mkdir()
        self.digests={}
        (self.out/'source-before.json').write_text(json.dumps({str(p):sha256(raw).hexdigest() for p,raw in self.pins.items()},indent=2,sort_keys=True)+'\n')

    def readback(self):
        for p,raw in self.pins.items():assert p.read_bytes()==raw

    def raw(self,data,extension):
        digest=sha256(data).hexdigest()
        if digest not in self.digests:
            name=digest+extension
            (self.sources/name).write_bytes(data);self.digests[digest]=name
        return self.digests[digest]

    def call(self,role,source,command,work,size,case):
        s=ctypes.create_string_buffer(source+CANARY)
        r=ctypes.create_string_buffer(command+CANARY)
        ret=self.images[role]._entry(s,len(source),r,len(command),work,size)
        self.entries[role]+=1
        event=struct.unpack_from('<16Q',work,0)
        assert ctypes.string_at(s,len(source)+32)==source+CANARY
        assert ctypes.string_at(r,len(command)+32)==command+CANARY
        assert ctypes.string_at(ctypes.addressof(work)+size,32)==CANARY
        row={'case':case,'role':role,'return':ret,'event':event,'workspace_bytes':size,
             'graph':self.raw(source,'.graph'),'command':self.raw(command,'.command'),
             'input_and_canaries_unchanged':True}
        self.log.write(json.dumps(row,sort_keys=True)+'\n');self.log.flush()
        return ret,event

    def serialize_graph(self,source,maximum,*,flags=3,digits=None,case='case'):
        if digits is None:digits=sys.get_int_max_str_digits()
        lease=struct.unpack_from('<Q',source,8)[0]
        root=struct.unpack_from('<Q',source,24)[0]
        command=struct.pack('<8Q',COMMAND,lease,1,root,maximum,flags,digits,0)
        size=32768;work=ctypes.create_string_buffer(size+32)
        ctypes.memset(ctypes.addressof(work)+size,0xb9,32)
        role='scan';grows=0;steps=0
        with patch('hepta.hia_program_tools.bounded_json_wire',side_effect=AssertionError('host wire disabled')):
            while True:
                steps+=1
                assert steps<1000
                ret,event=self.call(role,source,command,work,size,case)
                assert ret==128,{'return':ret,'event':event,'case':case}
                assert event[0]==EVENT and event[2:8]==(lease,1,root,maximum,flags,digits)
                if event[1]==1:
                    needed=event[10]
                    assert needed>size
                    new_size=max(needed,size*2)
                    replacement=ctypes.create_string_buffer(new_size+32)
                    ctypes.memmove(replacement,work,size)
                    ctypes.memset(ctypes.addressof(replacement)+new_size,0xb9,32)
                    work=replacement;size=new_size;grows+=1
                    continue
                if event[1]==2:
                    assert role=='scan' and event[13]==2 and event[8:10]==(0,0)
                    role='emit';continue
                if event[1]==3:
                    assert event[8] in ERRORS
                    result={'error':'E_HIA_EDIT: '+ERRORS[event[8]],'cause_kind':event[9]}
                    break
                assert event[1]==0 and role=='emit' and event[8:10]==(0,0)
                assert event[11]<=size and event[12]<=size-event[11]
                raw=ctypes.string_at(ctypes.addressof(work)+event[11],event[12])
                result={'wire':raw}
                break
        result['grows']=grows;result['calls']=steps
        return result

    def check(self,value,maximum=1048576,*,ensure_ascii=True,sort_keys=True,case='case'):
        graph=capture(value)
        expected=None
        try:
            expected={'wire':bounded_json_wire(value,maximum,ensure_ascii=ensure_ascii,sort_keys=sort_keys)}
        except Exception as exc:
            expected={'error':str(exc),'class':type(exc).__name__}
        actual=self.serialize_graph(graph,maximum,flags=int(ensure_ascii)+2*int(sort_keys),case=case)
        if 'wire' in expected:
            assert actual.get('wire')==expected['wire'],(case,expected,actual)
            expected_path=self.raw(expected['wire'],'.expected-wire')
            actual_path=self.raw(actual['wire'],'.actual-wire')
        else:
            assert actual.get('error')==expected['error'],(case,expected,actual)
            expected_path=actual_path=None
        return {'case':case,'status':'PASS','grows':actual['grows'],'calls':actual['calls'],
                'expected_class':expected.get('class'),'error':expected.get('error'),
                'expected_wire':expected_path,'actual_wire':actual_path,
                'wire_bytes':len(expected['wire']) if 'wire' in expected else None}

    def close(self):
        self.log.close();self.readback()
        (self.out/'source-after.json').write_text(json.dumps({str(p):sha256(raw).hexdigest() for p,raw in self.pins.items()},indent=2,sort_keys=True)+'\n')

