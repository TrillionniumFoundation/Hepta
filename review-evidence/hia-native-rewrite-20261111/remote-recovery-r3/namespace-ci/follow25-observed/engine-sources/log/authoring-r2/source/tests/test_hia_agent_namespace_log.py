"""Complete native record wire controls; no physical transaction qualification."""
from __future__ import annotations
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View

ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIANLG01','little')
RECORD_MAGIC=int.from_bytes(b'HIANLR01','little')
BAD=0xfffffffd
MASK=(1<<64)-1
WIDTH={1:6,2:3,3:5,4:6,5:7,6:4,7:5,8:3,9:5,10:3}


def payload(cells):
    return struct.pack('<Q',len(cells))+b''.join(struct.pack('<QQ',kind,len(raw))+raw for kind,raw in cells)


def record(kind,table,rowid,body):
    size=80+len(body)
    return struct.pack('<8Q',RECORD_MAGIC,1,kind,table,rowid&MASK,len(body),size,0)+body+struct.pack('<QQ',size,RECORD_MAGIC)


def frame(command,operation=1,sequence=0,lease=1,meta=(0,0,0,0),offset=0,body=b'',source=0,session=(101,202)):
    return struct.pack('<16Q',MAGIC,command,*session,operation,sequence,source,lease,*meta,offset,len(body),0,0)+body


class Session:
    def __init__(self,test):
        self.test=test;self.work=bytearray(1024);self.operation=0;self.sequence=0;self.lease=0;self.offset=0;self.meta=(0,0,0,0)

    def send(self,command,*,body=b'',output=192,grow=True):
        seq=0 if command in (1,4,7) else self.sequence+1
        raw=frame(command,self.operation,seq,self.lease,self.meta,self.offset,body,999 if command in (2,5) else 0)
        while True:
            main=bytes(self.work[:320])
            code,out=self.test.invoke(raw,self.work,output)
            h=struct.unpack_from('<24Q',out)
            self.test.assertEqual(h[:8],(MAGIC,code,101,202,self.operation,seq,command,self.lease))
            self.test.assertEqual(h[22:],(1,0))
            self.test.assertEqual(out[192+h[16]:],bytes(len(out)-192-h[16]))
            if code!=1 or not grow:break
            self.test.assertEqual(self.work[16:320],main[16:320])
            self.test.assertEqual(struct.unpack_from('<Q',self.work,8)[0],3)
            self.test.assertGreater(h[17],output)
            output=h[17]
            self.test.growths+=1
        if code in (0,2):self.sequence=seq
        return code,h,out[192:192+h[16]]

    def encode_begin(self,kind,table,rowid,body):
        self.operation+=1;self.lease+=1;self.offset=0;self.meta=(kind,table,rowid&MASK,len(body))
        code,h,out=self.send(1)
        self.test.assertEqual(code,2)
        self.test.assertEqual(out,record(kind,table,rowid,body)[:64])
        return out

    def encode(self,kind,table,rowid,body,chunks):
        result=bytearray(self.encode_begin(kind,table,rowid,body))
        for chunk in chunks:
            code,h,out=self.send(2,body=chunk)
            self.test.assertEqual(code,2,(kind,table,h))
            self.test.assertEqual(out,chunk)
            self.offset+=len(chunk);result.extend(out)
        code,h,out=self.send(3)
        self.test.assertEqual(code,0,h)
        result.extend(out)
        expected=record(kind,table,rowid,body)
        self.test.assertEqual(bytes(result),expected)
        self.test.observe('encoded_record',expected,bytes(result))
        return bytes(result)

    def decode_begin(self):
        self.operation+=1;self.lease+=1;self.offset=0;self.meta=(0,0,0,0)
        code,h,out=self.send(4);self.test.assertEqual((code,out),(2,b''))

    def decode(self,raw,chunks,expected):
        self.decode_begin()
        for chunk in chunks:
            code,h,out=self.send(5,body=chunk)
            self.test.assertEqual((code,out),(2,b''),h)
            self.offset+=len(chunk)
        code,h,out=self.send(6)
        self.test.assertEqual((code,out),(0,b''),h)
        kind,table,rowid,body=expected
        self.test.assertEqual(h[8:16],(2,kind,table,rowid&MASK,len(body),len(body),len(raw),len(raw)))
        self.test.observe('decoded_record_descriptor',struct.pack('<8Q',*h[8:16]),struct.pack('<8Q',2,kind,table,rowid&MASK,len(body),len(body),len(raw),len(raw)))


class NamespaceLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=(ROOT/'examples/hia_bootstrap/agent_namespace_log.hiaasm').read_bytes()
        cls.program=assemble_program(cls.raw);cls.entry=cls.program.as_dict()['functions'][0]
        cls.entries=cls.observations=cls.growths=0;cls.commands=set();cls.ledger=None
        location=os.environ.get('HIA_NAMESPACE_LOG_LEDGER')
        cls.evidence=Path(location) if location else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True,exist_ok=False)
            cls.ledger=gzip.open(cls.evidence/'invocations.jsonl.gz','wt',encoding='utf-8')

    @classmethod
    def tearDownClass(cls):
        if cls.ledger:
            cls.ledger.close()
            (cls.evidence/'counts.json').write_text(json.dumps({'entries':cls.entries,'observations':cls.observations,'commands':sorted(cls.commands),
                'scope':'RECORD CODEC ONLY; NO VIEW/COMMIT/MIGRATION QUALIFICATION'},sort_keys=True,indent=2)+'\n')

    def log(self,value):
        if self.ledger:
            self.ledger.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n');self.ledger.flush()

    def invoke(self,raw,work,output_size=256):
        before=bytes(work);original=bytes(raw)
        owners=[_Owner(-1,bytearray(original)),_Owner(-2,bytearray(output_size)),_Owner(-3,work)]
        machine=_Machine(self.program,8000000,128<<20,None,64)
        code=machine.invoke(self.entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        out=bytes(owners[1].data);type(self).entries+=1
        self.assertEqual(bytes(owners[0].data),original)
        if code in (0,2) and len(raw)>=16:type(self).commands.add(struct.unpack_from('<Q',raw,8)[0])
        self.log({'kind':'vm_entry','entry':type(self).entries,'test_id':self.id(),'input_hex':original.hex(),'output_hex':out.hex(),
                  'workspace_before_hex':before.hex(),'workspace_after_hex':bytes(work).hex(),'return':code,'output_descriptor_bytes':output_size})
        return code,out

    def observe(self,kind,expected,actual):
        type(self).observations+=1;self.assertEqual(actual,expected)
        self.log({'kind':kind,'test_id':self.id(),'expected_hex':expected.hex(),'actual_hex':actual.hex()})

    def reject(self,raw,state=None,output_size=256):
        work=bytearray(1024 if state is None else state)
        self.assertEqual(self.invoke(raw,work,output_size)[0],BAD)
        after=bytes(work)
        self.assertEqual(self.invoke(frame(4),work)[0],BAD)
        self.assertEqual(bytes(work),after)

    def test_all_ten_schemas_five_classes_and_sequence_cells(self):
        cells=[(0,b''),(1,struct.pack('<Q',MASK)),(2,struct.pack('<d',float('inf'))),(3,b'\x00\xfftext'),(4,b'\x00\xffblob')]
        enc=Session(self);dec=Session(self)
        for table,width in WIDTH.items():
            body=payload([cells[i%len(cells)] for i in range(width)])
            raw=enc.encode(1,table,-table,body,[body[:7],body[7:]])
            dec.decode(raw,[raw[:19],raw[19:65],raw[65:-3],raw[-3:]],(1,table,-table,body))
            raw=enc.encode(2,table,table,b'',[])
            dec.decode(raw,[raw],(2,table,table,b''))
        for cell in cells+[(2,struct.pack('<Q',0x7ff8000000000001))]:
            body=payload([cell]);raw=enc.encode(3,5,0,body,[body])
            dec.decode(raw,[raw],(3,5,0,body))

    def test_every_byte_boundary_through_header_values_and_footer(self):
        body=payload([(0,b''),(1,struct.pack('<q',-9)),(3,b'a\x00\xff')])
        raw=record(1,2,MASK,body)
        for cut in range(len(raw)+1):
            with self.subTest(decode_cut=cut):
                Session(self).decode(raw,[raw[:cut],raw[cut:]],(1,2,MASK,body))
        for cut in range(len(body)+1):
            with self.subTest(encode_cut=cut):
                Session(self).encode(1,2,MASK,body,[body[:cut],body[cut:]])

    def test_grow_retains_parser_state_and_malformed_precedes_capacity(self):
        body=payload([(3,b'abc')]*3)
        state=bytearray(1024)
        first=frame(1,meta=(1,2,1,len(body)))
        code,out=self.invoke(first,state,192);self.assertEqual(code,1)
        self.assertEqual(struct.unpack_from('<Q',state,32)[0],0)
        wrong=bytearray(first);struct.pack_into('<Q',wrong,56,2)
        self.reject(wrong,state)
        code,out=self.invoke(first,state,256);self.assertEqual(code,2)
        main=bytes(state[:320]);chunk=frame(2,sequence=1,meta=(1,2,1,len(body)),body=body,source=91)
        code,out=self.invoke(chunk,state,192);self.assertEqual(code,1)
        self.assertEqual(state[16:320],main[16:320])
        code,out=self.invoke(chunk,state,192+len(body));self.assertEqual(code,2)
        self.assertEqual(out[192:],body)
        bad_body=struct.pack('<Q',4)+body[8:]
        session=Session(self);session.encode_begin(1,2,1,body)
        invalid=frame(2,sequence=1,meta=(1,2,1,len(body)),body=bad_body,source=91)
        self.reject(invalid,session.work,192)

    def test_header_footer_value_mutations_and_truncation(self):
        body=payload([(0,b''),(1,bytes(8)),(3,b'z')]);valid=record(1,2,1,body)
        mutations=[]
        for offset,value in [(0,0),(8,2),(16,0),(16,4),(24,0),(24,11),(40,MASK),(48,len(valid)+1),(56,1),
                             (64,2),(72,5),(80,1),(96,7),(len(valid)-16,len(valid)-1),(len(valid)-8,0)]:
            bad=bytearray(valid);struct.pack_into('<Q',bad,offset,value);mutations.append(bytes(bad))
        mutations.extend([valid+b'x',valid[:-1],valid[:63],valid[:64],valid[:80]])
        for raw in mutations:
            session=Session(self);session.decode_begin()
            incoming=frame(5,sequence=1,body=raw,source=9)
            code,_=self.invoke(incoming,session.work)
            if code!=BAD:
                self.assertEqual(code,2)
                self.reject(frame(6,sequence=2,offset=len(raw)),session.work)
            else:
                self.reject(frame(4),session.work)
        for meta in [(0,1,0,0),(4,1,0,0),(1,0,0,100),(1,11,0,100),(2,1,0,1),(3,1,0,24),(3,5,1,24),(1,1,0,MASK)]:
            self.reject(frame(1,meta=meta))

    def test_large_raw_text_blob_actual_file_and_bounded_streams(self):
        body=payload([(4,bytes(range(256))*4096),(3,b'9'*16385),(0,b'')])
        enc=Session(self);chunks=[body[i:i+8192] for i in range(0,len(body),8192)]
        raw=enc.encode(1,2,-(1<<63),body,chunks)
        with tempfile.TemporaryDirectory(prefix='hia-native-record-') as directory:
            path=Path(directory)/'unpublished-record.bin'
            with path.open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            before=path.stat();dec=Session(self);dec.decode_begin();offset=0
            with path.open('rb') as stream:
                while True:
                    chunk=stream.read(16384)
                    if not chunk:break
                    code,h,out=dec.send(5,body=chunk);self.assertEqual((code,out),(2,b''),h)
                    dec.offset+=len(chunk);offset+=len(chunk)
            code,h,out=dec.send(6);self.assertEqual((code,out),(0,b''),h)
            after=path.stat();self.assertEqual((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns),
                                             (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
            self.assertEqual(offset,len(raw));self.observe('actual_file_bytes',raw,path.read_bytes())

    def test_session_sequence_extent_and_counter_refusals(self):
        body=payload([(0,b'')]*3);s=Session(self);s.encode_begin(1,2,1,body)
        valid=frame(2,sequence=1,meta=(1,2,1,len(body)),body=body,source=7)
        for offset,value in [(0,0),(8,5),(16,999),(24,999),(32,2),(40,0),(40,2),(48,0),(56,2),
                             (64,2),(72,3),(80,2),(88,len(body)+1),(96,1),(104,len(body)+1),(112,1),(120,1)]:
            bad=bytearray(valid);struct.pack_into('<Q',bad,offset,value);self.reject(bad,s.work)
        for cut in [0,1,63,127]:self.reject(valid[:cut],s.work)
        self.reject(frame(3,sequence=1,meta=(1,2,1,len(body))),s.work)
        altered=bytearray(s.work);struct.pack_into('<Q',altered,48,MASK);self.reject(valid,altered)
        altered=bytearray(s.work);struct.pack_into('<Q',altered,8,1);self.reject(valid,altered)
        altered=bytearray(s.work);struct.pack_into('<Q',altered,192,65);self.reject(valid,altered)
        altered=bytearray(s.work);struct.pack_into('<Q',altered,304,1);self.reject(valid,altered)
        for frames in ([frame(4),frame(5,sequence=1,source=9,body=b'H')],
                       [frame(1,meta=(2,1,1,0))],
                       [frame(4),frame(5,sequence=1,source=9,body=record(2,1,1,b''))]):
            work=bytearray(1024)
            for request in frames:self.assertEqual(self.invoke(request,work)[0],2)
            struct.pack_into('<Q',work,8,1)
            self.reject(frame(4,operation=2,lease=2),work)
        self.assertEqual(self.invoke(frame(4),bytearray(1023))[0],BAD)
        self.reject(frame(4),output_size=191)

    def test_repeated_records_close_and_no_restart(self):
        s=Session(self)
        for n in range(4):s.encode(2,n+1,n,b'',[])
        previous=bytes(s.work)
        self.reject(frame(4,operation=s.operation+1,lease=s.lease),previous)
        self.reject(frame(4,operation=s.operation+2,lease=s.lease+1),previous)
        s.operation+=1;s.lease=0;s.meta=(0,0,0,0);s.offset=0
        code,h,out=s.send(7);self.assertEqual((code,out),(0,b''))
        after=bytes(s.work);self.reject(frame(4,operation=s.operation+1,lease=9),after)
        self.reject(frame(7,operation=s.operation+1,lease=0),after)

    def test_seeded_random_cell_stream_roundtrips(self):
        rng=random.Random(0x4849414c4f47)
        enc=Session(self);dec=Session(self)
        for case in range(32):
            table=rng.randrange(1,11);cells=[]
            for _ in range(WIDTH[table]):
                kind=rng.randrange(5);size=0 if kind==0 else 8 if kind in (1,2) else rng.randrange(80)
                cells.append((kind,rng.randbytes(size)))
            body=payload(cells);rowid=rng.getrandbits(64)
            chunks=[];i=0
            while i<len(body):
                end=min(len(body),i+rng.randrange(1,42));chunks.append(body[i:end]);i=end
            raw=enc.encode(1,table,rowid,body,chunks)
            chunks=[];i=0
            while i<len(raw):
                end=min(len(raw),i+rng.randrange(1,58));chunks.append(raw[i:end]);i=end
            dec.decode(raw,chunks,(1,table,rowid,body))
