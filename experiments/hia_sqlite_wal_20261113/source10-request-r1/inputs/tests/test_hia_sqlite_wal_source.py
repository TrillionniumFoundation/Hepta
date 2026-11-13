"""Ten fixed source/VM controls for the WAL byte kernel, without database I/O."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest

from hepta import hia_sqlite_wal_native as bridge
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import generate_hia_sqlite_wal as author

ROOT=Path(__file__).resolve().parents[2]
EXPECTED_NAMES=(
    'test_01_Core_roundtrip_and_original_caps',
    'test_02_both_orders_seeds_and_independent_weighted_checksums',
    'test_03_incremental_composition_across_every_eight_byte_cut',
    'test_04_header_all_page_sizes_and_both_checksum_orders',
    'test_05_protocol_refusals_leave_all_spans_unchanged',
    'test_06_header_magic_size_checksum_and_version_precedence',
    'test_07_frame_chain_and_commit_marker_are_exact_bytes',
    'test_08_frame_corruption_salts_seed_and_zero_page_refuse',
    'test_09_bridge_types_bounds_and_foreign_custody_failures',
    'test_10_two_complete_original_oracles_remain_independent',
)


def weighted_checksum(raw,order,initial=(0,0)):
    """Independent closed-form Fibonacci weights, not the rolling update loop."""
    assert len(raw)>=8 and len(raw)%8==0
    count=len(raw)//8
    fib=[0,1]
    for _ in range(2*count):fib.append((fib[-2]+fib[-1])%2**32)
    a=fib[2*count-1]*initial[0]+fib[2*count]*initial[1]
    b=fib[2*count]*initial[0]+fib[2*count+1]*initial[1]
    for pair in range(count):
        x=int.from_bytes(raw[8*pair:8*pair+4],order)
        y=int.from_bytes(raw[8*pair+4:8*pair+8],order)
        remaining=count-1-pair
        a+=fib[2*remaining+1]*x+fib[2*remaining]*y
        b+=fib[2*remaining+2]*x+fib[2*remaining+1]*y
    return a%2**32,b%2**32


def make_header(order='little',page_size=512,checkpoint=0,salts=(0x12345678,0xabcdef01),version=3007000,magic=None):
    magic=(0x377f0682+int(order=='big')) if magic is None else magic
    raw=struct.pack('>6I',magic,version,page_size,checkpoint,*salts)
    return raw+struct.pack('>2I',*weighted_checksum(raw,order))


def make_frame(page,initial,order='little',page_number=1,commit=0,salts=(0x12345678,0xabcdef01)):
    prefix=struct.pack('>2I',page_number,commit)
    pair=weighted_checksum(prefix+page,order,initial)
    return prefix+struct.pack('>4I',*salts,*pair)+page,pair


def command(operation=1,order=0,seed=(0,0),page=0,salts=(0,0),magic=bridge.MAGIC):
    return struct.pack('<8Q',magic,operation,order,*seed,page,*salts)


class VMImage:
    def __init__(self,program):self.program,self.calls,self.label=program,[],'unlabelled'

    def raw(self,source,output,control):
        owners=[_Owner(-1,bytearray(source)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(control))]
        machine=_Machine(self.program,200000,1<<20,None,256)
        row={'case':self.label,'source_before_hex':bytes(source).hex(),'output_before_hex':bytes(output).hex(),
             'control_before_hex':bytes(control).hex(),'actual_returned':False}
        self.calls.append(row)
        try:
            status=machine.invoke(self.program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            row.update(status=status,actual_returned=True)
        except BaseException as exc:
            row['exception_type']=type(exc).__module__+'.'+type(exc).__qualname__;raise
        finally:
            row.update(source_after_hex=bytes(owners[0].data).hex(),output_after_hex=bytes(owners[1].data).hex(),control_after_hex=bytes(owners[2].data).hex())
        return status,bytes(owners[1].data),bytes(owners[2].data)

    def _entry(self,s,n,o,m,w,k):
        status,out,control=self.raw(ctypes.string_at(s,n),ctypes.string_at(o,m),ctypes.string_at(w,k))
        ctypes.memmove(o,out,m);ctypes.memmove(w,control,k)
        return status


class SQLiteWalSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document=author.document();cls.program=verify_program(cls.document)
        cls.assembly=render_assembly(cls.document);cls.vm=VMImage(cls.program)
        cls.kernel=object.__new__(bridge.NativeSQLiteWal);cls.kernel._entry=cls.vm._entry

    def setUp(self):self.vm.label=self.id()

    @classmethod
    def tearDownClass(cls):
        name=os.environ.get('HEPTA_SQLITE_WAL_SOURCE_EVIDENCE')
        if name is None:return
        root=Path(name)
        values={'sqlite_wal.hiaasm':cls.assembly,'CORE.json':json.dumps(cls.document,sort_keys=True,indent=2)+'\n',
                'VM-RAW.json':json.dumps({'schema':'hia.sqlite-wal.source-vm-raw.v1','native_executed':False,
                                         'compiler_executed':False,'calls':cls.vm.calls},sort_keys=True,indent=2)+'\n'}
        for name,body in values.items():
            with (root/name).open('x',encoding='utf-8') as f:f.write(body);f.flush();os.fsync(f.fileno())

    def refused(self,raw,cmd,capacity,status):
        out=b'\xa5'*capacity;observed=self.vm.raw(raw,out,cmd)
        self.assertEqual(observed,(status,out,cmd))

    def test_01_Core_roundtrip_and_original_caps(self):
        self.assertEqual(assemble_program(self.assembly).as_dict(),self.program.as_dict())
        self.assertEqual(self.assembly,render_assembly(author.document()))
        self.assertLessEqual(len(self.assembly.encode()),1<<20)
        self.assertLessEqual(len(self.assembly.split('\n')),16384)
        funcs=self.document['functions'];blocks=[b for f in funcs for b in f['blocks']]
        self.assertEqual(len(funcs),6);self.assertLessEqual(len(blocks),1536)
        self.assertLessEqual(sum(len(b['ops']) for b in blocks),8192)
        for f in funcs:
            self.assertLessEqual(len(f['blocks']),256);self.assertLessEqual(len(f['params']),16)
        def walk(value):
            if isinstance(value,dict):
                for k,v in value.items():
                    if k in ('args','params') and isinstance(v,list):self.assertLessEqual(len(v),16)
                    yield from walk(v)
            elif isinstance(value,list):
                for v in value:yield from walk(v)
            elif isinstance(value,str) and value.startswith('v') and value[1:].isdigit():yield int(value[1:])
        self.assertLessEqual(max(walk(self.document)),2047)

    def test_02_both_orders_seeds_and_independent_weighted_checksums(self):
        for order in ('little','big'):
            prefix='<' if order=='little' else '>'
            self.assertEqual(self.kernel.checksum(struct.pack(prefix+'2I',1,2),byte_order=order),(1,3))
            self.assertEqual(self.kernel.checksum(struct.pack(prefix+'4I',1,2,3,4),byte_order=order),(7,14))
            self.assertEqual(self.kernel.checksum(b'\xff'*8,byte_order=order,initial=(0xffffffff,0xffffffff)),(0xfffffffd,0xfffffffb))
            for n in (8,16,24,64,128):
                for seed in ((0,0),(1,2),(0xffffffff,0),(0xffffffff,0xffffffff)):
                    raw=bytes((i*73+19)%256 for i in range(n))
                    self.assertEqual(self.kernel.checksum(raw,byte_order=order,initial=seed),weighted_checksum(raw,order,seed))

    def test_03_incremental_composition_across_every_eight_byte_cut(self):
        raw=bytes((i*91+177)%256 for i in range(64))
        for order in ('little','big'):
            for seed in ((0,0),(0x80000000,0xffffffff)):
                expected=weighted_checksum(raw,order,seed)
                for cut in range(8,len(raw),8):
                    middle=self.kernel.checksum(raw[:cut],byte_order=order,initial=seed)
                    self.assertEqual(self.kernel.checksum(raw[cut:],byte_order=order,initial=middle),expected)

    def test_04_header_all_page_sizes_and_both_checksum_orders(self):
        salts=(0,0xffffffff)
        for order in ('little','big'):
            for exponent in range(9,17):
                page=1<<exponent;raw=make_header(order,page,0xffffffff,salts)
                pair=weighted_checksum(raw[:24],order)
                self.assertEqual(self.kernel.header(raw),(*pair,page,0xffffffff,*salts,int(order=='big'),3007000))

    def test_05_protocol_refusals_leave_all_spans_unchanged(self):
        raw=b'\x11'*8;cmd=command()
        for n in (0,1,7,9,15,65537):self.refused(b'\0'*n,cmd,8,bridge.REFUSE_PROTOCOL)
        for n in (0,1,7,9,16):self.refused(raw,cmd,n,bridge.REFUSE_PROTOCOL)
        for invalid in (b'',cmd[:8],cmd[:63],cmd+b'\0',command(magic=0),command(operation=0),command(operation=4),
                        command(order=2),command(seed=(1<<32,0)),command(seed=(0,1<<32)),command(page=512),command(salts=(1,0)),command(salts=(0,1))):
            self.refused(raw,invalid,8,bridge.REFUSE_PROTOCOL)
        header=make_header()
        for n in (0,1,23,24,31,33):self.refused((header+b'\0')[:n],command(2),32,bridge.REFUSE_PROTOCOL)
        for n in (0,8,31,33):self.refused(header,command(2),n,bridge.REFUSE_PROTOCOL)
        for offset in (16,24,32,40,48,56):
            invalid=bytearray(command(2));invalid[offset]=1
            self.refused(header,bytes(invalid),32,bridge.REFUSE_PROTOCOL)
        frame,_=make_frame(b'\0'*512,(0,0));framecmd=command(3,page=512,salts=(0x12345678,0xabcdef01))
        for n in (0,23,24,535,537):self.refused((frame+b'\0')[:n],framecmd,16,bridge.REFUSE_PROTOCOL)
        for page in (0,1,511,513,65537):self.refused(frame,command(3,page=page),16,bridge.REFUSE_PROTOCOL)
        for invalid in (command(3,order=2,page=512),command(3,seed=(1<<32,0),page=512),command(3,page=512,salts=(1<<32,0)),command(3,page=512,salts=(0,1<<32))):
            self.refused(frame,invalid,16,bridge.REFUSE_PROTOCOL)

    def test_06_header_magic_size_checksum_and_version_precedence(self):
        for magic in (0,0x377f0680,0x377f0681,0x377f0684,0xffffffff):
            self.refused(make_header(magic=magic),command(2),32,bridge.REFUSE_FORMAT)
        for page in (0,1,511,513,65535,65537,0xffffffff):
            self.refused(make_header(page_size=page),command(2),32,bridge.REFUSE_FORMAT)
        for order in ('little','big'):
            raw=make_header(order)
            for offset in (12,16,20,24,28,31):
                changed=bytearray(raw);changed[offset]^=1
                self.refused(bytes(changed),command(2),32,bridge.REFUSE_CHECKSUM)
            for version in (0,3007001,0xffffffff):
                self.refused(make_header(order,version=version),command(2),32,bridge.REFUSE_VERSION)
            unsupported=bytearray(make_header(order,version=0));unsupported[24]^=1
            self.refused(bytes(unsupported),command(2),32,bridge.REFUSE_CHECKSUM)

    def test_07_frame_chain_and_commit_marker_are_exact_bytes(self):
        salts=(0x12345678,0xabcdef01)
        for order in ('little','big'):
            header=make_header(order);seed=self.kernel.header(header)[:2]
            for index,page_number in enumerate((1,2,0xffffffff)):
                page=bytes((i*17+index*53)%256 for i in range(512));commit=0 if index<2 else 3
                raw,pair=make_frame(page,seed,order,page_number,commit,salts)
                self.assertEqual(self.kernel.frame(raw,byte_order=order,initial=seed,page_size=512,salts=salts),(*pair,page_number,commit))
                seed=pair

    def test_08_frame_corruption_salts_seed_and_zero_page_refuse(self):
        salts=(0x12345678,0xabcdef01);page=bytes(range(256))*2;seed=(0xdeadbeef,0xffffffff)
        for order in ('little','big'):
            raw,pair=make_frame(page,seed,order,1,2,salts);cmd=command(3,int(order=='big'),seed,512,salts)
            for offset in (8,12,15):
                changed=bytearray(raw);changed[offset]^=1
                self.refused(bytes(changed),cmd,16,bridge.REFUSE_SALT)
            for offset in (4,7,16,20,23,24,len(raw)-1):
                changed=bytearray(raw);changed[offset]^=1
                self.refused(bytes(changed),cmd,16,bridge.REFUSE_CHECKSUM)
            zero,_=make_frame(page,seed,order,0,2,salts)
            self.refused(zero,cmd,16,bridge.REFUSE_FORMAT)
            self.refused(raw,command(3,int(order=='big'),(seed[0]^1,seed[1]),512,salts),16,bridge.REFUSE_CHECKSUM)
            self.refused(raw,command(3,int(order!='big'),seed,512,salts),16,bridge.REFUSE_CHECKSUM)

    def test_09_bridge_types_bounds_and_foreign_custody_failures(self):
        for payload in (bytearray(b'\0'*8),'abcdefgh',None):
            with self.assertRaises(TypeError):self.kernel.checksum(payload,byte_order='little')
        for order in ('native',None,0,True):
            with self.assertRaises(ValueError):self.kernel.checksum(b'\0'*8,byte_order=order)
        for seed in ([0,0],(0,),(-1,0),(True,0),(0,1<<32)):
            with self.assertRaises(ValueError):self.kernel.checksum(b'\0'*8,byte_order='little',initial=seed)
        with self.assertRaises(ValueError):self.kernel.header(b'\0'*65561)
        def bad_entry(kind):
            def entry(s,n,o,m,w,k):
                if kind=='source':ctypes.memset(s,0,n)
                if kind=='control':ctypes.memset(w,0,1)
                if kind=='tail':ctypes.memset(ctypes.addressof(o)+m,255,1)
                if kind=='refused_write':ctypes.memset(o,0,1)
                return {'status':9,'boolean':True}.get(kind,bridge.REFUSE_PROTOCOL)
            return entry
        fake=object.__new__(bridge.NativeSQLiteWal)
        for kind in ('source','control','tail','refused_write','status','boolean'):
            fake._entry=bad_entry(kind)
            with self.assertRaises(bridge.SQLiteWalProtocolError):fake.checksum(b'\x11'*8,byte_order='little')

    def test_10_two_complete_original_oracles_remain_independent(self):
        expected={'3.46.0':(174376,'d4a104b5f3cb807e026a9dbcdb77519358b06b66f76cb6b6ef70e3793379dd62'),
                  '3.53.2':(177651,'64d2a6695fbf5d661a9ccb82d160a5fb18698d7175e41828c5ed9428992c7752')}
        for version,(size,digest) in expected.items():
            root=ROOT/('reference/sqlite-'+version);raw=(root/'wal.c.original').read_bytes()
            self.assertEqual((len(raw),sha256(raw).hexdigest()),(size,digest))
            for filename in ('checksum.inc','decode-frame.inc'):
                excerpt=(root/filename).read_bytes();self.assertIn(excerpt[:-1],raw)
        names={n.name for n in ast.parse(author.source()).body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(names,{'sqlite_wal','check_header','checksum_region','word','control_word','write_u32'})
        self.assertNotIn('sqlite3',bridge.__dict__)
        self.assertNotIn('weighted_checksum',bridge.__dict__)
        abi=json.loads((ROOT/'inputs/hepta/hia_sqlite_wal_abi.json').read_bytes())
        self.assertFalse(abi['database_io_lock_transactions_wal_scan_recovery_or_checkpoint_implemented'])
        self.assertFalse(abi['sqlite_engine_hook_or_default_agent_store_changed'])


if __name__=='__main__':unittest.main()
