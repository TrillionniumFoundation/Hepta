"""Observe actual native page policy through mechanical private-file I/O.

The Python adapter executes only emitted pread/pwrite actions. Independent
record fixtures and a complete structural walk check the resulting disk tree;
this component observer does not claim an installed/public cache owner.
"""
from __future__ import annotations
import argparse
import ctypes
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import time

from hepta.hia_json_preflight_native import NativeHiaJsonImage

MASK = (1 << 64)-1
PAGE = 4096
STATE = 65536


def record(n, *, owner='a'*64, tool='file_info', accepted=None, state=0,
           elapsed=None, stamp=1):
    raw = bytearray(384)
    raw[:64] = f'{n:064x}'.encode()
    raw[64:128] = owner.encode()
    raw[128:128+len(tool)] = tool.encode()
    accepted = n if accepted is None else accepted
    struct.pack_into('<6Q', raw, 192, len(tool), state, accepted & MASK,
                     accepted >> 64, int(elapsed is not None), elapsed or 0)
    struct.pack_into('<Q', raw, 240, stamp)
    return bytes(raw)


class Observer:
    def __init__(self, image, path, stream, counts):
        self.image, self.path = image, path
        self.stream, self.counts = stream, counts
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.reset()

    def reset(self):
        self.storage = ctypes.create_string_buffer(b'\xa5'*(STATE+64))
        self.address = ctypes.addressof(self.storage)+32
        ctypes.memset(self.address, 0, STATE)
        self.out = ctypes.create_string_buffer(4160+32)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def step(self, raw):
        src = ctypes.create_string_buffer(raw)
        ctypes.memset(self.out, 0xa7, 4160+32)
        result = self.image._entry(src, len(raw), self.out, 4160, self.address, STATE)
        assert result in (64, 448, 4160), result
        answer = bytes(self.out.raw[:result])
        assert self.out.raw[result:] == b'\xa7'*(4160+32-result)
        assert src.raw[:len(raw)] == raw
        assert ctypes.string_at(self.address-32,32) == ctypes.string_at(self.address+STATE,32) == b'\xa5'*32
        self.stream.write(struct.pack('<QQ',len(raw),result)+raw+answer)
        self.counts['calls'] += 1
        self.counts['raw_bytes'] += 16+len(raw)+len(answer)
        return answer

    def call(self, op, data=b'', fault=None):
        raw = struct.pack('<8Q',op,0,0,0,0,0,0,0)+data
        budget = 256
        while budget:
            budget -= 1
            answer = self.step(raw)
            kind, page = struct.unpack_from('<2Q',answer)
            if kind in (0,3):
                return struct.unpack('<8Q',answer[:64]), answer[64:]
            assert 0 <= page < (1 << 51)
            if kind == 1:
                assert len(answer) == 64
                chunk = os.pread(self.fd, PAGE, page*PAGE)
                self.counts['reads'] += 1
                size = len(chunk)
                if fault:
                    size, chunk = fault('read',page,size,chunk)
                raw = struct.pack('<8Q',size & MASK,0,0,0,0,0,0,0)+chunk
            else:
                assert kind == 2 and len(answer) == 4160
                chunk = answer[64:]
                size = os.pwrite(self.fd, chunk, page*PAGE)
                self.counts['writes'] += 1
                if fault:
                    size, _ = fault('write',page,size,b'')
                raw = struct.pack('<8Q',size & MASK,0,0,0,0,0,0,0)
        raise AssertionError('native tree continuation exceeded depth-derived bound')


def walk(path):
    """Check every reachable page against independent map and B+ tree invariants."""
    with path.open('rb') as f:
        head=f.read(PAGE)
        assert head[:8] == b'HIARIX01'
        version,root,nxt,count,generation=struct.unpack_from('<5Q',head,8)
        assert version == 1 and 0 < root < nxt and head[48:] == bytes(PAGE-48)
        seen=set(); entries={}; leaf_depths=set()
        def visit(page,depth):
            assert page not in seen and 0 < page < nxt and depth < 32
            seen.add(page); f.seek(page*PAGE); raw=f.read(PAGE)
            assert len(raw) == PAGE and raw[:8] == b'HIARIP01'
            kind,n=struct.unpack_from('<2Q',raw,8)
            assert raw[24:64] == bytes(40)
            if kind == 1:
                assert n <= 10
                rows=[raw[64+i*384:64+(i+1)*384] for i in range(n)]
                keys=[row[:64] for row in rows]
                assert keys == sorted(set(keys))
                assert raw[64+n*384:] == bytes(PAGE-64-n*384)
                for key,row in zip(keys,rows):
                    assert key not in entries
                    entries[key]=row
                leaf_depths.add(depth)
                return (keys[0],keys[-1]) if keys else (None,None)
            assert kind == 2 and 1 <= n <= 55
            keys=[raw[72+i*72:136+i*72] for i in range(n)]
            assert keys == sorted(set(keys))
            assert raw[72+n*72:] == bytes(PAGE-72-n*72)
            bounds=[visit(struct.unpack_from('<Q',raw,64+i*72)[0],depth+1) for i in range(n+1)]
            for i,key in enumerate(keys):
                assert bounds[i][1] < key == bounds[i+1][0]
            return bounds[0][0],bounds[-1][1]
        visit(root,0)
        assert len(entries) == count and len(leaf_depths) == 1
        return entries, {'root':root,'next':nxt,'rows':count,'generation':generation,
                         'reachable_pages':len(seen),'depth':next(iter(leaf_depths))}


def qualify(image_path, construction, output, size):
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    image_bytes=image_path.read_bytes(); pin=sha256(image_bytes).hexdigest()
    assert json.loads(construction.read_text())['image_sha256'] == pin
    image=NativeHiaJsonImage(image_bytes,pin)
    report={'schema':'hepta.hia.native-index-page-controls.v1','passed':False,
            'native_image_sha256':pin,'observer_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
            'checks':[],'counts':{'calls':0,'raw_bytes':0,'reads':0,'writes':0},
            'whole_cold_qualified':False,'whole_runtime_qualified':False,'public_integration_qualified':False,
            'original_rust_parity_claimed':False,'state_bytes':STATE,'page_bytes':PAGE}
    def check(label, condition):
        assert condition,label
        report['checks'].append({'case':label,'passed':True})
    stream=gzip.open(output/'native-observations.bin.gz','wb',compresslevel=1)
    observer=Observer(image,output/'index.pages',stream,report['counts'])
    started=time.monotonic()
    try:
        words,_=observer.call(0); check('private-empty-file-initializes',words[:2]==(0,0) and words[4]==0)
        words,_=observer.call(3); check('begin-owns-transaction',words[5]==1)
        order=list(range(size)); random.Random(2807).shuffle(order)
        expected={}
        for n in order:
            row=record(n,accepted=((1<<96)+n if n%7==0 else n),stamp=n+1)
            words,_=observer.call(2,row)
            assert words[:2]==(0,1),(n,words)
            expected[row[:64]]=row
        words,_=observer.call(4)
        check('random-full-retained-table-commits',words[:2]==(0,0) and words[4]==size and words[5]==0)
        actual,shape=walk(observer.path)
        check('every-retained-record-and-u128-field-match',actual==expected)
        check('real-disk-multilevel-bplus-structure',shape['depth']>=2 if size>=4096 else True)
        report['initial_tree']=shape
        print(json.dumps({'stage':'initial-committed','rows':size,'seconds':time.monotonic()-started}),flush=True)
        for n in range(size):
            key=f'{n:064x}'.encode(); words,row=observer.call(1,key)
            assert words[:2]==(0,1) and row==expected[key]
        check('every-native-lookup-matches-complete-independent-record',True)
        observer.reset(); words,_=observer.call(0)
        check('fresh-native-state-reopens-complete-disk-root',words[4]==size)
        for n in range(0,size,67):
            key=f'{n:064x}'.encode();words,row=observer.call(1,key)
            assert words[:2]==(0,1) and row==expected[key]
        check('reopened-lookup-returns-original-complete-bytes',True)
        prior=observer.path.read_bytes()
        observer.call(3)
        for n in range(min(size,512)):
            row=bytearray(expected[f'{n:064x}'.encode()]);struct.pack_into('<Q',row,200,1)
            struct.pack_into('<2Q',row,224,1,n);struct.pack_into('<Q',row,240,900000+n)
            words,_=observer.call(2,bytes(row)); assert words[:2]==(0,1)
            expected[bytes(row[:64])]=bytes(row)
        live=observer.path.read_bytes()
        check('transaction-never-writes-old-committed-pages',live[:len(prior)]==prior)
        observer.call(4)
        actual,shape=walk(observer.path);check('completion-cohort-commits-complete-records',actual==expected)
        check('commit-only-replaces-root-header-in-old-image',observer.path.read_bytes()[PAGE:len(prior)]==prior[PAGE:])
        before=observer.path.read_bytes(); observer.call(3)
        for n in range(size,size+300):
            words,_=observer.call(2,record(n));assert words[:2]==(0,1)
        words,_=observer.call(5)
        check('rollback-restores-transaction-root-and-count',words[4]==size and words[5]==0)
        check('rollback-retains-complete-previous-committed-image',observer.path.read_bytes()[:len(before)]==before)
        observer.reset();observer.call(0)
        actual,shape=walk(observer.path);check('fresh-reopen-excludes-uncommitted-tail',actual==expected)
        observer.call(3)
        selected=expected[f'{0:064x}'.encode()]
        before=observer.path.read_bytes(); words,_=observer.call(2,selected)
        check('identical-complete-record-is-no-op',words[:2]==(0,0) and observer.path.read_bytes()==before)
        older=bytearray(selected);struct.pack_into('<Q',older,200,0);struct.pack_into('<2Q',older,224,0,0)
        words,_=observer.call(2,bytes(older))
        check('terminal-record-wins-over-older-unknown',words[:2]==(0,0))
        stamped=bytearray(selected);struct.pack_into('<Q',stamped,240,123456789)
        words,_=observer.call(2,bytes(stamped));check('same-record-new-stamp-remains-allowed',words[:2]==(0,1))
        expected[bytes(stamped[:64])]=bytes(stamped);observer.call(4)
        immutable=observer.path.read_bytes()
        for label,offset,value,wanted in [('owner',64,b'b'*64,3),('tool',128,b'host_list',3),
                                            ('accepted',208,struct.pack('<Q',123456),3),
                                            ('terminal',200,struct.pack('<Q',2),4),
                                            ('elapsed',232,struct.pack('<Q',123456),4)]:
            observer.reset();observer.call(0);observer.call(3)
            row=bytearray(stamped);row[offset:offset+len(value)]=value
            words,_=observer.call(2,bytes(row))
            check('reject-original-immutable-'+label,words[:2]==(3,wanted))
            words,_=observer.call(1,bytes(stamped[:64]))
            check('failed-'+label+'-keeps-runtime-poisoned',words[:2]==(3,1))
            check('failed-'+label+'-does-not-publish-root',observer.path.read_bytes()[:len(immutable)]==immutable)
        observer.reset();observer.call(0)
        actual,shape=walk(observer.path);check('all-refusals-retain-last-successful-tree',actual==expected)
        report['final_tree']=shape
        report['passed']=True
    except BaseException as error:
        report['error']=repr(error)
        raise
    finally:
        observer.close();stream.close()
        report['seconds']=time.monotonic()-started
        report['files']=[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()}
                         for p in sorted(output.iterdir()) if p.is_file()]
        (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),
                          'counts':report['counts'],'seconds':report['seconds'],
                          'error':report.get('error')}),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True)
    p.add_argument('--construction',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--rows',type=int,default=16385);a=p.parse_args()
    qualify(a.image,a.construction,a.output,a.rows)
