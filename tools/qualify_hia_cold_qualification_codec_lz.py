"""External native qualification for the separate bounded HIAQAZ02 codec."""
from __future__ import annotations
import argparse
from collections import Counter
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import time
import traceback
from hepta.hia_json_preflight_native import NativeHiaJsonImage

OLD = b'HIAQAZ01'
NEW = b'HIAQAZ02'
FRAME = b'HIAQCP01'
MAX_RAW = 65504
MAX_ENCODED = 65536
WORK = 4 << 20
GUARD = b'\x91\xd3\x4a\x68' * 4
ROOT = Path(__file__).resolve().parents[1]


def decode(raw: bytes):
    """Independent specification decoder, with no encoder dictionary or state."""
    if not 33 <= len(raw) <= MAX_ENCODED:
        raise ValueError('encoded extent')
    magic, size, payload, mode = struct.unpack('<8s3Q', raw[:32])
    if magic not in (OLD, NEW) or not 1 <= size <= MAX_RAW or payload != len(raw) - 32:
        raise ValueError('header')
    if mode > (1 if magic == OLD else 2):
        raise ValueError('mode')
    if mode == 0:
        if payload != size:
            raise ValueError('raw extent')
        return raw[32:]
    pos = 32
    out = bytearray()
    while pos < len(raw):
        if mode == 1:
            if len(raw) - pos < 8:
                raise ValueError('RLE token')
            token, = struct.unpack_from('<Q', raw, pos)
            pos += 8
            amount = token >> 1
            if not amount:
                raise ValueError('zero token')
            if token & 1:
                if len(raw)-pos < 8 or amount > (size-len(out)) >> 3:
                    raise ValueError('RLE repeat')
                out.extend(raw[pos:pos+8] * amount)
                pos += 8
            else:
                if amount > len(raw)-pos or amount > size-len(out):
                    raise ValueError('RLE literal')
                out.extend(raw[pos:pos+amount])
                pos += amount
        else:
            if len(raw)-pos < 3:
                raise ValueError('LZ token')
            token, amount = struct.unpack_from('<BH', raw, pos)
            pos += 3
            if not amount:
                raise ValueError('zero token')
            if token == 0:
                if amount > len(raw)-pos or amount > size-len(out):
                    raise ValueError('LZ literal')
                out.extend(raw[pos:pos+amount])
                pos += amount
            else:
                if token != 1 or amount < 8 or len(raw)-pos < 2:
                    raise ValueError('LZ match')
                distance, = struct.unpack_from('<H', raw, pos)
                pos += 2
                if distance == 0 or distance > len(out) or amount > size-len(out):
                    raise ValueError('LZ distance/extent')
                for _ in range(amount):
                    out.append(out[-distance])
    if pos != len(raw) or len(out) != size:
        raise ValueError('decoded extent')
    return bytes(out)


class Codec:
    def __init__(self, path: Path):
        self.raw = path.read_bytes()
        self.image = NativeHiaJsonImage(self.raw, sha256(self.raw).hexdigest())
        self.work = ctypes.create_string_buffer(GUARD + bytes(WORK) + GUARD, WORK+32)
        self.address = ctypes.addressof(self.work) + 16
        self.seconds = 0.0

    def call(self, mode, raw, *, capacity=MAX_ENCODED, workspace=WORK, magic=FRAME):
        wire = magic + struct.pack('<Q', mode) + raw
        source = ctypes.create_string_buffer(GUARD + wire + GUARD, len(wire)+32)
        output = ctypes.create_string_buffer(GUARD + b'\xa5'*capacity + GUARD, capacity+32)
        began = time.monotonic()
        result = self.image._entry(ctypes.byref(source,16),len(wire),
                                   ctypes.byref(output,16),capacity,self.address,workspace)
        self.seconds += time.monotonic()-began
        assert source.raw == GUARD + wire + GUARD
        assert output.raw[:16] == GUARD and output.raw[-16:] == GUARD
        assert ctypes.string_at(self.address-16,16) == GUARD
        assert ctypes.string_at(self.address+WORK,16) == GUARD
        after = output.raw[16:-16]
        if result <= capacity:
            assert after[result:] == b'\xa5'*(capacity-result)
            return result, after[:result]
        assert after == b'\xa5'*capacity, ('refused call changed output', result)
        return result, b''

    def poison_decoder_dependencies(self, value):
        ctypes.memset(self.address+700000, value, 65504)
        ctypes.memset(self.address+3276800, value ^ 255, 16384)
        ctypes.memset(self.address+940000, value, 65504)


def chunk(payload, size, *, mode=2, magic=NEW):
    return struct.pack('<8s3Q',magic,size,len(payload),mode)+payload


def qualify(old_path, new_path, folder, journal=None):
    folder.mkdir(parents=True,exist_ok=False)
    old, new = Codec(old_path), Codec(new_path)
    counts=Counter()
    report={'schema':'hepta.hia.cold-journal-lz-qualification.v1','passed':False,
            'scope':'lossless native codec component; final master/archive deadline remains separate',
            'images':{'old':{'path':str(old_path),'sha256':sha256(old.raw).hexdigest()},
                      'new':{'path':str(new_path),'sha256':sha256(new.raw).hexdigest()}},
            'limits':{'raw_bytes':MAX_RAW,'encoded_bytes':MAX_ENCODED,'driver_workspace_bytes':WORK,
                      'dictionary_offset':3276800,'dictionary_bytes':16384},
            'groups':{},'journal':None}
    log=open(folder/'cases.jsonl','x',buffering=1)
    started=time.monotonic()

    def save():
        report['groups']=dict(counts)
        report['elapsed_seconds']=time.monotonic()-started
        report['native_seconds']={'old':old.seconds,'new':new.seconds}
        (folder/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')

    def row(group, name, **fields):
        counts[group]+=1
        log.write(json.dumps({'group':group,'case':name,'passed':True,**fields},separators=(',',':'))+'\n')

    def verify_encoded(group,name,encoded):
        try:
            wanted=decode(encoded)
        except ValueError:
            wanted=None
        result,actual=new.call(1,encoded)
        if wanted is None:
            assert result==0xffffffff and actual==b'',(group,name,result)
        else:
            assert result==len(wanted) and actual==wanted,(group,name,result)
        row(group,name,valid=wanted is not None,encoded_bytes=len(encoded))
        return wanted

    def roundtrip(group,name,raw):
        ro,eo=old.call(0,raw)
        rn,en=new.call(0,raw)
        assert ro==len(eo) and rn==len(en) and 33<=rn<=ro<=MAX_ENCODED,(name,ro,rn)
        assert en[:8]==NEW and decode(eo)==decode(en)==raw
        assert old.call(1,eo)==(len(raw),raw)
        assert new.call(1,eo)==new.call(1,en)==(len(raw),raw)
        if struct.unpack_from('<Q',en,24)[0]<2:
            assert en[8:]==eo[8:],name
        row(group,name,raw_bytes=len(raw),old_bytes=len(eo),new_bytes=len(en),
            mode=struct.unpack_from('<Q',en,24)[0],raw_sha256=sha256(raw).hexdigest(),
            new_sha256=sha256(en).hexdigest())
        return eo,en

    save()
    try:
        rng=random.Random(918746)
        cases=[b'\0',b'\xa5'*65504,bytes(65504),bytes(range(256))*255,b'abcdefgh'*8188,
               rng.randbytes(65504),rng.randbytes(1031),b'abc'+bytes(257),
               b'12345678'*3,b'12345678'*2,b'12345678'*4+b'tail',
               b'ABCDEF01'*7+rng.randbytes(19)+b'XYZ00000'*9]
        encodings=[]
        for index,raw in enumerate(cases):
            eo,en=roundtrip('original-roundtrips',str(index),raw);encodings.append((eo,en))
        original_bad=[(0,b''),(0,bytes(65505)),(1,b'bad')]
        for eo,en in encodings:
            original_bad.extend(((1,eo[:-1]),(1,eo+b'x')))
        eo=encodings[1][0]
        for offset in (0,8,16,24):
            bad=bytearray(eo);bad[offset:offset+8]=b'\xff'*8;original_bad.append((1,bytes(bad)))
        for token in (bytes(8),b'\xff'*8):
            bad=bytearray(eo);bad[32:40]=token;original_bad.append((1,bytes(bad)))
        for index,(mode,raw) in enumerate(original_bad):
            assert old.call(mode,raw)==new.call(mode,raw)==(0xffffffff,b'')
            row('original-refusals',str(index))
        for capacity in (0,1,31):
            assert new.call(0,b'a'*100,capacity=capacity)==(0xfffffffe,b'')
            row('entry-boundaries','short-output-'+str(capacity))
        for mode,raw,kwargs in [(2,b'x',{}),(0,b'x',{'workspace':3293183}),
                                (0,b'x',{'magic':b'BADMAGIC'}),(1,b'x'*65537,{})]:
            assert new.call(mode,raw,**kwargs)==(0xffffffff,b'')
            row('entry-boundaries',str((mode,len(raw),kwargs)))
        save();print('PASS original45 and entry boundaries',flush=True)

        for size in (1,7,8,15,16,23,24,31,32,55,56,63,64,127,128,255,256,511,512,1023,1024,
                     4095,4096,65503,65504):
            for pattern in (b'abcdefghX',b'abc',bytes(range(256))):
                raw=(pattern*((size+len(pattern)-1)//len(pattern)))[:size]
                roundtrip('chunk-boundaries',f'{size}-{len(pattern)}',raw)
        rng=random.Random(0x1a2c03)
        for index in range(1000):
            size=rng.randrange(1,MAX_RAW+1)
            if index%4==0:
                raw=rng.randbytes(size)
            else:
                period=rng.randrange(1,min(size,2048)+1)
                pattern=rng.randbytes(period)
                raw=(pattern*((size+period-1)//period))[:size]
                if index%4==2:
                    raw=raw[:size//2]+rng.randbytes(size-size//2)
            roundtrip('random-structured',str(index),raw)
        save();print('PASS boundaries and 1000 random/structured chunks',flush=True)

        manual=[]
        for distance in (*range(1,17),31,32,63,64,127,255,256,1023,4096,32768,65496):
            prefix=bytes((i*131+37)&255 for i in range(distance))
            amount=min(65504-distance,max(8,distance*2+7))
            body=struct.pack('<BH',0,len(prefix))+prefix+struct.pack('<BHH',1,amount,distance)
            encoded=chunk(body,distance+amount)
            wanted=verify_encoded('overlap-distance',str(distance),encoded)
            for poison in (0,0x6d,0xff):
                new.poison_decoder_dependencies(poison)
                assert new.call(1,encoded)==(len(wanted),wanted)
                row('decoder-dictionary-independent',str(distance)+'-'+str(poison))
            manual.append(encoded)
        encoded=chunk(struct.pack('<BH',0,1)+b'x'+struct.pack('<BHH',1,65503,1),65504)
        assert verify_encoded('overlap-distance','maximum-repeated-match',encoded)==b'x'*65504
        manual.append(encoded)
        valid=chunk(struct.pack('<BH',0,8)+b'abcdefgh'+struct.pack('<BHH',1,8,8),16)
        manual.append(valid)
        invalid=[
            chunk(b'\0\0\0',1),chunk(b'\1\x08\0\1\0',8),
            chunk(struct.pack('<BH',0,1)+b'x'+struct.pack('<BHH',1,7,1),8),
            chunk(struct.pack('<BH',0,1)+b'x'+struct.pack('<BHH',1,8,0),9),
            chunk(struct.pack('<BH',0,1)+b'x'+struct.pack('<BHH',1,8,2),9),
            chunk(struct.pack('<BH',0,1)+b'x'+struct.pack('<BHH',1,65535,1),65504),
            chunk(b'\x02\x01\0x',1),chunk(b'\0\x02\0x',2),
            chunk(b'\0\x01\0x',2),chunk(b'\0\x01\0xy',1),
            chunk(valid[32:],16,magic=OLD),chunk(valid[32:],16,mode=3),
            chunk(valid[32:],0),chunk(valid[32:],65505),
        ]
        for index,raw in enumerate(invalid):
            assert verify_encoded('LZ-invalid',str(index),raw) is None
        rng=random.Random(0xbadc0dec)
        for index in range(2000):
            raw=bytearray(rng.choice(manual+invalid+[x[1] for x in encodings]))
            action=rng.randrange(4)
            if action==0:
                raw=raw[:rng.randrange(len(raw)+1)]
            elif action==1:
                raw.extend(rng.randbytes(rng.randrange(1,9)))
            else:
                at=rng.randrange(len(raw));raw[at]^=rng.randrange(1,256)
            verify_encoded('mutated-grammar',str(index),bytes(raw))
        save();print('PASS overlap/independent decoder and damaged grammar',flush=True)

        if journal is not None:
            physical=sha256();raw_digest=sha256();new_physical=sha256()
            outpath=folder/'repacked.hiaqj'
            raw_total=old_total=new_total=chunks=0
            modes=Counter()
            began=time.monotonic()
            with open(journal,'rb') as source,open(outpath,'xb') as output:
                while True:
                    header=source.read(32)
                    if not header:break
                    assert len(header)==32 and header[:8]==OLD
                    _,raw_size,encoded_size,_=struct.unpack('<8s3Q',header)
                    body=source.read(encoded_size);assert len(body)==encoded_size
                    encoded=header+body;physical.update(encoded)
                    expected=decode(encoded)
                    result,raw=old.call(1,encoded);assert result==raw_size and raw==expected
                    result,rewritten=new.call(0,raw)
                    assert result==len(rewritten) and result<=len(encoded)
                    assert decode(rewritten)==raw and new.call(1,rewritten)==(len(raw),raw)
                    output.write(rewritten);new_physical.update(rewritten);raw_digest.update(raw)
                    raw_total+=len(raw);old_total+=len(encoded);new_total+=len(rewritten);chunks+=1
                    modes[struct.unpack_from('<Q',rewritten,24)[0]]+=1
                    if chunks%1000==0:
                        print('JOURNAL',chunks,raw_total,old_total,new_total,flush=True)
                output.flush()
                import os
                os.fsync(output.fileno())
            assert old_total==journal.stat().st_size
            readback=sha256();unpacked=sha256()
            with open(outpath,'rb') as source:
                while True:
                    header=source.read(32)
                    if not header:break
                    assert len(header)==32 and header[:8]==NEW
                    _,_,size,_=struct.unpack('<8s3Q',header)
                    body=source.read(size);assert len(body)==size
                    frame=header+body;readback.update(frame)
                    result,raw=new.call(1,frame);assert result==len(raw)
                    unpacked.update(raw)
            assert readback.digest()==new_physical.digest() and unpacked.digest()==raw_digest.digest()
            report['journal']={'input':str(journal),'output':str(outpath),'chunks':chunks,
                               'raw_bytes':raw_total,'old_physical_bytes':old_total,'new_physical_bytes':new_total,
                               'old_sha256':physical.hexdigest(),'new_sha256':new_physical.hexdigest(),
                               'complete_raw_sha256':raw_digest.hexdigest(),'native_encode_decode_every_chunk':True,
                               'fsync_then_actual_file_readback_equal':True,'modes':dict(modes),
                               'seconds':time.monotonic()-began}
            row('complete-actual-names-journal','all-chunks',chunks=chunks)
        assert old_path.read_bytes()==old.raw and new_path.read_bytes()==new.raw
        log.close()
        report['cases_sha256']=sha256((folder/'cases.jsonl').read_bytes()).hexdigest()
        report['passed']=True;save()
        print(json.dumps(report),flush=True)
    except BaseException:
        report['error']=traceback.format_exc();save();raise
    finally:
        if not log.closed:log.close()


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--old',type=Path,required=True)
    p.add_argument('--new',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--journal',type=Path)
    a=p.parse_args()
    qualify(a.old.resolve(),a.new.resolve(),a.output.resolve(),None if a.journal is None else a.journal.resolve())


if __name__=='__main__':
    main()
