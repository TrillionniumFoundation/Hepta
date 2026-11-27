"""Independent real CPU controls for the composed div/word native seed.

Original div and word emitters remain separate comparisons. Fixtures below
construct the compact resource/scalar wire directly. Expected data uses integer
arithmetic and complete guarded memory. No whole cold qualification is claimed.
"""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import resource
import signal
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds
from tools.qualify_hia_seed_cold_backend import Wire, call

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64)-1
GUARD = b'\x9d'*32


def pin(raw):
    return {'bytes':len(raw), 'sha256':sha256(raw).hexdigest()}


def fixture(mode, *, descriptor=(26,4,3,0), inputs=3, outputs=0):
    wire = Wire(16)
    wire.label('entry', function=True)
    for slot, value in ((3,0),(4,8),(12,517)):
        wire.constant(slot, value)
    read = wire.words([24,3,2,1])
    wire.op(38, read, wire.words([0,3]), 2, wire.words([5]), 1)
    wire.op(38, read, wire.words([0,4]), 2, wire.words([6]), 1)
    if mode in ('div','mixed'):
        wire.op(7,7,5,6,0,64,0,9)
        wire.op(8,8,5,6,0,64,0,9)
    if mode == 'div':
        wire.snapshot([7,8], 9)
    else:
        write = wire.words(descriptor)
        slots = [2,5,6] if mode == 'word' else [2,3,7]
        wire.op(38, write, wire.words(slots[:inputs]), inputs,
                wire.words([13] if outputs else []), outputs)
        if mode == 'mixed':
            wire.op(38, write, wire.words([2,4,8]), 3, wire.words([]), 0)
    wire.returned(12)
    return wire.pack()


def invoke(native, raw, output, before, extent=None, *, trap=False):
    source = ctypes.create_string_buffer(GUARD+raw+GUARD, len(raw)+64)
    full = GUARD+output+GUARD+before+GUARD
    region = mmap.mmap(-1, len(full), flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ|mmap.PROT_WRITE)
    region[:] = full
    view = (ctypes.c_char*len(full)).from_buffer(region)
    out_at, work_at = 32, 64+len(output)
    arguments = (ctypes.byref(source,32),len(raw),ctypes.byref(view,out_at),len(output),
                 ctypes.byref(view,work_at),len(before) if extent is None else extent)
    try:
        if trap:
            pid = os.fork()
            if pid == 0:
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                signal.alarm(5)
                native._entry(*arguments)
                os._exit(111)
            status = os.waitpid(pid,0)[1]
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGILL,status
        else:
            assert native._entry(*arguments)==517
        got = region[:]
        assert got[:32]==GUARD and got[32+len(output):work_at]==GUARD and got[-32:]==GUARD
        assert source.raw==GUARD+raw+GUARD
        return got[out_at:out_at+len(output)],got[work_at:work_at+len(before)]
    finally:
        del arguments,view
        region.close()


def qualify(bootstrap, output):
    seeds = HistorySeeds(ROOT,bootstrap,output)
    kept = []
    report = {'schema':'hepta.hia.div-word-native-controls.v1','passed':False,
              'whole_cold_qualified':False,'source_pins':{},'counts':{},'products':{}}
    observations = (output/'observations.jsonl').open('x')
    def image(raw):
        item = NativeHiaJsonImage(raw,sha256(raw).hexdigest());kept.append(item);return item
    def observe(group, **detail):
        report['counts'][group] = report['counts'].get(group,0)+1
        observations.write(json.dumps({'group':group,**detail},separators=(',',':'))+'\n')
    def emit(compiler, wire):
        result = call(compiler,wire,b'\xa5'*(1<<20),b'\x6d'*(1<<20))
        assert 0 < result[0] <= 1<<20,result[0]
        assert result[2][result[0]:]==b'\xa5'*((1<<20)-result[0])
        return result[2][:result[0]]
    try:
        sources = {name:(ROOT/'examples/hia_bootstrap'/('seed_'+name+'_backend.hepta')).read_bytes()
                   for name in ('div','word','div_word')}
        report['source_pins'] = {name:pin(raw) for name,raw in sources.items()}
        core = seeds.invoke(output/'hia-seed-assembly',sources['div_word'],'--agent-compact')
        source_wire = seeds.invoke(output/'hia-seed-projector',b'['+core+b',"f0",1]')
        b1 = seeds.invoke(output/'hia-seed-backend',source_wire);new=image(b1)
        b2 = emit(new,source_wire);next_image=image(b2)
        b3 = emit(next_image,source_wire);assert b2==b3
        div = image(seeds.compile(sources['div'],'v1'))
        word = image(seeds.compile(sources['word'],'v1'))
        report['fixedpoint'] = {'B1':pin(b1),'B2':pin(b2),'B3':pin(b3),
                               'B2_equals_B3':True,'B1_equals_B2':b1==b2}
        for label,raw in (('B1',b1),('B2',b2),('B3',b3)):
            (output/(label+'.flat')).write_bytes(raw)
        wires = {name:fixture(name) for name in ('div','word','mixed')}
        compiled = {}
        for name,wire in wires.items():
            raw = emit(new,wire);assert emit(next_image,wire)==raw
            compiled[name] = image(raw)
            report['products'][name] = {'wire':pin(wire),'image':pin(raw)}
            (output/(name+'.wire')).write_bytes(wire);(output/(name+'.flat')).write_bytes(raw)
        assert emit(div,wires['div'])==emit(new,wires['div'])
        assert emit(word,wires['word'])==emit(new,wires['word'])
        observe('original-div-code-identical')
        observe('original-word-code-identical')
        for label,compiler,wire in [('word-refuses-div',word,wires['div']),
                                    ('div-refuses-word',div,wires['word'])]:
            response = call(compiler,wire,b'\xa5'*(1<<20),b'\x6d'*(1<<20))
            assert response[0]>1<<20 and response[2]==b'\xa5'*(1<<20)
            observe('original-capability-refusals',case=label,status=response[0])
        values = (0,1,2,7,255,256,(1<<32)-1,1<<32,(1<<63)-1,1<<63,MASK)
        for left in values:
            for right in values[1:]:
                raw = struct.pack('<2Q',left,right)
                expected = struct.pack('<2Q',left//right,left%right)
                o,w = invoke(compiled['div'],raw,b'\x35'*32,b'\x4a'*32)
                assert o==expected+b'\x35'*16 and w==b'\x4a'*32
                o,w = invoke(compiled['mixed'],raw,b'\x35'*32,b'\x4a'*32)
                assert o==b'\x35'*32 and w==expected+b'\x4a'*16
                observe('div-rem-mixed',left=left,right=right)
        for extent in (8,9,15,16,31,64,255):
            for at in sorted({0,extent-8,1 if extent>8 else 0}):
                for value in values:
                    before = bytes((i*17+3)%256 for i in range(extent+16))
                    expected = before[:at]+struct.pack('<Q',value)+before[at+8:]
                    o,w = invoke(compiled['word'],struct.pack('<2Q',at,value),
                                 b'\x35'*8,before,extent)
                    assert o==b'\x35'*8 and w==expected
                    observe('whole-word-bounds',extent=extent,offset=at,value=value)
        for extent,at in ((0,0),(7,0),(8,1),(16,9),(16,16),(16,MASK),(16,MASK-3)):
            before=b'\x4a'*64
            o,w=invoke(compiled['word'],struct.pack('<2Q',at,MASK),b'\x35'*8,before,extent,trap=True)
            assert o==b'\x35'*8 and w==before
            observe('word-whole-range-traps',extent=extent,offset=at)
        for name in ('div','mixed'):
            o,w=invoke(compiled[name],struct.pack('<2Q',MASK,0),b'\x35'*32,b'\x4a'*32,trap=True)
            assert o==b'\x35'*32 and w==b'\x4a'*32
            observe('division-zero-traps',program=name)
        invalid=[('readonly-kind',(26,3,3,0),3,0),('wrong-input-arity',(26,4,2,0),2,0),
                 ('wrong-output-arity',(26,4,3,1),3,1),('unknown-resource',(27,4,3,0),3,0)]
        for label,descriptor,inputs,outputs in invalid:
            wire=fixture('word',descriptor=descriptor,inputs=inputs,outputs=outputs)
            results=[call(compiler,wire,b'\xa5'*(1<<20),b'\x6d'*(1<<20)) for compiler in (word,new,next_image)]
            assert len({result[0] for result in results})==1
            assert results[0][0]>1<<20 and all(result[2]==b'\xa5'*(1<<20) for result in results)
            observe('original-word-admission-refusals',case=label,status=results[0][0])
        for at in ((1<<32)-1,(1<<32)+1,(1<<32)+4095):
            extent=at+8
            region=mmap.mmap(-1,extent+16,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS|0x4000,
                             prot=mmap.PROT_READ|mmap.PROT_WRITE)
            before=b'\x6e'*32;region[at-8:at+24]=before
            view=ctypes.c_char.from_buffer(region)
            source=ctypes.create_string_buffer(struct.pack('<2Q',at,0x0123456789abcdef),16)
            target=ctypes.create_string_buffer(b'\x35'*8,8)
            try:
                assert compiled['word']._entry(source,16,target,8,ctypes.byref(view),extent)==517
                assert region[at-8:at+24]==b'\x6e'*8+struct.pack('<Q',0x0123456789abcdef)+b'\x6e'*16
                assert target.raw==b'\x35'*8
            finally:
                del view
                region.close()
            observe('real-sparse-above-u32',offset=at)
        report['passed']=True
        return report
    finally:
        observations.close();seeds.save()
        (output/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(qualify(args.bootstrap.resolve(),args.output.resolve()),sort_keys=True))


if __name__=='__main__':
    main()
