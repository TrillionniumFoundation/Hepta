"""Offline author and mechanical-capsule controls; not native HIA evidence."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,subprocess,sys,traceback
from qualify_hia_native_path_value import Pipeline,Flat,owner,packer,word,put,caps,ptr,ZERO,MASK,view
def correlation(op,status,pending,known,consumed):
    if status not in ({0,1,6,11}if op==29 else{0,6,11}):return False
    if status==0:return pending==0 and known==1 and consumed==(0 if op==31 else 1)
    if status==1:return pending==0 and known==1 and consumed==0
    if status==6:return known==1 and consumed==0
    if op==31:return known==1 and consumed==0
    if known==0:return consumed==0 and pending==0
    return True
def child_case(case):
    p=Pipeline();v=p.values;result=v.scalar('retained');obj=p.native_object('Actual',lambda:(0,result))
    if case=='postconsume-no-pending':p.drop_faults=[dict(status=11,consume=True)]
    elif case=='unknown-consumption':p.drop_faults=[dict(status=11,known=0)]
    elif case=='retained-cap-and-mapping-pending':p.drop_faults=[dict(status=11,known=1,consumed=0,pending=1)]
    elif case=='contradictory-success':p.drop_faults=[dict(status=0,consumed=1,pending=1)]
    elif case=='outside-producer-domain':p.drop_faults=[dict(status=999,consumed=1)]
    elif case.startswith('callback-'):p.callback_fault=case[9:]
    else:raise AssertionError(case)
    out=p.convert(obj);assert word(out,8)==4 and word(out,96)==1 and word(out,104)==1,(case,out.hex())
    assert p.callback_calls==1
    old=p.w.raw;before=word(p.engine.w,88);out=p.convert(mode=2)
    assert word(out,104)==1 and p.w.raw==old and word(p.engine.w,88)==before and p.callback_calls==1
    receiver=caps(p.w,512)
    if case=='retained-cap-and-mapping-pending':assert word(p.w,416)==1
    if case=='postconsume-no-pending':assert receiver==ZERO
    else:assert receiver!=ZERO
    return dict(name=case,frame_state=word(p.w,128),held_nodes=before,receiver_consumed=receiver==ZERO,passed=True)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output');ap.add_argument('--child');args=ap.parse_args()
    if args.child:print(json.dumps(child_case(args.child)));return
    dest=Path(args.output);dest.mkdir(parents=True,exist_ok=False);rows=[];p=Pipeline();ns=p.owner_ns
    for op in(29,31):
        for status in list(range(17))+[999,MASK]:
            for bits in range(8):
                pending=bits&1;known=(bits>>1)&1;consumed=bits>>2
                o=bytearray(32768);o[8192:8200]=b'HIABVR02'
                for at,x in((8200,status),(8272,pending),(8280,known),(8288,consumed)):put(o,at,x)
                got=ns['drop_ok'](o,op);want=correlation(op,status,pending,known,consumed)
                assert got==want,(op,status,pending,known,consumed,got,want)
                rows.append(dict(name='closed-drop-correlation',op=op,status=status,pending=pending,known=known,consumed=consumed,accepted=got))
    for op in(29,31):
        for at in list(range(16,80,8))+list(range(104,128,8)):
            o=bytearray(32768);o[8192:8200]=b'HIABVR02';put(o,8280,1);put(o,8288,0 if op==31 else 1);put(o,8192+at,1)
            assert ns['drop_ok'](o,op)==False
            rows.append(dict(name='drop-reserved-field',op=op,offset=at))
    p.finish()
    for case in('postconsume-no-pending','unknown-consumption','retained-cap-and-mapping-pending','contradictory-success','outside-producer-domain','callback-bad-context','callback-bad-magic','callback-bad-reserved','callback-borrowed-cap'):
        proc=subprocess.run([sys.executable,__file__,'--child',case],capture_output=True,text=True,timeout=30)
        (dest/(case+'.stdout')).write_text(proc.stdout);(dest/(case+'.stderr')).write_text(proc.stderr)
        assert proc.returncode==0,(case,proc.returncode,proc.stderr)
        rows.append(json.loads(proc.stdout))
    for phase in(50,102,110,113):
        p=Pipeline();v=p.values;result=v.scalar(None);obj=p.native_object('Allocation',lambda:(0,result));before=word(p.engine.w,88)
        p.mmap_faults.add(phase);out=p.convert(obj)
        assert word(out,8)==3 and word(out,96)==word(out,104)==0 and word(p.engine.w,88)==before,(phase,out.hex(),before,word(p.engine.w,88))
        assert p.callback_calls==(0 if phase==50 else 1)
        v.drop(obj);v.drop(result);p.finish();rows.append(dict(name='author-allocation-continuation',phase=phase,passed=True))
    # Private framing and range rejection must happen before touching context.
    p=Pipeline();s=C.create_string_buffer(128);o=C.create_string_buffer(32768);w=p.w
    good=bytearray(128);good[:8]=b'HIANPV01';put(good,16,1)
    private=[]
    for at in[0,8]+list(range(40,128,8)):
        raw=bytearray(good);put(raw,at,MASK);private.append(raw)
    for raw in private:
        C.memmove(s,bytes(raw),128);before=w.raw
        rc=p.image.f(s,128,o,32768,w,4096);assert rc==0xfffffffd and w.raw==before
        rows.append(dict(name='private-frame-rejected',passed=True))
    C.memmove(s,bytes(good),128)
    views=[(s,128,o,32767,w,4096),(s,128,o,32768,w,4095),(s,128,w,32768,w,4096),(w,128,o,32768,w,4096),(o,128,o,32768,w,4096),(s,128,o,MASK,w,4096),(s,128,o,32768,w,MASK),(MASK-32,128,o,32768,w,4096)]
    for spans in views:
        before=w.raw;rc=p.image.f(*spans);assert rc==0xfffffffd and w.raw==before;rows.append(dict(name='mechanical-borrowed-range-control',passed=True))
    p.finish()
    # HIA packer author and independent ELF layout agree, including flat view.
    n=dict(length=len,byte=lambda b,i:b[i],store=lambda b,i,v:b.__setitem__(i,v&255))
    exec('from __future__ import annotations\n'+packer.source_program(),n)
    for sizes in((1,1),(15,16),(16,17),(33,257)):
        flats=[bytes((i*17+j)&255 for j in range(size))for i,size in enumerate(sizes)]
        for mode in(0,1):
            s=struct.pack('<8s4Q',b'HIANPP01',2,*sizes,mode)+b''.join(flats)
            expected=packer.reference_flat(flats)if mode else packer.reference_object(flats)
            o=bytearray(b'\xa5'*len(expected));w=bytearray(512);rc=n['pack'](s,o,w)
            assert rc==len(expected)and o==expected,(sizes,mode,rc,len(expected))
            short=bytearray(b'\xa5'*(len(expected)-1));assert n['pack'](s,short,w)==0xfffffffe and short==b'\xa5'*len(short)
            rows.append(dict(name='packer-author-full-byte-layout',sizes=sizes,mode=mode,bytes=len(expected)))
    report=dict(schema='hia.native-path-value.controls.v1',scope='development-authors-and-actual-mechanical-capsule-only',native_hia_executed=False,passed=len(rows),rows=rows,whole_public_path_closed=False)
    (dest/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in('scope','passed','native_hia_executed')}))
if __name__=='__main__':main()
