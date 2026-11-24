"""Development differential qualification for native LZ forward-copy helpers.

Both helper images are independently compiled six-word ABI entry points taking
four little-endian u64 words (to, source, size, distance).  Invalid and mismatched
inputs run in forked children so the original trap and partial writes remain
observable.  This does not alter the production cold oracle or its budget.
"""
from __future__ import annotations
import argparse, ctypes, json, mmap, os, random, resource, signal, struct, time
from collections import Counter
from hashlib import sha256
from pathlib import Path
from hepta.hia_json_preflight_native import NativeHiaJsonImage

MASK=(1<<64)-1
GUARD=bytes.fromhex('91d34a68')*8

class Image:
    def __init__(self,path):
        self.path=Path(path); self.raw=self.path.read_bytes()
        self.image=NativeHiaJsonImage(self.raw,sha256(self.raw).hexdigest())
    def call(self,params,initial,*,forked=False,source_alias=None,output_alias=None):
        n=len(initial); raw=struct.pack('<4Q',*params)
        w=bytearray(initial)
        if source_alias is not None:
            assert 0<=source_alias<=n-32
            w[source_alias:source_alias+32]=raw
        initial=bytes(w)
        # Every byte outside the logical work view is observable and guarded.
        source_at=n+96; output_at=n+192; result_at=n+256
        total=n+288; mm=mmap.mmap(-1,total,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        mm[:]=(GUARD*((total+31)//32))[:total]
        mm[32:32+n]=initial; mm[source_at:source_at+32]=raw
        struct.pack_into('<Q',mm,result_at,MASK)
        before=bytes(mm)
        addr=ctypes.addressof(ctypes.c_char.from_buffer(mm))
        def invoke():
            rc=self.image._entry(addr+(source_at if source_alias is None else 32+source_alias),32,
                    addr+(output_at if output_alias is None else 32+output_alias),8,addr+32,n)
            struct.pack_into('<Q',mm,result_at,rc)
        if forked:
            pid=os.fork()
            if pid==0:
                resource.setrlimit(resource.RLIMIT_CORE,(0,0)); signal.alarm(3)
                invoke(); os._exit(0)
            _,status=os.waitpid(pid,0)
            assert not (os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGALRM),'helper did not terminate'
        else:
            invoke();status=0
        after=bytes(mm);rc=struct.unpack_from('<Q',after,result_at)[0];mm.close()
        # Only w and the explicit result cell may change, even after a trap.
        assert after[:32]==before[:32] and after[32+n:result_at]==before[32+n:result_at]
        assert after[result_at+8:]==before[result_at+8:]
        return status,rc,after[32:32+n],initial


def qualify(old_path,new_path,output):
    output=Path(output);output.mkdir(exist_ok=False,parents=True)
    old,new=Image(old_path),Image(new_path)
    report={'schema':'hepta.hia.cold-lz-prefix-copy-qualification.v1','passed':False,
            'scope':'native helper and full-memory behavior; full 60-phase cold deadline remains separate',
            'old':{'path':str(old.path),'sha256':sha256(old.raw).hexdigest()},
            'new':{'path':str(new.path),'sha256':sha256(new.raw).hexdigest()},'groups':{},'performance':[]}
    counts=Counter(); log=open(output/'cases.jsonl','x',buffering=1); began=time.monotonic(); rng=random.Random(0xC01DCAFE)
    def save():
        report['groups']=dict(counts);report['elapsed_seconds']=time.monotonic()-began
        (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def one(group,params,data,**kwargs):
        a=old.call(params,data,**kwargs);b=new.call(params,data,**kwargs)
        assert a==b,(group,params,kwargs,a[:2],b[:2],sha256(a[2]).hexdigest(),sha256(b[2]).hexdigest())
        to,source,size,distance=params
        if group in ('canonical','poison','aliases'):
            assert a[:2]==(0,0),(group,params,a[:2])
            expected=bytearray(a[3])
            for i in range(size):expected[to+i]=expected[source+i]
            assert a[2]==bytes(expected),(group,params,'independent forward byte oracle')
        counts[group]+=1
        log.write(json.dumps({'group':group,'params':params,'options':kwargs,'work_bytes':len(data),
             'status':a[0],'returncode':a[1],'full_work_sha256':sha256(a[2]).hexdigest()},separators=(',',':'))+'\n')
    save()
    try:
        distances=(*range(1,17),31,32,63,64,127,128,255,256,1023,4096,32768,65496,65504)
        for di,distance in enumerate(distances):
            for size in sorted({0,1,7,8,15,16,31,distance-1,distance,distance+1,2*distance+7,65504}):
                source=(di*7)%17;to=source+distance;n=to+size+97
                one('canonical',(to,source,size,distance),rng.randbytes(n))
                if size in (0,7,8,31,65504):
                    for poison in (0,0x6d,0xff):
                        initial=bytearray([poison])*n
                        initial[source:to]=bytes((j*131+37)&255 for j in range(distance))
                        one('poison',(to,source,size,distance),bytes(initial))
        save();print('PASS canonical/poison',dict(counts),flush=True)
        for distance in (1,3,7,8,13,16,31,64,256):
            for source_alias in (None,0,64,256):
                for output_alias in (None,0,63,128):
                    params=(64+distance,64,512,distance)
                    one('aliases',params,rng.randbytes(1024),source_alias=source_alias,output_alias=output_alias)
        # Valid addresses with a noncanonical relation must use the unchanged
        # word/byte fallback, including future-source reads and leftward copies.
        for to,source in ((0,0),(0,1),(0,8),(8,16),(16,8),(17,16),(31,29),(63,0),(0,63)):
            for distance in (0,1,7,8,9,31,64,MASK):
                for size in (0,1,7,8,9,17,48):
                    if to>=source and to-source==distance and distance:continue
                    one('fallback',(to,source,size,distance),rng.randbytes(128),forked=True)
        save();print('PASS aliases/fallback',dict(counts),flush=True)
        invalid=[]
        for n in (0,1,7,8,15,16,31,64):
            invalid.extend((n,p) for p in ((0,0,1,0),(n,0,1,n),(n+1,0,8,n+1),(0,n,1,0),
                 (1,0,n+1,1),(8,0,n+9,8),(0,0,MASK,8),(MASK,0,1,MASK),
                 (0,MASK,1,1),(MASK,0,8,MASK),(1,MASK,8,8),(MASK,MASK,0,0),
                 (MASK,0,0,MASK),(0,0,0,0),(n,0,0,n)))
        for n,params in invalid:one('invalid-or-empty',params,rng.randbytes(n),forked=True)
        save();print('PASS invalid/partial writes',dict(counts),flush=True)
        # Bound the benchmark, use the same actual bytes/calls, and keep it
        # explicitly separate from the retained full cold deadline.
        for distance in (1,3,7,8,16,256,4096):
            n=65536+distance;params=(distance,0,65504,distance);raw=struct.pack('<4Q',*params)
            src=ctypes.create_string_buffer(raw);out=ctypes.create_string_buffer(8)
            work=ctypes.create_string_buffer(rng.randbytes(n));count=1000; timings={}
            for name,im in (('old',old),('new',new)):
                t=time.monotonic()
                for _ in range(count):assert im.image._entry(src,32,out,8,work,n)==0
                timings[name]=time.monotonic()-t
            report['performance'].append({'distance':distance,'bytes_per_call':65504,'calls_each':count,**timings})
        report['passed']=True;log.close();report['cases_sha256']=sha256((output/'cases.jsonl').read_bytes()).hexdigest();save()
        print(json.dumps(report),flush=True)
    except BaseException:
        save();raise

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--old',required=True);p.add_argument('--new',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    qualify(a.old,a.new,a.output)
