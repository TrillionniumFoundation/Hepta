"""Complete byte-ledger mechanical execution for the type-context component.

No JSON decoding, type resolution, descriptor materialization or diagnostic
selection is performed in the native interval. The saved page order and every
page's SHA256 reconstruct each full advertised input/output/workspace.
"""
from __future__ import annotations
import ctypes,json,struct,zlib
from hashlib import sha256
from pathlib import Path

BAD=0xfffffffd;NEED=0xfffffffe;MAX=(1<<64)-1
WORK=128*1024*1024;OUTPUT=64*1024*1024;S=96*1024*1024;CONTEXT=S+192
PAGE=65536

def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def q(value):return struct.pack("<Q",value)

class Mechanical:
    def __init__(self,out,bundle,pin):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.out=Path(out);self.pin=pin;self.bundle=bundle;self.entries=0;self.by_role={}
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        self.libc.mmap.restype=ctypes.c_void_p
        self.libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        self.images={};self.pool={};self.zero=bytes(PAGE);self.buffers=[]
        for role,row in bundle["components"].items():
            raw=pin(row["image_path"]);source=pin(row["source_path"])
            assert (len(raw),sha256(raw).hexdigest())==(row["image_bytes"],row["image_sha256"])
            assert (len(source),sha256(source).hexdigest())==(row["source_bytes"],row["source_sha256"])
            self.images[role]=NativeHiaJsonImage(raw,expected_sha256=row["image_sha256"])
            self.by_role[role]=0
        self.page(self.zero)
    def save(self,path,obj):
        path=self.out/path;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
    def cas(self,raw):
        raw=bytes(raw);identity=sha256(raw).hexdigest()
        path=self.out/"cas"/(identity+".zlib")
        if not path.exists():
            path.parent.mkdir(parents=True,exist_ok=True)
            compressed=zlib.compress(raw,1)
            with path.open("xb") as stream:stream.write(compressed)
            assert zlib.decompress(path.read_bytes())==raw
        return dict(bytes=len(raw),sha256=identity,compression="zlib",
                    path=str(path.relative_to(self.out)))
    def page(self,raw):
        if raw==self.zero:raw=self.zero
        found=self.pool.get(raw)
        if found is not None:return found
        row=self.cas(raw);result=(raw,row)
        # Retain only a bounded evidence-byte cache. This is not a language,
        # descriptor or runtime command quota; eviction never discards CAS.
        if len(self.pool)>=256:
            self.pool.clear()
        self.pool[raw]=result
        return result
    def buffer(self,size,raw=b"",readonly=False):
        value=Buffer(self,size,raw,readonly);self.buffers.append(value);return value
    def snapshot(self,buffer):
        pages=[];hash_value=sha256()
        old=buffer.last;current=[]
        for index,at in enumerate(range(0,buffer.size,PAGE)):
            raw=ctypes.string_at(buffer.ptr+at,min(PAGE,buffer.size-at))
            hash_value.update(raw)
            if index<len(old) and raw==old[index][0]:
                value=old[index]
            else:value=self.page(raw)
            current.append(value);pages.append(value[1])
        buffer.last=current
        return dict(bytes=buffer.size,sha256=hash_value.hexdigest(),page_bytes=PAGE,pages=pages,
                    exact_advertised_extent=True)
    def invoke(self,role,first,second,third,label,extents=None):
        buffers=(first,second,third)
        assert len({id(b) for b in buffers})==3
        wanted=(True,True,False) if role=="context-reader" else (True,False,False)
        assert tuple(b.readonly for b in buffers)==wanted,(role,wanted)
        actual=tuple(b.size for b in buffers)
        extents=actual if extents is None else tuple(extents)
        assert all(0<=n<=b.physical_payload for n,b in zip(extents,buffers))
        before=[self.snapshot(b) for b in buffers]
        entry=self.entries+1
        pending=dict(entry=entry,label=label,role=role,
            image_sha256=self.bundle["components"][role]["image_sha256"],
            source_sha256=self.bundle["components"][role]["source_sha256"],
            input_rights=["R" if value else "RW" for value in wanted],
            allocated_payload_extents=actual,advertised_extents=extents,before=before)
        self.save(Path("pending-native-entry.json"),pending)
        ret=int(self.images[role]._entry(first.ptr,extents[0],second.ptr,extents[1],third.ptr,extents[2]))
        self.entries+=1;self.by_role[role]+=1
        after=[self.snapshot(b) for b in buffers]
        for index,b in enumerate(buffers):
            b.check()
            if wanted[index]:assert before[index]==after[index],(label,index,"readonly input changed")
        row=dict(pending,returned=ret,after=after,complete_readonly_bytes_and_canaries_unchanged=True)
        self.save(Path("entries")/(str(entry).zfill(6)+".json"),row)
        return ret,row
    def close(self):
        for b in self.buffers:b.close()
        for image in self.images.values():image._mapping.close()

class Buffer:
    def __init__(self,owner,size,raw=b"",readonly=False):
        raw=bytes(raw);assert 0<=len(raw)<=size
        self.owner=owner;self.size=size;self.last=[]
        self.map_bytes=((max(1,size)+128+4095)//4096)*4096
        self.base=int(owner.libc.mmap(None,self.map_bytes,3,0x22,-1,0))
        assert self.base!=ctypes.c_void_p(-1).value
        self.ptr=self.base+64;self.physical_payload=self.map_bytes-128
        self.readonly=False
        ctypes.memset(self.base,0x6b,self.map_bytes)
        ctypes.memset(self.ptr,0,max(1,size))
        if raw:ctypes.memmove(self.ptr,raw,len(raw))
        if readonly:self.protect(True)
    def value(self,at=0,size=None):
        size=self.size-at if size is None else size
        assert 0<=at<=self.size and 0<=size<=self.size-at
        return ctypes.string_at(self.ptr+at,size)
    def write(self,at,raw):
        raw=bytes(raw);assert not self.readonly and 0<=at<=self.size and len(raw)<=self.size-at
        if raw:ctypes.memmove(self.ptr+at,raw,len(raw))
    def protect(self,readonly):
        assert self.owner.libc.mprotect(self.base,self.map_bytes,1 if readonly else 3)==0
        self.readonly=readonly
    def check(self):
        assert ctypes.string_at(self.base,64)==b"k"*64
        n=max(1,self.size);tail=self.map_bytes-64-n
        assert ctypes.string_at(self.ptr+n,tail)==b"k"*tail
    def close(self):
        if self.base is not None:
            self.check();assert self.owner.libc.munmap(self.base,self.map_bytes)==0
            self.base=None;self.last=[]

def equal_except(left,right,excluded,label):
    assert left.size==right.size and len(left.last)==len(right.last),label
    changes=[]
    for index,((a,ar),(b,br)) in enumerate(zip(left.last,right.last)):
        if a==b:continue
        start=index*PAGE;end=start+len(a)
        cuts=sorted((max(start,lo)-start,min(end,hi)-start) for lo,hi in excluded
                    if lo<end and hi>start)
        cursor=0
        for lo,hi in cuts:
            assert a[cursor:lo]==b[cursor:lo],(label,index,cursor,lo)
            changes.append(dict(offset=start+lo,bytes=hi-lo,
                                old_sha256=sha256(a[lo:hi]).hexdigest(),new_sha256=sha256(b[lo:hi]).hexdigest()))
            cursor=max(cursor,hi)
        assert a[cursor:]==b[cursor:],(label,index,cursor,"tail")
    return dict(full_extent_bytes=left.size,equal_outside_exact_ranges=True,
                excluded_ranges=excluded,actual_changed_segments=changes)

class Pair:
    def __init__(self,mechanical):
        self.m=mechanical
        self.old_output=self.m.buffer(OUTPUT);self.old_work=self.m.buffer(WORK)
        self.new_output=self.m.buffer(OUTPUT);self.new_work=self.m.buffer(WORK)
        self.sequence=0
    def command(self,planned,label):
        self.sequence+=1;first=self.m.buffer(len(planned["wire"]),planned["wire"],readonly=True)
        try:
            old_ret,old_row=self.m.invoke("old-types",first,self.old_output,self.old_work,label+":old")
            new_ret,new_row=self.m.invoke("context-types",first,self.new_output,self.new_work,label+":new")
            assert 64<=old_ret<=OUTPUT and new_ret==old_ret,(label,old_ret,new_ret)
            old_header=self.old_output.value(0,64);new_header=self.new_output.value(0,64)
            old_error=word(old_header,8);new_error=word(new_header,8)
            want=planned["error"];old_want=6 if planned["mixed_bad_prefix"] else want
            assert (old_error,new_error)==(old_want,want),(label,old_error,new_error,old_want,want)
            assert word(old_header,24)==old_ret-64 and word(new_header,24)==new_ret-64
            if planned["identifier"] is not None:
                assert word(old_header,16)==word(new_header,16)==planned["identifier"],label
            outside_work=[(CONTEXT,CONTEXT+64)]
            outside_output=[]
            if planned["mixed_bad_prefix"]:
                assert planned["error"]==5 and planned["where"]!=0
                outside_work.append((S+8,S+16));outside_output.append((8,16))
            compared=dict(work=equal_except(self.old_work,self.new_work,outside_work,label+":work"),
                          output=equal_except(self.old_output,self.new_output,outside_output,label+":output"))
            context=self.new_work.value(CONTEXT,64)
            if planned["where"]:
                values=struct.unpack("<8Q",context)
                assert values[:4]==(int.from_bytes(b"HIATDX01","little"),1,want,planned["where"])
                assert values[6:]==(0,0)
            else:assert context==bytes(64),(label,context)
            row=dict(label=label,old_entry=old_row["entry"],new_entry=new_row["entry"],
                actual_native_frame_bytes=new_ret,old_header=self.m.cas(old_header),
                new_header=self.m.cas(new_header),actual_context=self.m.cas(context),
                actual_context_fields=list(struct.unpack("<8Q",context)),
                full_output_and_workspace_comparison=compared,
                original_public_message=planned["public_message"],
                mixed_bad_prefix_original_native_error_changed_only=planned["mixed_bad_prefix"])
            if planned["where"]:
                row["diagnostic"]=self.diagnostic(planned,new_ret,new_header,label)
            return row
        finally:first.close()
    def diagnostic(self,planned,extent,header,label):
        command=struct.pack("<8Q",int.from_bytes(b"HIATDC01","little"),1,
                            0x54594301,self.sequence,self.sequence,planned["operation"],extent,0)+header
        wire=self.m.buffer(128,command,readonly=True);small=self.m.buffer(128)
        self.new_work.protect(True)
        full=None
        try:
            returned,measurement=self.m.invoke("context-reader",self.new_work,wire,small,label+":measure")
            assert returned==NEED,(label,returned)
            measured=small.value();words=struct.unpack("<16Q",measured)
            assert words[:7]==(int.from_bytes(b"HIATDE01","little"),1,0x54594301,
                                self.sequence,self.sequence,planned["operation"],planned["error"])
            assert words[7]==planned["where"] and words[15]==0
            assert words[11]==128+words[10] and 0<words[10]<1024
            full=self.m.buffer(words[11])
            returned,completed=self.m.invoke("context-reader",self.new_work,wire,full,label+":complete")
            assert returned==words[11] and full.value(0,128)==measured
            text=full.value(128,words[10])
            expected=planned["public_message"].encode("utf-8")
            self.m.save(Path("diagnostics")/(label.replace(":","_")+".json"),dict(
                original_public_text=self.m.cas(expected),actual_native_text=self.m.cas(text),
                measurement=measurement["entry"],complete=completed["entry"]))
            assert text==expected,(label,text,expected)
            return dict(measurement_entry=measurement["entry"],complete_entry=completed["entry"],
                        original_and_actual_full_text_equal=True,full_text=self.m.cas(text),
                        actual_first_error_context=True,private_fixed_caller_required=True)
        finally:
            self.new_work.protect(False);wire.close();small.close()
            if full is not None:full.close()
    def close(self):
        for b in (self.old_output,self.old_work,self.new_output,self.new_work):b.close()
