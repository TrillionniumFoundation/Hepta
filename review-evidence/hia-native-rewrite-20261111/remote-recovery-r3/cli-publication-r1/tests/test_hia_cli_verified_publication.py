"""Fresh actual-HIA verified publication component and physical-file controls.

This is development instrumentation. Python forwards only the HIA-selected raw
filesystem primitives and the already bound native SHA service. It does not
choose read/link/check/cleanup order. Whole CLI path and staging are not claimed.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib.util,json,os,resource,stat,struct,sys,traceback,zlib
from unittest.mock import patch
MAX=(1<<64)-1
def magic(s):return int.from_bytes(s,"little")
def digest(s):return sha256(s).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
def module(name,path):
    sp=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m);return m
def guard(raw,size=None):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    b=ctypes.create_string_buffer(64+max(1,size));a=ctypes.addressof(b)+32
    ctypes.memset(a-32,0xa7,32);ctypes.memmove(a,raw,len(raw))
    ctypes.memset(a+max(1,size),0xa7,32)
    return b,a,size
def guarded(b):
    _,a,n=b
    assert ctypes.string_at(a-32,32)==b"\xa7"*32
    assert ctypes.string_at(a+max(1,n),32)==b"\xa7"*32
def packet(stage,dest,payload,lease=19):
    a=os.fsencode(stage);b=os.fsencode(dest)
    return struct.pack("<8Q",magic(b"HIAPVC01"),1,lease,1,len(a),len(b),len(payload),66+len(a)+len(b)+len(payload))+a+b"\0"+b+b"\0"+payload

class Runner:
    def __init__(self,image,hasher,out):
        self.image=image;self.hasher=hasher;self.out=out
        self.entries=0;self.hash_entries=0;self.syscalls=0;self.logs=[]
        self.fd=None;self.cas_index={};self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.syscall.restype=ctypes.c_long
    def cas(self,raw):
        raw=bytes(raw);h=digest(raw);p=self.out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if h not in self.cas_index:
            if not p.exists():p.write_bytes(zlib.compress(raw,6))
            assert zlib.decompress(p.read_bytes())==raw
            self.cas_index[h]=len(raw)
        else:assert self.cas_index[h]==len(raw)
        return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
    def call(self,s,r,w,label,which="publication"):
        a=guard(s);b=guard(r);before=ctypes.string_at(w[1],w[2])
        ret=int((self.image if which=="publication" else self.hasher)._entry(a[1],a[2],b[1],b[2],w[1],w[2]))
        if which=="publication":self.entries+=1
        else:self.hash_entries+=1
        for buf in (a,b,w):guarded(buf)
        assert ctypes.string_at(a[1],a[2])==s
        if which=="publication":assert ctypes.string_at(b[1],b[2])==r
        row=dict(label=label,role=which,return_value=ret,first=self.cas(s),second_before=self.cas(r),
                 second_after=self.cas(ctypes.string_at(b[1],b[2])),
                 workspace_before=self.cas(before),workspace_after=self.cas(ctypes.string_at(w[1],w[2])),
                 canaries_unchanged=True)
        self.logs.append(row)
        with (self.out/"entries.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
        return ret,ctypes.string_at(b[1],b[2])
    def native_hash(self,payload,label):
        work=guard(b"",1184)
        ret,_=self.call(b"\0",bytes(32),work,label+"/hash-init","sha")
        assert ret==0
        for offset in range(0,len(payload),8<<20):
            ret,_=self.call(b"\1"+payload[offset:offset+(8<<20)],bytes(32),work,label+"/hash-update","sha")
            assert ret==0
        ret,out=self.call(b"\2",bytes(32),work,label+"/hash-final","sha")
        assert ret==32
        return out
    def syscall(self,number,*args):
        ctypes.set_errno(0)
        ret=int(self.libc.syscall(ctypes.c_long(number),*(ctypes.c_long(x) for x in args)))
        self.syscalls+=1
        return ret,(ctypes.get_errno() if ret<0 else 0)
    def primitive(self,e,source,work,label,hook=None):
        op=e[4]
        def view(which,at,count):
            raw=source if which==0 else ctypes.string_at(work[1],work[2])
            assert which in (0,1) and at<=len(raw) and count<=len(raw)-at
            return raw[at:at+count]
        path=None;second=None;result=0;error=0;data=b""
        if op in (1,2,3,8):
            path=view(e[8],e[9],e[10]);assert path.endswith(b"\0") and b"\0" not in path[:-1]
        if hook is not None:hook("before",op,path)
        if op in (1,2):
            a=guard(path);buf=guard(b"",144)
            ret,error=self.syscall(6 if op==1 else 4,a[1],buf[1])
            for x in (a,buf):guarded(x)
            if not error:data=ctypes.string_at(buf[1],144)
        elif op==3:
            assert self.fd is None
            a=guard(path);ret,error=self.syscall(2,a[1],e[11],0);guarded(a)
            if not error:self.fd=ret;result=1
        elif op==4:
            assert self.fd is not None
            buf=guard(b"",144);ret,error=self.syscall(5,self.fd,buf[1]);guarded(buf)
            if not error:data=ctypes.string_at(buf[1],144)
        elif op==5:
            assert self.fd is not None
            buf=guard(b"",e[10]);ret,error=self.syscall(0,self.fd,buf[1],e[10]);guarded(buf)
            if not error:
                assert 0<=ret<=e[10];data=ctypes.string_at(buf[1],ret);result=ret
        elif op==6:
            assert self.fd is not None
            fd=self.fd;self.fd=None
            ret,error=self.syscall(3,fd)
        elif op==7:
            first=view(e[8],e[9],e[10]);second=view(e[11],e[12],e[13])
            assert all(x.endswith(b"\0") and b"\0" not in x[:-1] for x in (first,second))
            a=guard(first);b=guard(second);ret,error=self.syscall(86,a[1],b[1]);guarded(a);guarded(b)
        elif op==8:
            a=guard(path);ret,error=self.syscall(87,a[1]);guarded(a)
        elif op==9:
            data=self.native_hash(view(e[8],e[9],e[10]),label)
        else:raise AssertionError(("unknown primitive",op))
        if hook is not None:hook("after",op,path)
        if error:assert 1<=error<=4095
        header=struct.pack("<8Q",magic(b"HIAPVA01"),e[2],e[3],op,int(bool(error)),result if not error else 0,error,len(data))
        return header+data
    def run(self,command,label,hook=None,mutate=None):
        work=guard(b"",4096);reply=b"";loops=0;grows=0
        try:
            while True:
                loops+=1;assert loops<10000
                ret,_=self.call(command,reply,work,label)
                event=struct.unpack_from("<16Q",ctypes.string_at(work[1],work[2]),256)
                assert event[0]==magic(b"HIAPVE01") and event[2]==struct.unpack_from("<Q",command,16)[0]
                if ret==0xfffffffd:
                    assert mutate is not None
                    again,_=self.call(command,reply,work,label+"/poison-followup")
                    assert again==0xfffffffd
                    return dict(domain="PRIVATE_ABI_BAD",event=event,grows=grows)
                if event[1]==1:
                    assert ret==0xfffffffe and event[14]>work[2] and reply==b""
                    replacement=guard(ctypes.string_at(work[1],work[2]),event[14]);work=replacement;grows+=1
                    continue
                assert ret==128
                if event[1]==0:
                    assert self.fd is None
                    raw=command if event[8]==0 else ctypes.string_at(work[1],work[2])
                    at,count=event[9:11];assert at<=len(raw) and count<=len(raw)-at
                    value=raw[at:at+count]
                    if event[5]==0:return dict(domain=0,receipt=value.decode("ascii"),grows=grows)
                    if event[5]==1:return dict(domain=1,message=value.decode("utf-8"),grows=grows)
                    assert event[5]==2
                    return dict(domain=2,errno=event[7],path=value.hex(),grows=grows)
                assert event[1] in (2,3)
                reply=self.primitive(event,command,work,label,hook)
                if mutate is not None:
                    reply=mutate(reply);mutate=None
                    # Mark only the next call as an expected permanent refusal.
                    bad,_=self.call(command,reply,work,label+"/bad-reply")
                    assert bad==0xfffffffd
                    good=struct.pack("<8Q",magic(b"HIAPVA01"),event[2],event[3],event[4],1,0,2,0)
                    follow,_=self.call(command,good,work,label+"/good-followup")
                    assert follow==0xfffffffd
                    return dict(domain="PRIVATE_ABI_BAD",grows=grows)
        finally:
            if self.fd is not None:
                fd=self.fd;self.fd=None;os.close(fd)

def filesystem(root):
    rows=[]
    for p in sorted(root.iterdir()):
        st=p.lstat()
        row=dict(name=p.name,mode=stat.S_IFMT(st.st_mode))
        if stat.S_ISREG(st.st_mode):row["bytes"]=len(p.read_bytes());row["sha256"]=digest(p.read_bytes())
        if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p)
        rows.append(row)
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    p.add_argument("--reference",type=Path,required=True);p.add_argument("--compiler",type=Path,required=True)
    p.add_argument("--sha-source",type=Path,required=True);p.add_argument("--sha-image",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    root=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    fixtures=out.parent/"publication-filesystem-fixtures"
    fixtures.mkdir(parents=True,exist_ok=False)
    result=dict(status="FAIL",scope="NEW_NATIVE_VERIFIED_PUBLICATION_COMPONENT",
        whole_cli_closed=False,actual_fixed_publication_carrier=False,
        python_chooses_transaction_order=False,path_staging_owner_closed=False,
        raw_os_error_presentation_closed=False)
    pins={};cases=[];runner=None;original_error=None
    def pin(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==raw
        pins[path]=raw
        frozen=out/"frozen"/str(len(pins)).zfill(4);frozen.parent.mkdir(exist_ok=True)
        if not frozen.exists():frozen.write_bytes(raw)
        return raw
    try:
        sys.path[:0]=[str(root/"tools"),str(a.source.resolve()),str(root.parent/"Hepta-agent-edit-native")]
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring
        import cli_publication_verified_owner as owner
        for x in (Path(__file__),root/"tools/cli_authoring.py",root/"tools/cli_publication_verified_owner.py",
            root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py"):
            pin(x)
        compiler=pin(a.compiler)
        assert (len(compiler),digest(compiler))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        sha_source=pin(a.sha_source);sha_image=pin(a.sha_image)
        assert (len(sha_source),digest(sha_source))==(33683,"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a")
        assert (len(sha_image),digest(sha_image))==(38349,"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274")
        expanded=cli_authoring.expanded(owner.BODY+owner.message_body(),owner.CONSTANTS)
        document=cli_authoring.document(expanded,"cli_verified_publication");profile=cli_authoring.profile(document)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16
        hia=render_assembly(document).encode();assemble_program(hia)
        comp=out/"compile";comp.mkdir()
        (comp/"authoring-expanded.py").write_text(expanded);(comp/"source.hiaasm").write_bytes(hia);save(comp/"profile.json",profile)
        image_path,receipt=compile_stage(comp,"verified-publication",a.compiler,hia)
        image=pin(image_path)
        assert receipt["source_sha256"]==receipt["input_sha256"]==digest(hia)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==digest(compiler)
        assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["limits"]["core_dumpable"] is False
        save(comp/"manifest.json",dict(source_sha256=digest(hia),image_sha256=digest(image),receipt=receipt,profile=profile))
        oracle_path=a.reference/"hepta/artifact_publication.py";pin(oracle_path)
        assert "HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST" not in os.environ
        oracle=module("original_publication",oracle_path)
        runner=Runner(NativeHiaJsonImage(image,expected_sha256=digest(image)),
            NativeHiaJsonImage(sha_image,expected_sha256=digest(sha_image)),out)
        labels=[("success-"+str(n),n,"success") for n in (1,31,8191,8192,8193,65535,65536,65537,1048576,8388608)]
        labels += [(name,37,name) for name in ("wrong","short","long","empty","same","existing","directory-dest",
            "dangling-dest","missing-stage","directory-stage","fifo-stage","symlink-stage","missing-parent",
            "mutate-after-link","replace-dest","replace-stage","fifo-before-open","link-race","pathname-replace")]
        for index,(name,n,mode) in enumerate(labels):
            pattern=b"\0HIA verified publication\xff\n"
            payload=(pattern*((n+len(pattern)-1)//len(pattern)))[:n]
            assert len(payload)==n
            state=[]
            for which in ("reference","native"):
                folder=fixtures/name/which;folder.mkdir(parents=True)
                stage=folder/"stage";dest=folder/"destination";stage.write_bytes(payload)
                expected=payload
                if mode=="wrong":expected=b"x"*n
                if mode=="short":expected=payload[:-1]
                if mode=="long":expected=payload+b"!"
                if mode=="empty":expected=b""
                if mode=="same":dest=stage
                if mode=="existing":dest.write_bytes(b"competitor")
                if mode=="directory-dest":dest.mkdir()
                if mode=="dangling-dest":dest.symlink_to("absent")
                if mode=="missing-stage":stage.unlink()
                if mode=="directory-stage":stage.unlink();stage.mkdir()
                if mode=="fifo-stage":stage.unlink();os.mkfifo(stage)
                if mode=="symlink-stage":
                    stage.rename(folder/"real");stage.symlink_to("real")
                if mode=="missing-parent":dest=folder/"absent"/"destination"
                done=[False];lst=[0]
                def mutation(when,op,path):
                    if done[0]:return
                    if mode=="link-race" and when=="before" and op==7:
                        dest.write_bytes(b"competitor");done[0]=True;return
                    if mode=="pathname-replace" and when=="before" and op==1:
                        lst[0]+=1
                        if lst[0]==2:
                            stage.rename(folder/"previous");stage.write_bytes(payload);done[0]=True
                        return
                    if mode=="fifo-before-open" and when=="before" and op==3:
                        stage.rename(folder/"previous");os.mkfifo(stage);done[0]=True
                    if when=="after" and op==7:
                        if mode=="mutate-after-link":dest.write_bytes(b"tampered")
                        elif mode=="replace-dest":dest.unlink();dest.write_bytes(b"other writer")
                        elif mode=="replace-stage":stage.rename(folder/"previous");stage.write_bytes(payload)
                        else:return
                        done[0]=True
                if which=="reference":
                    original_link=os.link;original_open=os.open;original_lstat=oracle.Path.lstat
                    def linked(*args,**kwargs):
                        mutation("before",7,None)
                        answer=original_link(*args,**kwargs);mutation("after",7,None);return answer
                    def lstated(path,*args,**kwargs):
                        mutation("before",1,path)
                        return original_lstat(path,*args,**kwargs)
                    def opened(*args,**kwargs):
                        mutation("before",3,None);return original_open(*args,**kwargs)
                    try:
                        with patch.object(oracle.os,"link",new=linked),patch.object(oracle.os,"open",new=opened),patch.object(oracle.Path,"lstat",new=lstated):
                            value=oracle.publish_verified(stage,dest,expected)
                        outcome=dict(domain=0,receipt=json.dumps(value,sort_keys=True,separators=(",",":")))
                    except oracle.PublicationRejected as error:outcome=dict(domain=1,message=str(error))
                    except OSError as error:outcome=dict(domain=2,errno=error.errno,path=os.fsencode(error.filename).hex())
                else:
                    outcome=runner.run(packet(stage,dest,expected),name,hook=mutation)
                    outcome.pop("grows")
                state.append((outcome,filesystem(folder),
                    stage.exists() and dest.exists() and stage.is_file() and dest.is_file() and stage.stat().st_ino==dest.stat().st_ino))
            assert state[0]==state[1],(name,state)
            row=dict(label=name,status="PASS",outcome=state[1][0],files=state[1][1],same_inode=state[1][2])
            cases.append(row);save(out/"cases"/(str(index).zfill(4)+".json"),row)
        controls=[]
        folder=fixtures/"private";folder.mkdir();stage=folder/"stage";stage.write_bytes(b"control");dest=folder/"dest"
        command=packet(stage,dest,b"control")
        def replace_word(raw,which,value):
            b=bytearray(raw);struct.pack_into("<Q",b,which*8,value);return bytes(b)
        changes=[("magic",lambda r:replace_word(r,0,0)),
            ("lease",lambda r:replace_word(r,1,20)),("sequence",lambda r:replace_word(r,2,1)),
            ("operation",lambda r:replace_word(r,3,2)),("status",lambda r:replace_word(r,4,2)),
            ("result",lambda r:replace_word(r,5,1)),("errno",lambda r:replace_word(r,6,4)),
            ("payload",lambda r:replace_word(r,7,143)),("truncate",lambda r:r[:-1]),
            ("extra",lambda r:r+b"\0"),("short",lambda r:r[:31])]
        for label,change in changes:
            outcome=runner.run(command,"private-"+label,mutate=change)
            assert outcome["domain"]=="PRIVATE_ABI_BAD";controls.append(label)
        result.update(status="PASS",cases=len(cases),cases_data=cases,
            private_controls=len(controls),private_labels=controls,profile=profile,
            native_publication_entries=runner.entries,native_hash_entries=runner.hash_entries,
            actual_filesystem_syscalls=runner.syscalls)
    except BaseException as error:
        original_error=error
        result["failure"]=traceback.format_exc();print(result["failure"],file=sys.stderr,flush=True)
        raise
    finally:
        try:
            # The special filesystem fixtures remain outside the archived raw root.
            # Preserve every regular byte and special-object identity without
            # following symlinks or attempting to put hardlinks/FIFOs in the tar.
            inventory=[]
            for path in sorted(fixtures.rglob("*")):
                info=path.lstat()
                row=dict(path=path.relative_to(fixtures).as_posix(),
                    mode=stat.S_IMODE(info.st_mode),type=stat.S_IFMT(info.st_mode),
                    dev=info.st_dev,inode=info.st_ino,links=info.st_nlink,
                    uid=info.st_uid,gid=info.st_gid,bytes=info.st_size,
                    mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
                if stat.S_ISLNK(info.st_mode):row["target"]=os.readlink(path)
                elif stat.S_ISREG(info.st_mode):
                    assert runner is not None
                    row["data"]=runner.cas(path.read_bytes())
                inventory.append(row)
            save(out/"filesystem-object-inventory.json",inventory)
            if runner is not None:
                for h,size in runner.cas_index.items():
                    raw=zlib.decompress((out/"cas"/(h+".zlib")).read_bytes())
                    assert len(raw)==size and digest(raw)==h
                result["cas_readback"]=dict(status="PASS",objects=len(runner.cas_index),
                    raw_bytes=sum(runner.cas_index.values()))
            result["source_pins_unchanged"]=all(p.read_bytes()==raw for p,raw in pins.items())
            save(out/"source-pins.json",{str(p):dict(bytes=len(raw),sha256=digest(raw)) for p,raw in pins.items()})
            save(out/"summary.json",result);print(json.dumps(result,sort_keys=True),flush=True)
            assert result["source_pins_unchanged"]
        except BaseException as evidence_error:
            if original_error is not None:
                original_error.add_note("Publication evidence cleanup/readback also failed: "+repr(evidence_error))
            else:raise
if __name__=="__main__":main()
