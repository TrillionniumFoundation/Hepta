"""New actual HIA Path-prefix state machine; no full CLI/staging claim.
The reference executes the original publish_program prefix up to canonical_bytes.
Python forwards only issued primitive calls on the actual path side.
"""
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
import argparse,ctypes,importlib.util,json,os,resource,stat,struct,sys,traceback,zlib
M=(1<<64)-1
def magic(s):return int.from_bytes(s,"little")
def digest(raw):return sha256(raw).hexdigest()
def save(p,o):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True)+"\n")
def guard(raw,size=None):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    b=ctypes.create_string_buffer(64+max(1,size));a=ctypes.addressof(b)+32
    ctypes.memset(a-32,0xa5,32);ctypes.memmove(a,raw,len(raw));ctypes.memset(a+max(1,size),0xa5,32)
    return b,a,size
def intact(b):
    assert ctypes.string_at(b[1]-32,32)==bytes([0xa5])*32
    assert ctypes.string_at(b[1]+max(1,b[2]),32)==bytes([0xa5])*32
def command(path,lease=53):
    raw=path.encode("utf-8","surrogatepass")
    return struct.pack("<8Q",magic(b"HIAPPC01"),1,lease,1,len(raw),64+len(raw),0,0)+raw
def mapped(value,root):
    if value is None:return None
    raw=os.fsencode(value)
    a=os.fsencode(root)
    if raw.startswith(a):raw=b"<ROOT>"+raw[len(a):]
    return raw.hex()
class Native:
    def __init__(self,image,out):
        self.image=image;self.out=out;self.calls=0;self.syscalls=0;self.cas_index={}
        self.libc=ctypes.CDLL(None,use_errno=True);self.libc.syscall.restype=ctypes.c_long
    def cas(self,raw):
        raw=bytes(raw);h=digest(raw);p=self.out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw
        self.cas_index[h]=len(raw)
        return dict(path="cas/"+p.name,sha256=h,bytes=len(raw),compression="zlib")
    def call(self,s,r,w,label):
        first=guard(s);reply=guard(r);before=ctypes.string_at(w[1],w[2])
        ret=int(self.image._entry(first[1],first[2],reply[1],reply[2],w[1],w[2]));self.calls+=1
        for x in(first,reply,w):intact(x)
        assert ctypes.string_at(first[1],first[2])==s and ctypes.string_at(reply[1],reply[2])==r
        row=dict(label=label,return_value=ret,first=self.cas(s),reply=self.cas(r),
            workspace_before=self.cas(before),workspace_after=self.cas(ctypes.string_at(w[1],w[2])),
            canaries_and_immutable_inputs=True)
        with (self.out/"entries.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
        return ret
    def raw(self,number,*args):
        ctypes.set_errno(0)
        ret=int(self.libc.syscall(ctypes.c_long(number),*(ctypes.c_long(x) for x in args)))
        self.syscalls+=1
        return ret,ctypes.get_errno() if ret<0 else 0
    def primitive(self,event,work,label):
        op=event[4];data=b"";result=0;err=0;path=None
        if op!=14:
            at,n=event[8:10];assert at<=work[2] and n<=work[2]-at
            path=ctypes.string_at(work[1]+at,n)
            assert path and path[-1]==0 and b"\0" not in path[:-1]
            p=guard(path)
        if op in (7,8):
            assert event[10]==144;buf=guard(b"",144)
            ret,err=self.raw(4 if op==7 else 6,p[1],buf[1]);intact(p);intact(buf)
            if not err:data=ctypes.string_at(buf[1],144)
        elif op==11:
            ret,err=self.raw(83,p[1],event[11]);intact(p)
        elif op==13:
            assert event[10]==4096;buf=guard(b"",4096)
            ret,err=self.raw(89,p[1],buf[1],4096);intact(p);intact(buf)
            if not err:assert 0<=ret<=4096;result=ret;data=ctypes.string_at(buf[1],ret)
        elif op==14:
            buf=guard(b"",event[10]);ret,err=self.raw(79,buf[1],buf[2]);intact(buf)
            if not err:assert 0<ret<=buf[2];result=ret;data=ctypes.string_at(buf[1],ret)
        else:raise AssertionError(op)
        row=dict(label=label,op=op,event=list(event),path=None if path is None else path.hex(),
            raw_return=ret,errno=err,payload=self.cas(data))
        with (self.out/"syscalls.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
        return struct.pack("<8Q",magic(b"HIAPPA01"),event[2],event[3],op,int(bool(err)),
            result if not err else 0,err,len(data))+data
    def run(self,source,label,root,mutator=None):
        work=guard(b"",4096);reply=b"";grows=0;pending_mutator=mutator
        for entry in range(100000):
            ret=self.call(source,reply,work,label)
            event=struct.unpack_from("<16Q",ctypes.string_at(work[1],work[2]),256)
            assert event[0]==magic(b"HIAPPE01") and event[2]==53
            if ret==0xfffffffe:
                assert event[1]==1 and event[14]>work[2]
                previous=ctypes.string_at(work[1],work[2]);work=guard(previous,event[14]);grows+=1
                continue
            assert ret==128 and event[1] in (0,2),(ret,event)
            if event[1]==2:
                reply=self.primitive(event,work,label)
                if pending_mutator:
                    bad=pending_mutator(reply)
                    assert self.call(source,bad,work,label+"/bad")==0xfffffffd
                    assert self.call(source,reply,work,label+"/good-after-bad")==0xfffffffd
                    return dict(private_BAD=True,grows=grows)
                continue
            def span(at,n):
                assert at<=work[2] and n<=work[2]-at
                return ctypes.string_at(work[1]+at,n)
            assert event[15]==99
            if event[5]==0:
                fs=span(event[8],event[9]);parent=span(event[10],event[11]);text=span(event[12],event[13])
                assert text.decode("utf-8","surrogatepass").encode(sys.getfilesystemencoding(),"surrogateescape")==fs
                answer=dict(domain=0,destination=mapped(fs,root),parent=mapped(parent,root))
            elif event[5]==1:answer=dict(domain=1,code=event[6])
            elif event[5]==2:answer=dict(domain=2,errno=event[7],path=mapped(span(event[8],event[9]),root) if event[9] else None)
            else:
                assert event[5]==3 and event[6]==1 and event[7]==40
                answer=dict(domain=3,errno=40,path=mapped(span(event[8],event[9]),root))
            assert self.call(source,reply,work,label+"/terminal-reentry")==0xfffffffd
            return dict(answer=answer,grows=grows,event=list(event))
        raise AssertionError("test harness iteration ceiling, not a language limit")
def inventory(root):
    rows=[]
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in sorted(dirs+files):
            p=Path(folder)/name;info=p.lstat()
            row=dict(path=os.fsencode(p.relative_to(root)).hex(),type=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode))
            if stat.S_ISREG(info.st_mode):
                raw=p.read_bytes();row["sha256"]=digest(raw);row["bytes"]=len(raw);row["data_hex"]=raw.hex()
            if stat.S_ISLNK(info.st_mode):row["target"]=os.fsencode(os.readlink(p)).hex()
            rows.append(row)
    return rows
def setup(root):
    root.mkdir();(root/"existing").write_bytes(b"fixed\n");(root/"dir").mkdir()
    (root/"real").mkdir();(root/"real/inside").mkdir()
    os.symlink("real",root/"alias");os.symlink("missing",root/"dangling")
    os.symlink("loop2",root/"loop1");os.symlink("loop1",root/"loop2")
    os.symlink("inside",root/"real/cached")
class PrefixComplete(Exception):pass
class VerifiedFixture:
    @property
    def canonical_bytes(self):raise PrefixComplete()
def reference(raw,root,tools,program):
    before=os.getcwd()
    try:
        os.chdir(root)
        with patch.object(program,"verify_program",return_value=VerifiedFixture()):
            try:tools.publish_program({},raw)
            except PrefixComplete:
                p=Path(raw).absolute()
                return dict(answer=dict(domain=0,destination=mapped(str(p),root),parent=mapped(str(p.parent),root)),exception=None)
            except tools.HIAEditRejected as e:
                codes={"E_HIA_EDIT: destination must be a new file":1,
                    "E_HIA_EDIT: output parent must not traverse symlinks":2}
                return dict(answer=dict(domain=1,code=codes[str(e)]),exception=dict(type=type(e).__name__,message=str(e)))
            except OSError as e:
                return dict(answer=dict(domain=2,errno=e.errno,path=mapped(e.filename,root)),
                    exception=dict(type=type(e).__name__,message=str(e),errno=e.errno,filename=None if e.filename is None else os.fsencode(e.filename).hex()))
            except RuntimeError as e:
                # These fixtures reach ELOOP only if the original resolver does.
                return dict(answer=dict(domain=3,errno=40,path=None),exception=dict(type=type(e).__name__,message=str(e)))
            raise AssertionError("reference unexpectedly published")
    finally:os.chdir(before)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--reference",type=Path,required=True)
    p.add_argument("--compiler",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    root=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    fixtures=out.parent/"path-prefix-physical";fixtures.mkdir()
    pins={}
    def pin(path):
        path=path.resolve();raw=path.read_bytes();pins[str(path)]=digest(raw);return raw
    result=dict(scope="NEW_NATIVE_CLI_PUBLICATION_PATH_PREFIX",status="FAIL",whole_cli_closed=False,
        full_staging_closed=False,all_OS_error_text_native=False,over_PATH_MAX_getcwd_closed=False,
        host_recursion_limit_compatibility_closed=False,cases=0,private_controls=0)
    native=None
    try:
        sys.path[:0]=[str(root/"tools"),str(a.source.resolve()),str(root.parent/"Hepta-agent-edit-native")]
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring,cli_publication_path_owner as owner
        for path in sorted((root/"tools").glob("*.py")):pin(path)
        pin(Path(__file__));pin(root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py")
        compiler=pin(a.compiler);assert(len(compiler),digest(compiler))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        expanded=cli_authoring.expanded(owner.BODY,owner.CONSTANTS);(out/"authoring-expanded.py").write_text(expanded)
        doc=cli_authoring.document(expanded,"hia_cli_publication_path_prefix");prof=cli_authoring.profile(doc)
        assert prof["functions"]<=128 and prof["blocks"]<=1536 and prof["ops"]<=8192 and prof["max_params"]<=16,prof
        hia=render_assembly(doc).encode();assemble_program(hia);(out/"source.hiaasm").write_bytes(hia)
        where=out/"compile";where.mkdir();image_path,receipt=compile_stage(where,"cli-publication-path",a.compiler,hia)
        image=pin(image_path);assert receipt["input_sha256"]==receipt["source_sha256"]==digest(hia)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==digest(compiler)
        assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        save(where/"manifest.json",dict(source_sha256=digest(hia),image_sha256=digest(image),profile=prof,receipt=receipt))
        native=Native(NativeHiaJsonImage(image,expected_sha256=digest(image)),out)
        # Only this reference package is swapped, after development imports.
        for key in list(sys.modules):
            if key=="hepta" or key.startswith("hepta."):del sys.modules[key]
        sys.path.insert(0,str(a.reference.resolve()))
        import hepta.hia_program_tools as original
        import hepta.hia_program as original_program
        assert Path(original.__file__).resolve().is_relative_to(a.reference.resolve())
        pin(Path(original.__file__));pin(Path(original_program.__file__))
        cases=[("new","new"),("empty",""),("dot","."),("dot-slash","./"),("existing","existing"),("directory","dir"),
          ("relative-normalize","a//./b///new"),("nested","a/b/c/d/new"),("parent-file","existing/new"),
          ("live-link","alias"),("dangling-link","dangling"),("dangling-parent","dangling/new"),
          ("parent-alias","alias/new"),("parent-cycle","loop1/new"),("dotdot-parent","created/../new"),
          ("unicode","文/🙂.hia"),("surrogateescape","bad\udcff/new"),("long-component","x"*256),
          ("cached-symlink","real/cached/../cached/new"),("absolute","ABS/new"),
          ("double-root","DOUBLE/new"),("many-dots","././a/./b/./new"),
          ("root","/"),("root-double","//"),("empty-basename","fresh/"),("parent-dot","dir/./new")]
        cwd=Path.cwd();case_rows=[]
        for index,(label,path) in enumerate(cases):
            parent=fixtures/str(index);parent.mkdir();nroot=parent/"native";rroot=parent/"reference";setup(nroot);setup(rroot)
            nr=path;rr=path
            if path.startswith("ABS/"):nr=str(nroot)+path[3:];rr=str(rroot)+path[3:]
            elif path.startswith("DOUBLE/"):nr="/"+str(nroot)+path[6:];rr="/"+str(rroot)+path[6:]
            expected=reference(rr,rroot,original,original_program)
            os.chdir(nroot)
            try:actual=native.run(command(nr),label,nroot)
            finally:os.chdir(cwd)
            # Double-root rejection has no path payload; ordinary normalized paths use the mapping above.
            assert actual["answer"]==expected["answer"],(label,actual,expected)
            assert inventory(nroot)==inventory(rroot),(label,inventory(nroot),inventory(rroot))
            row=dict(label=label,actual=actual,reference=expected,filesystem=inventory(nroot))
            case_rows.append(row);save(out/"cases"/(str(index)+".json"),row);result["cases"]+=1
        private_root=fixtures/"private";setup(private_root)
        def field(index,value):
            def change(raw):
                x=bytearray(raw);struct.pack_into("<Q",x,index*8,value);return bytes(x)
            return change
        private=[("magic",field(0,0)),("lease",field(1,54)),("sequence",field(2,999)),("op",field(3,999)),
            ("status",field(4,2)),("error-with-result",field(5,1)),("errno-range",field(6,4096)),
            ("extent",field(7,1)),("truncated",lambda r:r[:-1]),("extra",lambda r:r+b"\0")]
        os.chdir(private_root)
        try:
            for label,mutator in private:
                # Absolute missing path ensures the first reply is a real ENOENT stat frame.
                answer=native.run(command(str(private_root/"fresh")),label,private_root,mutator)
                assert answer["private_BAD"];result["private_controls"]+=1
        finally:os.chdir(cwd)
        result.update(status="PASS",profile=prof,source_sha256=digest(hia),image_sha256=digest(image),
            native_entries=native.calls,actual_fs_syscalls=native.syscalls)
    except BaseException:
        result["failure"]=traceback.format_exc();raise
    finally:
        if native:
            result.update(native_entries=native.calls,actual_fs_syscalls=native.syscalls)
            cas=[]
            for h,n in sorted(native.cas_index.items()):
                raw=zlib.decompress((out/"cas"/(h+".zlib")).read_bytes());assert len(raw)==n and digest(raw)==h
                cas.append(dict(sha256=h,bytes=n))
            result["cas_readback"]=dict(objects=len(cas),logical_bytes=sum(x["bytes"] for x in cas),status="PASS")
            save(out/"cas-index.json",cas)
        result["source_pins_unchanged"]=all(digest(Path(path).read_bytes())==h for path,h in pins.items())
        save(out/"source-pins.json",pins);save(out/"physical-after.json",inventory(fixtures));save(out/"summary.json",result)
        print(json.dumps(result,sort_keys=True))
    assert result["status"]=="PASS" and result["cases"]==26 and result["private_controls"]==10
if __name__=="__main__":main()
