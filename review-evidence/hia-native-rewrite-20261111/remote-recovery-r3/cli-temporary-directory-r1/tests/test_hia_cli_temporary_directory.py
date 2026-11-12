"""New actual HIA TemporaryDirectory creation and complete fd-safe cleanup.
The development peer forwards raw syscalls only. CPython 3.12.14 owns the
independent reference. Scripted receipt controls are labelled separately.
"""
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
import argparse,ctypes,errno,importlib.util,json,os,resource,stat,struct,sys,tempfile,traceback,zlib
M=(1<<64)-1
def magic(s):return int.from_bytes(s,"little")
def digest(raw):return sha256(raw).hexdigest()
def save(p,value):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def guard(raw,size=None):
    raw=bytes(raw);size=len(raw) if size is None else size;assert len(raw)<=size
    b=ctypes.create_string_buffer(64+max(1,size));a=ctypes.addressof(b)+32
    ctypes.memset(a-32,0xa5,32);ctypes.memmove(a,raw,len(raw));ctypes.memset(a+max(1,size),0xa5,32)
    return b,a,size
def intact(b):
    assert ctypes.string_at(b[1]-32,32)==b"\xa5"*32 and ctypes.string_at(b[1]+max(1,b[2]),32)==b"\xa5"*32
def command(path,mode,policy=1,lease=71):
    p=os.fsencode(path)
    return struct.pack("<8Q",magic(b"HIATDC01" if mode=="create" else b"HIATRC01"),
                       1,lease,1,len(p),65+len(p),policy if mode=="create" else 0,0)+p+b"\0"
def norm(path,root):
    if path is None:return None
    raw=os.fsencode(path);base=os.fsencode(root)
    if raw.startswith(base):raw=b"<ROOT>"+raw[len(base):]
    return raw.hex()
def custom_error_text(error,root):
    text=str(error)
    if error.filename is None:return text
    # Only the separately created native/reference fixture root differs.
    # Preserve the entire remaining OSError string and the original raw text.
    suffix=": "+repr(error.filename)
    assert text.endswith(suffix),(text,suffix)
    name=bytes.fromhex(norm(error.filename,root))
    if isinstance(error.filename,str):name=os.fsdecode(name)
    return text[:-len(suffix)]+": "+repr(name)
def answer_error(error,root):
    return dict(kind=2 if error.errno is None else 1,errno=error.errno or 0,
                path=norm(error.filename,root),type=type(error).__name__,
                custom_text=custom_error_text(error,root) if error.errno is None else None)
def inventory(root,cas):
    out=[]
    if not os.path.lexists(root):return out
    todo=[Path(root)]
    while todo:
        p=todo.pop();st=p.lstat();row=dict(path=os.fsencode(os.path.relpath(p,root)).hex(),
            type=stat.S_IFMT(st.st_mode),mode=stat.S_IMODE(st.st_mode))
        if stat.S_ISREG(st.st_mode):row["contents"]=cas(p.read_bytes())
        elif stat.S_ISLNK(st.st_mode):row["target"]=os.fsencode(os.readlink(p)).hex()
        elif stat.S_ISDIR(st.st_mode):
            try:todo.extend(sorted(p.iterdir(),key=os.fsencode,reverse=True))
            except OSError as e:row["enumeration_error"]=dict(errno=e.errno,type=type(e).__name__)
        out.append(row)
    return sorted(out,key=lambda x:x["path"])
class Actual:
    def __init__(self,images,out):
        self.images=images;self.out=out;self.entries=0;self.syscalls=0;self.cas_index={};self.fds={};self.operations={}
        self.libc=ctypes.CDLL(None,use_errno=True);self.libc.syscall.restype=ctypes.c_long
    def cas(self,raw):
        raw=bytes(raw);h=digest(raw);p=self.out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw;self.cas_index[h]=len(raw)
        return dict(path="cas/"+p.name,bytes=len(raw),sha256=h,compression="zlib")
    def call(self,mode,source,reply,work,label):
        s=guard(source);r=guard(reply);before=ctypes.string_at(work[1],work[2])
        ret=int(self.images[mode]._entry(s[1],s[2],r[1],r[2],work[1],work[2]));self.entries+=1
        for b in(s,r,work):intact(b)
        assert ctypes.string_at(s[1],s[2])==source and ctypes.string_at(r[1],r[2])==reply
        row=dict(label=label,owner=mode,return_value=ret,source=self.cas(source),reply=self.cas(reply),
                 before=self.cas(before),after=self.cas(ctypes.string_at(work[1],work[2])),canaries=True)
        with (self.out/"entries.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
        return ret
    def raw(self,number,*args):
        ctypes.set_errno(0);ret=int(self.libc.syscall(ctypes.c_long(number),*(ctypes.c_long(v) for v in args)))
        self.syscalls+=1;return ret,ctypes.get_errno() if ret<0 else 0
    def span(self,w,at,n,nul=False):
        assert at<=w[2] and n<=w[2]-at,(at,n,w[2])
        raw=ctypes.string_at(w[1]+at,n)
        if nul:assert raw and raw[-1]==0 and b"\0" not in raw[:-1]
        return raw
    def primitive(self,mode,event,work,label,script=None):
        op=event[4];self.operations[op]=self.operations.get(op,0)+1
        if script is not None:
            issued=script(mode,event,work)
            if issued is not None:
                status,result,err,data=issued
                reply=struct.pack("<8Q",magic(b"HIATDA01" if mode=="create" else b"HIATRA01"),
                    event[2],event[3],op,status,result,err,len(data))+data
                self.log_syscall(label,op,event,None,result,err,data,True)
                return reply
        result=err=0;data=b"";p=None
        if mode=="create":
            if op==11:
                p=guard(self.span(work,event[8],event[9],True));ret,err=self.raw(83,p[1],event[11]);intact(p)
            elif op==15:
                buf=guard(b"",event[10]);ret,err=self.raw(318,buf[1],buf[2],event[11]);intact(buf)
                if not err:assert 0<=ret<=buf[2];result=ret;data=ctypes.string_at(buf[1],ret)
            elif op==24:
                buf=guard(b"",16);ret,err=self.raw(228,event[11],buf[1]);intact(buf)
                if not err:data=ctypes.string_at(buf[1],16)
            elif op==25:
                ret,err=self.raw(39)
                if not err:result=ret
            else:raise AssertionError(op)
        else:
            token,cap,a,b,other=event[10],event[11],event[12],event[13],event[18]
            if event[9]:p=guard(self.span(work,event[8],event[9],True))
            def fd(t):return -100 if t==M else self.fds[t]
            if op in(1,16,23):
                assert token not in self.fds and token not in(0,M)
                if op==1:ret,err=self.raw(2,p[1],a,b)
                elif op==16:ret,err=self.raw(257,fd(other),p[1],a,b)
                else:ret,err=self.raw(72,fd(other),1030,0)
                if not err:self.fds[token]=ret;result=token
            elif op==2:
                actual=self.fds.pop(token);ret,err=self.raw(3,actual)
            elif op in(3,7,8,17):
                assert cap==144;buf=guard(b"",144)
                if op==3:ret,err=self.raw(5,fd(token),buf[1])
                elif op==7:ret,err=self.raw(4,p[1],buf[1])
                elif op==8:ret,err=self.raw(6,p[1],buf[1])
                else:ret,err=self.raw(262,fd(token),p[1],buf[1],a)
                intact(buf)
                if not err:data=ctypes.string_at(buf[1],144)
            elif op==18:
                buf=guard(b"",cap);ret,err=self.raw(217,fd(token),buf[1],cap);intact(buf)
                if not err:assert 0<=ret<=cap;result=ret;data=ctypes.string_at(buf[1],ret)
            elif op==10:ret,err=self.raw(87,p[1])
            elif op==12:ret,err=self.raw(84,p[1])
            elif op==20:ret,err=self.raw(90,p[1],b)
            elif op==21:ret,err=self.raw(263,fd(token),p[1],a)
            else:raise AssertionError(op)
            if p:intact(p)
        path=None if p is None else ctypes.string_at(p[1],p[2])
        self.log_syscall(label,op,event,path,ret,err,data,False)
        return struct.pack("<8Q",magic(b"HIATDA01" if mode=="create" else b"HIATRA01"),
            event[2],event[3],op,int(bool(err)),result if not err else 0,err,len(data))+data
    def log_syscall(self,label,op,event,path,ret,err,data,scripted):
        row=dict(label=label,op=op,event=list(event),path=None if path is None else path.hex(),
                 raw_return=ret,errno=err,payload=self.cas(data),scripted_receipt=scripted)
        with (self.out/"syscalls.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
    def run(self,mode,source,label,root,script=None,bad=None,grow_bad=None,work_mutation=None):
        work=guard(b"",1024 if mode=="create" else 4096);reply=b"";grows=0;pending=bad
        mutated=False
        try:
            for iteration in range(100000):
                ret=self.call(mode,source,reply,work,label)
                e=struct.unpack_from("<16Q" if mode=="create" else "<32Q",
                                     ctypes.string_at(work[1],work[2]),256)
                assert e[0]==magic(b"HIATDE01" if mode=="create" else b"HIATRE01") and e[2]==71
                if ret==0xfffffffe:
                    assert e[1]==1 and e[14]>work[2]
                    previous=ctypes.string_at(work[1],work[2]);work=guard(previous,e[14]);grows+=1
                    if grow_bad is not None and reply:
                        altered=grow_bad(reply)
                        assert self.call(mode,source,altered,work,label+"/bad-grow")==0xfffffffd
                        assert self.call(mode,source,reply,work,label+"/after-poison")==0xfffffffd
                        return dict(private_BAD=True,grows=grows)
                    continue
                assert ret==(128 if mode=="create" else 256) and e[1] in(0,2),(ret,e)
                if e[1]==2:
                    reply=self.primitive(mode,e,work,label,script)
                    if pending is not None:
                        altered=pending(reply)
                        assert self.call(mode,source,altered,work,label+"/bad")==0xfffffffd
                        assert self.call(mode,source,reply,work,label+"/after-poison")==0xfffffffd
                        return dict(private_BAD=True,grows=grows)
                    if work_mutation is not None and not mutated:
                        work_mutation(work,e);mutated=True
                    continue
                error_presentation=None
                if mode=="create":
                    path=self.span(work,e[8],e[9]) if e[9] else None
                    stage=self.span(work,e[10],e[11]) if e[11] else None
                    answer=dict(code=e[5],errno=e[6],created=e[7],directory=norm(path,root),stage=norm(stage,root),
                                tries=e[12],raw_directory=None if path is None else path.hex(),
                                raw_stage=None if stage is None else stage.hex())
                else:
                    assert e[16]==0 and not self.fds
                    path=self.span(work,e[8],e[9]) if e[9] else None
                    answer=dict(kind=e[5],errno=e[6],path=norm(path,root),type=None,custom_text=None)
                    if e[5]==1:answer["type"]=type(OSError(e[6],os.strerror(e[6]))).__name__
                    if e[5]==2:
                        error=OSError("Cannot call rmtree on a symbolic link")
                        if path is not None:error.filename=os.fsdecode(path)
                        assert e[6]==0 and error.errno is None
                        answer=answer_error(error,root)
                        error_presentation=dict(type=type(error).__name__,text=str(error),errno=error.errno,
                            filename=None if error.filename is None else os.fsencode(error.filename).hex())
                assert self.call(mode,source,reply,work,label+"/terminal-reentry")==0xfffffffd
                return dict(answer=answer,grows=grows,event=list(e),error_presentation=error_presentation)
            raise AssertionError("test harness ceiling, not a filesystem or language quota")
        finally:
            # A private BAD deliberately abandons its lease. Close only its
            # remaining owned descriptors; record every actual teardown close.
            for token,fd in list(self.fds.items()):
                del self.fds[token];ret,err=self.raw(3,fd)
                with (self.out/"teardown.jsonl").open("a") as f:
                    f.write(json.dumps(dict(label=label,token=token,fd=fd,raw_return=ret,errno=err))+"\n")

def creation_names(policy):
    prefix=".hia-publish-" if policy==1 else ".hepta-json-view-"
    return prefix,["aaaaaaaa","________","ssssssss"]
def entropy_for(index):
    words=[0,(1<<64)-1,((18*(1<<53)+36)//37)<<11]
    return struct.pack("<8Q",*([words[index]]*8))
def physical_creation(actual,fixtures,policy,variant,records):
    case=fixtures/("create-"+str(policy)+"-"+variant);case.mkdir()
    nbase=case/"native";rbase=case/"reference";nbase.mkdir();rbase.mkdir()
    part={"unicode":"文🙂","surrogate":"bad\udcff"}.get(variant,"parent")
    np=nbase/part;rp=rbase/part
    if variant=="parent-file":np.write_bytes(b"x");rp.write_bytes(b"x")
    elif variant!="missing":np.mkdir();rp.mkdir()
    prefix,names=creation_names(policy)
    if variant=="collision":
        (np/(prefix+names[0])).mkdir();(rp/(prefix+names[0])).mkdir()
        (np/(prefix+names[1])).write_bytes(b"occupied");(rp/(prefix+names[1])).write_bytes(b"occupied")
    save(actual.out/"physical-before"/(case.name+".json"),dict(native=inventory(nbase,actual.cas),reference=inventory(rbase,actual.cas)))
    count=0
    def script(mode,event,work):
        nonlocal count
        if event[4]!=15:return None
        assert count<3
        data=entropy_for(count);count+=1
        return 0,len(data),0,data
    got=actual.run("create",command(np,"create",policy),case.name,nbase,script=script)
    with patch.object(tempfile,"_get_candidate_names",return_value=iter(names)):
        try:
            expected=tempfile.mkdtemp(prefix=prefix,dir=rp)
            reference=dict(code=0,errno=0,created=1,directory=norm(expected,rbase),
                           stage=norm(Path(expected)/("program.hia" if policy==1 else "view.json"),rbase))
        except OSError as e:
            reference=dict(code=1,errno=e.errno,created=0,directory=norm(e.filename,rbase),stage=None)
    for k,v in reference.items():assert got["answer"][k]==v,(case.name,k,got,reference)
    assert inventory(nbase,actual.cas)==inventory(rbase,actual.cas),(case.name,"filesystem")
    if got["answer"]["created"]:
        created=Path(os.fsdecode(bytes.fromhex(got["answer"]["raw_directory"])))
        assert stat.S_IMODE(created.stat().st_mode)==(0o700 & ~current_umask())
    row=dict(label=case.name,actual=got,reference=reference,
             name_bytes_controlled=True,actual_mkdir=True,
             native_filesystem=inventory(nbase,actual.cas),reference_filesystem=inventory(rbase,actual.cas))
    records.append(row)
def current_umask():
    value=os.umask(0);os.umask(value);return value
def cleanup_setup(base,variant,actual):
    base.mkdir();root=base/"root";root.mkdir();outside=base/"outside";outside.mkdir()
    (outside/"keep").write_bytes(b"outside-content\n")
    if variant=="one-file":(root/"program.hia").write_bytes(b'{"schema":"x"}')
    elif variant=="nested":
        for sub in("a","b","a/c"):
            (root/sub).mkdir(parents=True,exist_ok=True);(root/sub/"f").write_bytes(os.fsencode(sub))
    elif variant=="symlinks":
        (root/"file").write_bytes(b"inside");os.symlink("../outside/keep",root/"file-link")
        os.symlink("../outside",root/"dir-link");os.symlink(".",root/"self")
    elif variant=="broken":os.symlink("missing",root/"broken")
    elif variant=="unicode":(root/"文🙂").write_bytes(b"unicode")
    elif variant=="surrogate":(root/os.fsdecode(b"bad\xff")).write_bytes(b"surrogate")
    elif variant=="fifo":os.mkfifo(root/"fifo",0o600)
    elif variant=="hardlink":os.link(outside/"keep",root/"hard")
    elif variant=="readonly-file":
        (root/"f").write_bytes(b"readonly");(root/"f").chmod(0o400)
    elif variant in("root-mode0","nested-mode0"):
        folder=root if variant=="root-mode0" else root/"d"
        if folder!=root:folder.mkdir()
        (folder/"f").write_bytes(b"permission")
    elif variant=="missing":root.rmdir()
    elif variant=="root-file":root.rmdir();root.write_bytes(b"not-a-directory")
    elif variant=="root-link":root.rmdir();os.symlink("outside",root)
    elif variant=="wide":
        for i in range(900):(root/("entry-"+str(i).zfill(4))).write_bytes(bytes([i%251]))
    elif variant=="deep":
        p=root
        for i in range(40):p=p/("d"+str(i));p.mkdir();(p/"f").write_bytes(str(i).encode())
    elif variant=="mixed":
        for i in range(3):
            d=root/("d"+str(i));d.mkdir();(d/"f").write_bytes(b"f")
            os.symlink("../../outside/keep",d/"link")
        (root/"z").write_bytes(b"z")
    elif variant!="empty":raise AssertionError(variant)
    before=inventory(base,actual.cas)
    save(actual.out/"physical-before"/(base.parent.name+"-"+base.name+".json"),dict(objects=before,post_capture_permission_change=variant if variant in("root-mode0","nested-mode0") else None))
    if variant=="root-mode0":root.chmod(0)
    elif variant=="nested-mode0":(root/"d").chmod(0)
    return root,before
def physical_cleanup(actual,fixtures,variant,records):
    case=fixtures/("cleanup-"+variant);case.mkdir()
    nroot,n_before=cleanup_setup(case/"native",variant,actual)
    rroot,r_before=cleanup_setup(case/"reference",variant,actual)
    assert n_before==r_before
    expected=dict(kind=0,errno=0,path=None,type=None,custom_text=None)
    reference_error=None
    try:tempfile.TemporaryDirectory._rmtree(str(rroot))
    except OSError as error:
        expected=answer_error(error,case/"reference")
        reference_error=dict(type=type(error).__name__,text=str(error),errno=error.errno,
                             filename=None if error.filename is None else os.fsencode(error.filename).hex())
    got=actual.run("cleanup",command(nroot,"cleanup"),case.name,case/"native")
    assert got["answer"]==expected,(case.name,got,expected)
    n_after=inventory(case/"native",actual.cas);r_after=inventory(case/"reference",actual.cas)
    assert n_after==r_after,(case.name,n_after,r_after)
    assert (case/"native/outside/keep").read_bytes()==b"outside-content\n"
    row=dict(label=case.name,actual=got,reference=expected,reference_error=reference_error,
             before=n_before,native_after=n_after,reference_after=r_after)
    records.append(row)
def field(index,value):
    def change(raw):
        out=bytearray(raw);struct.pack_into("<Q",out,index*8,value);return bytes(out)
    return change
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    p.add_argument("--compiler",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    assert os.name=="posix" and sys.platform=="linux" and os.chmod not in os.supports_follow_symlinks
    assert tempfile.TMP_MAX==238328
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    project=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    fixtures=out/"physical";fixtures.mkdir();pins={};actual=None
    result=dict(status="FAIL",scope="NEW_NATIVE_TEMPDIR_CREATION_AND_FD_SAFE_CLEANUP",
        physical_creation_cases=0,actual_entropy_cases=0,physical_cleanup_cases=0,
        private_protocol_controls=0,extra_control_cases=0,whole_publication_parent_closed=False,
        Python_embedding_audit_hooks_or_async_exceptions_closed=False,
        entropy_internal_state_equivalence_claimed=False,scripted_receipts_are_physical_authority=False)
    def pin(path):
        path=path.resolve();raw=path.read_bytes();pins[str(path)]=digest(raw);return raw
    try:
        sys.path[:0]=[str(project/"tools"),str(a.source.resolve()),str(project.parent/"Hepta-agent-edit-native")]
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring
        import cli_publication_tempdir_owner as create
        import cli_publication_cleanup_owner as cleanup
        for path in sorted((project/"tools").glob("*.py")):pin(path)
        pin(Path(__file__));pin(project.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py")
        pin(Path(tempfile.__file__))
        import shutil
        pin(Path(shutil.__file__))
        compiler=pin(a.compiler)
        assert (len(compiler),digest(compiler))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        images={};profiles={}
        for mode,owner in(("create",create),("cleanup",cleanup)):
            directory=out/("compile-"+mode);directory.mkdir()
            expanded=cli_authoring.expanded(owner.BODY,owner.CONSTANTS)
            (directory/"expanded.py").write_text(expanded)
            doc=cli_authoring.document(expanded,"hia_cli_temporary_directory_"+mode)
            profile=cli_authoring.profile(doc);profiles[mode]=profile
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16,profile
            source=render_assembly(doc).encode();assemble_program(source)
            (directory/"source.hiaasm").write_bytes(source)
            image_path,receipt=compile_stage(directory,mode,a.compiler,source)
            image=pin(image_path)
            assert receipt["input_sha256"]==receipt["source_sha256"]==digest(source)
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==digest(compiler)
            assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            save(directory/"manifest.json",dict(source_sha256=digest(source),image_sha256=digest(image),profile=profile,receipt=receipt))
            images[mode]=NativeHiaJsonImage(image,expected_sha256=digest(image))
        actual=Actual(images,out);cases=[]
        for policy in(1,2):
            for variant in("plain","unicode","surrogate","missing","parent-file","collision"):
                physical_creation(actual,fixtures,policy,variant,cases);result["physical_creation_cases"]+=1
                save(out/"cases.json",cases)
            root=fixtures/("real-entropy-"+str(policy));root.mkdir()
            got=actual.run("create",command(root,"create",policy),"real-entropy-"+str(policy),root)
            assert got["answer"]["created"]==1 and got["answer"]["tries"]==0
            raw=bytes.fromhex(got["answer"]["raw_directory"]);name=os.path.basename(raw)
            prefix,_=creation_names(policy)
            assert name.startswith(prefix.encode()) and len(name)==len(prefix)+8
            assert all(x in b"abcdefghijklmnopqrstuvwxyz0123456789_" for x in name[-8:])
            assert stat.S_IMODE(os.stat(raw).st_mode)==(0o700 & ~current_umask())
            cases.append(dict(label="real-entropy-"+str(policy),actual=got,actual_getrandom=True))
            result["actual_entropy_cases"]+=1
            save(out/"cases.json",cases)
        variants=("empty","one-file","nested","symlinks","broken","unicode","surrogate","fifo","hardlink",
            "readonly-file","root-mode0","nested-mode0","missing","root-file","root-link","wide","deep","mixed")
        for variant in variants:
            physical_cleanup(actual,fixtures,variant,cases);result["physical_cleanup_cases"]+=1
            save(out/"cases.json",cases)
        private=fixtures/"private";private.mkdir()
        mutators=[("magic",field(0,0)),("lease",field(1,72)),("sequence",field(2,0)),
            ("op",field(3,99)),("status",field(4,2)),("bad-result",field(5,1)),
            ("errno-on-success",field(6,5)),("extent",field(7,1)),
            ("truncated",lambda r:r[:-1]),("extra",lambda r:r+b"\0")]
        for mode in("create","cleanup"):
            for label,mutator in mutators:
                got=actual.run(mode,command(private,mode),mode+"-private-"+label,private,bad=mutator)
                assert got["private_BAD"];result["private_protocol_controls"]+=1
        def replace_success_with_error(raw):
            values=list(struct.unpack_from("<8Q",raw));values[4:8]=[1,0,5,0]
            return struct.pack("<8Q",*values)
        got=actual.run("cleanup",command(private,"cleanup"),"cleanup-GROW-reply-replacement",private,
                       grow_bad=replace_success_with_error)
        assert got["private_BAD"];result["private_protocol_controls"]+=1
        # This is an explicitly private near-boundary state control; it does not
        # claim 238,328 actual filesystem collisions or calls.
        def last_attempt(work,event):
            assert event[4]==15;ctypes.memmove(work[1]+create.CONSTANTS["TRIES"],struct.pack("<Q",238327),8)
        def collision_script(mode,event,work):
            if event[4]==15:return 0,event[10],0,b"\0"*event[10]
            if event[4]==11:return 1,0,errno.EEXIST,b""
            return None
        got=actual.run("create",command(private,"create"),"last-collision-private-state",private,
                       script=collision_script,work_mutation=last_attempt)
        assert got["answer"]["code"]==2 and got["answer"]["errno"]==17 and not got["answer"]["created"]
        cases.append(dict(label="last-collision-private-state",actual=got,actual_collision_count=0));result["extra_control_cases"]+=1
        for label,script_values in(("partial-entropy",[InterruptedError(),b"\0"*20,b"\0"*44]),
                                     ("entropy-fallback",[BlockingIOError()])):
            parent=fixtures/label;parent.mkdir();queue=list(script_values)
            def script(mode,event,work):
                if event[4]!=15:return None
                value=queue.pop(0)
                if isinstance(value,InterruptedError):return 1,0,4,b""
                if isinstance(value,BlockingIOError):return 1,0,11,b""
                return 0,len(value),0,value
            got=actual.run("create",command(parent,"create"),label,parent,script=script)
            assert got["answer"]["created"]==1 and not queue
            cases.append(dict(label=label,actual=got,scripted_entropy_reply=True,actual_mkdir=True))
            result["extra_control_cases"]+=1
        save(out/"cases.json",cases)
        result.update(status="PASS",profiles=profiles)
    except BaseException:
        result["failure"]=traceback.format_exc();raise
    finally:
        if actual:
            result.update(native_entries=actual.entries,actual_syscalls=actual.syscalls,operations=actual.operations)
            save(out/"physical-after.json",inventory(fixtures,actual.cas))
            rows=[]
            for h,n in sorted(actual.cas_index.items()):
                raw=zlib.decompress((out/"cas"/(h+".zlib")).read_bytes())
                assert len(raw)==n and digest(raw)==h;rows.append(dict(sha256=h,bytes=n))
            save(out/"cas-index.json",rows)
            result["cas_readback"]=dict(status="PASS",objects=len(rows),logical_bytes=sum(x["bytes"] for x in rows))
        result["source_pins_unchanged"]=all(digest(Path(path).read_bytes())==h for path,h in pins.items())
        save(out/"source-pins.json",pins);save(out/"summary.json",result)
        print(json.dumps(result,sort_keys=True),flush=True)
    assert result["status"]=="PASS" and result["source_pins_unchanged"]
    assert (result["physical_creation_cases"],result["actual_entropy_cases"],result["physical_cleanup_cases"],
            result["private_protocol_controls"],result["extra_control_cases"])==(12,2,18,21,3)
if __name__=="__main__":main()
