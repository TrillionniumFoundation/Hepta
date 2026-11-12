"""HIA-only fixed-filesystem mechanical fixtures, not CLI path policy."""
import ast
from cli_publication_fixed_driver import COMMON,CONSTANTS,BODY,magic
class Flow:
    def __init__(self):self.rows=[]
    def add(self,label,body):self.rows.append((label,body.strip("\n")))
    def emit(self):
        names={name:index+1 for index,(name,_) in enumerate(self.rows)}
        lines=["def utility_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:"]
        for index,(name,body) in enumerate(self.rows):
            body=body.replace("@NEXT@",str(index+2))
            for label,value in names.items():body=body.replace("@"+label+"@",str(value))
            assert "@" not in body
            lines.append("    if phase == "+str(index+1)+":")
            lines.extend("        "+line for line in body.splitlines())
        lines.append("    return refuse(w, 8900)")
        return "\n".join(lines)+"\n"
def payload_writer(name,raw,offset):
    functions=[];calls=[]
    for start in range(0,len(raw),128):
        fn=name+"_"+str(start//128);calls.append("    "+fn+"(w)")
        lines=["def "+fn+"(w:mutbuf) -> u64:"]
        for at in range(start,min(start+128,len(raw)),8):
            lines.append("    put(w, "+str(offset+at)+", "+str(int.from_bytes(raw[at:at+8],"little"))+")")
        lines.append("    return 0");functions.append("\n".join(lines))
    return "def "+name+"(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"+"\n".join(functions)+"\n"
INIT=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 65536 or length(o) != 128:
        return ABI
    if get(w, L_MAGIC) == 0:
        if length(s) != 64 or word(s, 0) != CLI_INIT or word(s, 8) != 1:
            return refuse(w, 8901)
        put(w, L_MAGIC, LOWER_MAGIC)
        put(w, L_STATUS, 1)
        put(w, L_DRIVER, 7)
        put(w, C_LEASE, 1)
        put(w, C_PHASE, 1)
        put(w, CAPS + 8, word(s, 16))
        put(w, CAPS + 16, 65536)
        put(w, CAPS + 24, 128)
    elif acknowledge(s, w, 7) == 0:
        return refuse(w, 8902)
    while get(w, L_STATUS) == 1:
        result = utility_step(o, w, get(w, C_PHASE))
        if result != 0:
            return result
    return ABI

def utility_terminal(o:mutbuf, w:mutbuf) -> u32:
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, 1)
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 40, 13)
    put(o, 56, LOG_BYTES)
    put(w, L_STATUS, 2)
    return 128
'''
def make(folder,mode="all",fd_zero=False):
    paths=[str(folder/"directory").encode(),str(folder/"directory/file").encode(),
        str(folder/"directory/copy").encode(),str(folder/"symlink").encode(),
        b"file",b"copy",str(folder/"existing").encode()]
    raw=b"";spans=[]
    for path in paths:spans.append((len(raw),len(path)+1));raw+=path+b"\0"
    if mode=="path-interior":spans[6]=(spans[0][0],spans[1][0]+spans[1][1])
    f=Flow();calls=[]
    f.add("paths-grow","return grow(o, w, 4, "+str(len(raw))+", @NEXT@)")
    f.add("paths-copy","paths(w)\nreturn copy(o, w, 2, 22000, 4, 0, "+str(len(raw))+", @NEXT@)")
    f.add("paths-ro","return protect(o, w, 4, 1, @NEXT@)")
    f.add("data-grow","return grow(o, w, 5, 8, @NEXT@)")
    f.add("data-copy","put(w, WIRE, "+str(int.from_bytes(b"PUBFSr1\n","little"))+")\nreturn copy(o, w, 2, WIRE, 5, 0, 8, @NEXT@)")
    f.add("data-ro","return protect(o, w, 5, 1, @NEXT@)")
    f.add("scratch-grow","return grow(o, w, 6, 4096, @NEXT@)")
    def path(index):return [4,*spans[index]]
    def call(name,kind,token=0,first=None,a=0,second=None,b=0,check="zero",view=None):
        first=first or [0,0,0];second=second or [0,0,0]
        args=[kind,token,*first,a,*second,b]
        f.add(name,"return fs(o, w, "+", ".join(map(str,args))+", @NEXT@)")
        record="put(w, 20000 + "+str(len(calls)*16)+", "+str(kind)+")\nput(w, 20008 + "+str(len(calls)*16)+", get(w, C_RETURN))\n"
        calls.append(kind)
        if check=="zero":record+="if get(w, C_RETURN) != 0:\n    return refuse(w, 8910)\n"
        elif check=="fd":record+="if raw_error(get(w, C_RETURN)) != 0:\n    return refuse(w, 8911)\n"
        elif check=="fd0":record+="if get(w, C_RETURN) != 0:\n    return refuse(w, 8912)\n"
        elif check=="chmod2":record+="if get(w, C_RETURN) != 0 and get(w, C_RETURN) != 18446744073709551578:\n    return refuse(w, 8913)\n"
        elif isinstance(check,int):record+="if get(w, C_RETURN) != "+str(check)+":\n    return refuse(w, 8914)\n"
        elif check=="dents":record+="if get(w, C_RETURN) < 48 or get(w, C_RETURN) > 4096:\n    return refuse(w, 8915)\n"
        elif check=="cwd":record+="if get(w, C_RETURN) < 2 or get(w, C_RETURN) > 4096:\n    return refuse(w, 8916)\n"
        elif check!="none":raise AssertionError(check)
        if view:
            record+="return view(o, w, "+", ".join(map(str,view[:3]))+", @NEXT@)"
            f.add(name+"-check",record)
            f.add(name+"-view","if get(w, OBS) != "+str(view[3])+":\n    return refuse(w, 8917)\nput(w, C_PHASE, @NEXT@)\nreturn 0")
        else:
            record+="put(w, C_PHASE, @NEXT@)\nreturn 0";f.add(name+"-check",record)
    if mode=="all":
        call("mkdir",11,first=path(0),b=448)
        call("open-directory",1,token=1,first=path(0),a=589824,check="fd")
        call("openat-new",16,token=0,first=path(4),a=524481,second=[1,0,0],b=416,check="fd")
        call("write",5,token=0,first=[5,0,8],check=8)
        call("fsync",6,token=0)
        call("fstat",3,token=0,first=[6,0,144])
        call("fchmod",19,token=0,b=384)
        call("close-new",2,token=0)
        call("chmod",20,first=path(1),b=416)
        call("fchmodat2",22,token=1,first=path(4),b=420,check="chmod2")
        call("newfstatat",17,token=1,first=path(4),second=[6,0,144])
        call("openat-grow",16,token=512,first=path(4),second=[1,0,0],a=524288,check="fd")
        call("read",4,token=512,first=[6,0,8],check=8,view=[6,0,8,int.from_bytes(b"PUBFSr1\n","little")])
        call("close-grown",2,token=512)
        call("link",9,first=path(1),second=path(2))
        call("stat",7,first=path(2),second=[6,0,144])
        call("lstat",8,first=path(3),second=[6,0,144])
        call("readlink",13,first=path(3),second=[6,0,4096],check=8,view=[6,0,8,int.from_bytes(b"dir/file","little")])
        call("unlink-symlink",10,first=path(3))
        call("unlinkat",21,token=1,first=path(5))
        call("unlink",10,first=path(1))
        call("getdents",18,token=1,first=[6,0,4096],check="dents")
        call("getcwd",14,first=[6,0,4096],check="cwd")
        call("getrandom",15,first=[6,0,32],check=32)
        call("close-directory",2,token=1)
        call("rmdir",12,first=path(0))
        assert set(calls)==set(range(1,23))
    elif mode=="fd-zero":
        call("open-zero",1,first=path(6),a=524288,check="fd0" if fd_zero else "fd")
        call("close-zero",2)
    else:
        if mode in ("double-close","token-reopen","terminal-live","business-live","write-rw"):
            call("open-control",1,first=path(6),a=524288,check="fd")
        if mode=="double-close":call("close-first",2)
        if mode=="write-rw":
            f.add("copy-rw","return copy(o, w, 5, 0, 6, 0, 8, @NEXT@)")
        operations={
          "unknown-zero":[0,0,0,0,0,0,0,0,0,0],
          "unknown-high":[23,0,0,0,0,0,0,0,0,0],
          "unused-field":[14,0,6,0,8,1,0,0,0,0],
          "stat-short":[7,0,*path(6),0,6,0,143,0],
          "stat-long":[7,0,*path(6),0,6,0,145,0],
          "write-controller":[14,0,2,0,8,0,0,0,0,0],
          "write-readonly":[14,0,4,0,8,0,0,0,0,0],
          "path-no-nul":[1,0,4,spans[6][0],spans[6][1]-1,0,0,0,0,0],
          "path-interior":[1,0,*path(6),0,0,0,0,0],
          "path-overflow":[1,0,4,18446744073709551615,2,0,0,0,0,0],
          "token-missing":[2,700,0,0,0,0,0,0,0,0],
          "token-reopen":[1,0,*path(6),0,0,0,0,0],
          "double-close":[2,0,0,0,0,0,0,0,0,0],
          "open-max-token":[1,18446744073709551615,*path(6),0,0,0,0,0],
          "write-rw":[5,0,6,0,8,0,0,0,0,0]}
        if mode=="business-live":
            f.add("bad","put(w, C_OBSERVE, 0)\nargs(w, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)\nreturn event(o, w, 17, @NEXT@)")
        elif mode!="terminal-live":
            assert mode in operations,mode
            f.add("bad","return fs(o, w, "+", ".join(map(str,operations[mode]))+", @NEXT@)")
            f.add("bad-return","return refuse(w, 8918)")
    f.add("final-grow","return grow(o, w, 13, "+str(64+16*len(calls))+", @NEXT@)")
    f.add("final-header","zero(w, WIRE, 64)\nput(w, WIRE, "+str(magic("HIAPUT01"))+")\nput(w, WIRE + 8, 1)\nput(w, WIRE + 16, "+str(len(calls))+")\nreturn copy(o, w, 2, WIRE, 13, 0, 64, @NEXT@)")
    f.add("final-log","return copy(o, w, 2, 20000, 13, 64, "+str(16*len(calls))+", @NEXT@)")
    f.add("final-ro","return protect(o, w, 13, 1, @NEXT@)")
    f.add("done","return utility_terminal(o, w)")
    helpers={n.name:n for n in ast.parse(BODY).body}
    own=INIT+f.emit()+"\n".join(ast.unparse(helpers[n]) for n in ("fs","raw_error"))+"\n"
    own+=payload_writer("paths",raw,22000)+COMMON
    constants=dict(CONSTANTS);constants["LOG_BYTES"]=64+16*len(calls)
    return own,constants,dict(mode=mode,syscalls=calls,paths=[p.decode() for p in paths])
