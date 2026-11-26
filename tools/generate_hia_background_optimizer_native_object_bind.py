"""Private native initialization of one BG object's component contexts.

All pointers below are offsets inside the registered native allocation or fixed
entries copied by the trusted global initializer. No public request carries them.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
LAYOUT=dict(record_bytes=2097152,config=1024,global_copy=2048,runtime_copy=2560,future_copy=3072,
 queue=4096,jobs=8192,job_refs=8448,worker=8704,ledger=9216,decimal=13312,freezer=13568,
 submission=16384,business=24576,execution=1089536,account=1138688,snapshot=1175552,
 shutdown=1183744,constructor=1200128,decision=1495040,transport=1511424)
SIZES=dict(queue=4096,jobs=256,job_refs=64,worker=512,ledger=4096,decimal=256,freezer=2048,
 submission=8192,business=1064960,execution=49152,account=36864,snapshot=8192,shutdown=16384,
 constructor=294912,decision=16384,transport=256)
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(INPUT="HIABNBD1",REPLY="HIABNBR1",
 OBJECT="HIABGOB1",GLOBAL="HIABGNC1",CONFIG_MAGIC="HIABGCF1").items()}
C.update({k.upper():v for k,v in LAYOUT.items()})
def i(n):return str(n)
def e(n):return f"get(w,CONFIG_AT+136+{n}*8)"
def g(n):return f"get(w,GLOBAL_AT+{n})"
def r(n):return f"get(w,RUNTIME_AT+{n})"
def f(n):return f"get(w,FUTURE_AT+{n})"
def p(name):return "get(w,16)+"+str(LAYOUT[name])
def magic(x):return str(int.from_bytes(x.encode(),"little"))
def row(base,fields,copies=()):
    lines=[]
    for off,value in fields.items():lines.append(f"    put(w,{base+off},{value})")
    for off,source,n in copies:lines.append(f"    copy(w,{base+off},{source},{n})")
    return "\n".join(lines)+"\n"
def source_program():
    c=LAYOUT
    text=HEAD
    ctor={0:magic("HIABPCC1"),8:g(32),16:g(40),24:"256",32:e(17),40:e(18),48:e(19),
      56:e(20),64:e(21),72:e(22),80:e(23),88:e(25),96:r(104),104:r(112),112:"256",
      120:g(80),128:g(88),136:"768",144:e(26),152:e(27),160:"get(w,CONFIG_AT+64)",
      168:"get(w,CONFIG_AT+32)",176:"10100891",184:e(35),192:e(28),200:e(34),
      208:e(36),216:e(29),224:e(30),232:"get(w,CONFIG_AT+48)",240:"get(w,8)",264:e(24)}
    text+="\ndef bind_constructor(w:mutbuf) -> u64:\n"+row(c["constructor"],ctor)+"    return 0\n"
    common={8:g(32),16:g(40),24:"256",32:e(12),40:g(80),48:g(88),56:"768",
      88:r(104),96:r(112),104:"256",112:e(3),120:p("jobs"),128:"256",
      136:e(0),144:p("queue"),152:"4096",160:f(64)}
    ex=dict(common)
    ex.update({0:magic("HIABEXC3"),216:e(14),224:p("transport"),232:"256",240:e(37),
      248:"get(w,CONFIG_AT+64)",256:"get(w,CONFIG_AT+72)",264:"get(w,CONFIG_AT+88)",
      272:"get(w,CONFIG_AT+48)",280:"get(w,CONFIG_AT+32)",288:"10100891",
      296:e(31),304:p("decision"),312:"16384",320:p("submission"),328:"8192"})
    text+="\ndef bind_execution(w:mutbuf) -> u64:\n"+row(c["execution"],ex,
      [(64,240,24),(336,360,24),(360,288,24),(384,312,24),(408,608,24),(432,632,24)])+"    return 0\n"
    business=dict(common)
    business.update({0:magic("HIABWBC3"),168:g(56),176:g(64),184:"256",
      216:e(8),224:p("execution"),232:"49152",240:e(9),248:p("account"),256:"36864",
      320:p("submission"),328:"8192",384:f(80),392:"get(w,192)+256",400:"256"})
    text+="\ndef bind_business(w:mutbuf) -> u64:\n"+row(c["business"],business,
      [(64,240,24),(192,192,24),(288,360,24),(544,104,24)])+"    return 0\n"
    sub={0:magic("HIABSCC3"),8:g(32),16:g(40),24:"256",32:e(0),40:p("queue"),48:"4096",
      56:e(3),64:p("jobs"),72:"256",80:g(56),88:g(64),96:"256",
      152:g(80),160:g(88),168:"768",200:r(104),208:r(112),216:"256",224:e(13),
      232:"get(w,CONFIG_AT+32)",240:"10100891",248:e(15),256:p("freezer"),264:"2048",
      272:e(38),280:e(26),800:f(80),808:"get(w,192)+256",816:"256",
      832:e(33),840:g(112),848:"512",856:g(128)}
    # Provider nonce is the captured Future-provider nonce, not the BG nonce.
    sub[856]="get(w,FUTURE_PROVIDER_NONCE)"
    text+="\ndef bind_submission(w:mutbuf) -> u64:\n"+row(c["submission"],sub,
      [(104,192,24),(128,216,24),(176,240,24),(288,360,24),(312,384,24),
       (512,512,64),(576,512,64),(640,264,24),(664,408,24),(688,288,24),(864,104,24)])
    text+="    zero(w,384,24)\n    zero(w,408,24)\n    return 0\n"
    account={0:magic("HIABACC3"),8:g(32),16:g(40),24:"256",32:e(12),40:e(15),
      48:p("freezer"),56:"2048",64:e(1),72:p("ledger"),80:"4096",88:e(3),96:p("jobs"),
      104:"256",112:g(56),120:g(64),128:"256",160:f(64),168:e(2),176:p("decimal"),
      184:"256",192:f(80),200:"get(w,192)+256",208:"256",224:e(0),232:p("queue"),240:"4096"}
    text+="\ndef bind_account(w:mutbuf) -> u64:\n"+row(c["account"],account,[(136,192,24)])+"    return 0\n"
    snap={0:magic("HIABSPC2"),8:g(32),16:g(40),24:"256",32:e(0),40:p("queue"),48:"4096",
      56:e(1),64:p("ledger"),72:"4096",80:e(5),88:p("worker"),96:"512",
      104:e(3),112:p("jobs"),120:"256",128:e(2),136:p("decimal"),144:"256",
      152:r(104),160:r(112),168:"256",176:p("submission"),184:"8192",
      192:p("business"),200:"1064960",208:"get(w,8)"}
    text+="\ndef bind_snapshot(w:mutbuf) -> u64:\n"+row(c["snapshot"],snap)+"    return 0\n"
    shut={0:magic("HIABSHC2"),8:g(32),16:g(40),24:"256",32:e(0),40:p("queue"),48:"4096",
      56:e(3),64:p("jobs"),72:"256",80:g(56),88:g(64),96:"256",
      128:e(5),136:p("worker"),144:"512",152:p("submission"),160:"8192",
      192:f(80),200:"get(w,192)+256",208:"256"}
    text+="\ndef bind_shutdown(w:mutbuf) -> u64:\n"+row(c["shutdown"],shut,[(104,192,24)])+"    return 0\n"
    dec={0:magic("HIABDOC2"),8:g(32),16:g(40),24:"256",32:e(35),40:e(26),48:e(28),
      56:r(104),64:r(112),72:"256",80:"get(w,CONFIG_AT+48)",88:e(25),
      96:"get(w,CONFIG_AT+64)",104:"get(w,CONFIG_AT+32)",112:"10100891",120:e(34),
      128:e(29),136:e(30),144:e(36),152:e(39),160:e(27),168:e(22)}
    text+="\ndef bind_decision(w:mutbuf) -> u64:\n"+row(c["decision"],dec)+"    return 0\n"
    freeze={0:magic("HIABFZC3"),8:g(32),16:g(40),24:"256",32:e(14),40:e(26),48:e(28),
      56:r(104),64:r(112),72:"256",80:"get(w,CONFIG_AT+48)"}
    text+="\ndef bind_freezer(w:mutbuf) -> u64:\n"+row(c["freezer"],freeze)+"    return 0\n"
    transport={0:magic("HIABIC03"),8:g(32),16:g(40),24:"256"}
    refs={0:magic("HIABJRC2"),8:e(3),16:p("jobs"),24:"256"}
    text+="\ndef bind_small(w:mutbuf) -> u64:\n"+row(c["transport"],transport)+row(c["job_refs"],refs)+"    return 0\n"
    text+=HELPERS
    constants=dict(C,CONFIG_AT=c["config"],GLOBAL_AT=c["global_copy"],RUNTIME_AT=c["runtime_copy"],FUTURE_AT=c["future_copy"],FUTURE_PROVIDER_NONCE=704)
    for k,v in sorted(constants.items(),key=lambda x:-len(x[0])):text=re.sub(r"\b"+k+r"\b",str(v),text)
    return text
HEAD=r'''
def background_native_object_bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or word_load(s,0)!=INPUT or word_load(s,8)>2 or length(o)<128 or length(w)!=RECORD_BYTES:
        return 4294967293
    if get(w,0)!=OBJECT or get(w,8)<2 or get(w,16)==0 or get(w,24)!=RECORD_BYTES or get(w,32)==0 or get(w,40)==0 or get(w,48)==0:
        return 4294967293
    if get(w,GLOBAL_AT)!=GLOBAL or get(w,GLOBAL_AT+16)!=get(w,32) or get(w,GLOBAL_AT+128)!=get(w,40) or get(w,GLOBAL_AT+168)!=1:
        return 4294967293
    if get(w,CONFIG_AT)!=CONFIG_MAGIC or get(w,CONFIG_AT+16)!=get(w,32) or get(w,CONFIG_AT+24)!=get(w,40) or get(w,CONFIG_AT+128)!=40:
        return 4294967293
    if get(w,GLOBAL_AT+40)==0 or get(w,GLOBAL_AT+48)!=256 or get(w,GLOBAL_AT+72)!=256:
        return 4294967293
    mode=word_load(s,8)
    if mode==0:
        bind_constructor(w)
        bind_small(w)
    elif mode==1:
        if get(w,192)==0 or get(w,216)==0 or get(w,240)==0 or get(w,264)==0 or get(w,288)==0 or get(w,312)==0 or get(w,336)==0:
            return 4294967293
        if get(w,360)==0 or get(w,384)==0 or get(w,408)==0 or get(w,608)==0 or get(w,632)==0 or get(w,FUTURE_PROVIDER_NONCE)==0:
            return 4294967293
        bind_small(w)
        bind_freezer(w)
        bind_submission(w)
        bind_execution(w)
        bind_business(w)
        bind_account(w)
        bind_snapshot(w)
        bind_shutdown(w)
        bind_decision(w)
    else:
        if get(w,104)==0 or get(w,112)==0 or get(w,120)==0:
            return 4294967293
        copy(w,SUBMISSION+864,104,24)
        copy(w,BUSINESS+544,104,24)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,16,mode)
    return 0
'''
HELPERS=r'''
def get(b:mutbuf,at:u64) -> u64:
    return word_load(b,at)
def put(b:mutbuf,at:u64,v:u64) -> u64:
    i=0
    while i<8:
        store(b,at+i,(v>>(8*i))&255)
        i=i+1
    return 0
def zero(b:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,at+i,0)
        i=i+1
    return 0
def copy(b:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(b,to+i,byte(b,at+i))
        i=i+1
    return 0
'''
def main():
    d=document(source_program(),"background_optimizer_native_object_bind")
    p=ROOT/"examples/hia_bootstrap/background_optimizer_native_object_bind.hepta";p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
