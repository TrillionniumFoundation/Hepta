"""Actual same-holder GenerationInfo capture and owned publication replies.

This continuation is fixed in the runtime capsule. It observes actual mapping
code bytes, sealed descriptors, immutable decimal identities and prepared
generation state. It is not an externally callable proof-fact interface.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_effects as effects
ROOT=Path(__file__).resolve().parents[1]
C=dict(effects.C)
C.update({
'I_BASE':32768,'I_PUBLIC':32768,'I_HASH_DONE':32776,'I_INFO_DONE':32784,'I_RETURNED':32792,
'I_MAP_N':32800,'I_CODE':32808,'I_PTR':32816,'I_N':32824,'I_FRAMEPTR':32832,'I_FRAMEN':32840,
'I_OUTGO':32848,'I_FAILURE':32856,'I_FD':32864,'I_SEALS':32872,'I_JSONN':32880,
'I_EPOCH':32888,'I_EPOCHN':32896,'I_MEASN':32904,'I_MEASAT':32912,
'I_META':33792,'I_ABI':37888,'I_MAP':44032,'I_STAT':44288,'I_VALUE':44480,
'I_HASH':44608,'I_HASH_NEW':44640,'I_HEADER':44672,'I_WORK':45056,'I_FRAME':65536,
'INFO_MAGIC':int.from_bytes(b'HIAMVGI1','little'),'INFO_REPLY':int.from_bytes(b'HIAMVIR2','little'),
'PUB_MAGIC':int.from_bytes(b'HIAMVPI1','little')})
POLICY=r'''
def runtime_information_capture(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUTPUT or length(w)<WORK or get(o,I_PUBLIC)!=1:
        return 4294967293
    phase=get(o,PHASE)
    if phase==1200:
        put(o,PHASE,1201)
        return 22
    if phase==1201:
        ptr=get(o,FEEDBACK)
        n=get(o,I_MAP_N)
        if ptr==0 or n==0 or n>4194304:
            return capture_fail(o,9)
        put(o,I_CODE,ptr)
        zero(o,I_WORK,1184)
        return role(o,1202,24,0,ptr,n,3,I_HASH,32,3,I_WORK,1184)
    if phase==1202:
        if get(o,FEEDBACK)!=32:
            return capture_fail(o,9)
        put(o,I_HASH_DONE,1)
        return again(o,314)
    if phase==1210:
        zero(o,I_WORK,1184)
        return role(o,1211,24,0,get(o,I_CODE),get(o,I_MAP_N),3,I_HASH_NEW,32,3,I_WORK,1184)
    if phase==1211:
        if get(o,FEEDBACK)!=32:
            return capture_fail(o,9)
        i=0
        while i<32:
            if byte(o,I_HASH+i)!=byte(o,I_HASH_NEW+i):
                return capture_fail(o,38)
            i=i+1
        return memory(o,1213,0,get(o,GO+32)+GCTRL,3,I_META,4096)
    if phase==1213:
        n=get(o,I_META+128)
        gn=get(o,GO+104)
        if n<336 or n>5136 or gn==0 or gn>NONE-512-n:
            return capture_fail(o,9)
        return memory(o,1214,0,get(o,GO+32)+GABI,3,I_ABI,n)
    if phase==1214:
        return memory(o,1215,0,get(o,GO+32)+48,3,I_FD,8)
    if phase==1215:
        return system(o,1216,72,0,get(o,I_FD),1034,0,0,0,0)
    if phase==1216:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return again(o,1215)
        if raw>=NEGATIVE or (raw&15)!=15:
            return capture_fail(o,9)
        put(o,I_SEALS,raw)
        return system(o,1230,5,12,get(o,I_FD),I_STAT,0,0,0,0)
    if phase==1230:
        raw=get(o,FEEDBACK)
        if raw==NONE-3:
            return system(o,1230,5,12,get(o,I_FD),I_STAT,0,0,0,0)
        if raw!=0:
            return capture_fail(o,9)
        return memory(o,1231,0,get(o,GO+32)+165683216,3,I_MAP,128)
    if phase==1231:
        return memory(o,1232,0,get(o,GO+112),3,I_VALUE,96)
    if phase==1232:
        if get(o,I_VALUE)!=VALUE_MAGIC or get(o,I_VALUE+8)!=get(w,8) or get(o,I_VALUE+24)!=get(o,GO+104):
            return capture_fail(o,9)
        if get(o,I_VALUE+16)<96+get(o,GO+104):
            return capture_fail(o,9)
        info_frame(o)
        put(o,I_FRAMEN,512+get(o,GO+104)+get(o,I_META+128))
        return allocate(o,1233,get(o,I_FRAMEN))
    if phase==1233:
        if get(o,FEEDBACK)==0:
            return capture_fail(o,4)
        put(o,I_FRAMEPTR,get(o,FEEDBACK))
        return memory(o,1234,3,I_FRAME,0,get(o,I_FRAMEPTR),512)
    if phase==1234:
        return memory(o,1218,0,get(o,GO+112)+96,0,get(o,I_FRAMEPTR)+512,get(o,GO+104))
    if phase==1218:
        return memory(o,1235,3,I_ABI,0,get(o,I_FRAMEPTR)+512+get(o,GO+104),get(o,I_META+128))
    if phase==1235:
        zero(o,I_WORK,8192)
        return role(o,1219,23,0,get(o,I_FRAMEPTR),get(o,I_FRAMEN),3,0,0,3,I_WORK,8192)
    if phase==1219:
        if get(o,FEEDBACK)!=4294967294 or get(o,I_WORK)<32:
            return capture_fail(o,9)
        put(o,I_N,get(o,I_WORK))
        return allocate(o,1220,get(o,I_N))
    if phase==1220:
        if get(o,FEEDBACK)==0:
            return capture_fail(o,4)
        put(o,I_PTR,get(o,FEEDBACK))
        return role(o,1221,23,0,get(o,I_FRAMEPTR),get(o,I_FRAMEN),0,get(o,I_PTR),get(o,I_N),3,I_WORK,8192)
    if phase==1221:
        if get(o,FEEDBACK)!=0:
            return capture_fail(o,9)
        return memory(o,1222,0,get(o,I_PTR),3,I_HEADER,32)
    if phase==1222:
        if get(o,I_HEADER)!=INFO_REPLY or get(o,I_HEADER+8)!=0 or get(o,I_HEADER+16)!=0 or get(o,I_HEADER+24)!=get(o,I_N)-32:
            return capture_fail(o,9)
        put(o,GO+168,get(o,I_PTR))
        put(o,GO+176,get(o,I_N))
        return memory(o,1223,3,GO+168,0,get(o,GEN)+168,16)
    if phase==1223:
        put(o,I_PTR,0)
        put(o,I_N,0)
        return deallocate(o,1236,get(o,I_FRAMEPTR))
    if phase==1236:
        put(o,I_FRAMEPTR,0)
        put(o,I_FRAMEN,0)
        put(o,I_INFO_DONE,1)
        return again(o,317)
    if phase>=1250 and phase<1290:
        return capture_result(s,o,w,phase)
    if phase==1295:
        put(o,I_FRAMEPTR,0)
        put(o,I_FRAMEN,0)
        if get(o,I_PTR)!=0:
            return deallocate(o,1296,get(o,I_PTR))
        return again(o,1296)
    if phase==1296:
        put(o,I_PTR,0)
        put(o,I_N,0)
        error=get(o,I_FAILURE)
        put(o,NATIVE_ERROR,error)
        if get(o,I_OUTGO)==1:
            put(o,STATE_O+120,error)
            put(o,STATE_O,800)
            # The coordinator already removed this pending unlock from its
            # held mask before requesting action 2. Complete that physical
            # unlock first; only its feedback may enter the remaining unwind.
            return again(o,106)
        put(o,STATE_O+8,error)
        return role(o,200,14,3,CINPUT,96,3,STATE_O,4096,1,COOR,24576)
    return 4294967293

def info_frame(o:mutbuf) -> u64:
    zero(o,I_FRAME,512)
    put(o,I_FRAME,INFO_MAGIC)
    put(o,I_FRAME+16,get(o,GO+104))
    put(o,I_FRAME+24,get(o,I_META+128))
    put(o,I_FRAME+48,get(o,I_META+80))
    count=get(o,I_ABI+8)
    put(o,I_FRAME+56,choose(get(o,I_META+240)!=0,count,0))
    put(o,I_FRAME+64,choose(get(o,I_META+80)==0,count,0))
    put(o,I_FRAME+72,get(o,I_META+600))
    put(o,I_FRAME+80,get(o,I_META+840))
    put(o,I_FRAME+88,get(o,I_META+72))
    dev=get(o,I_STAT)
    put(o,I_FRAME+112,((dev>>8)&4095)|((dev>>32)&4294963200))
    put(o,I_FRAME+120,(dev&255)|((dev>>12)&4294967040))
    put(o,I_FRAME+128,get(o,I_STAT+8))
    put(o,I_FRAME+136,get(o,I_SEALS))
    within(o,I_FRAME+144,I_META+320,32)
    within(o,I_FRAME+176,I_META+288,32)
    within(o,I_FRAME+208,I_META+736,32)
    within(o,I_FRAME+240,I_HASH,32)
    put(o,I_FRAME+272,get(o,I_STAT+48))
    put(o,I_FRAME+280,count)
    i=0
    while i<count and i<16:
        put(o,I_FRAME+288+i*8,get(o,I_MAP+i*8))
        i=i+1
    return 0

def capture_result(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1250:
        put(o,I_RETURNED,1)
        put(o,I_OUTGO,1)
        if get(o,OP)==6:
            return memory(o,1251,0,get(o,LO+48),3,GO,256)
        slot=get(w,COOR+48)
        if slot>=64 or get(w,SLOTS+slot*16)==0:
            return capture_fail(o,9)
        return memory(o,1251,0,get(w,SLOTS+slot*16),3,GO,256)
    if phase==1251:
        if get(o,GO)!=GOBJ or get(o,GO+8)!=get(w,8) or get(o,GO+168)==0 or get(o,GO+176)<32:
            return capture_fail(o,9)
        if get(o,OP)!=2:
            put(o,I_N,get(o,GO+176))
            return allocate(o,1252,get(o,I_N))
        return memory(o,1260,0,get(o,GO+168),3,I_HEADER,32)
    if phase==1252:
        if get(o,FEEDBACK)==0:
            return capture_fail(o,4)
        put(o,I_PTR,get(o,FEEDBACK))
        return memory(o,1253,0,get(o,GO+168),0,get(o,I_PTR),get(o,I_N))
    if phase==1253:
        put(o,D_PTR,get(o,I_PTR))
        put(o,D_LEN,get(o,I_N))
        put(o,I_PTR,0)
        put(o,I_N,0)
        return again(o,106)
    if phase==1260:
        if get(o,I_HEADER)!=INFO_REPLY or get(o,I_HEADER+8)!=0 or get(o,I_HEADER+16)!=0 or get(o,I_HEADER+24)!=get(o,GO+176)-32:
            return capture_fail(o,9)
        put(o,I_JSONN,get(o,I_HEADER+24))
        zero(o,IREQ,64)
        put(o,IREQ,IDREQ)
        put(o,IREQ+8,7)
        put(o,IREQ+16,64)
        return role(o,1261,13,3,IREQ,64,3,IOUT,4096,1,IDENTITY,32768)
    if phase==1261:
        if get(o,FEEDBACK)!=0 or get(o,IOUT)!=IDREP or get(o,IOUT+8)!=0:
            return capture_fail(o,9)
        put(o,I_EPOCH,get(o,IOUT+16))
        put(o,I_EPOCHN,get(o,IOUT+48))
        return memory(o,1262,0,get(o,I_EPOCH),3,I_VALUE,96)
    if phase==1262:
        en=get(o,I_EPOCHN)
        if en==0 or en>NONE-96 or get(o,I_VALUE)!=VALUE_MAGIC or get(o,I_VALUE+8)!=get(w,8) or get(o,I_VALUE+24)!=en or get(o,I_VALUE+16)<96+en:
            return capture_fail(o,9)
        mn=0
        ma=0
        if word(s,120)==1:
            if get(o,MEAS_OUT)!=MREP or get(o,MEAS_OUT+8)!=0 or get(o,MEAS_OUT+56)!=1:
                return capture_fail(o,9)
            mn=get(o,MEAS_OUT+32)
            ma=128+get(o,MEAS_OUT+24)
            if ma>8388608 or mn>8388608-ma:
                return capture_fail(o,9)
        gn=get(o,I_JSONN)
        if gn>NONE-128 or en>NONE-128-gn or mn>NONE-128-gn-en:
            return capture_fail(o,4)
        put(o,I_MEASN,mn)
        put(o,I_MEASAT,ma)
        put(o,I_FRAMEN,128+gn+en+mn)
        zero(o,I_FRAME,128)
        put(o,I_FRAME,PUB_MAGIC)
        put(o,I_FRAME+8,2)
        put(o,I_FRAME+16,gn)
        put(o,I_FRAME+24,en)
        put(o,I_FRAME+32,mn)
        now=get(o,STATE_O+176)
        start=get(o,STATE_O+72)
        put(o,I_FRAME+40,choose(now>=start,now-start,NONE))
        put(o,I_FRAME+48,word(s,56))
        return allocate(o,1263,get(o,I_FRAMEN))
    if phase==1263:
        if get(o,FEEDBACK)==0:
            return capture_fail(o,4)
        put(o,I_FRAMEPTR,get(o,FEEDBACK))
        return memory(o,1264,3,I_FRAME,0,get(o,I_FRAMEPTR),128)
    if phase==1264:
        return memory(o,1265,0,get(o,GO+168)+32,0,get(o,I_FRAMEPTR)+128,get(o,I_JSONN))
    if phase==1265:
        return memory(o,1266,0,get(o,I_EPOCH)+96,0,get(o,I_FRAMEPTR)+128+get(o,I_JSONN),get(o,I_EPOCHN))
    if phase==1266:
        if get(o,I_MEASN)!=0:
            return memory(o,1267,3,MEAS_OUT+get(o,I_MEASAT),0,get(o,I_FRAMEPTR)+128+get(o,I_JSONN)+get(o,I_EPOCHN),get(o,I_MEASN))
        return again(o,1267)
    if phase==1267:
        zero(o,I_WORK,8192)
        return role(o,1268,23,0,get(o,I_FRAMEPTR),get(o,I_FRAMEN),3,0,0,3,I_WORK,8192)
    if phase==1268:
        if get(o,FEEDBACK)!=4294967294 or get(o,I_WORK)<32:
            return capture_fail(o,9)
        put(o,I_N,get(o,I_WORK))
        return allocate(o,1269,get(o,I_N))
    if phase==1269:
        if get(o,FEEDBACK)==0:
            return capture_fail(o,4)
        put(o,I_PTR,get(o,FEEDBACK))
        return role(o,1270,23,0,get(o,I_FRAMEPTR),get(o,I_FRAMEN),0,get(o,I_PTR),get(o,I_N),3,I_WORK,8192)
    if phase==1270:
        if get(o,FEEDBACK)!=0:
            return capture_fail(o,9)
        return deallocate(o,1271,get(o,I_FRAMEPTR))
    if phase==1271:
        put(o,I_FRAMEPTR,0)
        put(o,I_FRAMEN,0)
        return again(o,1253)
    return capture_fail(o,9)

def capture_fail(o:mutbuf,error:u64) -> u32:
    put(o,I_FAILURE,error)
    if get(o,I_FRAMEPTR)!=0:
        return deallocate(o,1295,get(o,I_FRAMEPTR))
    return again(o,1295)
'''
HELPERS=('role','memory','system','allocate','deallocate','again','word','get','put','copy','within','copy_input','zero','choose','narrow')
def source_program():
 s=POLICY
 for name in HELPERS:
  pat=r'^def '+name+r'\(.*?(?=^def |\Z)'
  m=re.search(pat,effects.SOURCE,re.M|re.S);assert m,name;s+='\n'+m.group(0)
 for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
 return s
def main():
 t=document(source_program(),'multiversion_runtime_information_capture')
 p=ROOT/'examples/hia_bootstrap/multiversion_runtime_information_capture.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
