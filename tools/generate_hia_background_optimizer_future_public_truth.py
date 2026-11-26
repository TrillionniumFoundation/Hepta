"""Native Future special-method truth, integer length and actual exception custody.

This role resumes the same Future continuation outside its registry mutex.
The only callable target is resolved by the unique Value code-provider owner.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_future_public_owner as owner
ROOT=Path(__file__).resolve().parents[1]
C=dict(owner.C)
C.update(VREQUEST4=int.from_bytes(b'HIABVQ04','little'))
SOURCE=r'''
def future_truth(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<65536 or length(w)<256:
        return 4294967293
    magic=readword(s,0)
    if magic!=MAGIC and magic!=MAGIC2 and magic!=MAGIC3 and magic!=MAGIC4:
        return 4294967293
    phase=get(o,PHASE)
    if phase<1800 or phase>=2100 or get(o,HELD)!=0 or get(o,X_PTR)==0:
        return 12
    if phase<1850:
        return truth_invoke(s,o,w,phase)
    if phase<1900:
        return truth_result(s,o,w,phase)
    if phase<1920:
        return truth_default(s,o,w,phase)
    if phase<1960:
        return truth_index(s,o,w,phase)
    if phase<1980:
        return truth_error_text(s,o,w,phase)
    return truth_error_object(s,o,w,phase)

def truth_packet(o:mutbuf,op:u64,magic:u64) -> u64:
    value_packet(o,op)
    put(o,RQ,magic)
    return 0

def truth_cap(o:mutbuf,at:u64,delivered:bool) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
        put(o,X_BAD,2)
        return False
    if get(o,VP+24)!=0 or get(o,VP+32)!=0 or get(o,VP+40)!=0:
        within(o,at,VP+24,24)
    if delivered:
        if get(o,VP+88)!=1 or get(o,VP+96)>1 or get(o,VP+80)>1:
            put(o,X_BAD,2)
            return False
        if get(o,VP+96)==1:
            if get(o,at)==0 or (get(o,at+8)==0 and get(o,at+16)==0):
                put(o,X_BAD,2)
                return False
            if get(o,VP+8)!=0 or get(o,VP+80)!=0 or get(o,VP+104)!=0:
                put(o,CLEANUP_FAILED,1)
            return True
    if value_local_status(o)!=0:
        return False
    if get(o,at)==0 or (get(o,at+8)==0 and get(o,at+16)==0):
        put(o,X_BAD,2)
        return False
    return True

def truth_drop_except(o:mutbuf,w:mutbuf,keep:u64,again_phase:u64,next:u64) -> u32:
    at=X_CLASS
    while at<=X_ATTR:
        if at!=keep and get(o,at)!=0:
            return extended_drop(o,w,at,again_phase)
        at=at+24
    if get(o,X_NAMED)!=0 and keep!=TYPE_CAP and get(o,TYPE_CAP)!=0:
        return extended_drop(o,w,TYPE_CAP,again_phase)
    return again(o,next)

def truth_success(o:mutbuf) -> u32:
    put(o,X_CLEAN_NEXT,get(o,EAFTER))
    return again(o,1570)

def truth_error(o:mutbuf,id:u64,mode:u64,at:u64) -> u32:
    put(o,T_ERRCLASS,id)
    put(o,T_MSGKIND,mode)
    put(o,T_TYPEAT,at)
    return again(o,1960)

def truth_invoke(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1800:
        if get(o,X_CLASS)!=0:
            return extended_drop(o,w,X_CLASS,1800)
        truth_packet(o,49,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST5))
        within(o,RQ+24,X_ATTR,24)
        return value(o,w,1801)
    if phase==1801:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return inherited_fail(o,107)
        status=value_local_status(o)
        kind=get(o,VP+16)
        if status==0 and (kind==3 or kind==4 or kind==5):
            if kind!=3:
                return again(o,1805)
            truth_packet(o,69,VREQUEST5)
            within(o,RQ+24,X_ATTR,24)
            within(o,RQ+48,get(o,X_AT),24)
            return value_wide(o,w,1802,128,16384)
        if status!=2 and status!=0:
            return inherited_fail(o,choose(status==5,103,107))
        value_packet(o,7)
        within(o,RQ+24,X_ATTR,24)
        return value(o,w,1803)
    if phase==1802:
        if truth_cap(o,X_KEY,True)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        return extended_drop(o,w,X_ATTR,1804)
    if phase==1803:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        if get(o,X_PROBE)==0 and get(o,VP+16)==0:
            return truth_error(o,23,6,get(o,X_AT))
        return truth_error(o,23,3,X_ATTR)
    if phase==1804:
        within(o,X_ATTR,X_KEY,24)
        zero(o,X_KEY,24)
        return again(o,1805)
    if phase==1805:
        truth_packet(o,3,VREQUEST)
        return value(o,w,1806)
    if phase==1806:
        if truth_cap(o,X_CLASS,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,40,VREQUEST4)
        within(o,RQ+24,X_CLASS,24)
        return value(o,w,1807)
    if phase==1807:
        if truth_cap(o,X_KEY,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        return extended_drop(o,w,X_CLASS,1808)
    if phase==1808:
        truth_packet(o,97,VREQUEST5)
        within(o,RQ+24,X_ATTR,24)
        within(o,RQ+48,X_KEY,24)
        return value_wide(o,w,1809,128,16384)
    if phase==1809:
        if truth_cap(o,X_CLASS,True)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        disposition=get(o,VP+64)
        if disposition!=1 and disposition!=2:
            put(o,X_BAD,2)
            return inherited_fail(o,107)
        put(o,T_DISP,disposition)
        if disposition==2:
            if get(o,RESULT_VALUE)!=0:
                put(o,X_BAD,2)
                return inherited_fail(o,107)
            within(o,RESULT_VALUE,X_CLASS,24)
            zero(o,X_CLASS,24)
            put(o,T_PRIMARY,1)
            category=get(o,VP+56)
            put(o,ERROR,choose(category==1 or category==2,category,107))
            put(o,RKIND,200)
            if category!=1 and category!=2:
                put(o,CLEANUP_FAILED,1)
        return extended_drop(o,w,X_ATTR,1810)
    if phase==1810:
        return extended_drop(o,w,X_KEY,1811)
    if phase==1811:
        if get(o,T_DISP)==2:
            put(o,X_CLEAN_NEXT,1400)
            return again(o,1570)
        return again(o,1850)
    return inherited_fail(o,107)

def truth_result(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1850:
        value_packet(o,7)
        within(o,RQ+24,X_CLASS,24)
        return value(o,w,1851)
    if phase==1851:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        kind=get(o,VP+16)
        put(o,T_DISP,kind)
        put(o,T_LIMIT,get(o,VP+72))
        if get(o,X_PROBE)==0:
            if kind!=1:
                return truth_error(o,23,0,X_CLASS)
            value_packet(o,19)
            within(o,RQ+24,X_CLASS,24)
            put(o,RQ+112,1)
            return value_wide(o,w,1852,128,8200)
        if kind==1 or kind==2:
            return again(o,1860)
        if kind==8:
            truth_packet(o,32,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
            put(o,RQ+104,3)
            return value(o,w,1853)
        if get(o,X_PROBE)==2:
            return truth_error(o,23,2,X_CLASS)
        return again(o,1920)
    if phase==1852:
        if value_ok(o)==False or get(o,VP+64)!=1:
            return inherited_fail(o,107)
        put(o,ETRUTH,choose(byte(o,VP+8192)!=0,1,0))
        return truth_success(o)
    if phase==1853:
        if truth_cap(o,X_ATTR,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,37,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        within(o,RQ+24,X_CLASS,24)
        within(o,RQ+48,X_ATTR,24)
        return value(o,w,1854)
    if phase==1854:
        if value_ok(o)==False or get(o,VP+48)>1:
            return inherited_fail(o,107)
        put(o,T_DISP,choose(get(o,VP+48)!=0,2,8))
        return extended_drop(o,w,X_ATTR,1855)
    if phase==1855:
        if get(o,T_DISP)==2:
            return again(o,1860)
        if get(o,X_PROBE)==2:
            return truth_error(o,23,2,X_CLASS)
        return again(o,1920)
    if phase==1860:
        n=get(o,T_LIMIT)
        if get(o,T_DISP)==1:
            n=1
        if n>32:
            n=32
        if n==0:
            return inherited_fail(o,107)
        put(o,T_CHUNK,n)
        value_packet(o,19)
        within(o,RQ+24,X_CLASS,24)
        put(o,RQ+112,n)
        return value_wide(o,w,1861,128,8224)
    if phase==1861:
        if value_ok(o)==False or get(o,VP+64)!=get(o,T_CHUNK):
            return inherited_fail(o,107)
        if get(o,T_DISP)==1:
            put(o,ETRUTH,choose(byte(o,VP+8192)!=0,1,0))
            return truth_success(o)
        n=get(o,VP+72)
        negative=byte(o,VP+8192)==45
        start=choose(negative,1,0)
        if n<=start:
            return inherited_fail(o,107)
        if negative:
            return truth_error(o,24,4,0)
        if n-start>19:
            return truth_error(o,39,5,0)
        amount=0
        i=start
        maximum=9223372036854775807
        while i<n:
            ch=byte(o,VP+8192+i)
            if ch<48 or ch>57:
                return inherited_fail(o,107)
            digit=ch-48
            if amount>maximum//10 or (amount==maximum//10 and digit>maximum%10):
                return truth_error(o,39,5,0)
            amount=amount*10+digit
            i=i+1
        put(o,ETRUTH,choose(amount!=0,1,0))
        return truth_success(o)
    return inherited_fail(o,107)

def truth_default(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1900:
        if get(o,X_CLASS)!=0:
            return extended_drop(o,w,X_CLASS,1900)
        truth_packet(o,26,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST2))
        within(o,RQ+24,get(o,X_AT),24)
        return value_wide(o,w,1901,128,16384)
    if phase==1901:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        within(o,X_CLASS,VP+8224,24)
        within(o,X_KEY,VP+8248,24)
        within(o,X_ATTR,VP+8272,24)
        kind=get(o,VP+8200)
        if kind==0 or kind==14:
            put(o,ETRUTH,1)
            return truth_success(o)
        if kind!=2 and kind!=3 and kind!=4 and kind!=5 and kind!=6 and kind!=7 and kind!=11:
            return inherited_fail(o,107)
        put(o,T_DISP,kind)
        value_packet(o,7)
        within(o,RQ+24,X_KEY,24)
        return value(o,w,1902)
    if phase==1902:
        if value_ok(o)==False or get(o,VP+16)!=get(o,T_DISP):
            return inherited_fail(o,107)
        kind=get(o,VP+16)
        if kind>=4:
            put(o,ETRUTH,choose(get(o,VP+48)!=0,1,0))
            return truth_success(o)
        if kind==2 and get(o,VP+72)>1:
            put(o,ETRUTH,1)
            return truth_success(o)
        value_packet(o,19)
        within(o,RQ+24,X_KEY,24)
        put(o,RQ+112,choose(kind==3,8,1))
        return value_wide(o,w,1903,128,8200)
    if phase==1903:
        if value_ok(o)==False:
            return inherited_fail(o,107)
        if get(o,T_DISP)==3:
            if get(o,VP+64)!=8:
                return inherited_fail(o,107)
            put(o,ETRUTH,choose((get(o,VP+8192)&9223372036854775807)!=0,1,0))
        else:
            if get(o,VP+64)!=1:
                return inherited_fail(o,107)
            put(o,ETRUTH,choose(byte(o,VP+8192)!=48,1,0))
        return truth_success(o)
    return inherited_fail(o,107)

def truth_index(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1920:
        if get(o,TYPE_CAP)!=0 or get(o,X_KEY)!=0 or get(o,X_ATTR)!=0 or get(o,X_NAMED)!=0:
            return inherited_fail(o,107)
        within(o,TYPE_CAP,X_CLASS,24)
        zero(o,X_CLASS,24)
        put(o,X_NAMED,1)
        truth_packet(o,36,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        within(o,RQ+24,TYPE_CAP,24)
        return value(o,w,1921)
    if phase==1921:
        if truth_cap(o,X_CLASS,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,2,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST))
        put(o,RQ+128,6879359912831967071)
        store(o,RQ+136,95)
        put(o,RQ+96,9)
        put(o,RQ+104,4)
        return value_wide(o,w,1922,137,8192)
    if phase==1922:
        if truth_cap(o,X_KEY,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,39,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        within(o,RQ+24,X_CLASS,24)
        within(o,RQ+48,X_KEY,24)
        return value(o,w,1923)
    if phase==1923:
        if get(o,FEEDBACK)!=0 or get(o,VP)!=VREPLY:
            return inherited_fail(o,107)
        status=value_local_status(o)
        if status==3:
            return truth_error(o,23,1,TYPE_CAP)
        if truth_cap(o,X_ATTR,False)==False:
            return inherited_fail(o,choose(status==5,103,107))
        return extended_drop(o,w,X_KEY,1924)
    if phase==1924:
        put(o,X_PROBE,2)
        put(o,X_AT,TYPE_CAP)
        return again(o,1800)
    return inherited_fail(o,107)

def truth_error_text(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1960:
        mode=get(o,T_MSGKIND)
        if mode==4 or mode==5:
            put(o,T_FULLN,0)
            put(o,T_LIMIT,0)
            return again(o,1964)
        keep=get(o,T_TYPEAT)
        at=X_CLASS
        while at<=X_ATTR:
            if at!=keep and get(o,at)!=0:
                return extended_drop(o,w,at,1960)
            at=at+24
        if get(o,X_NAMED)!=0 and keep!=TYPE_CAP and get(o,TYPE_CAP)!=0:
            return extended_drop(o,w,TYPE_CAP,1960)
        if keep==X_ATTR or keep==X_KEY or keep==TYPE_CAP:
            within(o,X_CLASS,keep,24)
            zero(o,keep,24)
            if keep==TYPE_CAP:
                put(o,X_NAMED,0)
            put(o,T_TYPEAT,X_CLASS)
        truth_packet(o,36,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        within(o,RQ+24,get(o,T_TYPEAT),24)
        return value(o,w,1961)
    if phase==1961:
        if truth_cap(o,X_KEY,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,38,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        within(o,RQ+24,X_KEY,24)
        return value(o,w,1962)
    if phase==1962:
        if truth_cap(o,X_ATTR,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        value_packet(o,7)
        within(o,RQ+24,X_ATTR,24)
        return value(o,w,1963)
    if phase==1963:
        if value_ok(o)==False or get(o,VP+16)!=4:
            return inherited_fail(o,107)
        n=get(o,VP+72)
        put(o,T_FULLN,n)
        mode=get(o,T_MSGKIND)
        if mode!=0 and mode!=6 and n>200:
            n=200
        put(o,T_LIMIT,n)
        return again(o,1964)
    if phase==1964:
        prefix=truth_literal(o,EBUF,get(o,T_MSGKIND),0)
        suffix=truth_literal(o,EBUF+prefix,get(o,T_MSGKIND),1)
        put(o,T_PREFIX,prefix)
        put(o,T_SUFFIX,suffix)
        n=get(o,T_LIMIT)
        if n>MAX-448-prefix-suffix:
            return inherited_fail(o,103)
        extent=(384+prefix+n+suffix+3+4095)&18446744073709547520
        if extent<4096:
            extent=4096
        put(o,T_MAPNEW,extent)
        if extent>get(o,T_MAPLEN):
            return system(o,1965,25,0,get(o,X_PTR),get(o,T_MAPLEN),extent,1,0,0)
        return again(o,1966)
    if phase==1965:
        ptr=get(o,FEEDBACK)
        if ptr==0 or ptr>=NEGATIVE:
            return inherited_fail(o,103)
        put(o,X_PTR,ptr)
        put(o,T_MAPLEN,get(o,T_MAPNEW))
        return again(o,1966)
    if phase==1966:
        put(o,T_INDEX,0)
        put(o,T_WRITTEN,0)
        return memory(o,1967,3,EBUF,0,get(o,X_PTR)+384,get(o,T_PREFIX))
    if phase==1967:
        at=get(o,T_INDEX)
        n=get(o,T_LIMIT)
        if at>=n:
            return again(o,1972)
        count=n-at
        if count>4096:
            count=4096
        put(o,T_CHUNK,count)
        value_packet(o,19)
        within(o,RQ+24,X_ATTR,24)
        put(o,RQ+104,at)
        put(o,RQ+112,count)
        return value_wide(o,w,1968,128,12288)
    if phase==1968:
        if value_ok(o)==False or get(o,VP+64)!=get(o,T_CHUNK):
            return inherited_fail(o,107)
        count=get(o,T_CHUNK)
        if get(o,T_LIMIT)<get(o,T_FULLN) and get(o,T_INDEX)+count==get(o,T_LIMIT):
            start=count-1
            while start>0 and (byte(o,VP+8192+start)&192)==128:
                start=start-1
            first=byte(o,VP+8192+start)
            required=1
            if first>=240:
                required=4
            elif first>=224:
                required=3
            elif first>=192:
                required=2
            if count-start<required:
                count=start
        put(o,T_COPY,count)
        return memory(o,1970,3,VP+8192,0,get(o,X_PTR)+384+get(o,T_PREFIX)+get(o,T_WRITTEN),count)
    if phase==1970:
        put(o,T_INDEX,get(o,T_INDEX)+get(o,T_CHUNK))
        put(o,T_WRITTEN,get(o,T_WRITTEN)+get(o,T_COPY))
        return again(o,1967)
    if phase==1972:
        n=truth_literal(o,EBUF,get(o,T_MSGKIND),1)
        return memory(o,1973,3,EBUF,0,get(o,X_PTR)+384+get(o,T_PREFIX)+get(o,T_WRITTEN),n)
    if phase==1973:
        n=get(o,T_PREFIX)+get(o,T_WRITTEN)+get(o,T_SUFFIX)
        put(o,T_MSGN,n)
        truth_packet(o,2,VREQUEST)
        put(o,RQ+96,n)
        put(o,RQ+104,4)
        return memory(o,1974,3,RQ,0,get(o,X_PTR)+256,128)
    if phase==1974:
        return truth_drop_except(o,w,0,1974,1975)
    if phase==1975:
        return invoke_absolute(o,1977,get(w,72),get(o,X_PTR)+256,128+get(o,T_MSGN),VP,8192,get(w,112),get(w,120))
    if phase==1977:
        if truth_cap(o,X_CLASS,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        return again(o,1980)
    return inherited_fail(o,107)

def truth_error_object(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1980:
        truth_packet(o,3,VREQUEST)
        return value(o,w,1981)
    if phase==1981:
        if truth_cap(o,X_KEY,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,16,VREQUEST)
        within(o,RQ+24,X_KEY,24)
        within(o,RQ+48,X_CLASS,24)
        return value(o,w,1982)
    if phase==1982:
        if value_ok(o)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        return extended_drop(o,w,X_CLASS,1983)
    if phase==1983:
        truth_packet(o,40,VREQUEST4)
        within(o,RQ+24,X_KEY,24)
        return value(o,w,1984)
    if phase==1984:
        if truth_cap(o,X_ATTR,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        return extended_drop(o,w,X_KEY,1985)
    if phase==1985:
        id=get(o,T_ERRCLASS)
        if id>=38:
            truth_packet(o,87,VREQUEST5)
        else:
            truth_packet(o,32,choose(get(o,M_DEFER)!=0,VREQUEST6,VREQUEST3))
        put(o,RQ+104,id)
        return value(o,w,1986)
    if phase==1986:
        if truth_cap(o,X_CLASS,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        truth_packet(o,75,VREQUEST5)
        within(o,RQ+24,X_CLASS,24)
        within(o,RQ+48,X_ATTR,24)
        return value(o,w,1987)
    if phase==1987:
        if truth_cap(o,X_KEY,False)==False:
            return inherited_fail(o,choose(value_local_status(o)==5,103,107))
        if get(o,RESULT_VALUE)!=0:
            put(o,X_BAD,2)
            return inherited_fail(o,107)
        within(o,RESULT_VALUE,X_KEY,24)
        zero(o,X_KEY,24)
        put(o,T_PRIMARY,1)
        put(o,ERROR,1)
        put(o,RKIND,200)
        put(o,X_CLEAN_NEXT,1400)
        return again(o,1570)
    return inherited_fail(o,107)
'''
LITERALS=(
 ("__bool__ should return bool, returned ",""),
 ("'","' object cannot be interpreted as an integer"),
 ("__index__ returned non-int (type ",")"),
 ("'","' object is not callable"),
 ("__len__() should return >= 0",""),
 ("cannot fit 'int' into an index-sized integer",""),
 ("'","' cannot be interpreted as a boolean"),
)
def literal_source():
 s='\ndef truth_literal(o:mutbuf,at:u64,mode:u64,suffix:u64) -> u64:\n'
 for index,pair in enumerate(LITERALS):
  for side,txt in enumerate(pair):
   raw=txt.encode()
   s+=f'    if mode=={index} and suffix=={side}:\n'
   for off in range(0,len(raw)//8*8,8):s+=f'        put(o,at+{off},{int.from_bytes(raw[off:off+8],"little")})\n'
   for off in range(len(raw)//8*8,len(raw)):s+=f'        store(o,at+{off},{raw[off]})\n'
   s+=f'        return {len(raw)}\n'
 return s+'    return 0\n'
def source_program():
 source=SOURCE+literal_source()
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):source=re.sub(r'\b'+key+r'\b',str(value),source)
 return owner.reachable_source(source+'\n'+owner.full_source_program(),'future_truth')
def program():return document(source_program(),'background_optimizer_future_public_truth')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_truth.hepta'
 p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
