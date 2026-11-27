"""Native PureWindowsPath string rendering from actual immutable path parts.

The author obtains Unicode lower and final-sigma properties from the pinned
original runtime. Generated HIA contains those data; Python is not a production
input and no path decision is delegated to a host-language callback.
"""
from tools.generate_hia_clang_capture_common import C,write_module
import unicodedata
MAP=[];flags=[]
for cp in range(0x110000):
 ch=chr(cp);low=ch.lower()
 if low!=ch:
  assert 1<=len(low)<=2
  MAP.append(cp|(ord(low[0])<<21)|((ord(low[1]) if len(low)==2 else 0)<<42))
 # These probes derive the exact properties used by the original final-sigma
 # rule, including case-ignorable precedence for characters with both flags.
 if ('A\u03a3'+ch).lower()[1]=='\u03c3':flag=2
 elif ('A\u03a3'+ch+'A').lower()[1]=='\u03c3':flag=1
 else:flag=0
 flags.append(flag)
PROPS=[];at=0
while at<len(flags):
 end=at+1
 while end<len(flags) and flags[end]==flags[at]:end+=1
 if flags[at]:PROPS.append(at|((end-1)<<21)|(flags[at]<<42))
 at=end
C.update(W_MAP=262144,W_MAP_N=len(MAP),W_PROPS=262144+len(MAP)*8,
 W_PROPS_N=len(PROPS),W_META=904,W_MASK=2097151)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<327680 or length(o)<length(s) or length(o)<4:
        return 4294967294
    tables(w)
    at=0
    n=0
    drive=0
    root=0
    while at<length(s):
        if length(s)-at<8:
            return 4294967293
        size=word(s,at)
        at=at+8
        if size>length(s)-at:
            return 4294967293
        if size!=0:
            split_s(s,w,at,size)
            pd=get(w,W_META)
            pr=get(w,W_META+8)
            tail=pd+pr
            if pr!=0:
                if pd!=0 or drive==0:
                    copy_s(s,o,at,0,pd)
                    drive=pd
                store(o,drive,byte(s,at+pd))
                copy_s(s,o,at+tail,drive+1,size-tail)
                root=1
                n=drive+1+size-tail
            else:
                replace=False
                if pd!=0:
                    if lower_equal(s,o,w,at,pd,drive)==False:
                        replace=True
                    if replace==False:
                        move_o(o,pd,drive,n-drive)
                        copy_s(s,o,at,0,pd)
                        n=n-drive+pd
                        drive=pd
                if replace:
                    copy_s(s,o,at,0,size)
                    drive=pd
                    root=0
                    n=size
                else:
                    if n>drive+root and sep(byte(o,n-1))==False:
                        store(o,n,92)
                        n=n+1
                    copy_s(s,o,at+pd,n,size-pd)
                    n=n+size-pd
        at=at+size
    if n>drive and root==0 and drive!=0 and sep(byte(o,drive-1))==False and byte(o,drive-1)!=58:
        move_o(o,drive+1,drive,n-drive)
        store(o,drive,92)
        n=n+1
    i=0
    while i<n:
        if byte(o,i)==47:
            store(o,i,92)
        i=i+1
    split_o(o,w,0,n)
    drive=get(w,W_META)
    root=get(w,W_META+8)
    if root==0 and drive!=0 and byte(o,0)==92 and byte(o,drive-1)!=92:
        separators=0
        server_end=drive
        i=0
        while i<drive:
            if byte(o,i)==92:
                separators=separators+1
                if separators==3:
                    server_end=i
            i=i+1
        ordinary=True
        if server_end==2:
            ordinary=False
        elif server_end==3 and (byte(o,2)==63 or byte(o,2)==46):
            ordinary=False
        elif server_end==4 and byte(o,2)==63 and byte(o,3)==46:
            ordinary=False
        if separators==5 or separators==3 and ordinary:
            store(o,drive,92)
            root=1
            n=drive+1
    return format_path(o,w,n,drive,root)

def format_path(o:mutbuf,w:mutbuf,n:u64,drive:u64,root:u64) -> u32:
    at=drive+root
    pos=at
    first=True
    while at<n:
        while at<n and byte(o,at)==92:
            at=at+1
        start=at
        while at<n and byte(o,at)!=92:
            at=at+1
        count=at-start
        if count!=0 and (count!=1 or byte(o,start)!=46):
            if first and drive==0 and root==0:
                cp=cp_o(o,start,start+count)
                if cp>>32==0:
                    return 4294967293
                width=cp>>32
                if count>width and byte(o,start+width)==58:
                    store(o,0,46)
                    store(o,1,92)
                    pos=2
            elif pos>drive+root:
                store(o,pos,92)
                pos=pos+1
            move_o(o,pos,start,count)
            pos=pos+count
            first=False
    if pos==0:
        store(o,0,46)
        pos=1
    return pos

def lower_equal(s:readbuf,o:mutbuf,w:mutbuf,start:u64,sn:u64,on:u64) -> bool:
    if sn==0 or on==0:
        return sn==on
    sa=start
    oa=0
    sp=1114112
    op=1114112
    while sa<start+sn or oa<on or sp!=1114112 or op!=1114112:
        if sp!=1114112:
            a=sp
            sp=1114112
        else:
            if sa==start+sn:
                return False
            info=cp_s(s,sa,start+sn)
            width=info>>32
            if width==0:
                return False
            cp=info&W_MASK
            mapped=lower(w,cp)
            if cp==931 and before_s(s,w,start,sa) and after_s(s,w,sa+width,start+sn)==False:
                mapped=962
            sa=sa+width
            a=mapped&W_MASK
            if mapped>>21!=0:
                sp=mapped>>21
        if op!=1114112:
            b=op
            op=1114112
        else:
            if oa==on:
                return False
            info=cp_o(o,oa,on)
            width=info>>32
            if width==0:
                return False
            cp=info&W_MASK
            mapped=lower(w,cp)
            if cp==931 and before_o(o,w,0,oa) and after_o(o,w,oa+width,on)==False:
                mapped=962
            oa=oa+width
            b=mapped&W_MASK
            if mapped>>21!=0:
                op=mapped>>21
        if a!=b:
            return False
    return True

def lower(w:mutbuf,cp:u64) -> u64:
    lo=0
    hi=W_MAP_N
    while lo<hi:
        mid=(lo+hi)//2
        row=get(w,W_MAP+mid*8)
        key=row&W_MASK
        if key<cp:
            lo=mid+1
        else:
            hi=mid
    if lo<W_MAP_N:
        row=get(w,W_MAP+lo*8)
        if row&W_MASK==cp:
            return row>>21
    return cp

def property(w:mutbuf,cp:u64) -> u64:
    lo=0
    hi=W_PROPS_N
    while lo<hi:
        mid=(lo+hi)//2
        row=get(w,W_PROPS+mid*8)
        if ((row>>21)&W_MASK)<cp:
            lo=mid+1
        else:
            hi=mid
    if lo<W_PROPS_N:
        row=get(w,W_PROPS+lo*8)
        if (row&W_MASK)<=cp:
            return row>>42
    return 0

def sep(b:u64) -> bool:
    return b==47 or b==92

def move_o(o:mutbuf,to:u64,source:u64,n:u64) -> u64:
    if to<source:
        i=0
        while i<n:
            store(o,to+i,byte(o,source+i))
            i=i+1
    elif to>source:
        i=n
        while i!=0:
            i=i-1
            store(o,to+i,byte(o,source+i))
    return 0

def copy_s(s:readbuf,o:mutbuf,source:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,source+i))
        i=i+1
    return 0
'''
SPAN=r'''
def cp_SUFFIX(s:TYPE,at:u64,end:u64) -> u64:
    if at>=end:
        return 0
    a=byte(s,at)
    if a<128:
        return a|4294967296
    need=0
    value=0
    if a>=194 and a<=223:
        need=2
        value=a&31
    elif a>=224 and a<=239:
        need=3
        value=a&15
    elif a>=240 and a<=244:
        need=4
        value=a&7
    if need==0 or need>end-at:
        return 0
    i=1
    while i<need:
        b=byte(s,at+i)
        if b<128 or b>191:
            return 0
        value=(value<<6)|(b&63)
        i=i+1
    if need==3 and value<2048 or need==4 and (value<65536 or value>1114111):
        return 0
    return value|(need<<32)

def before_SUFFIX(s:TYPE,w:mutbuf,start:u64,at:u64) -> bool:
    while at>start:
        end=at
        at=at-1
        while at>start and byte(s,at)>=128 and byte(s,at)<192:
            at=at-1
        cp=cp_SUFFIX(s,at,end)
        if cp>>32==0:
            return False
        flag=property(w,cp&W_MASK)
        if flag!=1:
            return flag==2
    return False

def after_SUFFIX(s:TYPE,w:mutbuf,at:u64,end:u64) -> bool:
    while at<end:
        cp=cp_SUFFIX(s,at,end)
        if cp>>32==0:
            return False
        flag=property(w,cp&W_MASK)
        if flag!=1:
            return flag==2
        at=at+(cp>>32)
    return False

def split_SUFFIX(s:TYPE,w:mutbuf,at:u64,n:u64) -> u64:
    drive=0
    root=0
    if n!=0 and sep(byte(s,at)):
        if n>=2 and sep(byte(s,at+1)):
            start=2
            if n>=8 and byte(s,at+2)==63 and sep(byte(s,at+3)) and (byte(s,at+4)|32)==117 and (byte(s,at+5)|32)==110 and (byte(s,at+6)|32)==99 and sep(byte(s,at+7)):
                start=8
            i=start
            while i<n and sep(byte(s,at+i))==False:
                i=i+1
            if i<n:
                i=i+1
                while i<n and sep(byte(s,at+i))==False:
                    i=i+1
            drive=i
            if i<n:
                root=1
        else:
            root=1
    elif n!=0:
        cp=cp_SUFFIX(s,at,at+n)
        width=cp>>32
        if width!=0 and n>width and byte(s,at+width)==58:
            drive=width+1
            if n>drive and sep(byte(s,at+drive)):
                root=1
    put(w,W_META,drive)
    put(w,W_META+8,root)
    return 0
'''
SOURCE+='\n'+SPAN.replace('SUFFIX','s').replace('TYPE','readbuf')
SOURCE+='\n'+SPAN.replace('SUFFIX','o').replace('TYPE','mutbuf')
ROWS=MAP+PROPS
CHUNKS=[ROWS[i:i+128]for i in range(0,len(ROWS),128)]
SOURCE+='\ndef tables(w:mutbuf) -> u64:\n'
for i in range(len(CHUNKS)):SOURCE+=f'    table_{i}(w)\n'
SOURCE+='    return 0\n'
for i,chunk in enumerate(CHUNKS):
 SOURCE+=f'\ndef table_{i}(w:mutbuf) -> u64:\n'
 for j,row in enumerate(chunk):SOURCE+=f'    put(w,{262144+(i*128+j)*8},{row})\n'
 SOURCE+='    return 0\n'
if __name__=='__main__':
 print('PINNED_UNICODE',unicodedata.unidata_version,'LOWER',len(MAP),'SIGMA_RANGES',len(PROPS),flush=True)
 write_module('clang_value_windows',SOURCE,'advance')
