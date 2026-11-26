"""Native Clang request framing and exact filesystem byte strings."""
from tools.generate_hia_clang_origin_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(w,P_BUF_OP)
    if op==0:
        return which(s,o,w)
    if op==1:
        return path(s,o,w)
    if op==2:
        return compiler(s,o,w)
    if op==3:
        return normalize(s,o,w)
    if op==4:
        return file_frame(s,o,w)
    if op==5:
        return capture_frame(s,o,w)
    if op==6:
        return directory(s,o,w)
    if op==7:
        return object_frame(s,o,w)
    if op==8:
        return shared_setup(s,o,w)
    if op==9:
        return inventory_normalize(s,o,w)
    if op==10:
        return origin_parent(s,o,w)
    if op==11:
        return catalog_measure(s,o,w)
    if op==12:
        return catalog_fill(s,o,w)
    return 4294967293

def b_copy(s:readbuf,o:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,b+i,byte(s,a+i))
        i=i+1
    return b+n

def b_out_copy(o:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,b+i,byte(o,a+i))
        i=i+1
    return b+n

def b_work_copy(w:mutbuf,o:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,b+i,byte(w,a+i))
        i=i+1
    return b+n

def which(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32+length(s):
        return 4294967294
    clear(o,0,32)
    put(o,0,WHICH_REQUEST)
    put(o,16,length(s))
    b_copy(s,o,0,32,length(s))
    return 32+length(s)

def path(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32+length(s):
        return 4294967294
    clear(o,0,32)
    put(o,0,PATH_REQUEST)
    put(o,16,length(s))
    b_copy(s,o,0,32,length(s))
    at=0
    i=0
    while i<length(s):
        if byte(s,i)==47:
            at=i+1
        i=i+1
    isclang=False
    if length(s)-at==5:
        isclang=byte(s,at)==99 and byte(s,at+1)==108 and byte(s,at+2)==97 and byte(s,at+3)==110 and byte(s,at+4)==103
    put(w,P_FOUND_CLANG,choose(isclang,1,0))
    return 32+length(s)

def compiler(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    at=get(w,P_COMPILER_OFF)
    n=get(w,P_COMPILER_N)
    if at>=length(o) or n>=length(o)-at:
        return 4294967294
    store(o,at+n,0)
    base=0
    i=0
    while i<n:
        if byte(o,at+i)==47:
            base=i+1
        i=i+1
    llvm=False
    if n-base==4:
        llvm=byte(o,at+base)==108 and byte(o,at+base+1)==108 and byte(o,at+base+2)==118 and byte(o,at+base+3)==109
    multi=llvm and get(w,P_FOUND_CLANG)!=0
    put(w,P_COMPILER_LLVM,choose(llvm,1,0))
    put(w,P_MULTICALL,choose(multi,1,0))
    return 0

def normalize(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=length(s)
    if n==0 or byte(s,0)!=47 or length(o)<2*n+16:
        return 4294967293
    i=0
    while i<n:
        if byte(s,i)==0:
            return 4294967293
        i=i+1
    root=1
    if n>1 and byte(s,1)==47:
        if n==2:
            root=2
        elif byte(s,2)!=47:
            root=2
    store(o,0,47)
    if root==2:
        store(o,1,47)
    end=root
    i=root
    while i<n:
        if byte(s,i)==47:
            i=i+1
        else:
            start=i
            while i<n and byte(s,i)!=47:
                i=i+1
            size=i-start
            dot=size==1 and byte(s,start)==46
            parent=size==2 and byte(s,start)==46 and byte(s,start+1)==46
            if parent:
                if end>root:
                    j=end
                    while j>root and byte(o,j-1)!=47:
                        j=j-1
                    if j>root:
                        end=j-1
                    else:
                        end=root
            elif dot==False:
                if end>root:
                    store(o,end,47)
                    end=end+1
                end=b_copy(s,o,start,end,size)
    store(o,end,0)
    put(w,P_DEST_OFF,0)
    put(w,P_DEST_N,end)
    parent=end
    while parent>root and byte(o,parent-1)!=47:
        parent=parent-1
    if parent>root:
        parent=parent-1
    else:
        parent=root
    off=n+8
    b_out_copy(o,0,off,parent)
    store(o,off+parent,0)
    put(w,P_PARENT_OFF,off)
    put(w,P_PARENT_N,parent)
    put(w,P_DIR_OFF,2*(n+8))
    put(w,P_SOURCE_OFF,3*(n+8)+32)
    put(w,P_ART_OFF,4*(n+8)+64)
    return 0

def directory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    parent=get(w,P_PARENT_OFF)
    n=get(w,P_PARENT_N)
    dest=get(w,P_DIR_OFF)
    at=b_out_copy(o,parent,dest,n)
    if byte(o,at-1)!=47:
        store(o,at,47)
        at=at+1
    at=b_work_copy(w,o,P_TEMP_NAME,at,20)
    store(o,at,0)
    size=at-dest
    put(w,P_DIR_N,size)
    src=get(w,P_SOURCE_OFF)
    end=b_out_copy(o,dest,src,size)
    end=literal_source(o,end)
    store(o,end,0)
    put(w,P_SOURCE_PATH_N,end-src)
    art=get(w,P_ART_OFF)
    end=b_out_copy(o,dest,art,size)
    if get(w,P_KIND)==0:
        end=literal_shared(o,end)
    else:
        end=literal_object(o,end)
    store(o,end,0)
    put(w,P_ART_PATH_N,end-art)
    return 0

def file_frame(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,P_FILE_PATH_N)
    en=get(w,P_EXPECT_N)
    off=get(w,P_FILE_PATH_OFF)
    if off>length(s) or n>length(s)-off or length(o)<193+n+en:
        return 4294967294
    clear(o,0,192)
    put(o,0,FILE_REQUEST)
    put(o,8,get(w,P_FILE_MODE))
    put(o,16,get(w,P_FILE_MAX))
    put(o,32,n)
    put(o,40,en)
    put(o,48,get(w,P_FILE_COMPARE))
    if get(w,P_FILE_COMPARE)!=0:
        b_work_copy(w,o,P_EXPECT_ID,64,64)
    b_copy(s,o,off,192,n)
    store(o,192+n,0)
    return 193+n+en

def argument(s:readbuf,o:mutbuf,at:u64,start:u64,n:u64) -> u64:
    put(o,at,n)
    end=b_copy(s,o,start,at+8,n)
    store(o,end,0)
    return end+1

def capture_frame(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    index=get(w,P_CAP_INDEX)
    count=2+get(w,P_MULTICALL)
    need=1024+get(w,P_COMPILER_N)
    if index==2:
        count=10+get(w,P_MULTICALL)
        need=need+get(w,P_SOURCE_PATH_N)+get(w,P_ART_PATH_N)
        if get(w,P_TARGET)==2:
            count=count+2
    if length(o)<need:
        return 4294967294
    clear(o,0,128)
    put(o,0,CAPTURE_REQUEST)
    put(o,16,count)
    put(o,40,choose(index==2,60000000000,10000000000))
    put(o,48,65536)
    put(o,56,choose(index==2,1048576,65536))
    put(o,64,1000000)
    at=argument(s,o,128,get(w,P_COMPILER_OFF),get(w,P_COMPILER_N))
    if get(w,P_MULTICALL)!=0:
        at=arg_clang(o,at)
    if index==0:
        at=arg_version(o,at)
    elif index==1:
        at=arg_dumpmachine(o,at)
    else:
        if get(w,P_TARGET)==0:
            at=arg_x86(o,at)
        elif get(w,P_TARGET)==1:
            at=arg_arm(o,at)
        else:
            at=arg_riscv(o,at)
        at=arg_x(o,at)
        at=arg_ir(o,at)
        at=arg_opt(o,at)
        at=arg_pic(o,at)
        if get(w,P_KIND)==0:
            at=arg_shared(o,at)
        else:
            at=arg_object(o,at)
        if get(w,P_TARGET)==2:
            at=arg_march(o,at)
            at=arg_mabi(o,at)
        at=argument(s,o,at,get(w,P_SOURCE_OFF),get(w,P_SOURCE_PATH_N))
        at=arg_output(o,at)
        at=argument(s,o,at,get(w,P_ART_OFF),get(w,P_ART_PATH_N))
    return at

def object_frame(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,P_ART_N)
    mn=get(w,P_META_N)-64
    if length(o)<64+n+mn:
        return 4294967294
    clear(o,0,64)
    put(o,0,OBJECT_REQUEST)
    machine=62
    if get(w,P_TARGET)==1:
        machine=183
    elif get(w,P_TARGET)==2:
        machine=243
    put(o,8,machine)
    put(o,16,n)
    put(o,24,get(w,P_META+32))
    b_work_copy(w,o,P_META+64,64+n,mn)
    return 64+n+mn
def shared_setup(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    clear(w,P_INV_WORK,1639448)
    put(w,P_INV_WORK,3621252868775954760)
    count=get(w,P_META+32)
    put(w,P_INV_WORK+1572880,count)
    at=P_META+64
    i=0
    while i<count:
        n=get(w,at)
        dest=P_INV_WORK+1572888+i*520
        put(w,dest,n)
        j=0
        while j<n:
            store(w,dest+8+j,byte(w,at+8+j))
            j=j+1
        at=at+8+n
        i=i+1
    return 0

def inventory_normalize(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    head=64
    count=get(w,P_INV_OUT+16)
    if get(w,P_KIND)==0:
        head=2112
        count=get(w,P_INV_OUT+8)
    if count>256:
        return 4294967293
    imports=0
    i=0
    while i<count:
        row=P_INV_OUT+head+i*24
        if get(w,row+16)==0:
            put(w,P_SMALL+1024+imports*8,row)
            imports=imports+1
        i=i+1
    i=1
    while i<imports:
        value=get(w,P_SMALL+1024+i*8)
        j=i
        while j>0 and name_before(s,w,value,get(w,P_SMALL+1024+(j-1)*8)):
            put(w,P_SMALL+1024+j*8,get(w,P_SMALL+1024+(j-1)*8))
            j=j-1
        put(w,P_SMALL+1024+j*8,value)
        i=i+1
    start=get(w,P_INV_OFF)
    if start>length(o) or length(o)-start<65536:
        return 4294967294
    clear(o,start,64)
    put(o,start,3544427800977033544)
    put(o,start+8,get(w,P_META+32))
    put(o,start+16,imports)
    at=b_work_copy(w,o,P_META+64,start+64,get(w,P_META_N)-64)
    i=0
    while i<imports:
        row=get(w,P_SMALL+1024+i*8)
        name=get(w,row)
        n=get(w,row+8)
        if name>length(s) or n>length(s)-name or at>length(o) or n>length(o)-at-8:
            return 4294967293
        put(o,at,n)
        at=b_copy(s,o,name,at+8,n)
        i=i+1
    put(o,start+24,at-start)
    put(w,P_INV_N,at-start)
    return 0

def name_before(s:readbuf,w:mutbuf,a:u64,b:u64) -> bool:
    x=get(w,a)
    y=get(w,b)
    xn=get(w,a+8)
    yn=get(w,b+8)
    i=0
    while i<xn and i<yn:
        p=byte(s,x+i)
        q=byte(s,y+i)
        if p!=q:
            return p<q
        i=i+1
    return xn<yn

def origin_parent(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=length(s)
    if n==0 or byte(s,0)!=47:
        return 4294967293
    at=n
    while at>0 and byte(s,at-1)!=47:
        at=at-1
    if at==0:
        return 4294967293
    if at>1:
        at=at-1
    put(w,P_ORIGIN_DIR_N,at)
    return 0

def catalog_measure(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or word(s,0)!=P_CATALOG_MAGIC or word(s,8)!=0 or word(s,24)!=length(s):
        return 4294967293
    count=word(s,16)
    if count==0 or count>(length(s)-32)//9:
        return 4294967293
    prefix=get(w,P_ORIGIN_DIR_N)
    if prefix>9223372036854771712-4096:
        return 4294967294
    data=(prefix+7)&18446744073709551608
    need=32
    at=32
    i=0
    while i<count:
        if at>length(s) or length(s)-at<8:
            return 4294967293
        n=word(s,at)
        if n==0 or n>length(s)-at-8 or n>9223372036854771712//2:
            return 4294967293
        if logical_name(s,at+8,n)==False:
            return 4294967293
        add=210+prefix+2*n
        if add>9223372036854771712-need:
            return 4294967294
        need=need+add
        at=at+8+n
        i=i+1
    if at!=length(s) or data>9223372036854771712-need:
        return 4294967293
    put(w,P_CATALOG_DATA_OFF,data)
    put(w,P_CATALOG_N,need)
    put(w,P_CATALOG_NEED,(data+need+4095)&18446744073709547520)
    return 0

def logical_name(s:readbuf,at:u64,n:u64) -> bool:
    component=0
    dots=0
    i=0
    while i<n:
        ch=byte(s,at+i)
        if ch==47:
            if component==0 or dots==component and dots<=2:
                return False
            component=0
            dots=0
        else:
            if (ch>=48 and ch<=57 or ch>=65 and ch<=90 or ch>=97 and ch<=122 or ch==95 or ch==45 or ch==46)==False:
                return False
            component=component+1
            if ch==46:
                dots=dots+1
        i=i+1
    return component!=0 and (dots==component and dots<=2)==False

def catalog_fill(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<get(w,P_CATALOG_NEED):
        return 4294967294
    start=get(w,P_CATALOG_DATA_OFF)
    count=word(s,16)
    prefix=get(w,P_ORIGIN_DIR_N)
    clear(o,start,32)
    put(o,start,ID_REQUEST)
    put(o,start+16,count)
    put(o,start+24,get(w,P_CATALOG_N))
    out=start+32
    at=32
    i=0
    while i<count:
        n=word(s,at)
        path=prefix+1+n
        frame=193+path
        put(o,out,n)
        put(o,out+8,frame)
        end=b_copy(s,o,at+8,out+16,n)
        clear(o,end,192)
        put(o,end,FILE_REQUEST)
        put(o,end+16,1073741824)
        put(o,end+24,1)
        put(o,end+32,path)
        dest=end+192
        b_out_copy(o,0,dest,prefix)
        dest=dest+prefix
        store(o,dest,47)
        dest=dest+1
        dest=b_copy(s,o,at+8,dest,n)
        store(o,dest,0)
        out=dest+1
        at=at+8+n
        i=i+1
    if out-start!=get(w,P_CATALOG_N):
        return 4294967293
    put(w,P_CATALOG,get(w,P_CATALOG_MAP)+start)
    put(w,P_CATALOG_READY,1)
    return 0

def relative_source(o:mutbuf,at:u64) -> u64:
    store(o,at,46)
    store(o,at+1,46)
    store(o,at+2,47)
    store(o,at+3,115)
    store(o,at+4,111)
    store(o,at+5,117)
    store(o,at+6,114)
    store(o,at+7,99)
    store(o,at+8,101)
    store(o,at+9,47)
    return at+10

'''
def literal(name,text,arg=False):
 raw=text.encode('ascii');lines=[f'def {name}(o:mutbuf,at:u64) -> u64:']
 if arg:lines+=['    put(o,at,'+str(len(raw))+')','    at=at+8']
 lines += [f'    store(o,at+{i},{b})'for i,b in enumerate(raw)]
 if arg:lines += [f'    store(o,at+{len(raw)},0)']
 lines += [f'    return at+{len(raw)+int(arg)}']
 return '\n'.join(lines)
for name,text in [('source','/program.ll'),('shared','/program.so'),('object','/program.o')]:
 SOURCE+='\n'+literal('literal_'+name,text)
for name,text in [('clang','clang'),('version','--version'),('dumpmachine','-dumpmachine'),('x86','--target=x86_64-unknown-linux-gnu'),('arm','--target=aarch64-unknown-linux-gnu'),('riscv','--target=riscv64-unknown-linux-gnu'),('x','-x'),('ir','ir'),('opt','-O3'),('pic','-fPIC'),('shared','-shared'),('object','-c'),('march','-march=rv64gc'),('mabi','-mabi=lp64d'),('output','-o')]:
 SOURCE+='\n'+literal('arg_'+name,text,True)
if __name__=='__main__':write_module('clang_origin_buffers',SOURCE)
