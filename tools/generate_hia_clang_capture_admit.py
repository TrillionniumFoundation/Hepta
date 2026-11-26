"""Admit the complete Linux argv/environment and byte-budget capture wire."""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def admit(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or word(s,0)!=REQUEST or word(s,8)!=0:
        first_error(w,E_ARGV,0)
        return reply(o,w)
    argc=word(s,16)
    envc=word(s,24)
    explicit=word(s,32)
    if argc==0 or argc>(length(s)-128)//10:
        first_error(w,E_ARGV,0)
        return reply(o,w)
    if explicit>1 or envc>256 or (explicit==0 and envc!=0):
        first_error(w,E_ENV,0)
        return reply(o,w)
    if word(s,40)>MAX_TIMEOUT or word(s,96)>1:
        first_error(w,E_BUDGET,0)
        return reply(o,w)
    if word(s,88)!=0 or word(s,104)!=0 or word(s,112)!=0 or word(s,120)!=0:
        first_error(w,E_ARGV,0)
        return reply(o,w)
    words=argc+envc+2
    if words>(length(w)-TABLE_BASE)//8:
        first_error(w,E_MEMORY,12)
        return reply(o,w)
    put(w,ARGC,argc)
    put(w,ENVC,envc)
    put(w,EXPLICIT_ENV,explicit)
    put(w,TIMEOUT,word(s,40))
    put(w,OUTPUT_LIMIT,word(s,48))
    put(w,ERROR_LIMIT,word(s,56))
    put(w,INPUT_LIMIT,word(s,64))
    put(w,INPUT_N,word(s,72))
    put(w,CWD_N,word(s,80))
    put(w,CWD_PRESENT,word(s,96))
    put(w,ARGV,get(w,WORK_PTR)+TABLE_BASE)
    put(w,ENVP,get(w,WORK_PTR)+TABLE_BASE+(argc+1)*8)
    at=128
    i=0
    budget=131072
    while i<argc+envc:
        if at>length(s) or length(s)-at<8:
            return rejected(o,w,i,argc)
        n=word(s,at)
        at=at+8
        if n>=length(s)-at or byte(s,at+n)!=0:
            return rejected(o,w,i,argc)
        if i<argc and n==0:
            return rejected(o,w,i,argc)
        equal=NONE
        j=0
        while j<n:
            ch=byte(s,at+j)
            if ch==0:
                return rejected(o,w,i,argc)
            if i>=argc and equal==NONE and ch==61:
                equal=j
            j=j+1
        if i>=argc:
            if equal==NONE or equal==0 or n+1>budget or utf8(s,at,n)==0:
                return rejected(o,w,i,argc)
            budget=budget-n-1
            put(w,TABLE_BASE+(i+1)*8,get(w,SOURCE_PTR)+at)
            if equal==4 and byte(s,at)==80 and byte(s,at+1)==65 and byte(s,at+2)==84 and byte(s,at+3)==72:
                put(w,PATH_PTR,get(w,SOURCE_PTR)+at+5)
                put(w,PATH_N,n-5)
                put(w,ENV_PATH_IN_SOURCE,1)
                put(w,ENV_PATH_CAPTURE,1)
        else:
            put(w,TABLE_BASE+i*8,get(w,SOURCE_PTR)+at)
            if i==0:
                put(w,ARG0_AT,at)
                put(w,ARG0_N,n)
        at=at+n+1
        i=i+1
    put(w,TABLE_BASE+argc*8,0)
    put(w,TABLE_BASE+(argc+envc+1)*8,0)
    if get(w,CWD_PRESENT)==1:
        n=get(w,CWD_N)
        if at>=length(s) or n>=length(s)-at or byte(s,at+n)!=0:
            first_error(w,E_EXEC,22)
            return reply(o,w)
        i=0
        while i<n:
            if byte(s,at+i)==0:
                first_error(w,E_EXEC,22)
                return reply(o,w)
            i=i+1
        put(w,CWD_AT,at)
        at=at+n+1
    elif get(w,CWD_N)!=0:
        first_error(w,E_EXEC,22)
        return reply(o,w)
    n=get(w,INPUT_N)
    if at>length(s) or n!=length(s)-at or utf8(s,at,n)==0:
        first_error(w,E_INPUT,0)
        return reply(o,w)
    if n>get(w,INPUT_LIMIT):
        first_error(w,E_INPUT_SIZE,0)
        return reply(o,w)
    put(w,INPUT_AT,at)
    return jump(w,20)

def rejected(o:mutbuf,w:mutbuf,i:u64,argc:u64) -> u32:
    first_error(w,choose(i<argc,E_ARGV,E_ENV),0)
    return reply(o,w)
'''
if __name__=='__main__':write_module('clang_capture_admit',SOURCE,'admit')
