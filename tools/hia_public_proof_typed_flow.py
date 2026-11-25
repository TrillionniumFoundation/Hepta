"""Embeddable HIA continuation for a freshly returned typed classifier value.

The final public owner supplies its existing get/put helpers and an owned,
disjoint result/target area. This is authoring input to that owner's HIA source,
not a third runtime role or a hosted production path.
"""
SOURCE=r'''
def public_typed_choice(w:mutbuf,source:u64,size:u64,call_profile:bool,target:u64) -> bool:
    if source>length(w) or size>length(w)-source or size<96:
        return False
    if target>length(w) or 192>length(w)-target:
        return False
    if source<target+192 and target<source+size:
        return False
    if get(w,source)!=3544413520107555144:
        return False
    valid=get(w,source+8)
    budget=get(w,source+16)
    selected=get(w,source+32)
    n=get(w,source+48)
    timeout_kind=get(w,source+56)
    function_kind=get(w,source+64)
    maximum=60000
    if call_profile:
        maximum=10000
    if valid>1 or selected>3 or timeout_kind>3 or function_kind>2 or n>128 or size!=96+n:
        return False
    if get(w,source+72)!=0 or get(w,source+80)!=0 or get(w,source+88)!=0:
        return False
    if valid==1 and (budget==0 or budget>maximum or timeout_kind!=0):
        return False
    if valid==0 and budget!=0:
        return False
    if (selected==0 and function_kind!=0) or (selected==1 and function_kind!=1) or (selected==2 and function_kind!=1) or (selected==3 and function_kind!=2):
        return False
    if (selected==1 and n==0) or (selected!=1 and n!=0):
        return False
    i=0
    while i<n:
        c=byte(w,source+96+i)
        if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i!=0 and c>=48 and c<=57))==False:
            return False
        i=i+1
    patch=0
    if valid==0:
        patch=2
    target_n=n
    if selected>=2:
        patch=patch|1
        if call_profile==False:
            target_n=5
    put(w,target,budget)
    put(w,target+8,target_n)
    put(w,target+16,patch)
    put(w,target+24,get(w,source+40))
    put(w,target+32,get(w,source+24))
    put(w,target+40,selected)
    put(w,target+48,valid)
    put(w,target+56,0)
    if selected==1:
        i=0
        while i<n:
            store(w,target+64+i,byte(w,source+96+i))
            i=i+1
    elif target_n==5:
        store(w,target+64,97)
        store(w,target+65,98)
        store(w,target+66,111)
        store(w,target+67,114)
        store(w,target+68,116)
    return True
'''
# Avoid a hand-transcribed magic: keep a symbolic check in the authoring source.
SOURCE=SOURCE.replace('3544413520107555144',str(int.from_bytes(b'HIAPTR01','little')))
