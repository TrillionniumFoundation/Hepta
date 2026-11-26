"""Native invocation queue lifecycle and mutex handoff for the sole Value entry."""
SOURCE=r'''
def invocation_owner_call(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    put(o,P_PHASE,400)
    return role(o,15,2,0,length(s),3,0,length(o),0,get(o,7040),get(o,7048))

def invocation_owner(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==400:
        action=get(o,P_FEEDBACK)
        if action==10:
            return invocation_owner_call(s,o,w)
        if action==1 or action==4 or action==8 or action==9:
            put(o,P_PHASE,401)
            return action
        if action!=0:
            put(o,8,11)
            put(o,80,1)
            put(o,104,11)
            put(o,120,1)
        copy(o,7680,0,128)
        put(o,7464,1)
        put(o,7480,1)
        if get(o,120)!=0:
            put(o,7472,95)
            return atom(o,2,420,32,0,1)
        return system(o,410,11,0,get(o,7040),get(o,7048),0,0,0,0)
    if phase==401:
        return invocation_owner_call(s,o,w)
    if phase==410:
        if get(o,P_FEEDBACK)!=0:
            put(o,7760,1)
            put(o,7784,11)
            put(o,7800,1)
            put(o,7472,95)
        else:
            put(o,7472,96)
        return atom(o,2,420,32,0,1)
    if phase==420:
        if get(o,P_FEEDBACK)==0:
            put(o,P_HELD,1)
            zero(o,6656,128)
            put(o,6656,MAGIC5)
            put(o,6664,get(o,7472))
            copy(o,6680,7056,24)
            put(o,G_PHASE,0)
            put(o,P_PHASE,423)
            return role(o,14,3,6656,128,3,0,length(o),1,0,get(w,40))
        return system(o,421,202,4,32,128,1,0,0,0)
    if phase==421:
        raw=get(o,P_FEEDBACK)
        if raw==0 or raw==MAX-3 or raw==MAX-10:
            return atom(o,2,420,32,0,1)
        put(o,7784,11)
        return atom(o,2,422,32,0,1)
    if phase==422:
        if get(o,P_FEEDBACK)==0:
            put(o,P_HELD,1)
            zero(o,6656,128)
            put(o,6656,MAGIC5)
            put(o,6664,get(o,7472))
            copy(o,6680,7056,24)
            put(o,G_PHASE,0)
            put(o,P_PHASE,423)
            return role(o,14,3,6656,128,3,0,length(o),1,0,get(w,40))
        return system(o,424,24,0,0,0,0,0,0,0)
    if phase==424:
        return atom(o,2,422,32,0,1)
    if phase==423:
        if get(o,P_FEEDBACK)!=0 or get(o,P_ERROR)!=0 or get(o,P_DROP_CONSUMED)!=1:
            put(o,7784,11)
            return atom(o,3,425,32,0,0)
        put(w,184,get(o,2104))
        put(w,176,get(o,2008))
        put(o,7040,0)
        put(o,7048,0)
        if readword(s,8)==115:
            zero(o,8152,32)
        put(o,2000,0)
        put(o,2016,0)
        if get(o,7496)!=0:
            copy(o,256,6144,512)
            original=get(o,6800)
            if get(o,7472)==95 and (drop_profile(s) or resource_retry(s) or resource_capture(s)) and original==0:
                original=11
            put(o,P_ERROR,original)
            put(o,7464,0)
            put(o,7496,0)
            if get(o,7472)==96 and get(o,7504)>1:
                put(o,7504,get(o,7504)-1)
                put(o,7480,0)
        else:
            put(o,P_ERROR,0)
        put(o,P_PHASE,200)
        return 10
    if phase==425:
        put(o,P_HELD,0)
        return system(o,426,24,0,0,0,0,0,0,0)
    if phase==426:
        return atom(o,2,420,32,0,1)
    return 4294967293

def invocation_drain_start(o:mutbuf,w:mutbuf) -> u64:
    copy(o,6144,256,512)
    put(o,6800,get(o,P_ERROR))
    if get(o,7504)==0:
        put(o,7504,get(w,184))
    zero(o,6656,128)
    put(o,6656,MAGIC5)
    put(o,6664,94)
    put(o,G_PHASE,0)
    put(o,P_PHASE,350)
    return role(o,14,3,6656,128,3,0,length(o),1,0,get(w,40))

def invocation_drain(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    put(w,184,get(o,2104))
    put(o,7480,1)
    if get(o,P_FEEDBACK)==0 and get(o,P_ERROR)==0 and get(o,G_CAP)!=0:
        put(o,7040,get(o,G_N))
        put(o,7048,get(o,G_BYTES))
        put(o,7056,get(o,G_CAP))
        put(o,7064,get(o,G_TAG0))
        put(o,7072,get(o,G_TAG1))
        put(o,7496,1)
        put(o,7464,0)
    else:
        copy(o,256,6144,512)
    put(o,P_ERROR,get(o,6800))
    put(o,P_PHASE,200)
    return 10

def invocation_finish_response(o:mutbuf) -> u64:
    copy(o,0,7680,128)
    if get(o,P_DROP_PENDING)!=0:
        put(o,80,1)
    if get(o,P_ERROR)!=0:
        put(o,104,11)
    put(o,120,0)
    return 0
'''
