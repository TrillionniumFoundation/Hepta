"""Typed shared-provider cleanup source, included in native HIA consumers."""
import ast
SOURCE=r'''
def provider_typed_valid(o:mutbuf) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=PROVIDER_TYPED_REPLY or get(o,RP+8)>3 or get(o,RP+64)>1:
        return False
    known=get(o,RP+72)
    consumed=get(o,RP+80)
    pending=get(o,RP+88)
    if known>1 or consumed>1 or pending>1 or (known==0 and consumed!=0):
        return False
    if get(o,RP+8)==0 and (known!=1 or pending!=0):
        return False
    at=96
    while at<128:
        if get(o,RP+at)!=0:
            return False
        at=at+8
    return True

def provider_empty_ack(o:mutbuf) -> bool:
    if provider_typed_valid(o)==False or get(o,RP+16)!=4 or get(o,RP+64)!=0:
        return False
    at=24
    while at<64:
        if get(o,RP+at)!=0:
            return False
        at=at+8
    return True

def provider_release(o:mutbuf,at:u64) -> u64:
    if provider_empty_ack(o)==False:
        return 2
    known=get(o,RP+72)
    consumed=get(o,RP+80)
    pending=get(o,RP+88)
    if known==1 and consumed==1:
        zero(o,at,24)
    if pending!=0:
        put(o,PROVIDER_PENDING,1)
    if get(o,RP+8)==0 and known==1 and consumed==1 and pending==0:
        return 0
    if known==1 and pending==1:
        return 1
    return 2

def provider_release_retry(o:mutbuf) -> u64:
    if provider_empty_ack(o)==False or get(o,RP+80)!=0:
        return 2
    known=get(o,RP+72)
    pending=get(o,RP+88)
    if get(o,RP+8)==0 and known==1 and pending==0:
        put(o,PROVIDER_PENDING,0)
        return 0
    if known==1 and pending==1:
        return 1
    return 2
'''
def selected(*names):
    functions={node.name:node for node in ast.parse(SOURCE).body}
    return '\n\n'.join(ast.unparse(functions[name])for name in names)+'\n'
