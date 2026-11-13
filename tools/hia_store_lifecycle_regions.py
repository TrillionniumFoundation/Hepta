"""Store-owned nested-exception control, emitted as HIA functions.

The shared frame protocol remains unchanged. Two HIA control functions are
replaced only for this image: unwind respects the explicit enclosing operand
stack and propagation exits one handler at a time. Table offsets 12..13 hold
the number of preserved slots; their u16 vector follows consume operands.
Instruction kind 7 is an internal HIA propagation edge, never a foreign effect.
"""
from __future__ import annotations

import ast
from hashlib import sha256

REVIEWED_CONTROL_SHA256 = '491faa2f279d9bf30f2ba99df5a37e91a536ac49c9f7dbc91605cc5c2012b6aa'

REGIONS = r'''
def dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    while True:
        stage=get(w,168)
        if stage == 8:
            return frame_retire(s,o,w)
        if stage == 3:
            return retire(s,o,w,get(w,288),get(w,296))
        if stage == 6:
            answer=unwind(s,o,w)
            if answer != 5:
                return answer
        if get(w,168) != 0:
            return ABI
        pc=get(w,160)
        if pc == 0 or pc > word(s,24):
            return ABI
        at=small(s,word(s,40)+(pc-1)*4)
        kind=byte(s,at)
        if kind == 1:
            put(w,200,at)
            put(w,192,small(s,at+8))
            return effect(s,o,w,at)
        if kind == 7:
            put(w,200,at)
            put(w,192,small(s,at+8))
            put(w,264,1)
            put(w,272,1)
            put(w,168,6)
        else:
            if kind == 2:
                put(w,160,small(s,at+1))
            else:
                if kind == 3:
                    put(w,160,small(s,at+choose(get(w,176)!=0,1,5)))
                else:
                    if kind == 4 or kind == 5:
                        put(w,168,choose(kind == 4,5,4))
                        finish(o,w,short(s,at+1))
                        return choose(kind == 4,0,2)
                    if kind == 6:
                        put(w,168,7)
                        finish(o,w,0)
                        return 3
                    return ABI
    return ABI

def unwind(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    at=get(w,200)
    if short(s,at+12) > get(w,248):
        return ABI
    if get(w,272) == 0:
        put(w,272,1)
        count=byte(s,at+5)
        if count != 0:
            start=at+14+byte(s,at+2)*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2
            put(w,288,start)
            put(w,296,count)
            return retire(s,o,w,start,count)
    latest=0
    selected=0
    i=0
    while i < get(w,248):
        birth=get(w,1024+i*8)
        if birth > latest and preserve_contains(s,at,i) == 0:
            latest=birth
            selected=i
        i=i+1
    if latest != 0:
        put(w,280,selected)
        header(o,w,RELEASE,0,0,0,1,3)
        put(o,128,selected)
        return 1
    handler=get(w,192)
    if handler != 0:
        put(w,160,handler)
        put(w,168,0)
        put(w,264,0)
        return 5
    put(w,168,7)
    finish(o,w,0)
    return 3

def preserve_contains(s:readbuf,at:u64,slot:u64) -> u64:
    start=at+14+byte(s,at+2)*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2+byte(s,at+5)*2
    count=short(s,at+12)
    i=0
    while i < count:
        if short(s,start+i*2) == slot:
            return 1
        i=i+1
    return 0
'''


def region_control_body(original):
    if type(original) is not str or sha256(original.encode()).hexdigest() != REVIEWED_CONTROL_SHA256:
        raise ValueError('Store lifecycle shared control input differs from the reviewed bytes')
    before = ast.parse(original)
    replacements = {node.name: node for node in ast.parse(REGIONS).body}
    if set(replacements) != {'dispatch', 'unwind', 'preserve_contains'}:
        raise ValueError('Store lifecycle region function inventory differs')
    seen = set()
    for index, node in enumerate(before.body):
        if node.name in replacements:
            if node.name == 'preserve_contains' or node.name in seen:
                raise ValueError('Store lifecycle region function collides with shared control')
            seen.add(node.name)
            before.body[index] = replacements[node.name]
    if seen != {'dispatch', 'unwind'}:
        raise ValueError('Store lifecycle shared control lacks the reviewed region functions')
    before.body.append(replacements['preserve_contains'])
    return ast.unparse(before) + '\n'
