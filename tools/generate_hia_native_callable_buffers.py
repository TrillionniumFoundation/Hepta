"""HIA-only captured source admission and bounded invocation-buffer transport."""
from tools.generate_hia_native_callable_common import ROOT, document, render_assembly, source

PREFIX = b'hia-asm.v1 hepta.hia.program.v9 '
ENTRY = b'fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n'
BLOCK = b'block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n'
SOURCE = r'''
def native_callable_buffers(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(o,NR_OP)
    if op==0 or op==1:
        n=readword(s,96)
        if n>length(w) or n>length(s)-128:
            return 11
        from_input(s,w,0,128,n)
        if op==0 and callable_source_valid(w,n)==False:
            return 3
        return 0
    if op==2:
        if length(w)!=NC_EXEC_SIZE:
            return 11
        action=get(o,NC_BODY_ACTION)
        if action==0:
            if get(w,NC_LIMIT)!=NC_BODY_REPLY:
                return 7
            to_output(w,o,NC_RESULT,NC_LIMIT,128)
            put(o,48,0)
            return 0
        if action==1:
            if get(w,NC_LIMIT)!=NC_BODY_VALUE:
                return 7
            n=get(w,NC_LIMIT+8)
            if n<128 or n>524160:
                return 7
            put(o,48,1)
            put(o,56,get(o,NC_EXEC)+NC_LIMIT+128)
            put(o,64,n)
            put(o,72,get(o,NC_EXEC)+NC_LIMIT+524288)
            put(o,104,524288)
            return 0
        return 7
    if op==3:
        if length(w)!=NC_EXEC_SIZE:
            return 11
        put(w,NC_LIMIT+112,readword(s,104))
        return 0
    return 11

def callable_source_valid(w:mutbuf,n:u64) -> bool:
    if n<PREFIX_LENGTH+1+ENTRY_LENGTH+BLOCK_LENGTH:
        return False
    if callable_prefix(w,0)==False:
        return False
    at=PREFIX_LENGTH
    start=at
    while at<n and byte(w,at)!=10:
        c=byte(w,at)
        if (c<65 or c>90) and (c<97 or c>122) and (c<48 or c>57) and c!=95:
            return False
        at=at+1
    if at==start or at-start>127 or at>=n:
        return False
    at=at+1
    if n-at<ENTRY_LENGTH+BLOCK_LENGTH:
        return False
    if callable_entry(w,at)==False:
        return False
    return callable_block(w,at+ENTRY_LENGTH)

def callable_uint(w:mutbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
'''


def exact(name, value):
    lines = [f'def {name}(w:mutbuf,at:u64) -> bool:']
    for at in range(0, len(value), 8):
        part = value[at:at + 8]
        lines.extend((f'    if callable_uint(w,at+{at},{len(part)})!={int.from_bytes(part,"little")}:',
                      '        return False'))
    lines.append('    return True')
    return '\n'.join(lines)


def program():
    body = SOURCE.replace('PREFIX_LENGTH', str(len(PREFIX))).replace('ENTRY_LENGTH', str(len(ENTRY))).replace('BLOCK_LENGTH', str(len(BLOCK)))
    body += '\n' + '\n\n'.join(exact(name, value) for name, value in (
        ('callable_prefix', PREFIX), ('callable_entry', ENTRY), ('callable_block', BLOCK)))
    return document(source('native_callable_buffers', body), 'native_callable_buffers')


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/native_callable_buffers.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
