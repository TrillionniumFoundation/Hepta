"""Closed native linker for independently emitted reference-VM kernels.

The input is HIAVLK01, public-mode 3 or 7, object length, then one exact
seven-section object from seed_vm_backend. Only original abort/memcpy/memset
relocations are admitted. All checks complete before any output byte changes.
The generated HIA contains the exact mechanical primitive bytes; native builds
do not execute the development assembler used to author that constant.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_seed_owned_backend import STRINGS,NAMES
ROOT=Path(__file__).resolve().parents[1]
MAGIC=b'HIAVLK01'
PLAN_ENTRY=bytes.fromhex('554889e54881ec500000004c8b9c24000000004889bdc0ffffff4889b5c8ffffff488995d0ffffff48898dd8ffffff4c8985e0ffffff4c898de8ffffff488dbdc0ffffff488db5f0ffffffe811000000488b85f0ffffff48c1e02048c1e820c9c3')
RUN_ENTRY=bytes.fromhex('554889e54881ec300000004c8b9c24000000004889b5f8ffffff488db5e0ffffffe81f000000488b85e0ffffff48c1e02048c1e8204c8b9df8ffffff49898300000000c9c3')

POLICY=r'''
def cold_reference_kernel_linker(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 536 or length(s) > 1048600:
        return 0
    if word_load(s,0) != @MAGIC@:
        return 0
    mode=word_load(s,8)
    if mode != 3 and mode != 7:
        return 0
    n=length(s)-24
    if word_load(s,16) != n or header(s) == 0:
        return 0
    sh=word(s,40)
    if sh < 64 or sh > n or n-sh != 448 or sh & 7 != 0:
        return 0
    text=word(s,sh+96)
    relabytes=word(s,sh+160)
    if text < 1 or text > n-64 or relabytes < 24 or relabytes > n:
        return 0
    rela=(64+text+7)&18446744073709551608
    if rela > n or relabytes > n-rela:
        return 0
    sym=rela+relabytes
    if sym > n or 240 > n-sym:
        return 0
    strings=sym+240
    names=strings+@STRINGS_N@
    if names > n or @NAMES_N@ > n-names:
        return 0
    if sh != (names+@NAMES_N@+7)&18446744073709551608:
        return 0
    if zeros(s,0+sh,64) == 0 or zeros(s,64+text,rela-64-text) == 0 or zeros(s,names+@NAMES_N@,sh-names-@NAMES_N@) == 0:
        return 0
    if section(s,sh+64,@TEXT_NAME@,1,6,64,text,0,0,16,0) == 0:
        return 0
    if section(s,sh+128,@RELA_NAME@,4,0,rela,relabytes,3,1,8,24) == 0:
        return 0
    if section(s,sh+192,@SYM_NAME@,2,0,sym,240,4,2,8,24) == 0:
        return 0
    if section(s,sh+256,@STR_NAME@,3,0,strings,@STRINGS_N@,0,0,1,0) == 0:
        return 0
    if section(s,sh+320,@NAMES_NAME@,3,0,names,@NAMES_N@,0,0,1,0) == 0:
        return 0
    if section(s,sh+384,@STACK_NAME@,1,0,names+@NAMES_N@,0,0,0,1,0) == 0:
        return 0
    public=@PLAN_N@
    if mode == 7:
        public=@RUN_N@
    if public >= text or symbol(s,sym+48,1,65554,0,public) == 0:
        return 0
    if mode == 3:
        if plan_entry(s,64) == 0:
            return 0
    else:
        if run_entry(s,64) == 0:
            return 0
    if zeros(s,sym,24) == 0 or symbol(s,sym+24,0,65539,0,0) == 0:
        return 0
    if imports(s,sym) == 0 or object_strings(s,strings) == 0 or object_names(s,names) == 0:
        return 0
    if text < 7 or object_byte(s,64+text-7) != 232 or word32(s,64+text-6) != 0 or object_byte(s,64+text-2) != 15 or object_byte(s,64+text-1) != 11:
        return 0
    if word(s,sym-24) != text-6 or word(s,sym-16) != 12884901892 or word(s,sym-8) != 18446744073709551612:
        return 0
    cursor=rela
    previous=0
    while cursor < sym:
        if sym-cursor < 24:
            return 0
        site=word(s,cursor)
        info=word(s,cursor+8)
        number=info>>32
        if site < 1 or site > text or 4 > text-site or site < previous or object_byte(s,64+site-1) != 232:
            return 0
        if info&4294967295 != 4 or word(s,cursor+16) != 18446744073709551612:
            return 0
        if number != 3 and number != 7 and number != 8:
            return 0
        if word32(s,64+site) != 0:
            return 0
        previous=site+4
        cursor=cursor+24
    if cursor != sym or @PREFIX_N@+text > 1048576 or length(o) < @PREFIX_N@+text:
        return 0
    prefix(o)
    copy(s,64,o,@PREFIX_N@,text)
    cursor=rela
    while cursor < sym:
        site=word(s,cursor)
        number=word(s,cursor+8)>>32
        target=@ABORT@
        if number == 7:
            target=@MEMSET@
        if number == 8:
            target=@MEMCPY@
        displacement=target-(@PREFIX_N@+site+4)
        put32(o,@PREFIX_N@+site,displacement)
        cursor=cursor+24
    return @PREFIX_N@+text

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at+24)

def object_byte(s:readbuf,at:u64) -> u64:
    return byte(s,at+24)

def word32(s:readbuf,at:u64) -> u64:
    return object_byte(s,at)|(object_byte(s,at+1)<<8)|(object_byte(s,at+2)<<16)|(object_byte(s,at+3)<<24)

def zeros(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if object_byte(s,at+i) != 0:
            return 0
        i=i+1
    return 1

def header(s:readbuf) -> u64:
    if word(s,0) != 282584257676671 or word(s,8) != 0 or word(s,16) != 4299030529 or word(s,24) != 0 or word(s,32) != 0:
        return 0
    if word(s,48) != 274877906944 or word(s,56) != 1407404952518656:
        return 0
    return 1

def section(s:readbuf,at:u64,name:u64,kind:u64,flags:u64,offset:u64,size:u64,link:u64,info:u64,alignment:u64,entry:u64) -> u64:
    if word(s,at) != name|(kind<<32) or word(s,at+8) != flags or word(s,at+16) != 0:
        return 0
    if word(s,at+24) != offset or word(s,at+32) != size or word(s,at+40) != link|(info<<32):
        return 0
    if word(s,at+48) != alignment or word(s,at+56) != entry:
        return 0
    return 1

def symbol(s:readbuf,at:u64,name:u64,tag:u64,value:u64,size:u64) -> u64:
    if word(s,at) != name|(tag<<32) or word(s,at+8) != value or word(s,at+16) != size:
        return 0
    return 1

def put(o:mutbuf,at:u64,value:u64) -> u64:
    store(o,at,value&255)
    store(o,at+1,(value>>8)&255)
    store(o,at+2,(value>>16)&255)
    store(o,at+3,(value>>24)&255)
    store(o,at+4,(value>>32)&255)
    store(o,at+5,(value>>40)&255)
    store(o,at+6,(value>>48)&255)
    store(o,at+7,(value>>56)&255)
    return 0

def put32(o:mutbuf,at:u64,value:u64) -> u64:
    store(o,at,value&255)
    store(o,at+1,(value>>8)&255)
    store(o,at+2,(value>>16)&255)
    store(o,at+3,(value>>24)&255)
    return 0

def copy(s:readbuf,at:u64,o:mutbuf,dst:u64,n:u64) -> u64:
    i=0
    while n-i >= 8:
        put(o,dst+i,word(s,at+i))
        i=i+8
    while i<n:
        store(o,dst+i,object_byte(s,at+i))
        i=i+1
    return 0
'''

def checked_literal(name,raw):
    lines=[f'def {name}(s:readbuf,at:u64) -> u64:']
    at=0
    while at+8<=len(raw):
        lines += [f'    if word(s,at+{at}) != {int.from_bytes(raw[at:at+8],"little")}:',
                  '        return 0']
        at+=8
    for pos in range(at,len(raw)):
        lines += [f'    if object_byte(s,at+{pos}) != {raw[pos]}:', '        return 0']
    return '\n'.join(lines+['    return 1'])

def template():
    with TemporaryDirectory(prefix='hia-reference-primitives-') as tmp:
        obj=Path(tmp)/'primitives.o';binary=Path(tmp)/'primitives.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_reference_primitives.S'),'-o',str(obj)],check=True,capture_output=True)
        rel=subprocess.check_output(['objdump','-r',str(obj)],text=True)
        assert 'R_X86_64' not in rel,rel
        subprocess.run(['objcopy','-O','binary','--only-section=.text',str(obj),str(binary)],check=True,capture_output=True)
        symbols={line.split()[-1]:int(line.split()[0],16) for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines() if len(line.split())==3}
        raw=binary.read_bytes()
    assert symbols['_start']==0 and symbols['cold_reference_text']==len(raw) and len(raw)<1024
    return raw,symbols

def program():
    prefix,symbols=template()
    names={'.text':'TEXT','.rela.text':'RELA','.symtab':'SYM','.strtab':'STR','.shstrtab':'NAMES','.note.GNU-stack':'STACK'}
    values={'MAGIC':int.from_bytes(MAGIC,'little'),'STRINGS_N':len(STRINGS),'NAMES_N':len(NAMES),'PLAN_N':len(PLAN_ENTRY),'RUN_N':len(RUN_ENTRY),'PREFIX_N':len(prefix),'ABORT':symbols['abort'],'MEMCPY':symbols['memcpy'],'MEMSET':symbols['memset']}
    values.update({label+'_NAME':NAMES.index(name.encode()+bytes(1)) for name,label in names.items()})
    result=POLICY
    for key,value in values.items():result=result.replace('@'+key+'@',str(value))
    assert '@' not in result
    result+='\n'+checked_literal('plan_entry',PLAN_ENTRY)+'\n'+checked_literal('run_entry',RUN_ENTRY)+'\n'+checked_literal('object_strings',STRINGS)+'\n'+checked_literal('object_names',NAMES)
    result+='\ndef imports(s:readbuf,at:u64) -> u64:\n'
    for i,name in enumerate(('abort','calloc','malloc','free','memset','memcpy','memmove')):
        result+=f'    if symbol(s,at+{(i+3)*24},{STRINGS.index(name.encode()+bytes(1))},16,0,0) == 0:\n        return 0\n'
    result+='    return 1\n\ndef prefix(o:mutbuf) -> u64:\n'
    for at in range(0,len(prefix)-7,8):result+=f'    put(o,{at},{int.from_bytes(prefix[at:at+8],"little")})\n'
    for at in range(len(prefix)//8*8,len(prefix)):result+=f'    store(o,{at},{prefix[at]})\n'
    return result+'    return 0\n'

def main():
    doc=document(program(),'cold_reference_kernel_linker')
    raw=render_assembly(doc).encode()
    (ROOT/'examples/hia_bootstrap/cold_reference_kernel_linker.hepta').write_bytes(raw)
    print('REFERENCE_KERNEL_LINKER',len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))

if __name__=='__main__':
    main()
