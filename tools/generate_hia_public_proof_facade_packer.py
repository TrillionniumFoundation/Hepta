"""Author the fixed combined public-proof HIA image packer.

The shared normalizer and each proof executable are embedded once. Five
qualified pure entries are borrowed from the actual embedded primitive image
through its validated fixed role table. No executable-image cap is widened.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import assemble_adapter
from tools.generate_hia_native_filter import bind_adapter,elf_header
from tools.generate_hia_safe_core_binder import document as transport_document
from tools.generate_hia_multiversion_prepare_process_packer import BRIDGE,HOLES
ROOT=Path(__file__).resolve().parents[1]
ADAPTER='tools/hia_public_proof_facade_syscalls.S'
PROCESS='tools/hia_multiversion_prepare_process_bridge.S'
PRIMITIVE='tools/hia_native_scalar_proof_syscalls.S'
ROLES=('public_proof_facade','cold_sha256_stream','multiversion_prepare_process',
       'native_public_proof_receipt','native_public_proof_json',
       'native_public_call_proof_receipt','public_proof_typed','public_proof_values',
       'bounded_transform','bounded_interface','bounded_proof','bounded_workflow',
       'normalizer_image','primitive_proof_image','call_proof_image','bounded_unroll_receipt')
BORROWED=(('native_scalar_proof_hash',1),('multiversion_proof_graph',4),
          ('evaluate_reference_wire',6),('scalar_reference',7),('general_cnf',8))
MAGIC=int.from_bytes(b'HIAUFP01','little')
POLICY=r'''
def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<136 or length(s)>16777352 or uint(s,0,8)!=MAGIC:
        return 4294967295
    size=extent(s)
    if size==0 or size>16777216 or size>length(o):
        return 4294967294
    envelope(o)
    put(o,96,size)
    put(o,104,size)
    index=0
    at=PREFIX
    source=136
    while index<16:
        aligned=(at+7)&18446744073709551608
        clear(o,at,aligned)
        at=aligned
        piece=uint(s,8+8*index,8)
        slot=choose(index==15,20,index)
        if index==0:
            write(o,POLICY_HOLE,at-POLICY_HOLE-4,4)
        if index==2:
            write(o,PROCESS_HOLE,at-PROCESS_HOLE-4,4)
            put(o,TABLE+16*slot,PROCESS_START-TABLE)
        else:
            put(o,TABLE+16*slot,at-TABLE)
        put(o,TABLE+16*slot+8,piece)
        copy_bytes(s,o,source,at,piece)
        if index==13:
            aliases(s,o,source,at)
        source=source+piece
        at=at+piece
        index=index+1
    return size

def extent(s:readbuf) -> u64:
    index=0
    at=PREFIX
    source=136
    while index<16:
        piece=uint(s,8+8*index,8)
        cap=1048576
        if index>=12 and index<=14:
            cap=8388608
        if piece==0 or piece>cap or piece>length(s)-source:
            return 0
        if index>=12 and index<=14 and child(s,source,piece,index!=12)==False:
            return 0
        if index==13 and primitive(s,source,piece)==False:
            return 0
        source=source+piece
        at=((at+7)&18446744073709551608)+piece
        if at>16777216:
            return 0
        index=index+1
    if source!=length(s):
        return 0
    return at

def child(s:readbuf,source:u64,n:u64,complete:bool) -> bool:
    if n<176:
        return False
    if uint(s,source,4)!=1179403647 or uint(s,source+4,1)!=2 or uint(s,source+5,1)!=1:
        return False
    loaded=uint(s,source+96,8)
    memory=uint(s,source+104,8)
    if complete:
        return loaded==n and memory==n
    return loaded>=176 and loaded<=n and memory==loaded

def primitive(s:readbuf,source:u64,n:u64) -> bool:
    if n<PRIMITIVE_TABLE+144:
        return False
    cursor=PRIMITIVE_TABLE+144
    index=0
    while index<9:
        relative=uint(s,source+PRIMITIVE_TABLE+16*index,8)
        amount=uint(s,source+PRIMITIVE_TABLE+16*index+8,8)
        if relative>n-PRIMITIVE_TABLE or amount==0 or amount>1048576:
            return False
        start=PRIMITIVE_TABLE+relative
        if start<cursor or start>n or amount>n-start or (start&7)!=0:
            return False
        cursor=start+amount
        index=index+1
    return cursor==n

def aliases(s:readbuf,o:mutbuf,source:u64,target:u64) -> u64:
    index=0
    while index<5:
        row=borrowed(index)
        relative=uint(s,source+PRIMITIVE_TABLE+16*row,8)
        amount=uint(s,source+PRIMITIVE_TABLE+16*row+8,8)
        put(o,TABLE+16*(15+index),target+PRIMITIVE_TABLE+relative-TABLE)
        put(o,TABLE+16*(15+index)+8,amount)
        index=index+1
    return 0

def borrowed(index:u64) -> u64:
    if index==0:
        return 1
    if index==1:
        return 4
    if index==2:
        return 6
    if index==3:
        return 7
    return 8

def clear(o:mutbuf,start:u64,end:u64) -> u64:
    while start<end:
        store(o,start,0)
        start=start+1
    return 0

def copy_bytes(s:readbuf,o:mutbuf,source:u64,target:u64,size:u64) -> u64:
    i=0
    while i<size:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0
'''
def document():
 adapter=(ROOT/ADAPTER).read_bytes();process=(ROOT/PROCESS).read_bytes();primitive=(ROOT/PRIMITIVE).read_bytes()
 with TemporaryDirectory(prefix='hia-public-facade-transport-') as td:
  stub,symbols,_=assemble_adapter(Path(td),ADAPTER,adapter)
  _,primitive_symbols,_=assemble_adapter(Path(td),PRIMITIVE,primitive)
 hole=symbols['public_policy_hole'];table=symbols['embedded_roles']
 assert stub[hole-1:hole+4]==b'\xe8\0\0\0\0' and table%8==0 and stub[table:table+336]==bytes(336)
 ph=HOLES['policy'];assert BRIDGE[ph-1:ph+4]==b'\xe8\0\0\0\0'
 header=elf_header();prefix=header+stub;prefix+=bytes((-len(prefix))%8)
 start=len(prefix);prefix+=BRIDGE;prefix+=bytes((-len(prefix))%8)
 constants={'PREFIX':len(prefix),'TABLE':len(header)+table,'POLICY_HOLE':len(header)+hole,'PROCESS_START':start,'PROCESS_HOLE':start+ph,'PRIMITIVE_TABLE':len(header)+primitive_symbols['embedded_roles'],'MAGIC':MAGIC}
 source=POLICY+'\ndef envelope(o:mutbuf) -> u64:\n'
 for at in range(0,len(prefix),8):
  piece=prefix[at:at+8];source+=f'    write(o, {at}, {int.from_bytes(piece,"little")}, {len(piece)})\n'
 source+='    return 0\n'
 result=transport_document(source,module='public_proof_facade_packer',extra=constants)
 return bind_adapter(result,adapter+b'\n'+process+b'\n'+primitive,prefix[len(header):],(hole,table,start-len(header)+ph))
if __name__=='__main__':
 target=ROOT/'examples/hia_bootstrap/public_proof_facade_packer.hepta';target.write_text(render_assembly(document()))
 print(target.name,target.stat().st_size,flush=True)
