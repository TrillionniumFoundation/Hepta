"""Original 12 selected-cell methods / 339 calls; pure expectations, no HIA/VM/C execution."""
from pathlib import Path
import hashlib,json,struct
import common
MAGIC=int.from_bytes(b'HIABTC01','little')
PROTOCOL,TRUNCATED,CAPACITY,FORMAT,LIMIT,INDEX=0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9
REFUSALS=(PROTOCOL,TRUNCATED,CAPACITY,FORMAT,INDEX,LIMIT)
MAX_PAYLOAD=65536
MAX_OUTPUT=128
MAX_COMMAND=72
CANARY=bytes(range(64))
EXPECTED_NAMES = (
    'test_01_Core_roundtrip_and_original_caps',
    'test_02_all_page_kinds_sizes_reserves_and_page_one',
    'test_03_all_rowid_boundaries_and_nonminimal_widths',
    'test_04_overflow_local_partition_and_large_payload_descriptors',
    'test_05_page_one_database_header_admission',
    'test_06_selected_cell_bounds_and_truncations',
    'test_07_protocol_controls_and_output_capacity',
    'test_08_pointer_geometry_index_and_page_number_refusals',
    'test_09_nonminimal_payload_width_and_numeric_limit',
    'test_10_minimum_cell_padding_and_zero_payloads',
    'test_11_bridge_custody_and_exact_public_types',
    'test_12_complete_upstream_sources_and_explicit_scope',
)
EXPECTED_COUNTS = (0, 72, 36, 108, 22, 14, 24, 14, 30, 16, 3, 0)
NAMES=EXPECTED_NAMES
COUNTS=EXPECTED_COUNTS
MODULE='tests.hia_sqlite_btree_cell_source_r1'
IDS=tuple(MODULE+'.SQLiteBtreeCellSourceTests.'+x for x in NAMES)
VERSIONS=('3.46.0','3.53.2')
SOURCE12_RAW_BYTES=16366443
SOURCE12_RAW_SHA='d1e23200de22b2a39aafc6258e74155fd667fea08489cdff913fd6acdf6b7cca'
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(value,message):
    if not value:raise ValueError(message)
def varint(raw,offset,end):
 x=0
 for j in range(9):
  need(offset<end,'complete successful varint');b=raw[offset];offset+=1
  if j==8:return (x<<8)|b,offset
  x=(x<<7)|(b&127)
  if b<128:return x,offset
 raise AssertionError('unreachable')
def expected_success(raw,control):
 need(len(control)==64,'successful command extent')
 magic,op,size,reserved,page,index,pages,zero=struct.unpack('<8Q',control)
 need(magic==int.from_bytes(b'HIABTC01','little') and op==1 and zero==0,'successful command constants')
 need(size in (512,1024,2048,4096,8192,16384,32768,65536) and len(raw)==size,'successful exact page size')
 need(0<=reserved<=255 and size-reserved>=480 and 1<=page<=pages<=4294967294,'successful page control bounds')
 usable=size-reserved
 def be(at,n):
  need(0<=at<=usable-n,'full big endian scalar span')
  return int.from_bytes(raw[at:at+n],'big')
 h=100 if page==1 else 0
 if page==1:
  need(raw[:16]==b'SQLite format 3\0','database magic')
  encoded=be(16,2);need((65536 if encoded==1 else encoded)==size and raw[20]==reserved,'database size and reserve')
  need(raw[18] in (1,2) and raw[19] in (1,2) and raw[21:24]==bytes((64,32,32)),'header versions and fractions')
  need(1<=be(44,4)<=4 and 1<=be(56,4)<=3 and raw[72:92]==bytes(20),'schema encoding reserved header')
  if be(24,4)==be(92,4) and be(28,4)!=0:need(be(28,4)==pages,'valid in-header database size')
 kind=raw[h];need(kind in (2,5,10,13) and (h!=100 or kind in (5,13)),'declared page kind')
 count,content=be(h+3,2),be(h+5,2);content=65536 if content==0 else content
 ptr=h+(12 if kind in (2,5) else 8)
 if kind in (2,5):need(1<=be(h+8,4)<=pages and be(h+8,4)!=page,'right child bound')
 need(content<=usable and ptr+count*2<=content and raw[h+7]<=60,'pointer-array geometry')
 free=be(h+1,2);need(free==0 or content<=free<=usable-4,'first freeblock position')
 need(index<count,'selected index')
 offset=be(ptr+index*2,2);need(content<=offset<=usable-4,'selected cell offset')
 at=offset;child=0
 if kind in (2,5):
  child=be(at,4);need(1<=child<=pages and child!=page,'left child bound');at+=4
 payload=0
 if kind!=5:
  payload,end=varint(raw,at,usable);need(end-at<=5 and payload<=2147483647,'payload width and numerical domain');at=end
 key=payload
 if kind in (5,13):key,at=varint(raw,at,usable)
 local=payload_at=overflow=overflow_at=overflow_pages=overflow_last=0
 end=at
 if kind!=5:
  payload_at=at;maxlocal=usable-35 if kind==13 else (usable-12)*64//255-23
  minlocal=(usable-12)*32//255-23
  local=payload
  if payload>maxlocal:
   surplus=minlocal+(payload-minlocal)%(usable-4);local=surplus if surplus<=maxlocal else minlocal
  need(local<=usable-at,'complete local payload')
  end=at+local
  if payload>local:
   overflow_at=end;overflow=be(end,4);need(1<=overflow<=pages and overflow!=page,'overflow page bound');end+=4
   overflow_pages,overflow_last=divmod(payload-local,usable-4)
   if overflow_last:overflow_pages+=1
   else:overflow_last=usable-4
  end=max(end,offset+4)
 need(end<=usable,'complete cell and padding')
 return struct.pack('<16Q',page,kind,usable,count,index,offset,end-offset,payload_at,payload,local,child,key,overflow,overflow_at,overflow_pages,overflow_last)

def project_cell(expected,returned,words):
    need(type(returned)is int and returned==0 and type(words)is list and len(words)==6
        and all(type(x)is int and 0<=x<1<<64 for x in words),'C exact CellInfo result types/arity/status')
    need(words==expected,'C complete CellInfo six-word projection differs')
    return dict(zip(('nKey_bits','payload_is_NULL','payload_page_offset','nPayload','nLocal','nSize'),words))
def specifications(root=None):
    need(root is not None,'frozen source12 actual root required')
    path=Path(root)/'reference/source12-actual/tests/VM-RAW.json'
    pin,body=common.read(path,32<<20)
    need(pin['bytes']==SOURCE12_RAW_BYTES and pin['sha256']==SOURCE12_RAW_SHA,'actual complete Source12 matrix byte pin')
    old=json.loads(body);calls=old['calls']
    need(old['schema']=='hia.sqlite-btree-cell.source-vm-raw.v1' and old['native_executed'] is False
        and old['compiler_executed'] is False and type(calls)is list and len(calls)==339,'frozen source12 matrix domain')
    per={name:0 for name in IDS};order=[name for name,count in zip(IDS,COUNTS) for _ in range(count)]
    accepted=refused=0
    for index,row in enumerate(calls,1):
        need(row['case']==order[index-1] and row['actual_returned'] is True and type(row['status'])is int
            and 'exception_type' not in row,'complete original ordered actual returns')
        spans={}
        for key in ('source_before_hex','source_after_hex','output_before_hex','output_after_hex',
                    'control_before_hex','control_after_hex'):
            need(type(row[key])is str,'original raw buffer text type')
            b=bytes.fromhex(row[key]);need(b.hex()==row[key],'original full buffer canonical encoding');spans[key]=b
        source,out,cmd=(spans[k] for k in ('source_before_hex','output_before_hex','control_before_hex'))
        need(spans['source_after_hex']==source and spans['control_after_hex']==cmd
            and len(out)==len(spans['output_after_hex']),'immutable original source/control/full output extent')
        need(len(source)<=MAX_PAYLOAD+1 and len(out)<=MAX_OUTPUT+1 and len(cmd)<=MAX_COMMAND,'fixed original raw spans')
        status=row['status'];words=cell=None
        if status in REFUSALS:
            need(spans['output_after_hex']==out,'original refusal made no output write');refused+=1
        else:
            need(status==128 and len(out)==128,'fixed actual success extent/status')
            layout=expected_success(source,cmd)
            need(layout==spans['output_after_hex'],'independent complete legal selected-cell admission')
            words=list(struct.unpack('<16Q',layout));kind=words[1]
            cell=[words[11],int(kind==5),0 if kind==5 else words[7],words[8],words[9],words[6]]
            project_cell(cell,0,cell);accepted+=1
        per[row['case']]+=1;method_index=IDS.index(row['case'])+1
        yield {'index':index,'method':row['case'],'label':'m%02d-%04d'%(method_index,per[row['case']]),
            'source_hex':source.hex(),'output_hex':out.hex(),'command_hex':cmd.hex(),
            'expected':{'status':status,'source_after_hex':source.hex(),'output_after_hex':spans['output_after_hex'].hex(),
                'command_after_hex':cmd.hex(),'words':words,'cell_info':cell,
                'C_applicability':'PREVALIDATED_COMPLETE_CELL' if cell is not None else 'NOT_CALLED_FROZEN_REFUSAL'}}
    need(tuple(per.values())==COUNTS and accepted==253 and refused==86,'original full 339 / 253 / 86 population')
def manifest(root=None):
    counts={k:0 for k in IDS};oracle={'cell_calls':0,'accepted_cells':0,'refused_cells_not_called':0}
    statuses={};digest=hashlib.sha256()
    for row in specifications(root):
        digest.update(wire(row));counts[row['method']]+=1;e=row['expected']
        statuses[str(e['status'])]=statuses.get(str(e['status']),0)+1
        if e['cell_info'] is None:oracle['refused_cells_not_called']+=1
        else:
            oracle['accepted_cells']+=1;oracle['cell_calls']+=1
            project_cell(e['cell_info'],0,e['cell_info'])
    need(list(counts.values())==list(COUNTS) and oracle=={'cell_calls':253,'accepted_cells':253,'refused_cells_not_called':86},
        'complete HIA and original C denominator')
    need(statuses=={'128':253,'4294967291':44,'4294967293':23,'4294967294':11,'4294967292':3,'4294967289':2,'4294967290':3},
        'all original fixture status classes')
    return {'schema':'hia.sqlite.btree.cell.native-matrix.v1','ids':list(IDS),'counts':counts,
        'native_returns':339,'oracle_calls_each':oracle,'oracle_versions':list(VERSIONS),
        'status_counts':statuses,'ordered_expected_rows_sha256':digest.hexdigest(),
        'original_methods_unchanged':12,'backend':'NativeImage; original _Machine denied, no VM rerun',
        'matrix_source':'Frozen actual R3 complete339 before/after records, plus independent complete-cell admission for C.',
        'source12_original_raw':{'bytes':SOURCE12_RAW_BYTES,'sha256':SOURCE12_RAW_SHA},
        'scope':'Single selected-cell byte kernel; C CellInfo only, no malformed C, wholepage/tree, SQL, database or durability'}
