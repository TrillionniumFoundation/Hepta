"""Static joins against retained VM bytes; no original tests or product imports."""
from pathlib import Path
import ast,hashlib,json,sys
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'control'))
import matrix,model
def require(v,m):
    if not v:raise RuntimeError(m)
def wire(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(p):
    b=p.read_bytes()
    return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def create(p,v):
    raw=wire(v)
    with p.open('xb')as f:f.write(raw);f.flush();__import__('os').fsync(f.fileno())
    require(p.read_bytes()==raw,'created proof differs')
checked=[]
for p in sorted((R/'control').glob('*.py')):
    ast.parse(p.read_bytes(),filename=str(p));checked.append(pin(p))
old=(R/'candidate/inputs/tests/test_hia_sqlite_wal_snapshot_source.py').read_bytes()
require(len(old)==27618 and hashlib.sha256(old).hexdigest()=='2bde9e21ca1de533449658464edea5dcd1597d9e880d9c9dfa0e1fab3cb10659','whole original test text')
original=list(matrix.original_calls(R));by={}
for row in original:by.setdefault(row['case'],[]).append(row)
fields=('source_before_hex','source_after_hex','output_before_hex','output_after_hex','state_before_hex','state_after_hex','status','actual_returned')
joins=[];used=set()
def join(method,offset,raw,pages,base_size=512,base_pages=9,label=''):
    rows,_,_=model.full_page_protocol(raw,pages,base_size,base_pages)
    actual=by[matrix.ORIGINAL_IDS[method-1]][offset:offset+len(rows)]
    require(len(actual)==len(rows),'retained VM window')
    for k,(a,b)in enumerate(zip(actual,rows)):
        require({x:a[x]for x in fields}=={x:b[x]for x in fields},'ABI model contradicts retained VM '+str((method,offset+k,label)))
        used.add((method,offset+k))
    joins.append({'method':matrix.ORIGINAL_IDS[method-1],'offset':offset,'rows':len(rows),'label':label})
    return offset+len(rows)
offset=0
for order in ('little','big'):
    offset=join(2,offset,model.wal(((1,0,11),(2,2,22),(1,0,33),(1,2,44),(1,0,55)),order),(1,2,3,1,2),label=order)
require(offset==76,'whole method02 model join')
offset=0
for order in ('little','big'):
    offset=join(3,offset,model.wal(((1,0,17),(2,0,29)),order),(1,3,4,1),base_pages=3,label=order)
offset=0
raw=model.wal(((1,1,9),(1,0,10),(1,1,11)));start=568
for p in (8,12,15,4,7,16,20,24,535):
    b=bytearray(raw);b[start+p]^=1;offset=join(5,offset,bytes(b),(1,),label='bad-second-'+str(p))
b=bytearray(raw);b[start:start+4]=b'\0'*4;offset=join(5,offset,bytes(b),(1,),label='zero-second-page')
for p in (8,16,24):
    b=bytearray(raw);b[32+p]^=1;offset=join(5,offset,bytes(b),(1,),label='bad-first-'+str(p))
require(offset==108,'whole method05 model join')
offset=0
for order in ('little','big'):
    for power in range(9,17):
        size=1<<power
        offset=join(6,offset,model.header(order,size)+b'x',(1,),base_size=size,label='header-'+str(size)+'-'+order)
raw=model.wal(((5,5,8),(1,0,9),(1,2,10),(5,0,11)))
join(8,0,raw,(1,2,3,5,5,2),label='shrinking commit and missing-page projection')
expected=json.loads((R/'EXPECTED-MATRIX.json').read_bytes())
require(matrix.manifest(R)==expected,'entire fixed metadata/trace arithmetic unchanged')
require(expected['native_returns']==2704 and expected['C_calls_each']==639
    and expected['populations']=={'original12':608,'full-page-extension':2096}
    and expected['combined_trace_bytes']==203187698,'exact finite counts')
method_counts={x:0 for x in matrix.IDS}
for spec in matrix.drives():method_counts[spec['method']]+=1
report={'schema':'hia.wal-snapshot.native-static-reference-joins.v1','status':'STATIC_SOURCE_AND_EXISTING_BYTES_ONLY',
        'controls_AST':checked,'unchanged_original_tests':pin(R/'candidate/inputs/tests/test_hia_sqlite_wal_snapshot_source.py'),
        'existing_VM_distinct_rows_compared':len(used),'existing_VM_joins':joins,
        'C_drives_by_method':method_counts,'expected_matrix':pin(R/'EXPECTED-MATRIX.json'),
        'no_qualification_execution':True,'no_original_method_call':True,'no_HIA_author_call':True,'no_VM_C_native':True}
create(R/'STATIC-REFERENCE-JOINS.json',report)
print(json.dumps({'status':report['status'],'original_VM_rows':len(used),'C_drives':method_counts,
                 'report':pin(R/'STATIC-REFERENCE-JOINS.json')},sort_keys=True))
