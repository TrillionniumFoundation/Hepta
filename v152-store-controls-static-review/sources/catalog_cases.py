"""Independent format vectors; hashlib is a development oracle only."""
from hashlib import sha256
import struct

GROUPS=(
 'catalog-genesis-empty-pages','catalog-ten-single-transitions','catalog-joint-transaction',
 'catalog-all-table-transition','catalog-uuid-generation','catalog-header-selector',
 'catalog-extents','catalog-table-order','catalog-root-bindings','catalog-sha-corruption',
 'catalog-change-mask','catalog-dirty-scratch','catalog-count-boundaries')
ABI=0xfffffffd
INVALID=0xfffffffc
UPDATE=0xfffffffb
UUID=bytes(range(1,17))

def changed(raw,offset,value):
    b=bytearray(raw);b[offset:offset+len(value)]=value;return bytes(b)
def word(raw,offset,value):return changed(raw,offset,struct.pack('<Q',value))
def rehash(raw):return raw[:544]+sha256(raw[:544]).digest()

def cases(O,group):
    assert group in GROUPS
    genesis=O.genesis(UUID)
    pair=lambda i:(i,sha256(('nonempty-table-'+str(i)).encode()).digest())
    updates={i:pair(i) for i in range(1,11)}
    current=O.transition(genesis,UUID,0,updates)
    validate=lambda raw,generation=0,uuid=UUID: O.REQUEST_MAGIC+struct.pack('<QQQ',0,generation,0)+uuid+bytes(80)+raw
    transition=lambda changes:O.request(1,UUID,0,expected=genesis,updates=changes)
    rows=[]
    def add(name,source,value,payload=None,output_size=1152,workspace=None,unchanged=False):
        rows.append(dict(id=name,source=source,returned=value,payload=payload,
            output=bytes((i*17+0xa5)&255 for i in range(output_size)),
            workspace=bytes(2048) if workspace is None else workspace,unchanged=unchanged))
    if group==GROUPS[0]:
        add('genesis-ten-families',O.request(2,UUID),576,genesis)
        for i in range(1,11):
            p=O.empty_page(UUID,i);add('empty-'+str(i),O.request(3,UUID,table=i),96,p+sha256(p).digest())
    elif group==GROUPS[1]:
        for i in range(1,11):
            delta={i:pair(i)};add('table-'+str(i),transition(delta),576,O.transition(genesis,UUID,0,delta))
    elif group==GROUPS[2]:
        delta={i:pair(i) for i in (4,7,8,10)}
        add('request-slot-version-budget',transition(delta),576,O.transition(genesis,UUID,0,delta))
    elif group==GROUPS[3]:
        add('one-generation-ten-updates',transition(updates),576,current)
        add('validate-complete-new-root',O.request(0,UUID,1,expected=current),576,current)
    elif group==GROUPS[4]:
        add('different-store',validate(genesis,uuid=bytes(range(16,0,-1))),INVALID)
        add('wrong-generation',validate(genesis,1),INVALID)
        top=O.encode_catalog(UUID,(1<<64)-1,tuple(pair(i) for i in range(1,11)))
        add('max-generation-valid-read',validate(top,(1<<64)-1),576,top)
        source=word(transition({1:pair(1)}),16,(1<<64)-1)
        add('max-generation-no-wrap',source,UPDATE,unchanged=True)
        add('zero-uuid',changed(O.request(2,UUID),32,bytes(16)),ABI,unchanged=True)
    elif group==GROUPS[5]:
        base=O.request(2,UUID)
        for at in (0,56,63,64,111,120,127):add('header-'+str(at),changed(base,at,b'\xff'),ABI,unchanged=True)
        for at,value in ((8,4),(8,(1<<64)-1),(16,1),(24,1),(48,1)):
            add('header-word-'+str(at)+'-'+str(value),word(base,at,value),ABI,unchanged=True)
        for table in (0,11,(1<<64)-1):add('empty-selector-'+str(table),word(O.request(3,UUID,table=1),48,table),ABI,unchanged=True)
    elif group==GROUPS[6]:
        for op,source in ((2,O.request(2,UUID)),(0,O.request(0,UUID,expected=genesis)),(1,transition({1:pair(1)}))):
            for size in dict.fromkeys((0,127,len(source)-1,len(source)+1)):
                s=source[:size] if size<len(source) else source+bytes(size-len(source))
                add('source-'+str(op)+'-'+str(size),s,ABI,unchanged=True)
        for size in (0,1151):add('output-'+str(size),O.request(2,UUID),ABI,output_size=size,unchanged=True)
        for size in (0,2047,2049):add('workspace-'+str(size),O.request(2,UUID),ABI,workspace=bytes(size),unchanged=True)
    elif group==GROUPS[7]:
        for i in range(1,11):
            invalid=word(genesis,64+(i-1)*48,0 if i==1 else i-1)
            add('missing-or-duplicate-'+str(i),validate(rehash(invalid)),INVALID)
        invalid=bytearray(genesis);invalid[64:112],invalid[112:160]=genesis[112:160],genesis[64:112]
        add('reordered-first-two',validate(rehash(bytes(invalid))),INVALID)
        add('table-count-nine',validate(rehash(word(genesis,40,9))),INVALID)
    elif group==GROUPS[8]:
        for i in range(1,11):
            start=64+(i-1)*48+16
            add('zero-root-'+str(i),validate(rehash(changed(genesis,start,bytes(32)))),INVALID)
            wrong=sha256(O.empty_page(UUID,1 if i!=1 else 2)).digest()
            add('wrong-table-empty-root-'+str(i),validate(rehash(changed(genesis,start,wrong))),INVALID)
        wrong=sha256(O.empty_page(bytes(range(16,0,-1)),1)).digest()
        add('wrong-store-empty-root',validate(rehash(changed(genesis,80,wrong))),INVALID)
    elif group==GROUPS[9]:
        for at in (0,7,8,16,32,40,48,63,64,79,80,543,544,575):
            add('corrupt-'+str(at),validate(changed(genesis,at,bytes([genesis[at]^1]))),INVALID)
        for at in (0,8,48,63):add('well-hashed-malformed-'+str(at),validate(rehash(changed(genesis,at,bytes([genesis[at]^1])))),INVALID)
    elif group==GROUPS[10]:
        base=transition({1:pair(1)})
        for mask in (0,1024,(1<<64)-1):add('bad-mask-'+str(mask),word(base,24,mask),ABI,unchanged=True)
        add('zero-selected-digest',changed(base,712,bytes(32)),UPDATE)
        unchanged=word(base,704,0);unchanged=changed(unchanged,712,genesis[80:112])
        add('selected-unchanged-pair',unchanged,UPDATE)
        add('nonzero-unselected-update',word(base,744,1),UPDATE)
        add('wrong-empty-selected-pair',word(base,704,0),UPDATE)
    elif group==GROUPS[11]:
        for fill in (0x5a,0xa5,0xff):
            add('dirty-genesis-'+str(fill),O.request(2,UUID),576,genesis,workspace=bytes([fill])*2048)
            add('dirty-validate-'+str(fill),O.request(0,UUID,expected=genesis),576,genesis,workspace=bytes([fill])*2048)
            add('dirty-error-'+str(fill),validate(changed(genesis,575,bytes([genesis[-1]^1]))),INVALID,workspace=bytes([fill])*2048)
    elif group==GROUPS[12]:
        huge=(1<<64)-1;delta={1:(huge,sha256(b'count-max-root').digest())}
        add('max-u64-count',transition(delta),576,O.transition(genesis,UUID,0,delta))
        empty_pair=(0,sha256(O.empty_page(UUID,1)).digest())
        add('nonempty-to-exact-empty',O.request(1,UUID,1,expected=current,updates={1:empty_pair}),576,O.transition(current,UUID,1,{1:empty_pair}))
        upper=O.encode_catalog(UUID,huge-1,tuple(pair(i) for i in range(1,11)))
        new={2:(huge,sha256(b'last-generation-root').digest())}
        add('last-valid-generation',O.request(1,UUID,huge-1,expected=upper,updates=new),576,O.transition(upper,UUID,huge-1,new))
    assert rows and len({r['id'] for r in rows})==len(rows)
    return rows

def run(engine,O,group):
    from observations import require,dump,pin
    rows=cases(O,group)
    dump(engine.output/'EXPECTED-CASES.json',[dict(id=r['id'],source=pin(r['source']),returned=r['returned'],
        output=pin(r['output']),workspace=pin(r['workspace']),expected_prefix=None if r['payload'] is None else r['payload'].hex(),
        preflight_unchanged=r['unchanged']) for r in rows])
    for row in rows:
        session=engine.session(row['id'],row['output'],row['workspace'])
        value,output,workspace=session.call(row['source'],'entry')
        require(value==row['returned'],'independent catalog result differs: '+row['id'])
        if row['payload'] is not None:require(output[:value]==row['payload'],'independent complete catalog/page bytes differ: '+row['id'])
        if row['unchanged']:require(output==row['output'] and workspace==row['workspace'],'rejected preflight wrote scratch: '+row['id'])
    require(engine.cases==[r['id'] for r in rows],'whole original case order differs')
    return dict(group=group,cases=[r['id'] for r in rows],independent_sha_oracle=True,all_native_vm_frames=True,
        catalogue_graph_verified=False,transaction_row_semantics_verified=False,durability=False)
