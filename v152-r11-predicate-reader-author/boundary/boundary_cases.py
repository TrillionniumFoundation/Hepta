"""Literal added R11 fixtures and the two independent scalar predicates.

This module imports no product code. It never supplies a lexer/identifier
implementation or synthesizes a successful VM result. Full-function controls
compare two actual executions of the complete independently verified programs.
"""
MASK=(1<<64)-1
DELIMITERS=(10,40,41,44,58,61,123,125,45,62,91,93)
BOUNDARY_CHARACTERS=(0,1,63,64,95,96,97,122,123,127,128,255,256,
    65535,65536,(1<<32)-1,1<<32,(1<<63)-1,1<<63,MASK)
INDEX_CLASSES=(0,1,MASK)

def dirty(size):
    return bytes(((37*index+0xA5)&255 for index in range(size)))

def workspace(cursor=0,start=0,quoted=0,error=0,size=512):
    raw=bytearray(dirty(512))
    raw[0:4]=cursor.to_bytes(4,'little')
    raw[24:28]=start.to_bytes(4,'little')
    raw[32]=quoted
    raw[40:48]=error.to_bytes(8,'little')
    # Truncate only after preparing the full fixture; no slice may extend a
    # deliberately short physical workspace.
    return bytes(raw[:size])

def cases():
    rows=[]
    def scalar(kind,character,index=0):
        group='scalar_'+kind
        rows.append({'id':group+'/'+str(len(rows)).zfill(4),'group':group,
            'kind':'scalar','predicate':kind,'character':character,'index':index})
    def full(group,function,source,*,cursor=None,start=0,quoted=0,error=0,size=512,
             source_view='readonly',workspace_view='mutable',alias=False):
        if cursor is None:cursor=len(source) if function=='f79' else 0
        raw=workspace(cursor,start,quoted,error,size)
        rows.append({'id':group+'/'+str(len(rows)).zfill(4),'group':group,
            'kind':'function','function':function,'source_hex':source.hex(),
            'workspace_hex':raw.hex(),'source_view':source_view,
            'workspace_view':workspace_view,'same_physical_owner':alias})
    characters=tuple(dict.fromkeys((*range(256),*BOUNDARY_CHARACTERS)))
    for c in characters:scalar('delimiter',c)
    for c in characters:
        for index in INDEX_CLASSES:scalar('identifier_invalid',c,index)

    for c in range(256):
        full('lexer_first_byte','f16',bytes([c])+b' A0_\n')
    for c in range(256):
        full('identifier_tail_byte','f79',b'A'+bytes([c]))

    for source,cursor in ((b'',0),(b'A',0),(b'A',1),(b'A',2),
        (b'A',65535),(b'A',65536),(b'A',(1<<32)-1),
        (b' ',0),(b'  A\n',0),(b'\n',0),(b'_',0),(b'_ ',0),
        (b'0',0),(b'9',0),(b'18446744073709551615 ',0),
        (b'18446744073709551616 ',0),
        (b'"',0),(b'""',0),(b'"A" ',0),(b'"A',0),
        (b'"0"',0),(b'"__hia_x"',0),(b'fn x\n',0),
        (b'A'*128+b'\n',0),(b'A'*129+b'\n',0)):
        full('lexer_edges','f16',source,cursor=cursor)
    for c in sorted({x for d in DELIMITERS for x in (d-1,d,d+1)}):
        full('delimiter_neighbors','f16',bytes([c])+b'\n')
    for source in (b'',b'A',b'A'*128,b'A'*129,b'0',b'A0',b'_',b'_0',
        b'__hia_',b'__hia_x',b'__hiA_x',b'A__hia_',b'"A"',b'"0"',
        b'"__hia_x"',b'""',b'"A',b'\xff',b'A\xff',b'A B'):
        full('identifier_edges','f79',source,
            quoted=1 if source.startswith(b'"') else 0)
    for start,cursor,quoted,source in (
        (3,8,0,b'preAlpha-tail'),(3,10,1,b'pre"Alpha"tail'),
        (0,1,1,b'A'),(1,0,0,b'A'),(0,0,1,b''),
        ((1<<32)-1,(1<<32)-1,0,b'A'),
        ((1<<32)-2,(1<<32)-1,0,b'A'),
        (65535,65536,0,b'A'),(65536,65537,0,b'A')):
        full('identifier_offsets','f79',source,start=start,cursor=cursor,quoted=quoted)

    # The existing first error must not suppress the real invocation. Both
    # successful and failing spellings run with exactly the dirty first-error
    # field supplied by this fixture.
    for error in (1,67,MASK):
        for source in (b'1',b'A0',b'__hia_x',b''):
            full('preexisting_error','f79',source,error=error)
        for source in (b'?',b'"A',b'A\n'):
            full('preexisting_error','f16',source,error=error)

    for size in (0,1,2,3,4,8,15,16,23,24,27,31,32,39,40,47,48,
                 103,104,111,112,119,120,121,122,123,124):
        full('short_workspace','f16',b'A\n',size=size)
    identifier_sizes=sorted({0,1,3,4,23,24,27,28,31,32,33,
        39,40,41,42,43,44,45,46,47,48,
        103,104,105,106,107,108,109,110,111,112,
        455,456,457,458,459,460,463,464,465,466,471,472,473,474,475,476})
    for size in identifier_sizes:
        full('short_workspace','f79',b'Alpha',size=size)
        if size<113:full('short_workspace_error','f79',b'1',size=size)
    for size in (0,1,2,5):
        for claimed in (size+1,6,128):
            full('short_source','f79',b'A'*size,cursor=claimed)
    for source_view,workspace_view in (
        ('readonly','readonly'),('readonly','expired_view'),
        ('readonly','expired_owner'),('expired_view','mutable'),
        ('expired_owner','mutable')):
        for function,source in (('f16',b'A\n'),('f79',b'Alpha'),('f79',b'1')):
            full('borrow_state',function,source,
                 source_view=source_view,workspace_view=workspace_view)

    # Explicit shared-owner fixtures preserve both logical observations of the
    # same real bytearray. No non-aliasing premise is added by the predicate.
    for function,start,cursor,spelling in (
        ('f16',0,0,b''),('f79',128,133,b'Alpha'),('f79',456,461,b'Alpha')):
        raw=bytearray(workspace(cursor,start))
        raw[start:start+len(spelling)]=spelling
        full('same_owner','f79' if function=='f79' else 'f16',bytes(raw),
             start=start,cursor=cursor,alias=True)
        rows[-1]['workspace_hex']=bytes(raw).hex()
    assert len({row['id'] for row in rows})==len(rows)
    assert all(0<=row['character']<=MASK and 0<=row['index']<=MASK
        for row in rows if row['kind']=='scalar')
    assert all(len(bytes.fromhex(row['workspace_hex']))<=512
        and len(bytes.fromhex(row['source_hex']))<=512
        for row in rows if row['kind']=='function')
    return rows

def scalar_oracle(case):
    c=case['character']
    if case['predicate']=='delimiter':return c in DELIMITERS
    assert case['predicate']=='identifier_invalid'
    return not (65<=c<=90 or 97<=c<=122 or c==95
        or case['index']!=0 and 48<=c<=57)
