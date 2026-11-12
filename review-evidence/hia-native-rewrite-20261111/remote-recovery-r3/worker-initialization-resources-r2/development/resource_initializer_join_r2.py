"""Mechanical P12 integration into the complete original initializer oracle.

Only actual HIA commands/results are forwarded. The complete old constructor
and old Store methods independently produce expected values before each case.
The other eleven initializer peer IDs and namespace effects remain foreign.
"""
BODY=r'''
RESOURCE_ROOT=Path(os.environ['HIA_RESOURCE_ROOT']).resolve()
RESOURCE_POOL=None
RESOURCE_CAPTURES=[]
RESOURCE_CAPTURE=False
RESOURCE_RESULTS=[]
resource_previous_peer=peer

def load_resource_components():
    global RESOURCE_POOL
    bundle=json.loads(read(RESOURCE_ROOT/'development/compile-r2/bundle.json'))
    assert bundle['status']=='PASS' and bundle['compiler_sha256']==COMPILER_SHA
    assert set(bundle['components'])=={'resources','metadata'}
    for role,row in bundle['components'].items():
        source=read(row['source_path']);image=read(row['image_path'])
        receipt=json.loads(read(row['receipt_path']))
        assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert receipt['image_sha256']==COMPILER_SHA
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image)
        DH.frozen(Path(row['source_path']),row['source_sha256'])
        DH.frozen(Path(row['image_path']),row['image_sha256'])
        DH.frozen(Path(row['receipt_path']))
        DH.images[role]=NativeHiaJsonImage(image,digest(image))
    RESOURCE_POOL=read(RESOURCE_ROOT/'development/resources-pool-r2.bin')
    spec=json.loads(read(RESOURCE_ROOT/'development/resources-source-r2.json'))
    assert len(RESOURCE_POOL)==spec['pool_bytes'] and digest(RESOURCE_POOL)==spec['pool_sha256']
    assert spec['constants']['RS_META_REQUIRED']==129420
    for path,row in spec['source_dependencies'].items():
        raw=read(path)
        assert (len(raw),digest(raw),Path(path).stat().st_mode&4095)==(row['bytes'],row['sha256'],row['mode'])
    save(OUT/'source-before.json',rows())
    DH.OUT.joinpath('source-before.json').write_text(json.dumps(DH.pins,sort_keys=True,indent=2)+'\n')

def resource_call(c,route,command,label):
    source=DH.Buffer(c['g'].n,c['g'].raw())
    second=DH.Buffer(len(command),command)
    before=route['w'].raw()
    result=DH.invoke('resources',source,second,route['w'],label)
    f=struct.unpack_from('<32Q',route['w'].raw(),2560)
    assert result==2816,(label,result,f)
    assert f[:5]==(M(b'HIAWRE01'),f[1],37,83,route['lease'])
    assert f[5]==route['seq']+1 and f[7]==0 and f[8]==route['pending']
    assert f[9]==route['operation'] and f[10]==53 and f[11]==4300
    assert f[28:]==(0,0,0,0)
    route['seq']=f[5];route['f']=f
    if RESOURCE_CAPTURE:
        RESOURCE_CAPTURES.append(dict(label=label,mode=struct.unpack_from('<Q',command,8)[0],
            source=source.raw(),command=command,workspace=before,result=result,
            after=route['w'].raw(),event=f,operation=route['operation']))
    return f

def resource_reply_command(c,route,mode,payload,result,role,extent):
    raw=c['g'].raw()
    return pack(M(b'HIAWRC01'),mode,37,83,route['lease'],route['seq'],
        struct.unpack_from('<Q',raw,8)[0],len(raw),len(payload),result,role,extent,0,0,0,0)+payload

def resource_import(c,wire,packet,label):
    fields=list(struct.unpack('<16Q',wire))
    assert fields[1]==3 and fields[4]==c['active'] and fields[5]==c['bseq']
    assert fields[8]==fields[13]==len(packet)
    expected,payload=registry_command(c,3,packet,foreign_bytes=len(packet))
    assert pack(*expected)==wire and payload==packet
    c['foreign_raw']=packet;c['foreign_bytes']=len(packet)
    reserved=c['pw'].raw()[512:768]
    f,r=prepare_import(c,packet,label)
    while True:
        merge_actual(c,f,r,label)
        f,r=merge_submit(c,label)
        if f[1]==4:continue
        assert f[1]==6
        handle=adopt_import(c,f,r)
        c['imports'].append(dict(ordinal=len(c['imports'])+1,label=label,
            initializer_pending=c['f'][7],foreign_graph=cas(packet),
            imported_graph=cas(c['g'].raw()),handle=handle,graph_root=f[20],
            source_lease=struct.unpack_from('<Q',reserved,72)[0],
            output_lease=struct.unpack_from('<Q',reserved,80)[0],
            foreign_issuer=False,actual_P12_static_resource=True))
        c['reg'].kinds[handle]='value'
        return handle,c['pw'].raw()[512:768]

def native_resources_peer(c):
    f=c['f'];assert f[1]==2 and f[5]==41 and f[6]==12 and 1<=f[13]<=6
    initial=c['w'].raw()
    before=dict(DH.counts);outer_before=dict(entries)
    route=dict(w=DH.Buffer(8192),seq=0,lease=990000+f[7],
        pending=f[7],operation=f[13],meta=None,own_grows=0,meta_grows=0)
    source=c['g'].raw();registry_event=c['pw'].raw()[512:768]
    payload=initial+registry_event+RESOURCE_POOL
    begin=pack(M(b'HIAWRC01'),1,37,83,route['lease'],0,
        struct.unpack_from('<Q',source,8)[0],len(source),len(payload),2304,len(initial),
        768,256,len(RESOURCE_POOL),0,0)+payload
    event=resource_call(c,route,begin,'resource-begin-'+str(f[13]))
    with ExitStack() as stack:
        stack.enter_context(patch('hepta.hia_schema.schema_registry',new=disabled))
        stack.enter_context(patch.object(service,'proof_contract_description',new=disabled))
        while True:
            action=event[1]
            if action==1:
                assert event[6]==1 and event[12]>route['w'].n
                need=event[12]
                if c['growth']=='staged' and route['own_grows']==0:
                    assert need-1>route['w'].n;need-=1
                route['w']=route['w'].grow(need);route['own_grows']+=1
                event=resource_call(c,route,begin,'resource-own-grow-'+str(f[13]))
                continue
            if action==2:
                assert event[13]==1 and event[15]==128
                wire=route['w'].raw()[event[14]:event[14]+event[15]]
                words=list(struct.unpack('<16Q',wire));assert words[1]==2
                assert words[4]==c['blast']+1 and words[5]==c['bseq']
                c['active']=words[4]
                rf,rr=registry_entry(c,words,b'','resource-actual-reserve')
                assert rr.raw()==wire and rf[1]==2
                actual=c['pw'].raw()[512:768]
                command=resource_reply_command(c,route,2,actual,768,1,len(actual))
                event=resource_call(c,route,command,'resource-reserve-response')
                continue
            if action==3:
                assert event[13]==2 and event[15]==96 and event[16]>=3072
                wire=route['w'].raw()[event[14]:event[14]+event[15]]
                if route['meta'] is None:
                    assert event[17]==1;route['meta']=DH.Buffer(event[16])
                else:
                    assert event[17]==0 and event[16]>route['meta'].n
                    route['meta']=route['meta'].grow(event[16]);route['meta_grows']+=1
                empty=DH.Buffer(0);request=DH.Buffer(96,wire)
                result=DH.invoke('metadata',empty,request,route['meta'],'resource-actual-schema-registry')
                actual=route['meta'].raw()
                command=resource_reply_command(c,route,3,actual,result,2,len(actual))
                event=resource_call(c,route,command,'resource-metadata-response')
                continue
            if action==4:
                assert event[13]==1 and event[15]==128 and event[19]>0
                wire=route['w'].raw()[event[14]:event[14]+event[15]]
                packet=route['w'].raw()[event[18]:event[18]+event[19]]
                handle,actual=resource_import(c,wire,packet,'actual-native-resource-'+str(f[13]))
                route['handle']=handle
                command=resource_reply_command(c,route,4,actual,768,1,len(actual))
                event=resource_call(c,route,command,'resource-import-response')
                continue
            assert action==0 and event[6]==90 and event[26]==256
            reply=route['w'].raw()[event[25]:event[25]+event[26]]
            q=struct.unpack('<32Q',reply)
            assert q[:9]==(M(b'HIAWIR01'),37,83,f[7],12,0,2,0,route['handle'])
            assert q[9:15]==(0,0,0,0,0,0) and q[15]==256 and q[16:]==(0,)*16
            assert event[27]==route['handle']
            break
    assert c['w'].raw()==initial and entries['sequence']==outer_before['sequence']
    actual=c['reg'].get(route['handle'])
    assert actual==c['baseline']['jsons'][f[13]-1],('resource-value',f[13])
    c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    row=dict(operation=f[13],pending=f[7],reply=cas(reply),expected=cas(encoded(c['baseline']['jsons'][f[13]-1])),
        actual=cas(encoded(actual)),handle=route['handle'],own_grows=route['own_grows'],
        metadata_grows=route['meta_grows'],metadata_actual=f[13]==1,
        additional_actual_entries={k:v-before.get(k,0) for k,v in DH.counts.items()},
        unchanged_initializer_workspace=True,sequence_not_reentered=True)
    RESOURCE_RESULTS.append(row)
    c.setdefault('resource_results',[]).append(row)

def peer(c,fail_at,false_dirs,mismatch):
    if c['f'][6]==12:native_resources_peer(c)
    else:resource_previous_peer(c,fail_at,false_dirs,mismatch)

def resource_semantic_cases():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    planned=2
    for label,paths in (('resources-empty',()),('resources-unicode-roots',('/e\u0301','/\u4e2d','/emoji-\U0001f642'))):
        c=check(label,paths)
        assert len(c['resource_results'])==6
        assert [r['operation'] for r in c['resource_results']]==list(range(1,7))
    save(OUT/'resource-results.json',RESOURCE_RESULTS)

def resource_capacity_cases():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    planned=1
    c=check('resources-each-workspace-short-once',growth='staged')
    assert len(c['resource_results'])==6
    assert all(r['own_grows']==2 for r in c['resource_results'])
    assert c['resource_results'][0]['metadata_grows']==1
    save(OUT/'resource-results.json',RESOURCE_RESULTS)

def resource_fault(label,snapshot,mutator,poison=True,advertised=None):
    before=dict(entries);before_native=dict(DH.counts)
    source=bytearray(snapshot['source']);command=bytearray(snapshot['command'])
    workspace=bytearray(snapshot['workspace'])
    mutator(source,command,workspace)
    s=DH.Buffer(len(source),bytes(source));r=DH.Buffer(len(command),bytes(command))
    w=DH.Buffer(len(workspace),bytes(workspace))
    if advertised is None:
        result=DH.invoke('resources',s,r,w,label)
    else:
        assert 0<=advertised<w.n
        old_s=s.raw();old_r=r.raw()
        result=int(DH.images['resources']._entry(s.memory,s.n,r.memory,r.n,w.memory,advertised))
        s.check();r.check();w.check();assert s.raw()==old_s and r.raw()==old_r
        DH.counts['resources']=DH.counts.get('resources',0)+1
        DH.log.write(json.dumps(dict(label=label,role='resources',entry=DH.counts['resources'],
            advertised_work=advertised,s=DH.save(old_s),r=DH.save(old_r),
            w=DH.save(bytes(workspace)),result=result,after_w=DH.save(w.raw()),
            same_inputs=True),sort_keys=True)+'\n');DH.log.flush()
    assert result==BAD,(label,result)
    after=w.raw()
    if poison:
        valid_s=DH.Buffer(len(snapshot['source']),snapshot['source'])
        valid_r=DH.Buffer(len(snapshot['command']),snapshot['command'])
        assert DH.invoke('resources',valid_s,valid_r,w,label+'-persistent')==BAD
        assert w.raw()==after
    record(label,before,dict(private_actual_frame_mutation=True,foreign_authority_not_claimed=True,
        full_input=cas(bytes(command)),full_source=cas(bytes(source)),full_before=cas(bytes(workspace)),
        full_after=cas(after),permanent_refusal=poison,short_workspace_caller_must_retire=not poison,
        additional_actual_entries={k:v-before_native.get(k,0) for k,v in DH.counts.items()}))

def resource_protocol_cases():
    global planned,CATALOG,RESOURCE_CAPTURE
    CATALOG=SMALL_CATALOG
    RESOURCE_CAPTURE=True
    c=check('resource-actual-frame-fixture')
    RESOURCE_CAPTURE=False
    begin=next(row for row in RESOURCE_CAPTURES if row['mode']==1 and len(row['workspace'])==8192)
    resumed=next(row for row in RESOURCE_CAPTURES if row['mode']==1 and row['event'][1]==2)
    reserve=next(row for row in RESOURCE_CAPTURES if row['mode']==2)
    meta_grow=next(row for row in RESOURCE_CAPTURES if row['mode']==3 and row['event'][1]==3)
    meta_done=next(row for row in RESOURCE_CAPTURES if row['mode']==3 and row['event'][1]==4)
    bound=next(row for row in RESOURCE_CAPTURES if row['mode']==4)
    faults=[]
    def word(label,snapshot,at,value):
        faults.append((label,snapshot,lambda s,r,w,at=at,value=value:struct.pack_into('<Q',r,at,value),True,None))
    for label,at,value in (('magic',0,0),('invocation',16,0),('call',24,0),('lease',32,0),
        ('first-sequence',40,1),('source-extent',56,len(begin['source'])+1),
        ('payload-extent',64,len(begin['command'])-127),('reserved',112,1),
        ('initializer-return',72,0),('initializer-extent',80,1),
        ('registry-return',88,0),('registry-extent',96,255),('pool-extent',104,len(RESOURCE_POOL)-1)):
        word('resource-begin-'+label,begin,at,value)
    for label,at,value in (('state-phase',128+SC['I_PHASE'],40),
        ('state-peer',128+SC['I_PEER'],13),('state-operation',128+SC['I_OP'],7),
        ('state-argument',128+SC['I_ARG0'],1),('event-phase',128+2048+40,40),
        ('event-operation',128+2048+104,7)):
        word('resource-initializer-'+label,begin,at,value)
    reg_at=128+struct.unpack_from('<Q',begin['command'],80)[0]
    for label,at,value in (('sequence',reg_at+32,0),('command',reg_at+40,0),
        ('error',reg_at+216,1),('phase',reg_at+240,10)):
        word('resource-old-registry-'+label,begin,at,value)
    faults.append(('resource-pool-checksum',resumed,lambda s,r,w:r.__setitem__(-1,r[-1]^1),True,None))
    for label,at,value in (('return',72,0),('foreign',128+72,0),
        ('output',128+80,0),('sequence',128+32,0),('state',128+240,0)):
        word('resource-reserve-'+label,reserve,at,value)
    for label,snapshot,at,value in (
        ('grow-required',meta_grow,128+2304+56,129419),
        ('grow-return',meta_grow,72,128),
        ('grow-state',meta_grow,128+2056,2),
        ('done-return',meta_done,72,0xfffffffe),
        ('done-lease',meta_done,128+2064,0),
        ('done-request',meta_done,128+2072,0),
        ('done-op',meta_done,128+2080,2),
        ('saved-command',meta_done,128+2560,0),
        ('done-output',meta_done,128+2304+40,0),
        ('done-reserved',meta_done,128+2304+64,1)):
        word('resource-metadata-'+label,snapshot,at,value)
    meta_at=128+struct.unpack_from('<Q',meta_done['command'],128+2304+40)[0]
    faults.append(('resource-metadata-full-value',meta_done,
        lambda s,r,w:r.__setitem__(meta_at,r[meta_at]^1),True,None))
    for label,at,value in (('return',72,0),('action',128+8,5),('sequence',128+32,0),
        ('command',128+40,0),('lease',128+48,0),('size',128+56,0),
        ('handle',128+168,0),('issued',128+192,0),('reserved',128+224,1)):
        word('resource-import-'+label,bound,at,value)
    faults.append(('resource-import-complete-scalar',bound,
        lambda s,r,w:s.__setitem__(-1,s[-1]^1),True,None))
    faults.append(('resource-short-workspace',begin,lambda s,r,w:None,False,8191))
    planned=1+len(faults)
    for args in faults:resource_fault(*args)
    save(OUT/'resource-results.json',RESOURCE_RESULTS)
'''
