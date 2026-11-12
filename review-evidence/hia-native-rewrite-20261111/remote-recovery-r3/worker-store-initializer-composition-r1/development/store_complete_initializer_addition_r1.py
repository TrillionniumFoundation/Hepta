
# NEW composition: complete original Store methods are now the oracle, while
# only the actual namespace put/SQL effect results remain foreign fixtures.
# All plans and Graph packets are frozen before the actual native interval.
LegacyNamespace=Namespace
legacy_initializer_oracle=oracle
legacy_configure=configure
legacy_initializer_drive=drive
ORACLE_STORE_RECORDS=[]
ORACLE_NAMESPACE_FAILURE=None
ORACLE_CORRUPTED_REFERENCE=None
ACTIVE_STORE_CASE=None

class StoreFixtureDB:
    def __init__(self,namespace):self.namespace=namespace
    def execute(self,sql,binds):
        ns=self.namespace;row=ns.active_store_record
        assert row is not None and row['peer']==11
        label=row['label']+':sql'
        operation=dict(operation=2,sql=sql,binds=tuple(binds),label=label)
        if ORACLE_NAMESPACE_FAILURE==label:
            operation['error']=label;row['operations'].append(operation)
            raise PeerFailure(label)
        operation['error']=None;row['operations'].append(operation)
        return None

class Namespace(LegacyNamespace):
    def __init__(self,root,observer,reference):
        super().__init__(root,observer,reference)
        self.db=StoreFixtureDB(self);self.active_store_record=None
    def start_store_record(self,peer,kind,number,args):
        assert self.active_store_record is None
        cells={} if self.observer is None else dict(zip(
            self.observer.__code__.co_freevars,
            [cell.cell_contents for cell in self.observer.__closure__ or ()]))
        row=dict(peer=peer,kind=kind,number=number,label='store-'+kind+':'+str(number),
            args=normalized(copy.deepcopy(args)),operations=[],result=None,error=None,
            state=snapshot(cells['owner']) if 'owner' in cells else None)
        ORACLE_STORE_RECORDS.append(row);self.active_store_record=row
        return row
    def profile(self,name,body):
        row=self.start_store_record(11,'profile',self.profile_count,(name,body))
        try:
            result=store.AgentStore.profile(self,name,body)
            row['result']=normalized(result)
        except BaseException as exc:
            row['error']=observed_exception(exc);raise
        finally:self.active_store_record=None
        self.observer('profile',(name,body),result)
        self.profile_count+=1
        return result
    def json(self,value,kind,metadata=None):
        if self.active_store_record is not None:
            # Original profile invokes original json, with no invented extra
            # initializer-level call or independent transaction.
            assert self.active_store_record['peer']==11 and kind=='profile'
            return store.AgentStore.json(self,value,kind,metadata)
        row=self.start_store_record(15,'json',self.json_count,(value,kind))
        try:
            result=store.AgentStore.json(self,value,kind,metadata)
            row['result']=normalized(result)
        except BaseException as exc:
            row['error']=observed_exception(exc);raise
        finally:self.active_store_record=None
        self.observer('json',(value,kind),result)
        self.json_count+=1
        return result
    def put(self,value,kind,metadata=None):
        row=self.active_store_record
        if row is None:
            assert metadata is None
            return super().put(value,kind)
        assert metadata is None
        label=row['label']+':put'
        operation=dict(operation=1,wire=bytes(value),kind=kind,metadata=metadata,label=label)
        if ORACLE_NAMESPACE_FAILURE==label:
            operation['error']=label;row['operations'].append(operation)
            raise PeerFailure(label)
        key=('profile-'+row['args'][0]) if row['peer']==11 else 'json-'+str(self.json_count)
        ref=self.reference(key)
        if ORACLE_CORRUPTED_REFERENCE is not None and ORACLE_CORRUPTED_REFERENCE[0]==row['label']:
            ref=copy.deepcopy(ref);ref['sha256']=ORACLE_CORRUPTED_REFERENCE[1]
        operation['error']=None;operation['result']=ref;row['operations'].append(operation)
        return ref

def oracle(paths,fail_at=None,false_dirs=(),mismatch=False,namespace_failure=None,corrupted_ref=None):
    global ORACLE_STORE_RECORDS,ORACLE_NAMESPACE_FAILURE,ORACLE_CORRUPTED_REFERENCE
    ORACLE_STORE_RECORDS=[];ORACLE_NAMESPACE_FAILURE=namespace_failure
    ORACLE_CORRUPTED_REFERENCE=corrupted_ref
    try:
        result=legacy_initializer_oracle(paths,fail_at,false_dirs,mismatch)
        result['store_records']=ORACLE_STORE_RECORDS
        # Capture immutable foreign result packets only after the complete
        # original constructor/methods have independently produced this trace.
        for row in result['store_records']:
            row['plan']=[]
            for operation in row['operations']:
                error=operation['error']
                row['plan'].append(dict(operation=operation['operation'],
                    error=None if error is None else ('fixture-issued-peer-exception:'+error).encode(),
                    result_packet=capture(operation['result'],lease=1)
                        if operation['operation']==1 and error is None else None))
        return result
    finally:
        ORACLE_NAMESPACE_FAILURE=None;ORACLE_CORRUPTED_REFERENCE=None

class StoreRegistryAdapter(DigestRegistryAdapter):
    def reserved_request(self):return self.c['rr'].raw()
    def packet(self,foreign):
        return self.import_packet(foreign,False,None)
    def packet_checked(self,foreign,expected):
        return self.import_packet(foreign,True,expected)
    def import_packet(self,foreign,native_profile,expected):
        c=self.c;c['foreign_raw']=foreign;c['foreign_bytes']=len(foreign)
        reserved=struct.unpack_from('<32Q',c['pw'].raw(),512)
        assert reserved[1]==2
        fields,payload=registry_command(c,3,foreign,foreign_bytes=len(foreign))
        if expected is not None:
            assert pack(*fields)==expected and payload==foreign
        label='actual-native-store-profile' if native_profile else 'foreign-issued-namespace-put'
        f,r=prepare_import(c,foreign,label)
        while True:
            merge_actual(c,f,r,label)
            f,r=merge_submit(c,label)
            if f[1]==4:continue
            handle=adopt_import(c,f,r)
            c['imports'].append(dict(ordinal=len(c['imports'])+1,label=label,
                initializer_pending=c['f'][7],foreign_graph=cas(foreign),
                imported_graph=cas(c['g'].raw()),handle=handle,graph_root=f[20],
                source_lease=reserved[9],output_lease=reserved[10],
                foreign_issuer=not native_profile))
            c['reg'].kinds[handle]='value'
            return handle,c['pw'].raw()[512:768]

def configure(paths,baseline=None,growth='exact',extra=(),mini=False):
    c=legacy_configure(paths,baseline,growth,extra,mini)
    assert ACTIVE_STORE_CASE is not None
    c['store_expectations']=ACTIVE_STORE_CASE['store_records']
    c['store_index']=0;c['store_results']=[]
    return c

def native_store_peer(c,fail_at):
    f=c['f'];peerid=f[6];assert f[1]==2 and peerid in (11,15)
    index=c['store_index'];assert index<len(c['store_expectations'])
    expected=c['store_expectations'][index];c['store_index']+=1
    assert expected['peer']==peerid
    # Snapshot/argument reads happen before the Store component's initial
    # native BORROW. No observer may advance its pending registry sequence.
    prior=native_state(c)
    value=c['reg'].get(f[14])
    literal=c['w'].raw()[f[23]:f[23]+f[24]].decode()
    args=(literal,value) if peerid==11 else (value,literal)
    assert normalized(args)==expected['args']
    assert prior==expected['state'],(expected['label'],'method-entry partial state')
    initial_workspace=c['w'].raw();before=dict(DH.counts);before_entries=dict(entries)
    adapter=StoreRegistryAdapter(c)
    route=SV.Route(adapter,initial_workspace,expected['plan'],
        label='full-initializer-'+expected['label'],
        own_short_once=(c['growth']=='staged'))
    reply=route.finish()
    assert c['w'].raw()==initial_workspace
    assert entries['sequence']==before_entries['sequence']
    calls=[]
    for operation in expected['operations']:
        if operation['operation']==1:
            calls.append({key:operation[key] for key in ('operation','wire','kind','metadata')})
        else:
            calls.append({key:operation[key] for key in ('operation','sql','binds')})
    verification=dict(result=expected['result'],calls=calls,error=None)
    if expected['error'] is not None:
        verification['error']=dict(error_class=expected['error']['error_class'],
            text=expected['error']['error'])
    route.validate(verification,peerid)
    q=struct.unpack_from('<32Q',reply)
    assert q[:5]==(M(b'HIAWIR01'),37,83,f[7],peerid)
    if q[5]==0:
        result=(c['reg'].get(q[8]),c['reg'].get(q[9])) if peerid==11 else c['reg'].get(q[8])
        kind='profile' if peerid==11 else 'json'
        namespace=c['reg'].get(f[15],'namespace')
        if observe(c,kind,args,result,fail_at):
            if peerid==11:namespace.profile_count+=1
            else:namespace.json_count+=1
            c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    else:
        assert q[5]==1 and q[6]==0
        c['r']=Buffer(len(reply),reply);c['reply_count']+=1
    c['store_results'].append(dict(
        label=expected['label'],peer=peerid,pending=f[7],
        expected_method=cas(encoded({k:v for k,v in expected.items() if k!='plan'})),
        actual_reply=cas(reply),owner_state_before=cas(encoded(prior)),
        owner_workspace_unchanged_during_store=True,sequence_not_reentered=True,
        native_store_entries={k:v-before.get(k,0) for k,v in DH.counts.items()},
        outer_entries={k:entries[k]-before_entries[k] for k in entries},
        namespace_calls=route.namespace_calls,namespace_results_are_foreign=True,
        actual_physical_namespace_entries=0,wire_sessions=route.wire_starts,
        own_grows=route.own_grows,wire_grows=route.producer_grows,
        profile_handle=route.handle,original_reference_handle=route.ref_handle,
        full_method_error_and_order_equal=True))

def peer(c,fail_at,false_dirs,mismatch):
    if c['f'][6]==8:native_digest_peer(c,fail_at)
    elif c['f'][6] in (11,15):native_store_peer(c,fail_at)
    elif c['f'][6] in (2,9,10,19):pure_peer(c,'pending-'+str(c['f'][7]))
    else:foreign_peer(c,fail_at,false_dirs,mismatch)

def drive(paths,label,fail_at=None,false_dirs=(),mismatch=False,baseline=None,growth='exact'):
    c=configure(paths,baseline,growth)
    while True:
        ret=invoke('sequence',c['s'],c['r'],c['w'],label)
        if ret==BAD:return dict(private_bad=True),c
        f=frame(c,ret)
        if f[1]==1:
            c['w']=resize(c,c['w'],f[8],'sequence');c['grows']+=1;continue
        if f[1]==2:
            peer(c,fail_at,false_dirs,mismatch);continue
        if f[1]==0:return dict(state=native_state(c),error=None),c
        assert f[1]==3
        if f[27]==0:
            assert f[28]==3
            payload=c['r'].raw()[f[30]:f[30]+f[31]]
            prefix=b'fixture-issued-peer-exception:'
            if f[29]==90001:
                assert payload.startswith(prefix)
                error=dict(error_class='PeerFailure',error=payload[len(prefix):].decode(),attributes={})
            else:
                # Comparison observer for the exact native exception capsule.
                # This is not a hosted production error-rendering fallback.
                assert f[29]==909 and len(payload)>=64
                ex=struct.unpack_from('<8Q',payload)
                assert ex[:3]==(M(b'HIAWSX01'),1,1) and 1<=ex[3]<=16
                assert ex[5]==len(payload)-64 and ex[6]==len(payload) and ex[7]==0
                error=dict(error_class='HIAEditRejected',error=payload[64:].decode(),attributes={})
        else:
            assert f[28]==2 and f[29]==37 and f[27] in (1,2)
            error=dict(error_class={1:'AgentRejected',2:'RuntimeError'}[f[27]],
                error=c['w'].raw()[f[30]:f[30]+f[31]].decode(),attributes=(dict(
                    code='E_HIA_PROFILE',phase='admission',retry_action='correct_input',
                    details_artifact=None) if f[27]==1 else {}))
        return dict(state=native_state(c),error=error),c

def check(label,paths=(),fail_at=None,false_dirs=(),mismatch=False,growth='exact',
          namespace_failure=None,corrupted_ref=None):
    global ACTIVE_STORE_CASE
    expected=oracle(paths,fail_at,false_dirs,mismatch,namespace_failure,corrupted_ref)
    baseline=oracle(paths)
    ACTIVE_STORE_CASE=expected
    before=dict(entries);before_native=dict(DH.counts)
    try:
        with forbidden_pure_owners(),SV.actual_only():
            actual,c=drive(paths,label,fail_at,false_dirs,mismatch,baseline,growth)
    finally:ACTIVE_STORE_CASE=None
    assert actual=={k:expected[k] for k in ('state','error')},(label,expected['error'],actual)
    assert c['trace']==expected['trace'],(label,'complete ordered calls/partial attributes',
        len(c['trace']),len(expected['trace']))
    assert c['store_index']==len(expected['store_records'])
    assert len(c['store_results'])==c['store_index']
    if expected['error'] is None:
        assert {r['peer'] for r in c['pure_results']}=={2,9,10,19}
        assert {r['mode'] for r in c['pure_results'] if r['peer']==9}==set(range(1,7))
        assert {r['mode'] for r in c['pure_results'] if r['peer']==10}=={1,2,3,4}
        assert {r['peer'] for r in c['store_results']}=={11,15}
        assert sum(r['peer']==11 for r in c['store_results'])==7
        assert c['store_results'][-1]['peer']==15
    aliases=initializer_aliases(c)
    assert all(a['ordinal']==i+1 for i,a in enumerate(c['imports']))
    assert entries['merge']-before['merge']>=2*len(c['imports'])
    record(label,before,dict(reference_trace=cas(encoded(expected['trace'])),
        actual_trace=cas(encoded(c['trace'])),expected_state=cas(encoded(expected['state'])),
        actual_state=cas(encoded(actual['state'])),error=actual['error'],
        reference_store_methods=cas(encoded([
            {k:v for k,v in r.items() if k!='plan'} for r in expected['store_records']])),
        store_results=c['store_results'],imports=c['imports'],actual_graph_alias_checks=aliases,
        pure_results=c['pure_results'],growth_events=c['growth_events'],
        actual_digest_results=c.get('digest_results',[]),
        actual_child_calls=c['child_calls'],actual_merge_calls=c['merge_calls'],
        actual_borrows=c['borrow_count'],
        additional_actual_entries={k:v-before_native.get(k,0) for k,v in DH.counts.items()},
        complete_original_store_methods_oracle=True,
        remaining_twelve_peer_ids_are_foreign=True,actual_namespace_entries=0,
        exact_complete_state_error_and_call_order=True,preloaded_future_values=False,
        ordinary_initialization_closed=False))
    c['observed_error']=actual['error'];return c

def store_semantics():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    cases=[
      ('empty',(),None,(),False),
      ('three-roots',('/one','/two','/three'),None,(),False),
      ('unicode-roots',('/e\u0301','/\u4e2d','/emoji-\U0001f642'),None,(),False),
      ('duplicate-roots',('/same','/same'),None,(),False),
      ('isdir-false',('/one','/two'),None,('/resolved/one',),False),
      ('example-assembly-mismatch',(),None,(),True),
      ('profile-observer-failure-after-native-sql',(),'profile:2',(),False),
      ('json-observer-failure-after-native-method',(),'json:6',(),False)]
    planned=len(cases)
    for args in cases:check(*args)

def store_effect_failures():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG
    complete_reference=oracle(())
    effects=[operation['label'] for row in complete_reference['store_records']
        for operation in row['operations']]
    assert len([s for s in effects if s.endswith(':sql')])==7
    chosen=['store-profile:0:put','store-profile:2:put','store-profile:6:put',
        'store-profile:0:sql','store-profile:3:sql','store-profile:6:sql',
        'store-json:0:put','store-json:6:put']
    final_json=[r for r in complete_reference['store_records'] if r['peer']==15][-1]['label']+':put'
    if final_json not in chosen:chosen.append(final_json)
    assert set(chosen)<=set(effects)
    planned=len(chosen)+3
    for point in chosen:
        c=check('effect-'+point,namespace_failure=point)
        assert c['observed_error']['error_class']=='PeerFailure'
    for name,value in (('bytes',b'not-json'),('surrogate','\ud800'),('nan',float('nan'))):
        c=check('reference-wire-'+name,corrupted_ref=('store-profile:2',value))
        assert c['observed_error']['error_class']=='HIAEditRejected'
        last=c['store_results'][-1]
        assert last['namespace_calls']==1 and last['profile_handle'] is None

def store_catalog():
    global planned,CATALOG
    CATALOG=json.loads(read(ROOT/'dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json'))
    assert len(CATALOG['tools'])==11
    planned=1;check('eleven-tools-complete-native-store-values',('/catalog-root',))
    CATALOG=SMALL_CATALOG

def store_growth():
    global planned,CATALOG
    CATALOG=SMALL_CATALOG;planned=3
    contexts=[check('whole-store-'+mode,('/a','/b'),growth=mode)
        for mode in ('exact','spare','staged')]
    assert contexts[0]['trace']==contexts[1]['trace']==contexts[2]['trace']
    assert all(c['store_results'] and c['digest_results'] for c in contexts)
    assert len(contexts[2]['growth_events'])>len(contexts[1]['growth_events'])
