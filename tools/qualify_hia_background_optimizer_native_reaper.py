"""Real installed BG autonomous-retirement qualification.

The observer never advances Value cleanup while native retirement is settling.
Both cases require actual kernel thread IDs, a separate owned reaper record,
actual second-RFQ completion, and complete cap/FD/global-loader retirement.
"""
import argparse

def qualify(args):
    from pathlib import Path
    import os,sys,ctypes as C,struct,json,hashlib,signal
    B=Path(__file__).resolve().parents[1];R=Path(args.reference_root)if args.reference_root else B;E=Path(args.evidence_root)
    D=Path(args.output);D.mkdir(exist_ok=False);signal.alarm(400)
    os.environ['Z3_LIBRARY_PATH']=str(E/'z3-qa-runtime')
    os.chdir(B);sys.path[:0]=[str(B),str(R),str(E/'z3-qa-runtime/python')]
    import tools;tools.__path__=[str(B/'tools'),str(R/'tools')]
    import importlib.abc,importlib.machinery
    class FrozenTools(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname.startswith('tools.'):
                return importlib.machinery.PathFinder.find_spec(fullname,[str(B/'tools'),str(R/'tools')])
    sys.meta_path.insert(0,FrozenTools())
    from tools import qualify_hia_generation_lease_owner as q
    from tools import qualify_hia_generation_runtime_global as globalqa
    from tools import qualify_hia_native_runtime_resources as resources
    tools.__path__=[str(B/'tools'),str(R/'tools')]
    path=Path(args.root)
    n=q.Owner(path);n.initialize();g=globalqa.Global(n)
    print('OWNER_INIT',{'state':q.get(n.context,80),'active':q.get(n.context,72)},flush=True)
    r=g.call(0);print('GLOBAL_INIT',r,flush=True);resources.ready(r)
    sc=globalqa.sidecar(n,0);print('SIDECAR_INIT',sc,flush=True);assert sc['status']==0 and sc['state']==2
    fn=n.lib.hia_generation_background_bind;fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
    rows=[]
    def call(op):
     raw=struct.pack('<16Q',int.from_bytes(b'HIAGBNQ1','little'),op,*([0]*14))
     s=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*(3<<20),3<<20)
     rc=int(fn(s,len(raw),out,len(out),n.context,2048))
     head=[q.get(out,off)for off in range(0,128,8)]
     r=dict(op=op,rc=rc,magic=out.raw[:8].decode('ascii','replace'),head=head,root_active=q.get(n.context,72),sidecar_active=q.get(n.context,1208),mask=q.get(n.context,680),
     metadata=[q.get(out,off)for off in range(2097152,2097720,8)])
     gp=q.get(n.context,1088)
     if gp:
      ar=C.string_at(gp+7340544,512);r['anchor']=[q.get(ar,off)for off in range(0,512,8)]
      if q.get(ar,32):r['loader_prefix']=[q.get(C.string_at(q.get(ar,32)+4096,512),off)for off in range(0,512,8)]
     r['child_head']=[q.get(out,off)for off in range(2113536,2113792,8)]
     r['wire_head']=[q.get(out,off)for off in range(2101248,2101504,8)]
     rows.append(r);(D/'calls.json').write_text(json.dumps(rows,indent=2)+'\n');print('BG_BINDER_CALL',json.dumps(r),flush=True)
     assert s.raw==raw+b'\0'and rc==0 and out.raw[:8]==b'HIAGBNR1',(rc,out.raw[:128].hex())
     return out.raw

    a=call(0);assert q.get(a,8)==0 and q.get(a,16)==2 and q.get(a,80)==254
    from types import SimpleNamespace
    from tools import qualify_hia_result_value_invocations as inv
    from tools import qualify_hia_generation_future_managed_binding as binding
    from tools.qualify_hia_background_public_constructor import make
    from hepta.hia_program import verify_program
    from hepta.hia_background_optimizer import BackgroundOptimizer
    from hepta.hia_multiversion import ScalarMultiversionRuntime
    bound=SimpleNamespace(owner=n,value=q.get(n.context,40))
    engine=inv.Engine(bound);v=inv.Values(engine)
    assert C.addressof(engine.context)==C.addressof(n.context)+512
    gp=q.get(n.context,1088);anchor=(C.c_char*512).from_address(gp+7340544)
    bgctx=(C.c_char*512).from_address(q.get(anchor,32))
    assert q.get(bgctx,32)==q.get(n.context,40)and q.get(bgctx,40)==C.addressof(engine.context)
    public_rows=[]
    def public(op,caps=(),want=0):
     raw=bytearray(192);raw[:8]=b'HIABGPQ1';struct.pack_into('<Q',raw,8,op)
     for i,cap_ in enumerate(caps):struct.pack_into('<3Q',raw,24+24*i,*cap_)
     s=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(b'\xa5'*((3<<20)+32),(3<<20)+32)
     rc=int(fn(s,192,out,3<<20,n.context,2048));r=out.raw[:2<<20]
     row=dict(op=op,rc=rc,status=q.get(r,8),kind=q.get(r,16),cap=struct.unpack_from('<3Q',r,24),
      delivered=q.get(r,48),known=q.get(r,56),map=q.get(r,64),queue=q.get(r,72),unknown=q.get(r,80),
      cleanup=q.get(r,88),detail=q.get(r,96),raw_owned=q.get(r,104),error_format=q.get(r,112),error_n=q.get(r,120))
     public_rows.append(row);(D/'public-calls.json').write_text(json.dumps(public_rows,indent=2)+'\n')
     print('ACTUAL_CANONICAL_BG_CALL',row,flush=True)
     if rc!=0 or q.get(r,8)!=want or q.get(r,80)!=0:
      (D/('failure-op'+str(op)+'.json')).write_text(json.dumps(dict(row=row,
        outer=[q.get(r,i)for i in range(0,640,8)],raw=[q.get(r,65536+i)for i in range(0,256,8)],
        method=[q.get(r,98304+i)for i in range(0,256,8)],
        child=[q.get(r,163840+i)for i in range(0,512,8)],
        owner=[q.get(n.context,i)for i in range(512,768,8)],
        global_=[q.get(bgctx,i)for i in range(0,512,8)]),indent=2)+'\n')
     assert rc==0 and r[:8]==b'HIABGPR1'and s.raw==bytes(raw)and out.raw[3<<20:]==b'\xa5'*32
     assert q.get(r,8)==want and q.get(r,56)==1 and q.get(r,80)==0,row
     return r
    def snapshot(bg):
     r=public(1,[bg]);assert q.get(r,48)==1 and q.get(r,16)==1
     c=v.keep(r);out=v.python_value(c);v.drop(c);return out
    borrow=g.call(2);resources.ready(borrow);assert borrow['consumed']==1
    files=[(q.get(n.context,88+8*i),(E/'shared-custody'/name).read_bytes())for i,name in enumerate(('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'))]
    carrier=q.Carrier(n);parent=D/'native-runtime';parent.mkdir()
    raw_runtime=q.old.create(carrier,files,parent)
    cloned=carrier.q(2,raw_runtime);assert cloned['row']['kind']==1
    captured=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']))
    assert (q.get(captured,80),q.get(captured,88),q.get(captured,96))==(0,1,1)
    runtime=v.keep(captured);baseline=q.old.scalar_program(None)
    bridge={'binary':str(E/'shared-custody/builder-539ce9.bin'),'build_receipt':str(B/'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs=[runtime,make(v,baseline),make(v,'calculate'),make(v,bridge),(0,0,0),(0,0,0),(0,0,0)]
    oracle_parent=D/'original-runtime';oracle_parent.mkdir()
    oldruntime=ScalarMultiversionRuntime(baseline,oracle_parent)
    original=BackgroundOptimizer(oldruntime,baseline,function='calculate',bridge=bridge)
    before=q.get(v.raw(47),48);fd_before=set(os.listdir('/proc/self/fd'))
    def fdrows():
     out={}
     for p in Path('/proc/self/fd').iterdir():
      try:out[p.name]=os.readlink(p)
      except FileNotFoundError:pass
     return out
    fd_before_rows=fdrows()
    (D/'fd-before.json').write_text(json.dumps(fd_before_rows,indent=2)+'\n')

    r=public(0,inputs);assert q.get(r,48)==1 and q.get(r,16)==1 and q.get(r,104)==0
    bg=v.keep(r);weak=struct.unpack_from('<3Q',v.raw(80,a=bg),24)
    actual_class=v.keep(v.raw(36,a=bg));expected_class=v.keep(v.raw(57,arg0=35))
    assert v.same(actual_class,expected_class)
    v.drop(actual_class);v.drop(expected_class)
    assert q.get(bgctx,192)==1 and q.get(bgctx,184)==0
    print('ACTUAL_CANONICAL_BG_KIND6_AND_WORKER_READY',flush=True)
    observed=snapshot(bg);expected=original.snapshot()
    assert observed==expected,(observed,expected)
    assert observed['worker_alive']is True and observed['closed']is False
    cases=[dict(case='native-global-loader-NI2-kind6-actual-pthread-and-original-snapshot',passed=True,snapshot=observed)]


    if args.mode=='idle':
        # Drop the only caller BG capability without explicit public shutdown.
        # No Value entry is called by the observer until the native reaper has settled.
        import time
        rawbg=struct.unpack_from('<3Q',v.raw(49,a=bg),24)
        def registry_borrow(cap):
         regq=bytearray(128);regq[:8]=b'HIABGRG1';struct.pack_into('<Q',regq,8,6);struct.pack_into('<3Q',regq,24,*cap)
         s=C.create_string_buffer(bytes(regq),128);out=C.create_string_buffer(8192)
         f=inv.ENTRY(q.get(bgctx,144));rc=f(s,128,out,8192,q.get(bgctx,152),256)
         assert rc==0 and out.raw[:8]==b'HIABGRR1'and q.get(out,8)==0 and q.get(out,40)==32 and q.get(out,80)==1
         return C.string_at(q.get(out,64),32)
        row=registry_borrow(rawbg)
        worker_before=C.string_at(q.get(row,0)+8704,512)
        worker_tid=q.get(worker_before,32);assert worker_tid and worker_tid!=os.getpid()
        rc,release=engine.call(inv.frame(29,a=bg))
        assert rc==0 and release[:8]==b'HIABVR02'and q.get(release,8)in(0,11),release[:128].hex()
        assert (q.get(release,88),q.get(release,96))==(1,1);v.held.remove(bg)
        (D/'last-drop.json').write_text(json.dumps(dict(head=[q.get(release,i)for i in range(0,128,8)],caller_tid=os.getpid(),worker_tid=worker_tid),indent=2)+'\n')
        cfg=C.string_at(q.get(bgctx,240),512);reaper_cap=struct.unpack_from('<3Q',cfg,464)
        assert reaper_cap[0]and q.get(cfg,488)==1
        rr=registry_borrow(reaper_cap);reaper_ptr=q.get(rr,0);assert q.get(rr,8)==1048576
        deadline=time.monotonic()+10
        observed=[]
        while True:
         h=C.string_at(reaper_ptr,512)
         state=dict(state=q.get(h,160),seq=q.get(h,208),status=q.get(h,216),known=q.get(h,224),consumed=q.get(h,232),
           pending=q.get(h,240),unknown=q.get(h,336),token=q.get(h,184),mapping=q.get(h,256),
           objects=q.get(bgctx,192),active=q.get(bgctx,184),queue=q.get(engine.context,176),continuations=q.get(engine.context,184))
         if not observed or observed[-1]!=state:observed.append(state)
         if state['state']==7 and state['objects']==state['active']==state['queue']==state['continuations']==0:break
         if time.monotonic()>=deadline:
          (D/'pending-reaper-record.bin').write_bytes(h)
          (D/'pending.json').write_text(json.dumps(dict(states=observed,bg=[q.get(bgctx,i)for i in range(0,512,8)],
              threads={p.name:(p/'wchan').read_text()for p in Path('/proc/self/task').iterdir()}),indent=2)+'\n')
          raise AssertionError(('native reaper did not settle',observed))
         time.sleep(.002)
        assert q.get(h,208)>=2 and (q.get(h,224),q.get(h,232),q.get(h,240),q.get(h,248))==(1,1,0,0)
        assert q.get(h,184)==q.get(h,256)==q.get(h,336)==0 and q.get(h,176)==1 and q.get(h,296)==0
        assert q.get(h,408)==os.getpid()and q.get(h,304)not in(0,os.getpid(),worker_tid)
        (D/'settled-native-reaper.json').write_text(json.dumps(dict(record=[q.get(h,i)for i in range(0,512,8)],states=observed,no_host_Value_draining=True),indent=2)+'\n')
        probe=v.raw(47);assert q.get(probe,48)==before
        assert fdrows()==fd_before_rows,(fdrows(),fd_before_rows)
        stale=v.raw(80,a=weak,arg0=1,want=3);assert struct.unpack_from('<3Q',stale,24)==(0,0,0)
        cases.append(dict(case='caller-last-drop-autonomous-native-reaper-SHUT-join-second-RFQ-and-token-release',passed=True,
         initial_release=[q.get(release,i)for i in range(0,128,8)],native_states=observed,no_host_Value_drain=True,
         actual_worker_tid=worker_tid,actual_reaper_tid=q.get(h,304),actual_first_RFQ_tid=q.get(h,408)))
        original.shutdown();oldruntime.close();carrier.q(3,raw_runtime)
        for c in list(v.held):v.drop(c)
        assert not list(parent.iterdir())and not list(oracle_parent.iterdir())
        drop=g.call(3,borrow['cap']);resources.ready(drop);assert drop['consumed']==1
        a=call(1);assert q.get(a,8)==0 and q.get(a,16)==4 and q.get(a,40)==1 and q.get(a,80)==190
        cases.append(dict(case='context-close-actual-reaper-pthread-join-registry-unlink-and-loader-global-guard-release',passed=True))
        sc=globalqa.sidecar(n,1);assert sc['status']==0 and sc['retired']==1,sc
        r=g.call(1);globalqa.closed(n,g,r)
        report=dict(schema='hia.BG.native-autonomous-reaper.v1',passed=True,cases=cases,
         native_root=str(path),public_calls=public_rows,binder_calls=rows,host_pointer_or_mask_write=False,
         actual_single_Value=True,actual_global_resource_borrow=True,actual_installed_child_admission=True,
         native_reaper_last_drop=True,self_worker_last_drop=False,whole_background_closed=False)
        (D/'report.json').write_text(json.dumps(report,indent=2)+'\n');signal.alarm(0)
        print('ACTUAL_NATIVE_BG_REAPER_IDLE_PASS',len(cases),flush=True)

    else:
        # Actual submit/worker/Future path. No injected rank callback or host worker.
        from hepta.hia_background_optimizer import TARGET
        from tools import qualify_hia_future_managed_edges as managed
        timing={'submit_work_ns','queue_wait_ns','rank_call_wall_ns','job_wall_before_future_completion_ns',
                'worker_elapsed_ns','observed_submit_and_worker_ns','actual_adapter_ns','total_search_ns','search_at_native_rank_ns'}
        def stable(x):
         if isinstance(x,dict):
          answer={}
          for key,value in x.items():
           if key in timing:
            assert type(value)is int and value>=0,(key,value)
            answer[key]='<actual measured duration>'
           else:answer[key]=stable(value)
          return answer
         if isinstance(x,list):return [stable(y)for y in x]
         return x

        def comparable_result(x):
         import copy
         from hepta.hia_ndu_optimizer import _digest,ns_to_ms_q32
         r=x['ranking'];cost=r['costs'];req=r['native_request'];obs={z['id']:z['observation']for z in r['candidate_reports']}
         objective=r['objective'];calls=objective['expected_calls'];cap=objective['resource_cap_ns']
         assert cost['total_search_ns']==cost['supplied_search_ns']+cost['actual_adapter_ns']
         assert 0<=cost['search_at_native_rank_ns']<=cost['total_search_ns']
         assert cost['search_at_native_rank_ns']<=cap-r['native_rank_admission']['remaining_budget_ns']<=cost['total_search_ns']
         assert req['resource_cap_q32']==ns_to_ms_q32(cap)
         assert req['objective_sha256']==r['objective_sha256']
         assert _digest(req)==r['request_sha256']
         base=100000-1;last=-1
         for report,row in zip(r['candidate_reports'],req['candidates'][1:]):
          seen=report['observation'];spent=report['preproof_cost_lower_bound_ns']
          assert last<=spent<=cost['search_at_native_rank_ns'];last=spent
          assert report['proof_remaining_budget_ns']==cap-spent
          assert report['proof_remaining_margin_ns']==base*calls-(seen['runtime_ns']+seen['uncertainty_ns'])*calls-spent
          assert row==dict(id=report['id'],cost_q32=ns_to_ms_q32((seen['runtime_ns']+seen['uncertainty_ns'])*calls+cost['search_at_native_rank_ns']),
           uncertainty_q32=ns_to_ms_q32(seen['uncertainty_ns']*calls),resource_q32=ns_to_ms_q32(cost['search_at_native_rank_ns']),
           hard_violation=not report['equivalence_proved'],support_sha256=_digest(report))
         c=x['costs']
         assert c['observed_submit_and_worker_ns']==c['submit_work_ns']+c['worker_elapsed_ns']
         assert c['job_wall_before_future_completion_ns']>=c['worker_elapsed_ns']>=c['rank_call_wall_ns']>=cost['actual_adapter_ns']>=0
         normalized=copy.deepcopy(x);rr=normalized['ranking']
         for report in rr['candidate_reports']:
          for key in ('preproof_cost_lower_bound_ns','proof_remaining_budget_ns','proof_remaining_margin_ns'):report[key]='<verified actual time-derived value>'
         rr['native_rank_admission']['remaining_budget_ns']='<verified actual time-derived value>'
         for row in rr['native_request']['candidates'][1:]:
          for key in ('cost_q32','resource_q32','support_sha256'):row[key]='<verified actual time-derived value>'
         rr['request_sha256']='<verified actual time-derived value>'
         return stable(normalized)


        def comparable_snapshot(snapshot,result):
         import copy
         ac=snapshot['cost_accounting'];rows=ac['recent_jobs']
         assert ac['settled_jobs']==1 and len(rows)==1
         row=rows[0];assert row['job']==result['job']
         assert row['costs']==result['costs']
         assert row['native_request_sha256']==result['ranking']['request_sha256']
         assert row['reported_ranking_costs']=={k:result['ranking']['costs'][k]for k in row['reported_ranking_costs']}
         assert ac['observed_submit_and_worker_ns']==sum(r['costs']['observed_submit_and_worker_ns']for r in rows)
         normalized=copy.deepcopy(snapshot)
         normalized['cost_accounting']['recent_jobs'][0]['native_request_sha256']='<verified actual report digest>'
         return stable(normalized)

        canonical=verify_program(baseline)
        candidates=[dict(id='A',action='identity',program=baseline),dict(id='B',action='second',program=baseline)]
        observations={name:dict(runtime_ns=100000,uncertainty_ns=1,search_ns=0,program_sha256=canonical.sha256)for name in ('abstain','A','B')}
        objective=dict(expected_calls=1,resource_cap_ns=0,target=TARGET,measurement_profile='measure')
        original_future=original.submit(candidates,observations,objective)
        expected_result=original_future.result(timeout=30)
        (D/'original-result.json').write_text(json.dumps(expected_result,indent=2)+'\n')
        print('ORIGINAL_REAL_JOB_RESULT',expected_result,flush=True)
        rawbg=struct.unpack_from('<3Q',v.raw(49,a=bg),24)
        def registry_borrow(cap):
         regq=bytearray(128);regq[:8]=b'HIABGRG1';struct.pack_into('<Q',regq,8,6);struct.pack_into('<3Q',regq,24,*cap)
         s=C.create_string_buffer(bytes(regq),128);out=C.create_string_buffer(8192)
         f=inv.ENTRY(q.get(bgctx,144));rc=f(s,128,out,8192,q.get(bgctx,152),256)
         assert rc==0 and out.raw[:8]==b'HIABGRR1'and q.get(out,8)==0 and q.get(out,40)==32 and q.get(out,80)==1
         return C.string_at(q.get(out,64),32)
        row=registry_borrow(rawbg)
        worker_before=C.string_at(q.get(row,0)+8704,512)
        worker_tid=q.get(worker_before,32);assert worker_tid and worker_tid!=os.getpid()

        held_before_job=set(v.held)
        job_inputs=[make(v,candidates),make(v,observations),make(v,objective)]
        job_input_held=[c for c in v.held if c not in held_before_job]

        submitted=public(3,[bg,*job_inputs]);future=v.keep(submitted)
        # Retain the caller's input caps for now: issuing no main-thread Value calls
        # after this release proves any subsequent BG RFQ is native worker driven.
        rc,release=engine.call(inv.frame(29,a=bg))
        assert rc==0 and release[:8]==b'HIABVR02'and q.get(release,8)in(0,11)
        assert(q.get(release,88),q.get(release,96))==(1,1);v.held.remove(bg)
        import time
        deadline=time.monotonic()+10
        while True:
         cfg=C.string_at(q.get(bgctx,240),512)
         if q.get(cfg,488)==1 and all(struct.unpack_from('<3Q',cfg,464)):break
         assert time.monotonic()<deadline,('native worker did not schedule BG retirement',q.get(bgctx,192),q.get(engine.context,176))
         time.sleep(.002)
        reaper_cap=struct.unpack_from('<3Q',cfg,464);rr=registry_borrow(reaper_cap);reaper_ptr=q.get(rr,0)
        assert q.get(rr,8)==1048576
        observed=[]
        while True:
         h=C.string_at(reaper_ptr,512)
         state=dict(state=q.get(h,160),seq=q.get(h,208),status=q.get(h,216),known=q.get(h,224),consumed=q.get(h,232),
         pending=q.get(h,240),unknown=q.get(h,336),token=q.get(h,184),mapping=q.get(h,256),
         objects=q.get(bgctx,192),active=q.get(bgctx,184),queue=q.get(engine.context,176),continuations=q.get(engine.context,184))
         if not observed or observed[-1]!=state:observed.append(state)
         if state['state']==7 and state['objects']==state['active']==state['queue']==state['continuations']==0:break
         if time.monotonic()>=deadline:
          (D/'pending-reaper-record.bin').write_bytes(h)
          (D/'pending.json').write_text(json.dumps(dict(states=observed,bg=[q.get(bgctx,i)for i in range(0,512,8)],
             threads={p.name:(p/'wchan').read_text()for p in Path('/proc/self/task').iterdir()}),indent=2)+'\n')
          raise AssertionError(('native worker reaper did not settle',observed))
         time.sleep(.002)
        receipt=dict(record=[q.get(h,i)for i in range(0,512,8)],states=observed,worker_tid=worker_tid,caller_tid=os.getpid(),
         no_host_Value_draining=True,release=[q.get(release,i)for i in range(0,128,8)])
        (D/'settled-self-worker-reaper.json').write_text(json.dumps(receipt,indent=2)+'\n')
        assert q.get(h,408)==worker_tid and q.get(h,408)!=os.getpid(),receipt
        assert q.get(h,304)not in(0,worker_tid,os.getpid())
        assert q.get(h,208)>=2 and(q.get(h,224),q.get(h,232),q.get(h,240),q.get(h,248))==(1,1,0,0)
        assert q.get(h,184)==q.get(h,256)==q.get(h,336)==0 and q.get(h,176)==1 and q.get(h,296)==0
        cases.append(dict(case='actual-worker-thread-last-BG-release-autonomous-other-thread-join-and-second-RFQ',passed=True,
         actual_worker_tid=worker_tid,actual_reaper_tid=q.get(h,304),first_RFQ_tid=q.get(h,408),native_states=observed,
         no_host_Value_drain=True))
        for c in job_input_held:v.drop(c)
        cls=v.keep(v.raw(36,a=future));canonical_class=v.keep(v.raw(114,arg0=74))
        assert v.same(cls,canonical_class);v.drop(cls);v.drop(canonical_class)
        owned=binding.Fixture.__new__(binding.Fixture);owned.v=v;owned.engine=engine
        sidecarptr=q.get(n.context,1152);owned.provider_ctx=(C.c_char*512).from_address(sidecarptr+1536)
        owned.provider=SimpleNamespace(entry=inv.ENTRY(q.get(engine.context,224)))
        pp=managed.PrivatePublic.__new__(managed.PrivatePublic);pp.value=v;pp.calls=0;pp.factories=[];pp.futures=[]
        pp.ctx=(C.c_char*256).from_address(sidecarptr+1280);pp.image=SimpleNamespace(entry=n.lib.hia_background_optimizer_future_public)
        pp.image.entry.argtypes=[C.c_void_p,C.c_uint64]*3;pp.image.entry.restype=C.c_uint32
        owned.public=pp
        strong,pair=owned.acquire(future)
        limit=v.scalar(5.0)
        raw=bytearray(192);raw[:8]=b'HIABFP04';struct.pack_into('<Q',raw,8,10)
        struct.pack_into('<3Q',raw,16,*pair[0]);struct.pack_into('<3Q',raw,40,*pair[1]);struct.pack_into('<3Q',raw,104,*limit)
        s=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(b'\xa5'*65568,65568)
        rc=pp.image.entry(s,192,out,65536,pp.ctx,256);result_reply=out.raw[:65536]
        assert rc==0 and result_reply[:8]==b'HIABFRP3'and s.raw==bytes(raw)and out.raw[65536:]==b'\xa5'*32
        assert q.get(result_reply,8)==0 and q.get(result_reply,16)==4,result_reply[:192].hex()
        result_cap=v.keep(result_reply,72);actual_result=v.python_value(result_cap)
        assert comparable_result(actual_result)==comparable_result(expected_result),(actual_result,expected_result)
        (D/'actual-result.json').write_text(json.dumps(actual_result,indent=2)+'\n')
        for c in(result_cap,limit,strong,future):v.drop(c)
        cases.append(dict(case='canonical74-Future-result-survives-owner-worker-self-retirement',passed=True,
         actual_result=actual_result,original_result=expected_result))
        assert q.get(v.raw(47),48)==before
        assert q.get(engine.context,176)==q.get(engine.context,184)==q.get(bgctx,192)==q.get(bgctx,184)==0
        assert fdrows()==fd_before_rows
        stale=v.raw(80,a=weak,arg0=1,want=3);assert struct.unpack_from('<3Q',stale,24)==(0,0,0)
        original.shutdown();oldruntime.close();carrier.q(3,raw_runtime)
        for c in list(v.held):v.drop(c)
        assert not list(parent.iterdir())and not list(oracle_parent.iterdir())
        drop=g.call(3,borrow['cap']);resources.ready(drop);assert drop['consumed']==1
        a=call(1);assert q.get(a,8)==0 and q.get(a,16)==4 and q.get(a,40)==1 and q.get(a,80)==190
        cases.append(dict(case='actual-reaper-thread-joined-and-all-raw-registry-global-loader-custody-retired',passed=True))
        sc=globalqa.sidecar(n,1);assert sc['status']==0 and sc['retired']==1,sc
        r=g.call(1);globalqa.closed(n,g,r)
        report=dict(schema='hia.BG.native-self-worker-reaper.v1',passed=True,cases=cases,native_root=str(path),
         actual_single_Value=True,host_pointer_or_mask_write=False,native_reaper_last_drop=True,
         self_worker_last_drop=True,queued_rank_result_preserved=True,whole_background_closed=False,
         public_calls=public_rows,binder_calls=rows)
        (D/'report.json').write_text(json.dumps(report,indent=2)+'\n');signal.alarm(0)
        print('ACTUAL_NATIVE_BG_SELF_WORKER_REAPER_PASS',len(cases),flush=True)


def main(argv=None):
    p=argparse.ArgumentParser(__doc__)
    p.add_argument('--root',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--evidence-root',required=True)
    p.add_argument('--reference-root')
    p.add_argument('--mode',choices=('idle','self-worker'),required=True)
    qualify(p.parse_args(argv))

if __name__=='__main__':main()
