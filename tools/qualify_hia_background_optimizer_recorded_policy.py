"""Compare full original rank/worker policy against actual native receipts.

Native proof, evaluator and Runtime publication facts are replayed only at
those primitive boundaries in the Python oracle. Native products execute
normally before this checker runs. Original source/AST, full result objects,
clock ordering, budgets and accounting are retained.
"""
from pathlib import Path
import ast,collections,copy,hashlib,inspect,json,textwrap,threading,types

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def same_tree(actual,expected,path="$"):
    assert type(actual)is type(expected),(path,type(actual).__name__,type(expected).__name__)
    if isinstance(actual,dict):
        assert list(actual)==list(expected),(path,list(actual),list(expected))
        for k in actual:same_tree(actual[k],expected[k],path+"."+k)
    elif isinstance(actual,list):
        assert len(actual)==len(expected),(path,len(actual),len(expected))
        for i,(a,b)in enumerate(zip(actual,expected)):same_tree(a,b,path+"["+str(i)+"]")
    else:assert actual==expected,(path,actual,expected)

def compile_original(fn,scope,name=None):
    raw=textwrap.dedent(inspect.getsource(fn))
    tree=ast.parse(raw)
    before=ast.dump(tree,include_attributes=False)
    oldname=tree.body[0].name
    if name is not None:tree.body[0].name=name
    exec(compile(ast.fix_missing_locations(tree),inspect.getsourcefile(fn),"exec"),scope)
    if name is not None:tree.body[0].name=oldname
    assert ast.dump(tree,include_attributes=False)==before
    return scope[name or oldname],dict(source_file=inspect.getsourcefile(fn),function=oldname,
        source=pin(raw.encode()),ast_sha256=hashlib.sha256(before.encode()).hexdigest())

class Clock:
    def __init__(self,stamps):
        assert all(type(t)is int for t in stamps)
        assert all(a<=b for a,b in zip(stamps,stamps[1:])),stamps
        self.pending=collections.deque(stamps);self.used=[]
    def perf_counter_ns(self):
        assert self.pending,"unexpected original clock call"
        stamp=self.pending.popleft();self.used.append(stamp);return stamp
    def complete(self):assert not self.pending,("unused actual timing facts",list(self.pending))

def compare_rank(actual,inputs):
    import hepta.hia_ndu_optimizer as original
    from hepta.hia_program import verify_program
    baseline=verify_program(inputs["baseline"])
    assert baseline.sha256==actual["before_sha256"] and baseline.input_sha256==actual["before_input_sha256"]
    supplied=sum(r["search_ns"]for r in inputs["observations"].values())
    start=10**15;stamps=[start];proofs=[]
    for row in actual["candidate_reports"]:
        if "preproof_cost_lower_bound_ns"not in row:continue
        stamp=start+row["preproof_cost_lower_bound_ns"]-supplied;stamps.append(stamp)
        if "proof_timeout_ms"in row:
            stamps.extend([stamp,stamp+row["proof_wall_ns"]])
            proofs.append((row["id"],row["proof_timeout_ms"],row["equivalence_proved"],row["proof"]))
    stamps.append(start+actual["costs"]["search_at_native_rank_ns"]-supplied)
    stamps.append(start+inputs["objective"]["resource_cap_ns"]-supplied-actual["native_rank_admission"]["remaining_budget_ns"])
    final=actual["selected_proof_admission"]
    if final is not None:
        stamp=start+final["spent_search_ns"]-supplied;stamps.append(stamp)
        if final["solver_started"]:
            stamps.extend([stamp,stamp+final["wall_ns"]])
            p=actual["selected_fresh_proof"]
            proofs.append((final["candidate_id"],final["timeout_ms"],p["status"]=="proved",p))
    stamps.append(start+actual["costs"]["actual_adapter_ns"])
    clock=Clock(stamps);pending=collections.deque(proofs);proof_calls=[];native_calls=[]
    candidates={row["id"]:verify_program(row["program"])for row in inputs["candidates"]}
    def proof(before,after,function,timeout):
        assert pending,"unrecorded original proof invocation"
        cid,deadline,proved,receipt=pending.popleft()
        assert before.sha256==baseline.sha256 and after.sha256==candidates[cid].sha256
        assert function==inputs["function"] and timeout==deadline
        assert receipt["before_sha256"]==before.sha256 and receipt["after_sha256"]==after.sha256
        proof_calls.append(dict(candidate=cid,timeout_ms=timeout,proved=proved))
        return proved,copy.deepcopy(receipt)
    def native(bridge,request,*,timeout_s):
        assert {k:str(v)for k,v in bridge.items()}==inputs["bridge"]
        assert request==actual["native_request"] and timeout_s==actual["native_rank_admission"]["timeout_s"]
        assert actual["native_rank_admission"]["invoked"]is True
        assert hashlib.sha256(original._bytes(request)).hexdigest()==actual["request_sha256"]
        native_calls.append(dict(timeout_s=timeout_s,request_sha256=actual["request_sha256"]))
        return copy.deepcopy(actual["native_response"]),copy.deepcopy(actual["bridge"])
    scope=dict(vars(original));scope.update(time=clock,_fresh_proof=proof,_native_rank=native)
    fn,source=compile_original(original.rank_candidates,scope,"reference_rank")
    expected=fn(inputs["baseline"],inputs["candidates"],inputs["observations"],
        function=inputs["function"],bridge=inputs["bridge"],objective=inputs["objective"],
        generation=inputs["generation"],timeout_ms=inputs["timeout_ms"],bridge_timeout_s=inputs["bridge_timeout_s"])
    same_tree(actual,expected);clock.complete();assert not pending and len(native_calls)==1
    return dict(passed=True,source=source,clock_samples=len(clock.used),actual_proof_replays=proof_calls,
        actual_native_evaluator_replays=native_calls,complete_original_rank_tree_and_order_equal=True)

def compare_worker(actual,inputs,initial_runtime_snapshot,observed_snapshot=None):
    import hepta.hia_background_optimizer as original
    from hepta.hia_program import verify_program
    from hepta.hia_multiversion import MultiversionRejected
    base=verify_program(inputs["baseline"]);costs=actual["costs"]
    assert initial_runtime_snapshot["closed"]is False
    assert initial_runtime_snapshot["current_generation"]==inputs["expected_generation"]
    assert initial_runtime_snapshot["selection_epoch"]==inputs["expected_epoch"]
    start=10**15
    enqueued=start+costs["submit_work_ns"]
    now=start+costs["job_wall_before_future_completion_ns"]
    work_started=now-costs["worker_elapsed_ns"]
    execute_started=enqueued+costs["queue_wait_ns"]
    rank_started=execute_started
    rank_finished=rank_started+costs["rank_call_wall_ns"]
    handoff=execute_started+costs["coordinator_before_publish_ns"]-costs["submit_work_ns"]+actual["ranking"]["costs"]["actual_adapter_ns"]
    publication_started=handoff+costs.get("publication_handoff_ns",0)
    publication_finished=publication_started+costs["publication_call_wall_ns"]
    clock=Clock([work_started,execute_started,rank_started,rank_finished,handoff,publication_started,publication_finished,now])
    token=original.PublicationCancellation();future=original._OptimizationFuture(token)
    payload=original._pack({k:inputs[k]for k in ("candidates","observations","objective")})
    job=original._Job(actual["job"],base,inputs["expected_generation"],inputs["expected_epoch"],
        payload,future,token,start,submit_work_ns=costs["submit_work_ns"],enqueued_ns=enqueued)
    calls=[];snapshots=[]
    class RuntimeReplay:
        def snapshot(self):
            snapshots.append(True);return copy.deepcopy(initial_runtime_snapshot)
        def publish_if_current(self,candidate,generation,*,expected_epoch,max_prepare_ns,cancellation,preparation_started_ns):
            assert generation==inputs["expected_generation"] and expected_epoch==inputs["expected_epoch"]
            assert candidate.as_dict()==verify_program(actual["ranking"]["selected_program"]).as_dict()
            assert max_prepare_ns==costs["publication_budget_ns"] and preparation_started_ns==handoff
            assert cancellation is token and not token.cancelled() and not token.committed()
            calls.append(dict(generation=generation,epoch=expected_epoch,max_prepare_ns=max_prepare_ns))
            if actual["publication"]is None:
                assert actual["status"]=="rejected" and actual["reason"]=="MultiversionRejected"
                raise MultiversionRejected(actual["detail"])
            assert actual["publication"]["max_prepare_ns"]==max_prepare_ns
            with token._lock:token._committed=True
            return copy.deepcopy(actual["publication"])
    rank_calls=[]
    def rank(baseline,candidates,observations,**kw):
        assert verify_program(baseline).sha256==base.sha256
        assert candidates==inputs["candidates"] and observations==inputs["observations"]
        assert kw["function"]==inputs["function"] and kw["generation"]==inputs["generation"]
        assert kw["objective"]==inputs["objective"]
        assert kw["timeout_ms"]==inputs["timeout_ms"] and kw["bridge_timeout_s"]==inputs["bridge_timeout_s"]
        assert {k:str(v)for k,v in kw["bridge"].items()}==inputs["bridge"]
        rank_calls.append(True);return copy.deepcopy(actual["ranking"])
    scope=dict(vars(original));scope.update(time=clock,rank_candidates=rank)
    owner=original.BackgroundOptimizer.__new__(original.BackgroundOptimizer)
    owner._function=inputs["function"];owner._baseline=base
    owner._bridge={k:Path(v)for k,v in inputs["bridge"].items()}
    owner._timeout=inputs["timeout_ms"];owner._bridge_timeout=inputs["bridge_timeout_s"]
    owner._runtime=RuntimeReplay();owner._condition=threading.Condition()
    owner._queue=collections.deque([job]);owner._pending={job.number:job};owner._active=None
    owner._closed=True;owner._last_program=base;owner._worker_failure=None
    owner._recent_jobs=collections.deque(maxlen=64);owner._settled_jobs=0;owner._observed_work_ns=0;owner._outcomes={}
    sources=[]
    for name in ("_execute","_work","_account_job"):
        fn,source=compile_original(getattr(original.BackgroundOptimizer,name),scope)
        setattr(owner,name,types.MethodType(fn,owner));sources.append(source)
    owner._work()
    assert future.done() and not future.cancelled() and owner._worker_failure is None,owner._worker_failure
    expected=future.result(timeout=0);same_tree(actual,expected);clock.complete()
    assert len(calls)==1 and len(rank_calls)==1 and len(snapshots)==(2 if actual["publication"]is not None else 3)
    assert owner._settled_jobs==1 and owner._observed_work_ns==costs["observed_submit_and_worker_ns"]
    assert owner._outcomes=={actual["status"]:1} and not owner._pending and not owner._queue
    receipt=json.loads(owner._recent_jobs[0])
    if observed_snapshot is not None:
        account=observed_snapshot["cost_accounting"]
        assert account["settled_jobs"]==1 and account["observed_submit_and_worker_ns"]==owner._observed_work_ns
        assert account["execution_outcomes_at_accounting"]==owner._outcomes
        assert len(account["recent_jobs"])==1
        same_tree(account["recent_jobs"][0],receipt,"$.native_snapshot.cost_accounting.recent_jobs[0]")
    return dict(passed=True,sources=sources,clock_samples=len(clock.used),actual_snapshot_accounting_compared=(observed_snapshot is not None),complete_original_worker_result_and_order_equal=True,
        original_conditional_publication_arguments=calls,original_accounting_receipt=receipt,
        original_Future_completed_once=True,actual_timing_intervals_reconstructed=True,
        unreported_rank_entry_offset_selected_without_affecting_any_observable_result=True)

def compare(actual,inputs,output,initial_runtime_snapshot,observed_snapshot=None):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    import hepta.hia_background_optimizer as original
    inputs=dict(inputs)
    # submit stores the exact original sorted _pack payload before the worker.
    inputs.update(json.loads(original._pack({k:inputs[k]for k in ("candidates","observations","objective")})))
    result=dict(passed=False,whole_background_closed=False,primitive_boundary_replay_only=True,original_submit_payload_freeze_retained=True)
    try:
        result["rank"]=compare_rank(actual["ranking"],inputs)
        result["worker"]=compare_worker(actual,inputs,initial_runtime_snapshot,observed_snapshot)
        result["passed"]=True
    finally:(output/"report.json").write_text(json.dumps(result,indent=2)+"\n")
    return result
