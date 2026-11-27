"""Source-only review of three exact checksum-extent hoists; never executes an image."""
from __future__ import annotations
import ast, hashlib, json, re
from pathlib import Path
ROOT=Path("/workspace/scratch/dda74a4fae35")
OLD=ROOT/"v82-service-artifacts-development-r4/source"
NEW=ROOT/"v83-native-receipt-throughput-r1/source"
OUT=Path(__file__).resolve().parent

def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
        "blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def block(text,name):
    m=re.search(r"^def "+re.escape(name)+r"\(.*?(?=^def |^'''|\Z)",text,re.M|re.S)
    if m is None:raise ValueError("missing "+name)
    value=m.group(0).rstrip()+"\n"
    ast.parse(value)
    return {"line":text[:m.start()].count("\n")+1,"text":value,"identity":identity(value.encode())}
def main():
    candidate=json.loads((NEW.parent/"CANDIDATE.json").read_bytes())
    rows=[]
    for name,word,start in (("artifact_namespace",54,512),("request_journal",11,0),("slot_ledger",55,512)):
        path="tools/generate_hia_"+name+".py"
        before=(OLD/path).read_bytes();after=(NEW/path).read_bytes()
        needle=f"    i = {start}\n    while i < get(w, {word}):\n        value = ((value << 7) | (value >> 57)) ^ byte(w, "
        replacement=f"    extent = get(w, {word})\n    i = {start}\n    while i < extent:\n        value = ((value << 7) | (value >> 57)) ^ byte(w, "
        old=before.decode();new=after.decode()
        if old.count(needle)!=1 or old.replace(needle,replacement)!=new:
            raise ValueError("candidate differs outside exact hoist")
        declared=candidate["patches"][name]
        if identity(before)["sha256"]!=declared["before_sha256"] or identity(after)["sha256"]!=declared["after_sha256"]:
            raise ValueError("candidate authority differs")
        checksum=block(new,"checksum");getter=block(new,"get")
        body=ast.parse(checksum["text"]).body[0]
        calls=[x.func.id for x in ast.walk(body) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)]
        if set(calls)!={"get","byte"}:
            raise ValueError("checksum call closure changed")
        getcalls=[x.func.id for x in ast.walk(ast.parse(getter["text"])) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)]
        if set(getcalls)!={"byte"}:
            raise ValueError("get call closure changed")
        rows.append({"path":path,"before":identity(before),"after":identity(after),
            "exact_only_hoist":True,"extent_word":word,"payload_start":start,
            "checksum":checksum,"get":getter,"checksum_calls":calls,
            "new_extent_read_after_unchanged_header_loop":True})
    provider_paths=("hepta/hia_artifact_namespace_native.py","hepta/hia_request_journal_native.py",
        "hepta/hia_slot_ledger_native.py","hepta/hia_json_preflight_native.py")
    providers={path:identity((OLD/path).read_bytes()) for path in provider_paths}
    report={"schema":"hia.checksum-extent-hoist.independent-source-review.v1",
        "reviewer":"hia_surface_audit","baseline_commit":"1cd416ab028a4c59ac76bf4b8e2c4018fb552d9d",
        "baseline_tree":"eca3dd8ba5067d77fb56454ee354bd0eddb9cfe9",
        "candidate_report_identity":identity((NEW.parent/"CANDIDATE.json").read_bytes()),
        "candidate_reported_tree":candidate["candidate_tree"],
        "candidate_complete_tree_independently_recomputed_in_this_review":False,
        "generators":rows,"provider_source_identities":providers,
        "findings":[
            "No definite new observable difference was identified for the existing serialized or creator-thread owner calls without external concurrent mutation of their private workspace.",
            "Every extent snapshot remains after the unchanged complete header read/hash loop and before the first payload byte. The only preceding reassigned scalar is private i; no store, callback or foreign operation occurs inside checksum/get.",
            "A zero payload still performs its original first extent read. Ordinary s/o/w aliasing alone cannot write the header during the read-only checksum body; all three adapters pass distinct input/output allocations around the held workspace.",
            "valid_state is not the only checksum path. Initialization sealing and slot-ledger direct_valid_state also invoke it. Existing entry minimum extents and initialized bounded extent words must remain in the real controls.",
            "NamespaceState.call and cleanup_claim hold the same RLock; RequestState.call and claim_rollback hold their same RLock; LedgerState.check preserves creator PID/thread. No new serialization or GIL claim was introduced.",
            "The actual entry mapping uses ctypes.CFUNCTYPE. These findings do not prove equivalence for arbitrary direct raw-entry calls sharing a mutable workspace or unsynchronized writes to state.buffer. A writer changing the extent during the payload loop can distinguish a repeated read from one snapshot.",
            "Existing full workspace/output/canary, invalid header/extent, zero/max payload, original native control and original budget comparisons remain required. This review ran no image, compiler, business test or timing measurement."
        ],
        "scope":{"source_review_only":True,"machine_tests_run":False,"performance_measured":False,
            "current_source_cold":False,"whole_native":False,"unrestricted_concurrent_workspace_equivalence":False}}
    raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
    (OUT/"REPORT.json").write_bytes(raw)
    print(json.dumps({"report":identity(raw),"exact_generators":len(rows),"runtime_qualifications":False},sort_keys=True))
if __name__=="__main__":main()

