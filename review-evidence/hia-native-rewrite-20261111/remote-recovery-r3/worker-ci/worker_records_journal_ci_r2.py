"""Independent CI qualification of records and the complete journal transport.

All execution is new, under the original compiler and per-child native limits.
This does not supply ordinary Worker, namespace, full business or cold closure.
"""
from __future__ import annotations
import ast
from hashlib import sha1,sha256
import importlib.util,json,os,sqlite3,stat,subprocess,sys,traceback
from pathlib import Path
sys.dont_write_bytecode=True
PINS={
  "dependency_index": {
    "path": "worker_ci_dependencies_r2.json",
    "bytes": 11581,
    "sha256": "58281cd95288e6ec3108d4214203847fef764765e1b35f597eb696e404c32bcb",
    "gitsha": "c86f3db86034d71a0e5966341d2a532f65c88fa5"
  },
  "restore": {
    "path": "worker_ci_restore_r1.py",
    "bytes": 7621,
    "sha256": "f7456e8e5e39cb284e4447d3b6e2898748dd5b93cdfbb3ce0c35016a11d37ddb",
    "gitsha": "07785fec88f5471c237e29198eeaf30e7b8a2b81"
  },
  "compile": {
    "path": "compile_worker_peers_ci_r1.py",
    "bytes": 6697,
    "sha256": "74b644e9e96fbf2dddac82d864debfb4b9dcd3c6e52a708fa2b2028ef2cecad2",
    "gitsha": "024d17dcf205c633e055a6633e397ada3a21bdd3"
  },
  "harness": {
    "path": "development/journal_bridge_ci_harness_r1.py",
    "bytes": 13893,
    "sha256": "58aede7e8cb00a9d460b7b997abb19451469c3910f8f1ef8777aa3135ee520fc",
    "gitsha": "5e6bf5c6b9badbb0862d20ab83dc6979f4308ced"
  },
  "tests": {
    "path": "development/test_journal_bridge_ci_r1.py",
    "bytes": 10545,
    "sha256": "d5c84eafe7815a900926a6fcb3e4c86108843b3c3147e48645bb61351dd577ae",
    "gitsha": "dabea00219a9931bc28667d170ba9c278fce7f72"
  },
  "protocol": {
    "path": "development/test_journal_bridge_protocol_ci_r1.py",
    "bytes": 6997,
    "sha256": "26a3b46aec740eed2d28d7a77bd484b042fd11bb2e0a755a827bb89ffb4be1ca",
    "gitsha": "d7f705a40819e80a73d559c92ec33e1a1cce94b6"
  }
}
COMMON_SHA="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve()
common_raw=COMMON.read_bytes()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
assert gitsha(common_raw)==COMMON_SHA
spec=importlib.util.spec_from_file_location("worker_common_ci",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
self_raw=Path(__file__).read_bytes()
context=None;work=None
submitted={}
details=dict(scope="FRESH_RECORDS_AND_SELECTED_JOURNAL_TRANSPORT_NOT_WHOLE_WORKER",
    historical_pass_inheritance=False,namespace_effects=0,
    pending_whole_worker_owners=["tool schema fresh reconstruction","full call orchestration","11 tool businesses","native namespace"],
    sqlite_version=sqlite3.sqlite_version,exact_namespace_sqlite_oracle_claim=False,
    records_rog_archive_upload_complete=False,rog_bridge_r4_launch_status="UNKNOWN_NOT_RECONCILED_BY_CI")
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def materialize(name,target):
    row=PINS[name]
    raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",row["gitsha"]],cwd=context["repo"])
    assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),name
    if target.suffix==".py":ast.parse(raw,filename=str(target))
    target.parent.mkdir(parents=True,exist_ok=True)
    assert not target.exists(),str(target)
    with target.open("xb") as f:f.write(raw)
    submitted[target]=raw
    return target
def summaries():
    result=[]
    for p in sorted((work/"native-agent-service-call-next/development").glob("journal-ci-*/summary.json")):
        result.append(dict(path=str(p),summary=json.loads(p.read_bytes())))
    return result
status="FAIL"
try:
    context=common.prepare()
    output=Path(context["output"])
    save(output/"worker-submitted-inputs.json",dict(common_git_sha=COMMON_SHA,script_pins=PINS,
        driver=dict(bytes=len(self_raw),sha256=digest(self_raw),gitsha=gitsha(self_raw))))
    own=Path(context["base"])/"worker-ci-source"
    index=materialize("dependency_index",own/"worker_ci_dependencies_r2.json")
    restore=materialize("restore",own/"worker_ci_restore_r1.py")
    compile_script=materialize("compile",own/"compile_worker_peers_ci_r1.py")
    common.run("worker-exact-dependency-restore",[sys.executable,"-B",restore,output/"context.json",index],timeout=300)
    work=Path(context["base"])/"worker-recovery/work-r2"
    records=work/"native-agent-service-controller-next"
    bridge=work/"native-agent-service-call-next"
    for name in ("harness","tests","protocol"):
        materialize(name,bridge/PINS[name]["path"])
    components=os.environ.get("HIA_WORKER_COMPONENTS","all")
    assert components in ("all","records","bridge")
    details["requested_components"]=components
    if components in ("all","records"):
        common.run("worker-fresh-graph-peer-compiles",[sys.executable,"-B",compile_script,work,"graph"],timeout=180)
        original=records/"development/compile_records_recovered_r2.py"
        original_raw=original.read_bytes()
        compile_raw=original_raw.replace(b"New ROG development compile",b"New CI development compile")
        compile_raw=compile_raw.replace(b"NEW_ROG_DEVELOPMENT_NOT_COLD_OR_NAMESPACE_OR_COMPLETE_WORKER",
                                        b"NEW_CI_DEVELOPMENT_NOT_COLD_OR_NAMESPACE_OR_COMPLETE_WORKER")
        assert compile_raw!=original_raw and compile_raw.count(b"NEW_CI_DEVELOPMENT_NOT_COLD_OR_NAMESPACE_OR_COMPLETE_WORKER")==1
        compile_ci=records/"development/compile_records_ci_r1.py"
        assert not compile_ci.exists()
        compile_ci.write_bytes(compile_raw)
        submitted[compile_ci]=compile_raw
        save(output/"records-compile-metadata-adaptation.json",dict(
            original=dict(bytes=len(original_raw),sha256=digest(original_raw)),
            executed=dict(bytes=len(compile_raw),sha256=digest(compile_raw)),
            only_change="two ROG scope labels become CI; compilation semantics and limits unchanged",
            test_scripts_unchanged=True))
        common.run("worker-records-fresh-compile",[sys.executable,"-B",compile_ci],cwd=records,timeout=180)
        common.run("worker-records-semantic-110",[sys.executable,"-B",records/"development/test_records_semantic_recovered_r2.py",
            records/"development/semantic-ci-r1"],cwd=records,timeout=180)
        common.run("worker-records-protocol-108",[sys.executable,"-B",records/"development/test_records_protocol_recovered_r2.py",
            records/"development/protocol-ci-r1"],cwd=records,timeout=180)
        common.run("worker-records-original-boundaries",[sys.executable,"-B",records/"development/run_records_boundaries_recovered_r1.py"],
            cwd=records,timeout=450)
        records_summaries=[json.loads((records/"development"/name/"summary.json").read_bytes())
            for name in ("semantic-ci-r1","protocol-ci-r1","records-boundary-small-recovered-r1",
                         "records-boundary-exact-recovered-r1","records-boundary-plusone-recovered-r1")]
        assert all(v["status"]=="PASS" for v in records_summaries)
        counts={k:sum(v["entries"][k] for v in records_summaries) for k in ("records","scan","emit")}
        cases=sum(v["cases"] for v in records_summaries)
        assert cases==228 and counts=={"records":466,"scan":240,"emit":348},(cases,counts)
        details["records"]=dict(status="PASS",cases=cases,entries=counts,total_actual_entries=sum(counts.values()),
                               observations="NEW_GITHUB_ACTIONS",summaries=records_summaries)
    if components in ("all","bridge"):
        common.run("worker-journal-bridge-fresh-compiles",[sys.executable,"-B",compile_script,work,"bridge"],timeout=180)
        for mode in ("smoke","semantic","diagnostics","faults","foreign-boundary","boundary-exact","boundary-plusone"):
            common.run("worker-journal-"+mode,[sys.executable,"-B",bridge/"development/test_journal_bridge_ci_r1.py",
                bridge/("development/journal-ci-"+mode),mode],cwd=bridge,timeout=180)
        common.run("worker-journal-private-protocol",[sys.executable,"-B",bridge/"development/test_journal_bridge_protocol_ci_r1.py",
            bridge/"development/journal-ci-protocol"],cwd=bridge,timeout=180)
        reports=summaries()
        assert len(reports)==8 and all(r["summary"]["status"]=="PASS" for r in reports),reports
        assert set().union(*(r["summary"].get("stages",[]) for r in reports))==set(range(11))
        details["journal"]=dict(status="PASS",groups=reports,
            complete_transport_stages=list(range(11)),full_call_fsm_closed=False,
            native_namespace_closed=False,ordinary_worker_closed=False,
            records_owner_called_by_full_call_fsm=False)
    input_pins=json.loads((output/"worker-restore/input-pins.json").read_bytes())
    assert all(Path(r["path"]).is_file() and Path(r["path"]).stat().st_size==r["bytes"]
        and digest(Path(r["path"]).read_bytes())==r["sha256"]
        and stat.S_IMODE(Path(r["path"]).stat().st_mode)==r["mode"] for r in input_pins)
    assert all(p.read_bytes()==raw for p,raw in submitted.items())
    assert Path(__file__).read_bytes()==self_raw and COMMON.read_bytes()==common_raw
    details["all_submitted_and_restored_input_bytes_unchanged"]=True
    status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    if work is not None:details["completed_journal_groups"]=summaries()
    traceback.print_exc()
finally:
    roots={}
    if work is not None:
        roots={"records":work/"native-agent-service-controller-next","journal":work/"native-agent-service-call-next",
               "fresh-graph-compiles":work/"native-agent-edit-render-next/development/compile-r3"}
    if context is not None:roots["submitted-ci-sources"]=Path(context["base"])/"worker-ci-source"
    common.finish("worker-records-journal-component-ci-r1",status,details,roots=roots)
if status!="PASS":raise SystemExit(1)
