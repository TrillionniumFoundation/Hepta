"""Read complete bootstrap raw evidence without importing any product/oracle."""
from __future__ import annotations
import argparse,ast,base64,csv,io,json,sys,zipfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as s
FIXTURE=ROOT/"tests/fixtures/hia_service_bootstrap_original_r12"
DOMAIN={"bytes":41048,"sha256":"cb514a6ba953e6ffb3cbf293ded95fb1bd6631cb42a06212345bb94987221c57"}
BASIS_IDS=(
 "__init__.both-selected.outer0","__init__.root-not-directory.outer0",
 "__init__.cleanup-first-call-error.outer0","__init__.cleanup-second-call-error.outer0",
 "__init__.dynamic-profiles-error.outer1","close.budget-present.outer0",
 "close.body-and-finally-error-context.outer1","_profiles.complete-all27-outer-writes.outer0",
 "_profile.provider-returns-opaque-object.outer0","_program.normal.outer0",
 "generator_protocol.send-none.outer0","generator_protocol.body-StopIteration-PEP479.outer0")
CHANNELS=("observations.jsonl","late-events.jsonl","raw-tracebacks.jsonl","case-terminals.jsonl")
def equal(left,right,message):
    if not s.same(left,right):raise ValueError(message)
def integer(value,expected=None):
    if type(value) is not int or value<0 or expected is not None and value!=expected:
        raise ValueError("exact integer field differs")
    return value
def capture(path,expected,captured):
    raw,value,pin=s.capture_json(path,expected);captured.append((Path(path),raw))
    return value
def unchanged(captured):
    for path,raw in captured:s.exact_reread(path,raw)
def stream_identity(path,pin):
    s.require_pin(pin);equal(s.file_pin(path),pin,"stream changed")
def terminal_receipt(directory,record,start,result,checkpoint,captured):
    """Independently recheck the completed process and checkpoint-prefix chain."""
    terminal=capture(directory/"process-terminal.json",record["terminal"],captured)
    if (terminal["schema"]!="hepta.hia.service-bootstrap-process-terminal.v3"
            or terminal["status"]!="TERMINAL_COMPLETE"
            or terminal["label"]!=record["label"] or terminal["lane"]!=checkpoint["lane"]
            or terminal["natural_exit"] is not True or terminal["owned_group_gone"] is not True):
        raise ValueError("finite lane has no qualifying process-terminal seal")
    for field in ("pid","pgid"):integer(terminal[field],start["pid"])
    integer(terminal["sealer_pid"])
    integer(start["started_time_ns"])
    integer(result["started_time_ns"],start["started_time_ns"])
    integer(result["ended_time_ns"])
    integer(terminal["sealed_time_ns"])
    if (terminal["sealer_pid"]==0 or result["ended_time_ns"]<result["started_time_ns"]
            or terminal["sealed_time_ns"]<result["ended_time_ns"]):
        raise ValueError("terminal seal timing/identity differs")
    equal(terminal["checkpoint_report"],{"relative":"report.json",**record["report"]},
          "terminal replaced the original child checkpoint pin")
    equal(terminal["start"],{"relative":record["label"]+".start.json",**record["start"]},
          "terminal start is not its actual owned start")
    equal(terminal["result"],{"relative":record["label"]+".result.json",**record["result"]},
          "terminal result is not its actual owned result")
    equal(terminal["checkpoint_files"],checkpoint["files"],"checkpoint raw identities changed")
    equal(terminal["files"],record["files"],"terminal raw inventory differs")
    if type(terminal["files"]) is not dict or set(terminal["files"])!=set(checkpoint["files"]):
        raise ValueError("terminal stream set differs from the child checkpoint")
    late=terminal["late"]
    old=s.require_pin(checkpoint["files"]["late-events.jsonl"])
    final=s.require_pin(terminal["files"]["late-events.jsonl"])
    if late["relative"]!="late-events.jsonl" or late["checkpoint_prefix_preserved"] is not True:
        raise ValueError("terminal late prefix declaration differs")
    equal(late["checkpoint"],old,"terminal checkpoint late identity differs")
    equal(late["terminal"],final,"terminal late identity differs")
    integer(late["append_bytes"])
    integer(final["bytes"],old["bytes"]+late["append_bytes"])
    prefix_digest,full_digest,total=sha256(),sha256(),0
    with (directory/"late-events.jsonl").open("rb") as stream:
        while True:
            chunk=stream.read(1<<20)
            if not chunk:break
            if total<old["bytes"]:prefix_digest.update(chunk[:old["bytes"]-total])
            full_digest.update(chunk);total+=len(chunk)
    if total<old["bytes"] or prefix_digest.hexdigest()!=old["sha256"]:
        raise ValueError("late bytes rewrote or truncated the original checkpoint prefix")
    equal({"bytes":total,"sha256":full_digest.hexdigest()},final,
          "actual terminal late bytes differ from the sealed stream")
    expected_names=set(checkpoint["files"])|{"report.json","process-terminal.json"}
    if {p.name for p in directory.iterdir()}!=expected_names:
        raise ValueError("unbound files appeared in the process-terminal child directory")
    for name,pin in terminal["files"].items():
        if type(name) is not str or Path(name).name!=name:
            raise ValueError("terminal file leaves its owned child directory")
        if name!="late-events.jsonl":
            equal(pin,checkpoint["files"][name],"a nonlate checkpoint pin was replaced")
        path=directory/name
        if path.is_symlink() or not path.is_file():
            raise ValueError("terminal stream is not a regular owned file")
        stream_identity(path,pin)
    return {**checkpoint,"files":terminal["files"],
            "checkpoint_files":checkpoint["files"],"process_terminal":record["terminal"]}


def receipt(parent,label,record,captured,source,*,lane,seconds):
    directory=parent/label
    if record["label"]!=label:raise ValueError("terminal lane record label differs")
    start=capture(parent/(label+".start.json"),record["start"],captured)
    result=capture(parent/(label+".result.json"),record["result"],captured)
    report=capture(directory/"report.json",record["report"],captured)
    integer(start["pid"]);integer(start["pgid"],start["pid"])
    if start["pid"]==0:raise ValueError("an owned child must have a positive PID")
    integer(result["pid"],start["pid"]);integer(result["pgid"],start["pid"])
    integer(report["pid"],start["pid"]);integer(report["pgid"],start["pid"])
    integer(start["timeout_seconds"],seconds);integer(start["cleanup_seconds"],3)
    integer(result["timeout_seconds"],seconds);integer(result["cleanup_seconds"],3)
    integer(result["returncode"],0)
    if (result["timeout"] is not False or result["reaped"] is not True
            or result["cleanup_error"] is not None or result["supervisor_error"] is not None
            or result["cleanup"]["reaped"] is not True or result["cleanup"]["after"]!=[]
            or result["cleanup"]["signals"]!=[]):
        raise ValueError("owned child did not terminate naturally and completely")
    command=start["command"]
    equal(command,result["command"],"child argv differs")
    equal(command[3:],report["argv"],"inner child argv differs")
    equal(command[:3],[report["executable"],"-I","-B"],"isolated interpreter command differs")
    if Path(command[3]).resolve()!=ROOT/"tests/hia_service_bootstrap_observer.py":
        raise ValueError("finite command did not use the bound observer")
    if start["cwd"]!=str(ROOT) or result["cwd"]!=str(ROOT) or report["cwd"]!=str(ROOT):
        raise ValueError("child source root differs")
    if report["lane"]!=lane or report["runtime"]!=sys.version:
        raise ValueError("finite role or actual runtime differs")
    equal(report["source_before"],source,"child source before differs")
    equal(report["source_after"],source,"child source after differs")
    equal(result["report"],{"relative":"report.json",**record["report"]},"child inner pin differs")
    for suffix in ("stdout","stderr"):
        stream_identity(parent/(label+"."+suffix+".log"),result[suffix])
    integer(result["stderr"]["bytes"],0)
    integer(report["differences"],0)
    if (report["schema"]!="hepta.hia.service-bootstrap-finite-observations.v3"
            or report.get("case_terminal_protocol")!=s.CASE_TERMINAL_SCHEMA
            or report["late_differences"] is not None
            or report["process_terminal_required"] is not True
            or report["late_comparison"]!="PENDING_PROCESS_TERMINAL"):
        raise ValueError("child report does not declare a pending process-terminal checkpoint")
    if report["unraisables"]!=[]:raise ValueError("unraisable provider failure")
    expected_status="CHECKPOINT_ORIGINAL_COMPLETE" if lane=="original" else "CHECKPOINT_CANDIDATE_COMPLETE"
    if report["status"]!=expected_status:raise ValueError("finite checkpoint is not complete")
    entries=integer(report["native_or_VM_entries"])
    if lane in ("original","unselected"):
        integer(entries,0)
    elif entries<=0:raise ValueError("selected candidate did not execute its actual entry")
    report=terminal_receipt(directory,record,start,result,report,captured)
    return directory,report


def rows(directory,report,cases):
    s.case_terminals(directory,report,cases)
    count=0
    for ordinal,raw,row in s.json_lines(directory/"observations.jsonl",report["files"]["observations.jsonl"]):
        if ordinal>=len(cases):raise ValueError("extra original row")
        case=cases[ordinal]
        if row["id"]!=case["id"] or row["method"]!=case["method"] or row["scenario"]!=case["scenario"]:
            raise ValueError("full ordered observation identity differs")
        equal(row["outer_exception"],case["outer_exception"],"outer input state differs")
        expected_parts=2 if case["method"]=="generator_protocol" else 1
        integer(len(row["parts"]),expected_parts)
        for index,part in enumerate(row["parts"]):
            if part["unraisable"] or part["thread_errors"]:raise ValueError("unhandled provider/thread result")
            fault=case.get("fault")
            if fault is not None:
                expected=[] if index!=fault["part"] else [{"index":fault["local_index"],
                    **{key:fault[key] for key in ("label","occurrence","phase")}}]
                equal(part["target_hits"],expected,"a complete original fault target was not hit exactly")
        count+=1
        yield row
    integer(count,len(cases));integer(report["count"],len(cases))
    equal(report["ordered_ids"],[case["id"] for case in cases],"complete IDs differ")

def original_authority(path,pin,captured):
    path=Path(path);root=path.parent
    value=capture(path,pin,captured)
    if (value["schema"]!="hepta.hia.service-bootstrap-original-authority.v3"
            or value.get("case_terminal_protocol")!=s.CASE_TERMINAL_SCHEMA
            or value["process_terminal_complete"] is not True
            or value["checkpoint_reports_preserved"] is not True
            or value["late_comparison_scope"]!="CASE_LOCAL_COLLECTION_THEN_NATURAL_PROCESS_EXIT"):
        raise ValueError("wrong complete original authority")
    source=s.source_snapshot()
    equal(value["source_before"],source,"authority current source differs")
    equal(value["source_after"],source,"authority terminal source differs")
    if value["runtime"]!=sys.version or value["implementation"]!=sys.implementation.name:
        raise ValueError("expected observations are from another actual runtime")
    domain=capture(FIXTURE/"observation-domain.json",DOMAIN,captured)
    base=capture(root/"base-inputs.json",value["base_inputs"],captured)
    complete=capture(root/"complete-inputs.json",value["complete_inputs"],captured)
    freeze=capture(root/"derived-input-freeze.json",value["derived_input_freeze"],captured)
    base_cases=domain["cases"];integer(len(base_cases),232)
    equal(base["cases"],base_cases,"original base232 changed")
    equal(base["original_domain"],DOMAIN,"base source pin differs")
    equal(base["basis_ids"],list(BASIS_IDS),"base cutpoint family changed")
    equal(base["fault_families"],domain["fault_families"],"fault family domain changed")
    equal(complete["cases"][:232],base_cases,"complete prefix changed")
    equal(freeze["complete_inputs"],value["complete_inputs"],"derived freeze input pin differs")
    equal(freeze["basis_ids"],list(BASIS_IDS),"derived basis changed")
    equal(freeze["fault_families"],domain["fault_families"],"derived families changed")
    integer(value["base_count"],232)
    integer(value["count"],len(complete["cases"]))
    integer(freeze["count"],len(complete["cases"]))
    ids=[case["id"] for case in complete["cases"]]
    if len(ids)!=len(set(ids)):raise ValueError("complete fault IDs repeat")
    equal(value["ordered_ids"],ids,"authority domain IDs differ")
    equal(freeze["ordered_ids"],ids,"freeze domain IDs differ")
    labels=["basis-first","basis-second","complete-first","complete-second"]
    equal([lane["label"] for lane in value["lanes"]],labels,"four complete original lanes required")
    lanes={}
    for record in value["lanes"]:
        directory,report=receipt(root,record["label"],record,captured,source,lane="original",seconds=600)
        expected_input=value["base_inputs"] if record["label"].startswith("basis") else value["complete_inputs"]
        equal(report["input"],expected_input,"original input bytes differ")
        lanes[record["label"]]=(directory,report)
    basis_records={}
    for label,(directory,report) in lanes.items():
        cases=base_cases if label.startswith("basis") else complete["cases"]
        for row in rows(directory,report,cases):
            if label=="basis-first" and row["id"] in BASIS_IDS:basis_records[row["id"]]=row
    if set(basis_records)!=set(BASIS_IDS):raise ValueError("original basis records incomplete")
    rebuilt=list(base_cases);by_id={case["id"]:case for case in base_cases}
    for identity in BASIS_IDS:
        original=basis_records[identity]
        for hit in original["hits"]:
            part=original["parts"][hit["part"]]
            first=min((failure["index"] for failure in part["scenario_faults"]),default=None)
            for family in domain["fault_families"]:
                target={**hit,"family":family}
                if first is not None and hit["local_index"]<=first:
                    target["replace_scenario_at_or_after"]=hit["local_index"]
                rebuilt.append({**by_id[identity],"id":identity+".fault."+str(hit["index"])+"."+family,"fault":target})
    equal(rebuilt,complete["cases"],"complete derived domain omitted/changed an original target")
    for role in ("basis","complete"):
        left,lp=lanes[role+"-first"];right,rp=lanes[role+"-second"]
        for channel in CHANNELS:
            if not s.identical_files(left/channel,right/channel,lp["files"][channel],rp["files"][channel]):
                raise ValueError("fresh originals differ in the complete "+channel)
    unchanged(captured)
    return value,complete["cases"],lanes["complete-first"],source

def read_finite(directory,authority_path,authority_pin,lane):
    directory=Path(directory);captured=[]
    authority,cases,(original_path,original_report),source=original_authority(authority_path,authority_pin,captured)
    comparison=capture(directory/"report.json",None,captured)
    if comparison["schema"]!="hepta.hia.service-bootstrap-finite-comparison.v3" or comparison["status"]!="PASS_FINITE_ONLY":
        raise ValueError("finite comparison report is incomplete")
    equal(comparison["authority"],authority_pin,"finite authority pin differs")
    equal(comparison["complete_inputs"],authority["complete_inputs"],"comparison input pin differs")
    candidate_path,report=receipt(directory,"candidate",comparison["candidate"],captured,source,lane=lane,seconds=1800)
    equal(report["expected_authority"],authority_pin,"candidate expected authority differs")
    equal(report["input"],authority["complete_inputs"],"candidate parsed input bytes differ")
    _read_finite_source_domains(candidate_path, report, captured, source, lane, comparison)
    for _ in rows(candidate_path,report,cases):pass
    for channel in ("observations.jsonl","late-events.jsonl","case-terminals.jsonl"):
        if not s.identical_files(original_path/channel,candidate_path/channel,
                original_report["files"][channel],report["files"][channel]):
            raise ValueError("full actual/raw original channel differs: "+channel)
    count=0;entries=0
    for ordinal,raw,row in s.json_lines(candidate_path/"entry-counts.jsonl",report["files"]["entry-counts.jsonl"]):
        if ordinal>=len(cases) or row["id"]!=cases[ordinal]["id"]:raise ValueError("entry identity differs")
        n=integer(row["entries"]);entries+=n;count+=1
        unselected=(lane=="unselected" or (cases[ordinal]["method"]=="__init__" and
                     cases[ordinal]["scenario"]=="actual-public-unselected"))
        equal(row["explicit_unselected"],unselected,"public selection scope differs")
        if unselected:integer(n,0)
        elif n==0:raise ValueError("selected case had no actual native/VM entry")
    integer(count,len(cases));integer(report["native_or_VM_entries"],entries)
    progress=[]
    for _,_,row in s.json_lines(candidate_path/"progress.jsonl",report["files"]["progress.jsonl"]):
        progress.append(row)
    equal(progress,[{"event":event,"ordinal":i,"id":case["id"]} for i,case in enumerate(cases) for event in ("start","stop")],
          "not all cases have exact ordered starts/stops")
    ordering=capture(candidate_path/"ordering.json",report["files"]["ordering.json"],captured)
    equal(ordering,["source-and-inputs-captured","all-original-bytes-admitted","candidate-import-and-image"],
          "candidate imports preceded complete originals")
    integer(report["files"]["differences.jsonl"]["bytes"],0)
    integer(report["files"]["late-differences.jsonl"]["bytes"],0)
    if (comparison["late_comparison_scope"]!="CASE_LOCAL_COLLECTION_AND_BOTH_NATURAL_PROCESS_TERMINALS"
            or comparison.get("case_terminal_protocol")!=s.CASE_TERMINAL_SCHEMA
            or comparison.get("complete_case_terminals_equal") is not True
            or comparison["checkpoint_reports_preserved"] is not True
            or comparison["complete_late_byte_equality"] is not True):
        raise ValueError("late equality was not established at both completed process terminals")
    equal(comparison["candidate_report"],comparison["candidate"]["report"],"candidate checkpoint pin differs")
    equal(comparison["candidate_terminal"],report["process_terminal"],"candidate terminal pin differs")
    equal(comparison["original_terminal"],original_report["process_terminal"],"original terminal pin differs")
    integer(comparison["terminal_late_difference_count"],0)
    late_diff=comparison["terminal_late_differences"]
    if type(late_diff) is not dict or set(late_diff)!={"relative","bytes","sha256"} or late_diff["relative"]!="terminal-late-differences.jsonl":
        raise ValueError("terminal late difference file is not the declared owned file")
    late_diff_pin={key:late_diff[key] for key in ("bytes","sha256")}
    stream_identity(directory/late_diff["relative"],late_diff_pin)
    integer(late_diff_pin["bytes"],0)
    # Raw tracebacks are completely retained and hash-bound. Their additional
    # transport frames are not removed or made into business-value expectations.
    trace_count=0
    for i,_,row in s.json_lines(candidate_path/"raw-tracebacks.jsonl",report["files"]["raw-tracebacks.jsonl"]):
        if row["id"]!=cases[i]["id"]:raise ValueError("raw traceback ID differs")
        trace_count+=1
    integer(trace_count,len(cases))
    for field in ("source_before","source_after"):equal(comparison[field],source,"comparison source differs")
    unchanged(captured)
    return {"status":"PASS_READBACK_ONLY","lane":lane,"count":len(cases),"entries":entries,
            "actual_full_raw_equal":True,"complete_late_equal":True,"raw_tracebacks_preserved":True,
            "whole_native_stack_qualified":False}



def _read_current_dispatch_control(value, expected_code, lane):
    if (type(value) is not dict or set(value) != {'schema', 'status', 'domain', 'lane',
            'physical_source', 'actual_public_code', 'current_reference_code', 'option_names',
            'actual_public_complete_code', 'current_reference_complete_code',
            'init_cases', 'init_rows', 'program_cases', 'program_rows', 'current_source_unchanged',
            'retained_poison_calls', 'complete_current_semantics_qualified', 'whole_native_stack_qualified'}
            or value['schema'] != 'hepta.hia.bootstrap-current-dispatch-controls.v3'
            or value['status'] != 'PASS_CURRENT_INIT_AND_PROGRAM_ONLY'
            or value['domain'] != 'CURRENT_PHYSICAL_PUBLIC_DISPATCH' or value['lane'] != lane
            or value['current_source_unchanged'] is not True
            or value['retained_poison_calls'] != []
            or value['complete_current_semantics_qualified'] is not False
            or value['whole_native_stack_qualified'] is not False):
        raise ValueError('current Bootstrap dispatcher scope or evidence differs')
    equal(value['actual_public_code'], expected_code['public'], 'current public source code differs')
    equal(value['current_reference_code'], expected_code['retained'], 'current reference source code differs')
    equal(value['actual_public_complete_code'], expected_code['public_complete'],
          'current complete public source code differs')
    equal(value['current_reference_complete_code'], expected_code['retained_complete'],
          'current complete reference source code differs')
    equal(value['option_names'], ['native_store', 'native_edit_query', 'native_candidate_import'],
          'current constructor option order differs')
    integer(value['init_cases'], 8)
    bits = [[a,b,c] for a in (False,True) for b in (False,True) for c in (False,True)]
    if type(value['init_rows']) is not list or len(value['init_rows']) != 8:
        raise ValueError('current constructor complete option combinations are missing')
    init_events = ['selected_candidate_budget', 'selected_slot_ledger', 'catalog',
                   'installation_manifest', 'AgentStore', 'profiles']
    def entries(row, *, reference):
        n = integer(row['entries'])
        if reference or lane == 'unselected':
            integer(n, 0)
        elif n == 0:
            raise ValueError('selected current dispatcher has no actual entry')
    for row, combination in zip(value['init_rows'], bits):
        if type(row) is not dict or set(row) != {'options', 'reference', 'current', 'actual_service_subclass'}:
            raise ValueError('current constructor observation shape differs')
        equal(row['options'], combination, 'current constructor combination order differs')
        if row['actual_service_subclass'] is not True:
            raise ValueError('current constructor did not use an actual Service subclass')
        for key in ('reference', 'current'):
            item = row[key]
            if (type(item) is not dict or set(item) != {'events', 'entries', 'opaque_option_identity',
                    'complete_state_identity', 'tool_role_and_item_identity', 'profile_calls',
                    'explicit_store_keyword_preserved', 'frame_options_forwarded'}):
                raise ValueError('current constructor result shape differs')
            equal(item['events'], init_events, 'current constructor foreign effect order differs')
            entries(item, reference=key == 'reference')
            for field in ('opaque_option_identity', 'complete_state_identity',
                          'tool_role_and_item_identity', 'explicit_store_keyword_preserved'):
                if item[field] is not True:
                    raise ValueError('current constructor identity or keyword semantics differ')
            integer(item['profile_calls'], 1)
            if item['frame_options_forwarded'] is not (key == 'current' and lane != 'unselected'):
                raise ValueError('current frame option forwarding differs')
    cases = (
        'native-success', 'native-refusal-valid', 'native-refusal-invalid', 'native-throws',
        'store-throws', 'native-getter-order', 'none-reference-override', 'native-reference-throws',
        'none-admission-override', 'native-admission-override',
        'none-reference-default', 'none-reference-invalid',
    )
    events = {
        'native-success': ['store.get', 'native.retained_program'],
        'native-refusal-valid': ['store.get', 'native.retained_program', 'reference_import'],
        'native-refusal-invalid': ['store.get', 'native.retained_program', 'reference_import'],
        'native-throws': ['store.get', 'native.retained_program'],
        'store-throws': ['store.get'],
        'native-getter-order': ['store.get', 'native.getter', 'native.getter', 'native.retained_program'],
        'none-reference-override': ['store.get', 'reference_import'],
        'native-reference-throws': ['store.get', 'native.retained_program', 'reference_import'],
        'none-admission-override': ['store.get', 'admission-override'],
        'native-admission-override': ['store.get', 'admission-override'],
        'none-reference-default': ['store.get', 'reference_import'],
        'none-reference-invalid': ['store.get', 'reference_import'],
    }
    integer(value['program_cases'], len(cases))
    if type(value['program_rows']) is not list or len(value['program_rows']) != len(cases):
        raise ValueError('current retained-program cases are incomplete')
    opaque_returns = {'native-success', 'native-getter-order', 'none-reference-override',
                      'none-admission-override', 'native-admission-override'}
    opaque_errors = {'native-throws', 'store-throws', 'native-reference-throws'}
    for row, case in zip(value['program_rows'], cases):
        if (type(row) is not dict or set(row) != {'case', 'reference', 'current', 'actual_service_subclass'}
                or row['case'] != case or row['actual_service_subclass'] is not True):
            raise ValueError('current retained-program identity or case order differs')
        for key in ('reference', 'current'):
            item = row[key]
            if type(item) is not dict or set(item) != {'events', 'outcome', 'entries'}:
                raise ValueError('current retained-program result shape differs')
            equal(item['events'], events[case], 'current retained-program effect/getter order differs')
            entries(item, reference=key == 'reference')
        equal(row['reference']['outcome'], row['current']['outcome'],
              'current retained-program original and selected outcomes differ')
        outcome = row['current']['outcome']
        if case in opaque_returns:
            equal(outcome, {'kind':'return','type':'object','opaque_identity':True},
                  'current retained-program opaque return identity differs')
        elif case == 'none-reference-default':
            equal(outcome, {'kind':'return','type':'VerifiedProgram','opaque_identity':False,
                            'default_program_exact':True}, 'current default program differs')
        elif case in opaque_errors:
            equal(outcome, {'kind':'raise','type':'LookupError','message':'opaque-provider-failure',
                            'supplied_exception_identity':True}, 'current provider exception identity differs')
        elif case == 'native-refusal-valid':
            equal(outcome, {'kind':'raise','type':'ValueError',
                            'message':'native Agent retained-program refusal disagrees with hosted admission',
                            'supplied_exception_identity':False}, 'current native-refusal diagnostic differs')
        elif (type(outcome) is not dict or set(outcome) != {'kind','type','message','supplied_exception_identity'}
                or outcome['kind'] != 'raise' or outcome['type'] != 'HIAEditRejected'
                or type(outcome['message']) is not str or not outcome['message']
                or outcome['supplied_exception_identity'] is not False):
            raise ValueError('current invalid-source reference diagnostic differs')
    return value

def _read_finite_source_domains(candidate_path, report, captured, source, lane, comparison):
    from tools import hia_bootstrap_source_history as history
    reader = captured_bytes(ROOT / history.HELPER, source[history.HELPER], captured)
    if Path(history.__file__).read_bytes() != reader:
        raise ValueError('Bootstrap source relation reader differs from captured bytes')
    historical, expected, saved = history.capture(ROOT, take=lambda path:
        captured_bytes(path, source[path.relative_to(ROOT).as_posix()], captured))
    expected.update(history.graph_bindings(saved[history.SOURCE], historical))
    equal(report['candidate_source_domain'],
          'HISTORICAL_FIVE_BODY_COMPATIBILITY',
          'Bootstrap candidate historical/current domain differs')
    proof = capture(candidate_path/'historical-source-binding.json',
                    report['files']['historical-source-binding.json'], captured)
    equal(proof, expected, 'complete historical source binding differs')
    equal(report['public_code_binding'], expected['historical_code']['public'],
          'historical public wrappers do not match the restored full source')
    current = _read_current_dispatch_process(
        candidate_path, report, captured, source, lane, comparison, expected['current_code'])
    equal(current['physical_source'], expected['physical_source'],
          'current dispatcher physical source differs')
    history.unchanged(ROOT, saved, take=lambda path:
        captured_bytes(path, source[path.relative_to(ROOT).as_posix()], captured))
    return {'historical_source': proof, 'current_dispatch': current}


def _read_current_dispatch_process(candidate_path, candidate, captured, source, lane, comparison, expected_code):
    record = comparison['current_dispatch']
    if (type(record) is not dict or set(record) != {'label', 'start', 'result', 'report'}
            or record['label'] != 'current-dispatch'):
        raise ValueError('current dispatcher owned process record differs')
    parent = Path(candidate_path).parent
    report, result, start = owned_child(
        parent, 'current-dispatch', 'tests/hia_bootstrap_current_dispatch.py',
        60, captured, fixed=record)
    if (report['schema'] != 'hepta.hia.bootstrap-current-dispatch-process.v1'
            or report['status'] != 'PASS_CURRENT_INIT_AND_PROGRAM_PROCESS_ONLY'
            or report['lane'] != lane or report['whole_native_stack_qualified'] is not False):
        raise ValueError('current dispatcher fresh process scope differs')
    if (integer(report['pid']) == 0
            or report['pid'] == candidate['pid']
            or integer(report['pgid']) == candidate['pgid']):
        raise ValueError('current dispatcher shares the historical process or group')
    for field in ('source_before', 'source_after'):
        equal(report[field], source, 'current dispatcher actual source differs')
    equal(report['manifest'], comparison['manifest'], 'current dispatcher actual manifest differs')
    terminal = capture(Path(candidate_path) / 'process-terminal.json',
                       comparison['candidate_terminal'], captured)
    if (integer(start['started_time_ns']) < integer(terminal['sealed_time_ns'])
            or integer(result['ended_time_ns']) < start['started_time_ns']):
        raise ValueError('current controls ran before historical natural-terminal admission')
    command = [report['executable'], '-I', '-B',
               str(ROOT / 'tests/hia_bootstrap_current_dispatch.py'),
               '--lane', lane, '--output', str(parent / 'current-dispatch')]
    if lane == 'native':
        argv = candidate['argv']
        if argv.count('--manifest') != 1 or argv.index('--manifest') + 1 >= len(argv):
            raise ValueError('historical native manifest argument differs')
        command += ['--manifest', argv[argv.index('--manifest') + 1]]
    equal(start['command'], command, 'current controls do not use the declared exact invocation')
    integer(result['stdout']['bytes'], 0)
    current = report['current_dispatch']
    return _read_current_dispatch_control(current, expected_code, lane)


def owned_child(parent,label,filename,seconds,captured,*,fixed=None,stderr_empty=True):
    parent=Path(parent)
    fixed={} if fixed is None else fixed
    start=capture(parent/(label+".start.json"),fixed.get("start"),captured)
    result=capture(parent/(label+".result.json"),fixed.get("result"),captured)
    pin={key:result["report"][key] for key in ("bytes","sha256")}
    if fixed.get("report") is not None:equal(pin,fixed["report"],"fixed child report pin changed")
    report=capture(parent/label/"report.json",pin,captured)
    integer(start["pid"]);integer(start["pgid"],start["pid"])
    for item in (result,report):
        integer(item["pid"],start["pid"]);integer(item["pgid"],start["pid"])
    for item in (start,result):
        integer(item["timeout_seconds"],seconds);integer(item["cleanup_seconds"],3)
    integer(result["returncode"],0)
    if (result["timeout"] is not False or result["reaped"] is not True
            or result["cleanup_error"] is not None or result["supervisor_error"] is not None
            or result["cleanup"]["reaped"] is not True
            or result["cleanup"]["after"]!=[] or result["cleanup"]["signals"]!=[]):
        raise ValueError("child execution/cleanup is not complete natural success")
    equal(result["command"],start["command"],"child result command differs")
    equal(report["argv"],start["command"][3:],"child inner argv differs")
    equal(start["command"][:3],[report["executable"],"-I","-B"],"isolated child prefix differs")
    if Path(start["command"][3]).resolve()!=ROOT/filename:
        raise ValueError("child is not the declared full source program")
    for item in (start,result,report):
        if item["cwd"]!=str(ROOT):raise ValueError("child cwd differs")
    if report["runtime"]!=sys.version:raise ValueError("child runtime differs")
    for suffix in ("stdout","stderr"):
        stream_identity(parent/(label+"."+suffix+".log"),result[suffix])
    if stderr_empty:integer(result["stderr"]["bytes"],0)
    return report,result,start

def captured_bytes(path,expected,captured):
    path=Path(path);raw=path.read_bytes()
    if expected is not None:equal(s.bytes_pin(raw),s.require_pin(expected),"consumed bytes differ")
    captured.append((path,raw));return raw

def actual_manifest_list(path,pin,captured):
    declarations=capture(path,pin,captured)
    if set(declarations)!={"bootstrap","store","transaction","context","candidate","ledger"}:
        raise ValueError("all six actual same-attempt images are required")
    manifest_schemas={
        "bootstrap":"hepta.hia.service-bootstrap.v1",
        "store":"hepta.hia.store-artifact-profile.v1",
        "transaction":"hepta.hia.store-transaction.v1",
        "context":"hepta.hia.service-context-native.v1",
        "candidate":"hepta.hia.candidate-budget-native.v1",
        "ledger":"hepta.hia.slot-ledger-native.v1"}
    source_stems={"bootstrap":"service_bootstrap","store":"store_artifact_profile",
        "transaction":"store_transaction","context":"service_context","candidate":"candidate_budget",
        "ledger":"slot_ledger"}
    images={};values={}
    for key,filename in declarations.items():
        path0=Path(filename)
        manifest=capture(path0,None,captured)
        if manifest["schema"]!=manifest_schemas[key] or Path(manifest["image_path"]).name!=manifest["image_path"]:
            raise ValueError("wrong image schema/sibling path")
        source_name="examples/hia_bootstrap/"+source_stems[key]+".hepta"
        source=captured_bytes(ROOT/source_name,None,captured)
        image=captured_bytes(path0.parent/manifest["image_path"],None,captured)
        equal(manifest["source_sha256"],s.bytes_pin(source)["sha256"],"manifest source identity differs")
        equal(manifest["image_sha256"],s.bytes_pin(image)["sha256"],"manifest image bytes differ")
        images[key]={"image":s.bytes_pin(image)}
        # Pin comes from the same raw already parsed, never a later promoted hash.
        images[key]["manifest"]=s.bytes_pin(next(raw for p,raw in reversed(captured) if p==path0))
        values[key]=(path0,manifest,source,image)
    return declarations,images,values

def literal_assignment(path,name,captured):
    raw=captured_bytes(path,None,captured)
    tree=ast.parse(raw)
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("literal source declaration missing: "+name)

def native_cold_inputs(path,cold,captured):
    from tools.hia_component_cold_readback import native_cold_inputs as read_inputs
    inputs=read_inputs(ROOT,path,read=lambda member:captured_bytes(member,None,captured))
    if not inputs.native:
        raise ValueError("native readback cannot substitute a hosted cold domain")
    equal(inputs.report,cold,"native original cold report differs")
    for member,raw in inputs.files:
        equal(captured_bytes(member,None,captured),raw,"actual native cold input changed")
    inputs.unchanged()
    return inputs

def native_source_custody(inputs,source,captured):
    from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS
    values={name:captured_bytes(ROOT/name,pin,captured) for name,pin in source.items()}
    values.update({name:captured_bytes(ROOT/name,None,captured) for name in NATIVE_CUSTODY_INPUTS})
    return inputs.capture_custody(values,root=ROOT)

def native_builder_input_names(path,captured):
    """Read explicit source declarations without executing builders or products."""
    raw=captured_bytes(path,None,captured)
    names={}
    def read(node,local):
        if isinstance(node,ast.Constant) and type(node.value)is str:return node.value
        if isinstance(node,ast.Name) and node.id in local:return local[node.id]
        if isinstance(node,(ast.Tuple,ast.List)):
            result=[]
            for item in node.elts:
                if isinstance(item,ast.Starred):result.extend(read(item.value,local))
                else:result.append(read(item,local))
            return tuple(result)
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            return read(node.left,local)+read(node.right,local)
        if isinstance(node,ast.JoinedStr):
            return ''.join(read(part,local) for part in node.values)
        if isinstance(node,ast.FormattedValue) and node.conversion==-1 and node.format_spec is None:
            value=read(node.value,local)
            if type(value)is str:return value
        if isinstance(node,ast.GeneratorExp) and len(node.generators)==1:
            clause=node.generators[0]
            if isinstance(clause.target,ast.Name) and not clause.is_async and not clause.ifs:
                return tuple(read(node.elt,{**local,clause.target.id:value})
                             for value in read(clause.iter,local))
        raise ValueError("unsupported explicit native builder input declaration")
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in ("SOURCE_NAME","ORIGINAL_DIRECTORY","METHOD_NAMES","INPUTS"):
                if key in names:raise ValueError("duplicate builder input declaration")
                names[key]=read(node.value,names)
    result=names.get("INPUTS")
    if type(result)is not tuple or not result or len(result)!=len(set(result)) or any(
            type(name)is not str or Path(name).is_absolute() or ".." in Path(name).parts for name in result):
        raise ValueError("native builder input whitelist differs")
    return result

def native_component_custody(build,inputs,captured):
    from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS
    builders={"hepta.hia.service-bootstrap.v1":"service_bootstrap",
              "hepta.hia.store-artifact-profile.v1":"store_artifact_profile",
              "hepta.hia.store-transaction.v1":"store_transaction",
              "hepta.hia.service-context-native.v1":"service_context"}
    schema=build["manifest"]["schema"]
    if schema not in builders:raise ValueError("undeclared native component custody owner")
    names=native_builder_input_names(ROOT/("tools/build_hia_"+builders[schema]+".py"),captured)
    values={name:captured_bytes(ROOT/name,None,captured) for name in names}
    equal(build["component_inputs"],{name:s.bytes_pin(raw)["sha256"] for name,raw in values.items()},
          "native component fixed input whitelist or actual bytes differ")
    development={name:captured_bytes(ROOT/name,None,captured) for name in NATIVE_CUSTODY_INPUTS}
    equal(build.get("development_inputs"),{name:s.bytes_pin(raw)["sha256"] for name,raw in development.items()},
          "native component development dependencies differ")
    custody=inputs.capture_custody({**values,**development},root=ROOT)
    equal(build.get("component_input_custody"),custody,"native component source/Git custody differs")

def construction(root,pin,captured,source,*,require_cold):
    root=Path(root)
    report=capture(root/"construction.json",pin,captured)
    compiler_path=Path(report["compiler_path"])
    compiler=captured_bytes(compiler_path,report["compiler"],captured)
    cold=None;native_inputs=None
    if report["scope"]=="MATCHING_SOURCE_COLD":
        cold=capture(report["cold_report_path"],report["cold_report"],captured)
        from tools.hia_native_cold_admission import SCHEMA
        if cold.get("schema")==SCHEMA:
            native_inputs=native_cold_inputs(report["cold_report_path"],cold,captured)
            if native_inputs.compiler!=compiler_path.absolute() or native_inputs.compiler_bytes!=compiler:
                raise ValueError("native construction compiler path or bytes differ")
            native_source_custody(native_inputs,source,captured)
        else:
            required={
                "export_manifest_matches_qualification","isolated_python_without_site",
                "nested_full_qualification_pass","nested_process_exit_zero","no_ancestor_git_identity",
                "no_bytecode_cache_created","no_inherited_home_or_python_cache",
                "no_inherited_seed_or_successor_images","origin_hashes_preserved",
                "owned_process_tree_cleanup_confirmed","source_export_hashes_preserved"}
            profile=literal_assignment(ROOT/"tools/hia_selfhost_contract.py","PROFILE",captured)
            if (cold["schema"]!="hepta.hia.selfhost-cold-replay.v1" or cold["profile"]!=profile
                    or cold["status"]!="COLD_SELFHOST_REPLAY_PASS" or set(cold["checks"])!=required
                    or any(v is not True for v in cold["checks"].values())):
                raise ValueError("matching complete cold admission differs")
            integer(cold["returncode"],0)
            equal(cold["generation_sha256"],[report["compiler"]["sha256"]]*3,"cold compiler generations differ")
            full=cold["source_manifest"]
            contract_path=literal_assignment(ROOT/"tools/hia_selfhost_contract.py","CONTRACT_PATH",captured)
            contract=capture(ROOT/contract_path,None,captured)
            expected={**contract["source_identity"]["files"]}
            expected[contract_path]=s.bytes_pin(next(raw for p,raw in reversed(captured) if p==ROOT/contract_path))["sha256"]
            equal(full,expected,"cold full declared source map differs")
            for name,digest in full.items():
                if type(name) is not str or Path(name).is_absolute() or ".." in Path(name).parts:
                    raise ValueError("cold source leaves the product root")
                raw_source=captured_bytes(ROOT/name,None,captured)
                equal(s.bytes_pin(raw_source)["sha256"],digest,"cold current source bytes differ")
            for name,value in source.items():
                if full.get(name)!=value["sha256"]:raise ValueError("component source is not in this cold")
            nested=capture(cold["nested_report"],None,captured)
            if Path(nested["generations"][-1]["produced_image"]).resolve()!=compiler_path.resolve():
                raise ValueError("cold compiler path differs")
    elif report["scope"]=="DEVELOPMENT_ONLY":
        if require_cold or report["cold_report"] is not None or report["cold_report_path"] is not None:
            raise ValueError("DEV evidence cannot satisfy matching-cold qualification")
    else:raise ValueError("undeclared construction scope")
    declarations,images,values=actual_manifest_list(root/"manifest-list.json",None,captured)
    equal(report["manifests"],images,"construction images differ")
    for key,(manifest_path,manifest,source_raw,image) in values.items():
        if manifest["compiler_sha256"]!=report["compiler"]["sha256"]:
            raise ValueError("companion image used a different actual compiler")
        build=capture(manifest_path.parent/"build.json",None,captured)
        equal(build["manifest"],manifest,"builder manifest differs")
        equal(build["cold_report_sha256"],None if cold is None else report["cold_report"]["sha256"],
              "builder cold authority differs")
        if cold is not None:
            equal(build["source_manifest"],cold["source_manifest"],"builder complete source differs")
        elif build.get("source_manifest") is not None:
            raise ValueError("development builder invented cold source admission")
        if "component_inputs" in build:
            from tools.hia_component_cold_readback import read_component_inputs
            read_component_inputs(ROOT,build,compiler,None if cold is None else report["cold_report_path"],
                read=lambda path:captured_bytes(path,None,captured))
            if key=="bootstrap":
                equal(build["component_inputs"],{name:value["sha256"] for name,value in source.items()},
                      "complete bootstrap source snapshot differs from its builder inputs")
            if native_inputs is not None:
                native_component_custody(build,native_inputs,captured)
        verify_pack(manifest_path,manifest,build,compiler,source_raw,image,captured)
    unchanged(captured)
    return report,declarations,images

def verify_pack(manifest_path,manifest,build,compiler,source_raw,image,captured):
    receipt0=build["native_compile_receipt"]
    produced=Path(receipt0["produced_image"])
    if produced.resolve()!=(manifest_path.parent/manifest["image_path"]).resolve():
        raise ValueError("native receipt publishes a different image")
    if not produced.name.endswith(".image.bin"):raise ValueError("unexpected native output suffix")
    stem=produced.name[:-len(".image.bin")]
    receipt1=capture(manifest_path.parent/(stem+".receipt.json"),None,captured)
    equal(receipt0,receipt1,"raw native pack receipt differs")
    full_output=captured_bytes(manifest_path.parent/(stem+".output.bin"),None,captured)
    size=integer(receipt1["core_u32"])
    integer(receipt1["result_u64"],size);integer(receipt1["abi_status"],0)
    integer(receipt1["input_bytes"],len(source_raw));integer(receipt1["produced_bytes"],len(image))
    if not 0<size<=len(full_output)<=1<<20 or size!=len(image):
        raise ValueError("native pack length/capacity differs")
    for field,value in {
        "status":"returned","format":"flat-x86-64","return_encoding":"zero-extended-u32",
        "output_sha256":s.bytes_pin(full_output)["sha256"],
        "artifact_sha256":s.bytes_pin(compiler)["sha256"],
        "image_sha256":s.bytes_pin(compiler)["sha256"],
        "input_sha256":s.bytes_pin(source_raw)["sha256"],
        "source_sha256":s.bytes_pin(source_raw)["sha256"],
        "produced_sha256":s.bytes_pin(image)["sha256"]}.items():
        equal(receipt1[field],value,"complete pack field differs: "+field)
    if receipt1["source_unchanged"] is not True or receipt1["forbidden_compiler_modules_loaded"]!=[]:
        raise ValueError("native pack source/compiler custody differs")
    if full_output[:size]!=image:raise ValueError("published image differs from complete native output")


def read_control(root,action,source,images,captured,manifest_pin):
    label="lazy" if action=="lazy" else "control-"+action
    report,result,start=owned_child(root,label,"tests/hia_service_bootstrap_controls.py",180,captured)
    if report["schema"]!="hepta.hia.service-bootstrap-controls.v1" or report["status"]!="PASS_CONTROL_ONLY":
        raise ValueError("control report did not complete")
    equal(report["action"],action,"wrong actual control action")
    equal(report["source_before"],source,"control source differs")
    equal(report["source_after"],source,"control final source differs")
    if action!="lazy":
        equal(report["manifest_list"],manifest_pin,"control manifests differ")
        equal(report["images_before"],images,"control actual image before differs")
        equal(report["images_after"],images,"control actual image after differs")
    value=report["observation"]
    if action=="lazy":
        if value["empty_provider_effects"]!=0 or value["absent_imported_owner"] is not False:
            raise ValueError("lazy/empty real public refusal differs")
        equal(value["empty_methods"],["__init__","close","_profiles","_profile","_program"],"five public refusals missing")
    elif action=="public":
        integer(len(value["rows"]),5)
        if value["all_five_methods"] is not True or value["retained_poisoned"] is not True:
            raise ValueError("complete public/poison controls missing")
        for row in value["rows"]:
            if integer(row["entries"])<=0:raise ValueError("public control had no actual entry")
            for part in row["observation"]["parts"]:
                if part["outcome"]["kind"]!="return":raise ValueError("normal public control failed")
    elif action=="packets":
        equal(value["fresh_machine_limits"],[4_000_000,16<<20,128],"VM packet budgets differ")
        integer(value["provider_effects"],0)
        if value["complete_request_output_state_bytes"] is not True:raise ValueError("packet byte scope differs")
        expected=["valid-initialize","magic","sequence","port","observation","mode","nonce","reserved",
                  "short-buffer-0","short-buffer-1","short-buffer-2",
                  *["state-byte-"+str(i) for i in (0,8,16,24,40,48,80,184)],
                  "valid-claim","valid-ack","replayed-ack"]
        equal([row["label"] for row in value["records"]],expected,"packet controls omitted/reordered")
        for row in value["records"]:
            integer(row["native_code"]);integer(row["VM_code"],row["native_code"])
            equal(row["native"],row["VM"],"full VM/native packet bytes differ")
            integer(len(row["native"]),3)
            for size,actual,before in zip(row["sizes"],row["native"],row["before"]):
                integer(size);integer(len(bytes.fromhex(actual)),size);integer(len(bytes.fromhex(before)),size)
    elif action=="loss":
        equal([row["case"] for row in value["rows"]],
              ["prepare-pack","return-lost","output-magic","request-corrupt","state-canary",
               "MemoryError","KeyboardInterrupt","SystemExit"],"complete loss controls differ")
        for row in value["rows"]:
            integer(row["actual_entries"],0 if row["case"]=="prepare-pack" else 1)
            if row["case"]!="prepare-pack":integer(row["retained_loss_delta"],1)
        if value["rows"][0]["same_error"] is not True:raise ValueError("preparation identity changed")
    elif action=="ownership":
        equal(value["controls"],["thread-refused-parent-remains-live","completed-frame-refused",
            "fork-refused-parent-remains-live","same-frame-reentry-before-cleanup",
            "fresh-context-has-no-invented-ancestor"],"ownership controls incomplete")
    elif action=="loader":
        equal(value["controls"],["source_sha256","image_sha256","schema","image_path"],"loader controls incomplete")
        if value["production_source_modified"] is not False:raise ValueError("drift mutated product source")
    else:
        equal(value["controls"],["undeclared-copy","nested-worker","worker-thread","binding-after-scope",
                                "unselected-worker"],"pinned scope controls incomplete")
        if value["exact_image"] is not True:raise ValueError("pinned scope mapped a different image")
    unchanged(captured)
    return {"action":action,"status":"PASS_READBACK_ONLY"}



def record_rows(raw):
    rows={}
    for row in csv.reader(io.StringIO(raw.decode("utf-8"))):
        if len(row)!=3 or row[0] in rows:raise ValueError("duplicate or malformed RECORD row")
        rows[row[0]]=tuple(row[1:])
    return rows

def zip_installation(root,expected,captured):
    import configparser
    installed=Path(root)/"installed"
    wheels=list((Path(root)/"wheels").glob("*.whl"))
    if len(wheels)!=1:raise ValueError("installed gate did not use exactly one wheel")
    wheel=wheels[0];wheel_raw=captured_bytes(wheel,expected["wheel"],captured)
    files={};extra={}
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)):raise ValueError("duplicate wheel member")
        record_name,=[name for name in names if name.endswith(".dist-info/RECORD")]
        original_record=archive.read(record_name)
        equal(s.bytes_pin(original_record),expected["wheel_record"],"wheel RECORD bytes differ")
        old=record_rows(original_record)
        if set(old)!={name for name in names if not name.endswith("/")}:
            raise ValueError("wheel RECORD does not enumerate the entire regular wheel")
        for name,(digest,size) in old.items():
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("wheel path leaves its root")
            raw=archive.read(name)
            encoded="sha256="+base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
            if name==record_name:
                equal((digest,size),("",""),"RECORD self row differs")
            else:
                equal((digest,size),(encoded,str(len(raw))),"full wheel RECORD content differs")
                actual=captured_bytes(installed/name,s.bytes_pin(raw),captured)
                if actual!=raw:raise ValueError("actual installed bytes differ from wheel")
                files[name]=s.bytes_pin(raw)
        installed_record=captured_bytes(installed/record_name,
            {key:expected["installed_record"][key] for key in ("bytes","sha256")},captured)
        now=record_rows(installed_record)
        for name,value in old.items():equal(now.get(name),value,"an original RECORD row changed")
        directory=str(Path(record_name).parent)
        additions={"../../bin/hia",directory+"/INSTALLER",directory+"/REQUESTED",directory+"/direct_url.json"}
        if set(now)-set(old)!=additions:raise ValueError("pip metadata addition set changed")
        for name in sorted(additions):
            actual_relative="bin/hia" if name=="../../bin/hia" else name
            raw=captured_bytes(installed/actual_relative,None,captured)
            digest="sha256="+base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
            equal(now[name],(digest,str(len(raw))),"actual metadata bytes differ from RECORD")
            extra[name]={"actual_relative":actual_relative,**s.bytes_pin(raw)}
        if (installed/directory/"INSTALLER").read_bytes()!=b"pip\n" or (installed/directory/"REQUESTED").read_bytes()!=b"":
            raise ValueError("installer markers changed")
        direct=capture(installed/directory/"direct_url.json",expected["direct_url"],captured)
        equal(direct["url"],wheel.resolve().as_uri(),"direct_url URI differs")
        equal(direct["archive_info"]["hashes"],{"sha256":expected["wheel"]["sha256"]},"direct_url wheel differs")
        config=configparser.ConfigParser()
        config.read_string(archive.read(directory+"/entry_points.txt").decode())
        module,function=map(str.strip,config["console_scripts"]["hia"].split(":"))
        console=(installed/"bin/hia").read_text()
        if "from "+module+" import "+function not in console or "sys.exit("+function+"())" not in console:
            raise ValueError("actual installed console script differs")
    equal(expected["wheel_member_files"],files,"full installed source/data files differ")
    equal(expected["installed_additions"],extra,"actual installed metadata mapping differs")
    integer(expected["common_rows"],len(old));integer(expected["installed_rows"],len(now))
    if expected["RECORD_file_bytes_expected_identical"] is not False:
        raise ValueError("pip RECORD is being misrepresented as byte-identical to wheel RECORD")
    equal(expected["installed_record"]["path"],record_name,"installed RECORD path differs")
    packaged=installed/"hepta/_data/examples/hia_bootstrap/service_bootstrap_word.hepta"
    actual=captured_bytes(packaged,None,captured)
    source=captured_bytes(ROOT/"examples/hia_bootstrap/service_bootstrap_word.hepta",None,captured)
    if actual!=source:raise ValueError("installed bootstrap HIA source differs")
    return installed

def installed_worker_identity(installed,identity,captured):
    path=installed/"hepta/hia_agent_contract.py"
    entries={}
    for file in sorted((installed/"hepta").rglob("*.py")):
        relative=file.relative_to(installed/"hepta")
        if relative.parts[0]=="_data":continue
        entries[str(file.relative_to(installed))]=s.bytes_pin(captured_bytes(file,None,captured))["sha256"]
    discovery=literal_assignment(path,"DISCOVERY_FILES",captured)
    sources=[]
    for name in ("NATIVE_SOURCE_FILES","SOURCE_BUILD_FILES","COMPILER_BUILD_FILES","PUBLICATION_BUILD_FILES",
                 "BACKEND_BUILD_FILES","EMITTER_BUILD_FILES","BYTE_WRAPPER_BUILD_FILES","MACHINE_OBJECT_BUILD_FILES",
                 "EXECUTION_OBSERVATION_BUILD_FILES","CONTINUATION_BUILD_FILES"):
        values=literal_assignment(path,name,captured)
        if type(values) is not tuple or any(type(value) is not str for value in values):
            raise ValueError("installed declared build resources are not their fixed tuple")
        sources.extend(values)
    for name in [*["docs/"+name for name in discovery],*sources]:
        if Path(name).is_absolute() or ".." in Path(name).parts:raise ValueError("installed data path escapes")
        entries[name]=s.bytes_pin(captured_bytes(installed/"hepta/_data"/name,None,captured))["sha256"]
    equal(identity["worker_sha256"],sha256(s.canonical(entries)).hexdigest(),"actual full installed worker hash differs")
    equal(identity["catalog_sha256"],entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"],"installed catalog differs")
    value=identity["backend_sha256"]
    if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("actual worker backend identity is not a SHA256")
    # Backend identity is the real worker CLI result and is propagated exactly.
    # Reading it is not an execution or independent qualification of the backend.
    return {"full_worker_and_catalog_recomputed":True,"backend_identity_from_actual_CLI":value}

def read_installed_describe_requests(directory,record,commands,observations,identity,
                                    installed,bundle_path,bundle_sha,captured):
    """Read both versioned request kinds from their own captured bytes."""
    directory=Path(directory)
    labels=["worker-first","worker-replay","worker-manifest-first","worker-manifest-replay"]
    equal(record["schema"],"hepta.hia.installed-describe-controls.v2","request-control schema differs")
    equal(record["status"],"PASS_REQUEST_CONTROLS_ONLY","request controls incomplete")
    equal(record["ordered_labels"],labels,"installed request order differs")
    integer(record["new_worker_commands"],2)
    for name in ("durable_request_key_supplied","cached_journal_replay_claimed"):
        if record[name] is not False:raise ValueError("describe cannot claim keyed cache replay")
    for name in ("malformed_repeated_rejection_checked","valid_manifest_completed_repeat_checked"):
        if record[name] is not True:raise ValueError("request class was not checked")
    equal(sorted(record["cases"]),["malformed","manifest"],"request class inventory differs")
    catalog=capture(ROOT/"docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json",None,captured)
    tool,=[item for item in catalog["tools"] if item["name"]=="hia_describe"]
    equal(tool["inputSchema"]["required"],["section"],"actual describe required field changed")
    if ("manifest" not in tool["inputSchema"]["properties"]["section"]["enum"]
            or "request_key" in tool["inputSchema"]["properties"]
            or tool["inputSchema"]["additionalProperties"] is not False):
        raise ValueError("actual describe request/repeat contract differs")
    event_expected=[];previous=None
    flags=["--expected-worker-sha256",identity["worker_sha256"],
           "--expected-backend-sha256",identity["backend_sha256"],
           "--expected-catalog-sha256",identity["catalog_sha256"]]
    for kind,arguments,pair,filename in (
            ("malformed",{},labels[:2],"worker-request.json"),
            ("manifest",{"section":"manifest"},labels[2:],"worker-manifest-request.json")):
        case=record["cases"][kind]
        equal(case["file"],filename,"request source filename differs")
        equal(case["labels"],pair,"request pair differs")
        request=capture(directory/filename,case["pin"],captured)
        expected={"schema":"hia-agent-worker-request-v1","tool":"hia_describe","arguments":arguments,
                  "profile_sha256":"a"*64,"catalog_sha256":identity["catalog_sha256"]}
        expected["request_sha256"]=sha256(s.canonical(expected)).hexdigest()
        equal(request,expected,"actual installed request is not the declared original shape")
        equal(case["value"],request,"request aggregate changed from captured raw")
        body=s.canonical(request)
        raw=next(raw for path,raw in reversed(captured) if path==directory/filename)
        if raw!=body+b"\n":raise ValueError("request file is not the exact declared worker body")
        equal(case["stdin"],s.bytes_pin(body),"worker stdin pin differs")
        expected_id="r-"+sha256(s.canonical({"tool":"hia_describe","arguments":arguments})).hexdigest()
        first=None
        for label in pair:
            observation=observations[label]
            equal(observation["request_kind"],kind,"worker received wrong request class")
            equal(observation["request"],case["pin"],"worker request source pin differs")
            equal(observation["stdin"],case["stdin"],"worker stdin changed")
            argv=commands[label]["command"]["argv"]
            equal(argv[3:],[str(directory/"worker.py"),str(installed),
                "--state-root",str(directory/"worker-state"),"--artifact-root",str(directory/"files"),
                "--request-json-stdin","--native-helpers-manifest",str(bundle_path),
                "--expected-native-helpers-sha256",bundle_sha,*flags],
                "actual installed request argv or expected flags differs")
            raw=captured_bytes(directory/label/"stdout.log",observation["stdout"],captured)
            if captured_bytes(directory/label/"stderr.log",observation["stderr"],captured)!=b"":
                raise ValueError("successful/rejected correlated worker wrote stderr")
            value=s.parse(raw)
            equal(value,observation["response"],"full worker response changed")
            equal(sorted(value),sorted({"schema","tool","request_sha256","profile_sha256","catalog_sha256",
                "backend_sha256","worker_sha256","complete","response","native_helpers_sha256"}),
                "worker response envelope fields differ")
            equal(value["schema"],"hia-agent-worker-report-v1","worker report schema differs")
            if value["complete"] is not True:raise ValueError("worker did not attest its response")
            for name in ("tool","request_sha256","profile_sha256","catalog_sha256"):
                equal(value[name],request[name],"actual worker request correlation differs")
            for name in ("worker_sha256","backend_sha256","catalog_sha256"):
                equal(value[name],identity[name],"worker actual identity differs")
            equal(value["native_helpers_sha256"],bundle_sha,"worker used another native bundle")
            response=value["response"]
            equal(response["request_id"],expected_id,"response request ID differs")
            equal(response["contract_version"],"hepta.hia.agent-native.v1","response contract differs")
            if kind=="malformed":
                equal(sorted(response),["contract_version","error","request_id","status"],
                      "malformed request response fields differ")
                equal(response["status"],"rejected","old malformed request was not rejected")
                equal(response["error"],{"code":"E_HIA_SCHEMA","phase":"admission",
                    "message":"arguments: missing fields section","retry_action":"correct_input",
                    "details_artifact":None},"old schema refusal changed")
            else:
                equal(sorted(response),["contract_version","request_id","result","status"],
                      "valid manifest response fields differ")
                equal(response["status"],"completed","valid manifest request did not complete")
                result=value["response"]["result"]
                equal(sorted(result),sorted(tool["outputSchema"]["properties"]["result"]["required"]),
                      "complete manifest result fields differ")
                equal(result["catalog_sha256"],identity["catalog_sha256"],"manifest catalog differs")
                equal(result["resources"],[result["manifest"]],"manifest resource route differs")
                if result["next_cursor"] is not None:raise ValueError("unexpected manifest continuation")
            data=capture(directory/label/"database.json",observation["database_pin"],captured)
            equal(data,observation["database"],"complete original database snapshots differ")
            equal(sorted(data),["artifacts","costs","profiles","requests"],"original four-table scope differs")
            equal(data["requests"],[],"describe invented a keyed journal request")
            costs=data["costs"];old=[] if previous is None else previous["costs"]
            integer(len(costs),len(old)+1)
            equal(costs[:-1],old,"existing cost rows changed")
            last=costs[-1]
            equal(last["context_id"],None,"describe acquired a context")
            equal(last["tool"],"hia_describe","cost tool differs")
            equal(last["request_id"],expected_id,"cost event request differs")
            equal(last["status"],response["status"],"cost status differs")
            if type(last["wall_ns"]) is not str or not last["wall_ns"].isdecimal():
                raise ValueError("actual cost elapsed value is not its original decimal string")
            equal(s.parse(last["details"].encode()),{"error":response.get("error"),"replayed":False},
                  "actual cost details changed or repeat was relabelled cached")
            if first is None:first=(raw,data)
            else:
                if raw!=first[0]:raise ValueError("repeated worker full raw stdout differs")
                for name in ("requests","artifacts","profiles"):
                    equal(data[name],first[1][name],"repeated request changed original non-cost table")
            previous=data
            event_expected.extend((
                {"event":"start","id":label,"kind":kind,"stdin":case["stdin"]},
                {"event":"stop","id":label,"kind":kind,"status":response["status"],
                 "stdout":observation["stdout"],"database":observation["database_pin"]}))
    event_raw=captured_bytes(directory/"worker-request-events.jsonl",record["events"],captured)
    expected_raw=b"".join(s.canonical(row)+b"\n" for row in event_expected)
    if event_raw!=expected_raw:raise ValueError("complete ordered actual request event stream differs")
    captured_bytes(directory/"worker-state/state.sqlite3",record["state_file"],captured)
    unchanged(captured)
    return {"schema":"hepta.hia.installed-describe-controls-readback.v2",
            "ordered_labels":labels,"malformed_rejections":2,"valid_manifest_completions":2,
            "original_cost_rows":4,"cached_journal_replay_claimed":False,
            "full_stdout_database_events_and_flags_bound":True}


def read_installed(root,source,images,manifest_pin,captured):
    report,result,start=owned_child(root,"installed","tests/hia_service_bootstrap_installed.py",1800,captured)
    directory=Path(root)/"installed"
    if report["schema"]!="hepta.hia.service-bootstrap-installed.v2" or report["status"]!="PASS_INSTALLED_ONLY":
        raise ValueError("complete installed report failed")
    for field in ("source_before","source_after"):equal(report[field],source,"installed source changed")
    for field in ("images_before","images_after"):equal(report[field],images,"installed image changed")
    equal(report["manifest_list"],manifest_pin,"installed image list differs")
    for field in ("whole_native_stack_qualified","independent_budget_B_selected"):
        if report[field] is not False:raise ValueError("installed evidence overstates its resource scope")
    for field in ("all_repeated_worker_expected_flags","all_five_public_methods_selected"):
        if report[field] is not True:raise ValueError("installed method/worker scope incomplete")
    commands=capture(directory/"commands.json",report["commands"],captured)
    observations=capture(directory/"observations.json",report["observations"],captured)
    labels=["wheel","install","identity","worker-first","worker-replay",
        "worker-manifest-first","worker-manifest-replay","consumer-normal",
        "consumer-lost_program_FINALIZE","worker-source-LF","worker-extra-module","worker-manifest-source","worker-image-byte"]
    if set(commands)!=set(labels) or set(observations)!=set(labels):
        raise ValueError("all thirteen v2 installed commands must be present")
    installed=zip_installation(directory,report["installation"],captured)
    bundle=capture(directory/"bundle.json",report["bundle"],captured)
    identity_raw=captured_bytes(directory/"identity/stdout.log",report["worker_identity"]["raw"],captured)
    identity=s.parse(identity_raw)
    equal(identity,report["worker_identity"]["value"],"actual identity parsed value differs")
    equal(identity["native_helpers_sha256"],report["bundle"]["sha256"],"worker bundle identity differs")
    identity_check=installed_worker_identity(installed,identity,captured)
    expected_flags={"--expected-worker-sha256":identity["worker_sha256"],
                    "--expected-backend-sha256":identity["backend_sha256"],
                    "--expected-catalog-sha256":identity["catalog_sha256"]}
    bundle_rows=bundle["helpers"]
    expected_selectors={
        "bootstrap":"HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST",
        "store":"HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST",
        "transaction":"HEPTA_HIA_STORE_TRANSACTION_MANIFEST",
        "ledger":"HEPTA_HIA_SLOT_LEDGER_MANIFEST",
        "context":"HEPTA_HIA_SERVICE_CONTEXT_MANIFEST"}
    if set(report["selected_helpers"])!=set(expected_selectors):
        raise ValueError("installed helper scope includes or omits a resource owner")
    equal(sorted(row["selector"] for row in bundle_rows),sorted(expected_selectors.values()),"bundle helper selectors differ")
    selector_keys={value:key for key,value in expected_selectors.items()}
    for row in bundle_rows:
        equal(row["manifest_sha256"],images[selector_keys[row["selector"]]]["manifest"]["sha256"],
              "bundle current manifest identity differs")
        stream_identity(row["manifest_path"],images[selector_keys[row["selector"]]]["manifest"])
    # Script source is tied to the literal in the actual pinned producer file.
    for variable,filename in (("WORKER","worker.py"),("CONSUMER","consumer.py")):
        expected=literal_assignment(ROOT/"tests/hia_service_bootstrap_installed.py",variable,captured).encode()
        if captured_bytes(directory/filename,None,captured)!=expected:
            raise ValueError("installed child script differs from bound source")
    for label in labels:
        recorded=commands[label]
        actual=capture(directory/label/"result.json",None,captured)
        equal(actual,recorded,"installed original result differs")
        spec=capture(directory/label/"command.json",None,captured)
        equal(spec,actual["command"],"installed original command differs")
        integer(spec["timeout_seconds"],60);integer(spec["cleanup_seconds"],5)
        integer(actual["pid"],spec["pid"]);integer(spec["pgid"],spec["pid"])
        integer(actual["exit_code"],2 if label in labels[-4:] else 0)
        if (actual["timed_out"] is not False or actual["interruption"] is not None
                or actual["owned_cleanup"]["reaped"] is not True
                or actual["owned_cleanup"]["after"]!=[] or actual["owned_cleanup"]["signals"]!=[]):
            raise ValueError("installed child did not exit naturally within its original budget")
        for name in ("stdout","stderr"):
            raw=captured_bytes(directory/label/(name+".log"),actual[name],captured)
            equal(observations[label][name],s.bytes_pin(raw),"installed full log differs")
        argv=spec["argv"]
        equal(argv[:3],[report["executable"],"-I","-B"],"installed isolated prefix changed")
        if label.startswith("worker-"):
            if Path(argv[3])!=directory/"worker.py" or Path(argv[4])!=installed:
                raise ValueError("worker command path differs")
            for flag,value in expected_flags.items():
                if argv.count(flag)!=1 or argv[argv.index(flag)+1]!=value:
                    raise ValueError("actual worker expected identity flag missing/different")
        if label.startswith("consumer-"):
            if Path(argv[3])!=directory/"consumer.py" or Path(argv[4])!=installed:
                raise ValueError("consumer command path differs")
            if argv[5]!=label[len("consumer-"):]:raise ValueError("installed consumer mode differs")
    for label in ("worker-first","worker-replay","worker-manifest-first","worker-manifest-replay",
                  "consumer-normal","consumer-lost_program_FINALIZE"):
        raw=captured_bytes(directory/label/"stdout.log",observations[label]["stdout"],captured)
        equal(s.parse(raw),observations[label]["response"],"actual worker/consumer response differs")
    requests=read_installed_describe_requests(directory,report["worker_requests"],commands,
        observations,identity,installed,directory/"bundle.json",report["bundle"]["sha256"],captured)
    normal=observations["consumer-normal"]["response"];unknown=observations["consumer-lost_program_FINALIZE"]["response"]
    if not {"1","2","3","4","5"}<=set(normal["counts"]["mode"]):
        raise ValueError("actual installed public five modes incomplete")
    integer(normal["counts"]["close_body"],1);integer(normal["resources"],0);integer(normal["lost_records"],0)
    integer(unknown["counts"]["close_body"],0)
    if unknown["close_refused"] is not True or integer(unknown["resources"])<=0 or integer(unknown["lost_records"])<=0:
        raise ValueError("actual lost program read did not retain/fence Store")
    unchanged(captured)
    return {"status":"PASS_READBACK_ONLY","commands":len(labels),"independent_budget_B_selected":False,
            "actual_Store_close_and_loss_checked":True,"request_controls":requests,**identity_check}



RESOURCE_IDS=(
 "confirmed-child-parent-ACK-loss","actual-child-loss-swallowed","actual-child-loss-replaced",
 "ordinary-provider-error-confirmed","late-FINALIZE-ACK-loss","actual-B-used-A-unassociated",
 "same-resource-new-Context","different-healthy-resource","nested-child-confirmed-outer-loss",
 "healthy-resource-retirement","constructor-before-Store","constructor-Store-provider-error",
 "constructor-inside-try-cleanup","independent-budget-B-retirement",
 "generator-first-advance-loss","generator-second-advance-loss","generator-confirmed-yield-retirement")

def read_resources(root,source,images,manifest_pin,captured):
    records=[]
    for name in RESOURCE_IDS:
        report,result,start=owned_child(root,"resource-"+name,"tests/hia_service_bootstrap_resources.py",180,captured)
        if (report["schema"]!="hepta.hia.service-bootstrap-resource-control.v1"
                or report["case"]!=name or report["status"]!="PASS_CONTROL_ONLY"
                or report["validated"] is not True):
            raise ValueError("a complete actual resource control failed: "+name)
        for field in ("source_before","source_after"):equal(report[field],source,"resource source differs")
        for field in ("images_before","images_after"):equal(report[field],images,"resource images differ")
        equal(report["manifest_list"],manifest_pin,"resource image authority differs")
        if not report["owner_entries"]:raise ValueError("resource control had no actual owner entry")
        for row in report["owner_entries"]:
            integer(row["code"],96);integer(row["event"]);integer(row["mode"]);integer(row["port"])
        if name in RESOURCE_IDS[:10]:
            if not report["child_entries"] or not any("INSERT" in sql.upper() for sql in report["SQL"]["B"]):
                raise ValueError("real Store B Native/SQLite effect was not observed")
            if name not in ("ordinary-provider-error-confirmed","healthy-resource-retirement"):
                if report["parent_lost"] is not True or report["parent_native_failed"] is not True:
                    raise ValueError("actual parent UNKNOWN responsibility was discarded")
                if report["retire_B"]["kind"]!="raised" or report["unassociated_A_retired"] is not True:
                    raise ValueError("lost B or unrelated A retirement differs")
        if name=="independent-budget-B-retirement":
            if (report["budget_B_distinct_from_Store_A"] is not True
                    or report["budget_B_closed_before"] is not False
                    or report["budget_B_closed_after"] is not False
                    or report["budget_B_close"]["kind"]!="raised"):
                raise ValueError("actual independent SQLite Budget B has no retirement boundary")
        if name.startswith("generator-"):
            expected=2 if name=="generator-second-advance-loss" else 1 if name=="generator-first-advance-loss" else 2
            integer(len(report["path_calls"]),expected)
            if name!="generator-confirmed-yield-retirement" and report["retire_B"]["kind"]!="raised":
                raise ValueError("generator actual loss did not retain its Store")
        records.append({"id":name,"status":"PASS_READBACK_ONLY",
                        "owner_entries":len(report["owner_entries"]),"actual_SQL_scopes":sorted(report["SQL"])})
    unchanged(captured);return records

SELECTIONS={
 "source":("tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests",
           "tests.test_hia_service_bootstrap_qualification.ServiceBootstrapQualificationSourceTests"),
 "native":("tests.test_hia_service_bootstrap_qualification.ServiceBootstrapNativeTests",
           "tests.test_hia_service_bootstrap_qualification.ServiceBootstrapResourceTests")}
# Preserve the original six Source methods and name both reviewed additions.
# Counting alone would allow one original method to be replaced by another.
ORIGINAL_SOURCE_METHOD_IDS=(
    SELECTIONS["source"][0]+".test_five_original_definitions_signatures_and_retained_prefix",
    SELECTIONS["source"][0]+".test_complete_protocol_graph_and_effect_set",
    SELECTIONS["source"][0]+".test_packaged_source_and_complete_original_caller_scope",
    SELECTIONS["source"][1]+".test_01_generated_complete_graph_original_sources_and_actual_profile_limits",
    SELECTIONS["source"][1]+".test_02_complete_prior_originals_and_all_derived_faults_through_VM",
    SELECTIONS["source"][1]+".test_03_complete_unselected_public_domain_and_lazy_empty_refusal")
SUPPLEMENTAL_SOURCE_METHOD_IDS=(
    SELECTIONS["source"][0]+".test_reviewed_scope_proof_matches_physical_captures_and_independent_reader",
    SELECTIONS["source"][0]+".test_historical_service_inverse_refuses_changed_physical_input")

def method_ids(suite,captured):
    result=[]
    for selector in SELECTIONS[suite]:
        module,classname=selector.rsplit(".",1)
        raw=captured_bytes(ROOT/(module.replace(".","/")+".py"),None,captured)
        tree=ast.parse(raw)
        node=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==classname)
        result.extend(module+"."+classname+"."+name for name in sorted(
            n.name for n in node.body if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")))
    if suite=="source":
        expected=ORIGINAL_SOURCE_METHOD_IDS+SUPPLEMENTAL_SOURCE_METHOD_IDS
        integer(len(result),len(expected))
        equal(sorted(result),sorted(expected),"source suite original/supplement method inventory differs")
    else:
        integer(len(result),12)
    return result

def read_suite(directory,report_pin,*,require_cold):
    directory=Path(directory);captured=[]
    outer=capture(directory/"report.json",report_pin,captured)
    if outer["schema"]!="hepta.hia.service-bootstrap-owned-suite.v1" or outer["status"]!="PASS_COMPLETE_SUITE":
        raise ValueError("complete outer suite is not PASS")
    suite=outer["suite"]
    if suite not in SELECTIONS:raise ValueError("undeclared complete suite")
    fixed={"start":outer["outer_start"],"result":outer["outer_result"],"report":outer["suite_report"]}
    report,result,start=owned_child(directory,"suite","tests/hia_service_bootstrap_suite.py",1800,
                                    captured,fixed=fixed,stderr_empty=False)
    source=s.source_snapshot()
    for value in (outer,report):
        for field in ("source_before","source_after"):equal(value[field],source,"suite complete source changed")
        if value["whole_native_stack_qualified"] is not False:raise ValueError("whole-stack flag was raised")
    equal(report["suite"],suite,"suite role changed")
    equal(outer["command"],start["command"],"outer complete command differs")
    ids=method_ids(suite,captured)
    for field in ("planned","starts","stops"):equal(report[field],ids,"full original method inventory differs")
    integer(report["run"],len(ids));integer(report["new_outer_budget_seconds"],1800)
    for field in ("failures","errors","skips","expected_failures","unexpected_successes"):
        integer(report[field],0)
    equal(report["method_statuses"],{name:"success" for name in ids},"a real unittest method did not pass")
    events=[row for _,_,row in s.json_lines(directory/"suite/events.jsonl",report["events"])]
    equal(events,[event for name in ids for event in (
        {"event":"start","id":name},{"event":"stop","id":name,"status":"success"})],
        "complete actual start/stop stream differs")
    component=Path(report["component_evidence"])
    if not component.resolve().is_relative_to((directory/"component").resolve()):
        raise ValueError("component evidence escapes its actual owned output root")
    equal(outer["component_evidence"],str(component),"outer/inner component root differs")
    parent=capture(component/"parent.json",None,captured)
    for field in ("pid","pgid","argv","executable","cwd","runtime"):
        equal(parent[field],report[field],"component parent identity differs")
    # The actual enclosing marker is preserved verbatim, including None. This
    # standalone suite does not pretend to be either of the retained35 stages.
    if parent["enclosing_source_build_observations"] is not None and type(parent["enclosing_source_build_observations"]) is not str:
        raise ValueError("source-stage marker has an undeclared type")
    result_summary={"suite":suite,"method_count":len(ids),"ordered_ids":ids,
                    "enclosing_source_build_observations":parent["enclosing_source_build_observations"]}
    if suite=="source":
        equal(parent["evidence_variable"],"HEPTA_HIA_SERVICE_BOOTSTRAP_SOURCE_EVIDENCE","Source evidence channel differs")
        authority=report["component_authority"]
        if Path(authority["path"]).resolve()!=(component/"originals/authority.json").resolve():
            raise ValueError("Source original authority path differs")
        result_summary["VM"]=read_finite(component/"complete-vm",authority["path"],authority["pin"],"vm")
        result_summary["unselected"]=read_finite(component/"complete-unselected",authority["path"],authority["pin"],"unselected")
        result_summary["lazy"]=read_control(component,"lazy",source,None,captured,None)
        custody=capture(component/"source-custody.json",None,captured)
        equal(custody,{"before":source,"after":source},"Source terminal custody differs")
        result_summary["construction_scope"]="SOURCE_AND_VM_ONLY"
    else:
        equal(parent["evidence_variable"],"HEPTA_HIA_SERVICE_BOOTSTRAP_EVIDENCE","Native evidence channel differs")
        bound=report["component_authority"]
        if Path(bound["path"]).resolve()!=(component/"authority.json").resolve():
            raise ValueError("native component authority path differs")
        authority=capture(bound["path"],bound["pin"],captured)
        if authority["schema"]!="hepta.hia.service-bootstrap-component-authority.v1":
            raise ValueError("wrong native component authority")
        equal(authority["source_before"],source,"native build source differs")
        cons,manifests,images=construction(component,authority["construction"],captured,source,require_cold=require_cold)
        equal(authority["scope"],cons["scope"],"native cold/DEV classification differs")
        equal(authority["images"],images,"native initial image identities differ")
        stream_identity(component/"manifest-list.json",authority["manifest_list"])
        originals=authority["originals"]
        if Path(originals["path"]).resolve()!=(component/"originals/authority.json").resolve():
            raise ValueError("native prior original path differs")
        result_summary["finite"]=read_finite(component/"complete-native",originals["path"],originals["pin"],"native")
        comparison=capture(component/"complete-native/report.json",None,captured)
        equal(comparison["manifest"],images["bootstrap"]["manifest"],"finite native image differs from shared authority")
        result_summary["controls"]=[read_control(component,action,source,images,captured,authority["manifest_list"])
                                    for action in ("public","packets","loss","ownership","loader","pinned")]
        result_summary["installed"]=read_installed(component,source,images,authority["manifest_list"],captured)
        result_summary["resources"]=read_resources(component,source,images,authority["manifest_list"],captured)
        for classname in ("ServiceBootstrapNativeTests","ServiceBootstrapResourceTests"):
            custody=capture(component/(classname+"-custody.json"),None,captured)
            equal(custody["source_before"],source,"native class initial source differs")
            equal(custody["source_after"],source,"native class terminal source differs")
            equal(custody["images_before"],images,"native class initial images differ")
            equal(custody["images_after"],images,"native class terminal images differ")
            equal(custody["runtime"],sys.version,"native class runtime differs")
        result_summary["construction_scope"]=cons["scope"]
    equal(s.source_snapshot(),source,"source changed during complete readback")
    unchanged(captured)
    return {"schema":"hepta.hia.service-bootstrap-readback.v1","status":"PASS_READBACK_ONLY",
            "producer_report":report_pin,**result_summary,"whole_native_stack_qualified":False}

def read_callers_original_administrator(directory,inner,ids,captured):
    closed=("tests.test_hia_service_context_native.ServiceContextNativeTests."
            "test_all_four_actual_public_routes_use_native_with_references_poisoned")
    expected=[closed] if inner["scope"]=="context" else []
    equal(inner["closed_administrator_method_ids"],expected,"original closed administrator inventory differs")
    equal(inner["selection_boundary_errors"],[],"original selector boundary failed")
    if (inner["old_administrator_bundle_enlarged"] is not False
            or inner["all_original_methods_claimed_bootstrap_selected"] is not False):
        raise ValueError("original administrator scope was enlarged or relabelled")
    manifest_path=inner["manifest_path"]
    boundaries=[]
    for name in expected:
        boundaries.extend([
            {"test":name,"event":"start","selector_before":manifest_path,"selector_after":None},
            {"test":name,"event":"stop","selector_before":None,"selector_after":manifest_path}])
    equal(inner["closed_administrator_boundaries"],boundaries,"closed administrator selector boundaries differ")
    for field,aggregate in (("frames_by_test","frames_by_mode"),("entries_by_test","actual_entries_by_event")):
        values=inner[field]
        if type(values) is not dict or any(name not in ids+["outside-test"] for name in values):
            raise ValueError("caller native observations are not tied to declared original methods")
        combined={}
        for name,counters in values.items():
            if type(counters) is not dict:
                raise ValueError("caller per-method native counters are not objects")
            for event,count in counters.items():
                integer(count)
                if count<=0:raise ValueError("caller recorded an empty actual native event")
                combined[event]=combined.get(event,0)+count
            if name in expected and counters:
                raise ValueError("bootstrap entered the original closed four-owner administrator scope")
        equal(combined,inner[aggregate],"per-method native observations do not cover the aggregate")
    records=inner["closed_administrator_artifacts"]
    if type(records) is not dict or set(records)!=set(expected):
        raise ValueError("original administrator artifacts are missing or relabelled")
    specs={
        "HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST":("candidate_budget","candidate-budget","NativeCandidateBudgetImage"),
        "HEPTA_HIA_EXECUTION_BUDGET_MANIFEST":("execution_budget","execution-budget","NativeExecutionBudgetImage"),
        "HEPTA_HIA_SERVICE_CONTEXT_MANIFEST":("service_context","service-context","NativeServiceContextImage"),
        "HEPTA_HIA_STORE_LIFECYCLE_MANIFEST":("store_lifecycle","store-lifecycle","NativeStoreLifecycleImage"),
    }
    for name in expected:
        record=records[name]
        equal(sorted(record),["bundle.json","composition.json"],"original administrator artifact inventory differs")
        values={}
        for basename in ("bundle.json","composition.json"):
            item=record[basename]
            equal(sorted(item),["bytes","path","sha256"],"original administrator artifact pin shape differs")
            path=Path(directory)/"callers/original-component/four-owner-composition"/basename
            equal(item["path"],str(path.resolve()),"original administrator artifact path differs")
            values[basename]=capture(path,{"bytes":item["bytes"],"sha256":item["sha256"]},captured)
        bundle=values["bundle.json"]
        equal(sorted(bundle),["abi","helpers","schema","target"],"original administrator bundle fields differ")
        equal(bundle["schema"],"hepta.hia.native-helpers.v1","original administrator schema differs")
        equal(bundle["target"],"linux-x86_64-lp64","original administrator target differs")
        equal(bundle["abi"],"hia-byte-six-argument-v1","original administrator ABI differs")
        helpers=bundle["helpers"]
        equal([row["selector"] for row in helpers],sorted(specs),"original four-owner selectors were changed")
        for row in helpers:
            equal(sorted(row),["manifest_path","manifest_sha256","selector"],"original helper pin fields differ")
            source_name,schema_name,_=specs[row["selector"]]
            path=Path(row["manifest_path"])
            raw=captured_bytes(path,None,captured);manifest=s.parse(raw)
            equal(s.bytes_pin(raw)["sha256"],row["manifest_sha256"],"original helper manifest changed")
            equal(manifest["schema"],"hepta.hia."+schema_name+"-native.v1","original helper schema differs")
            equal(manifest["compiler_sha256"],inner["compiler_sha256"],"original helper compiler differs")
            source=captured_bytes(ROOT/("examples/hia_bootstrap/"+source_name+".hepta"),None,captured)
            equal(manifest["source_sha256"],s.bytes_pin(source)["sha256"],"original helper source changed")
            if Path(manifest["image_path"]).name!=manifest["image_path"]:
                raise ValueError("original helper image path escapes its manifest")
            image=captured_bytes(path.parent/manifest["image_path"],None,captured)
            equal(manifest["image_sha256"],s.bytes_pin(image)["sha256"],"original helper image changed")
        composition=values["composition.json"]
        equal(sorted(composition),sorted(("scope","actual_native_entries","original_context_wall_ms",
            "context_store_execution_and_candidate_budget_composed",
            "all_retained_policy_references_forbidden","whole_native_delivery_qualified")),
            "original composition fields differ")
        scope="MATCHING_SOURCE_COLD_COMPONENT" if inner["qualification_mode"]=="MATCHING_SOURCE_COLD_COMPLETE_CALLERS" else "DEVELOPMENT_COMPONENT"
        equal(composition["scope"],scope,"original composition authority differs")
        integer(composition["original_context_wall_ms"],3000)
        if (composition["context_store_execution_and_candidate_budget_composed"] is not True
                or composition["all_retained_policy_references_forbidden"] is not True
                or composition["whole_native_delivery_qualified"] is not False):
            raise ValueError("original four-owner composition result differs")
        counts=composition["actual_native_entries"]
        equal(sorted(counts),sorted(spec[2] for spec in specs.values()),"original native owner inventory differs")
        for count in counts.values():
            if integer(count)<=0:raise ValueError("an original composed native owner did not execute")
    return expected

_CALLER_SCOPE_AUTHORITY = 'tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json'
_CALLER_SCOPE_AUTHORITY_PIN = {
    'bytes': 28102,
    'sha256': 'b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4',
}
_CALLER_DIAGNOSTICS_PATH = 'tests/test_hia_agent_native_tools.py'
_CALLER_DIAGNOSTICS_HELPER = 'tests/hia_caller_diagnostics_admission.py'
_CALLER_DIAGNOSTICS_HELPER_PIN = {
    'bytes': 5185,
    'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578',
}
_CALLER_DIAGNOSTICS_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_CALLER_DIAGNOSTICS_FIXTURE_PIN = {
    'bytes': 3545,
    'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c',
}
_CALLER_DIAGNOSTICS_OLD = {
    'bytes': 45385,
    'sha256': 'c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a',
}
_CALLER_DIAGNOSTICS_NEW = {
    'bytes': 46518,
    'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355',
}
_CALLER_JOURNAL_PATH = 'tests/test_hia_agent_journal_native.py'
_CALLER_JOURNAL_HELPER = 'tests/hia_journal_installed_preparation.py'
_CALLER_JOURNAL_HELPER_PIN = {
    'bytes': 15935,
    'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797',
}
_CALLER_JOURNAL_FIXTURE = 'tests/fixtures/journal_installed_preparation_v2.json'
_CALLER_JOURNAL_FIXTURE_PIN = {
    'bytes': 14729,
    'sha256': '81914ecb2bef21e9c641282dc8530158146ecadd4b86e8e4e6b3f83e71b73e7b',
}
_CALLER_JOURNAL_ARCHIVE = 'tests/fixtures/journal_installed_preparation_v1.py.txt'
_CALLER_JOURNAL_OLD = {
    'bytes': 48482,
    'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077',
}
_CALLER_JOURNAL_NEW = {
    'bytes': 48798,
    'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c',
}
_CALLER_JOURNAL_PREPARATION = 'hepta.hia.journal-installed-resource-preparation.v2'


def _restore_caller_diagnostic_source(raw, provenance):
    """Independently reverse and replay the two reviewed diagnostic splices.

    The producer and its admission helper are not imported or executed here.
    Reconstructed historical bytes are evidence only, never executed callers.
    """
    if type(raw) is not bytes or type(provenance) is not bytes:
        raise ValueError('caller diagnostics require complete raw bytes')
    equal(s.bytes_pin(raw), _CALLER_DIAGNOSTICS_NEW,
          'caller diagnostic current whole source differs')
    equal(s.bytes_pin(provenance), _CALLER_DIAGNOSTICS_FIXTURE_PIN,
          'caller diagnostic fixed provenance differs')
    value = s.parse(provenance)
    expected_fields = {
        'schema': 'hepta.hia.caller-deadline-diagnostics-source.v1',
        'state': 'FROZEN_EXACT_FAILURE_DIAGNOSTICS_SUCCESSOR',
        'path': _CALLER_DIAGNOSTICS_PATH,
        'original': _CALLER_DIAGNOSTICS_OLD,
        'current': _CALLER_DIAGNOSTICS_NEW,
        'definition': 'NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable',
        'original_deadline_seconds': 5,
        'original_native_budget_ms': 1,
        'original_method_ids_unchanged': True,
        'production_source_exception': False,
    }
    if type(value) is not dict or set(value) != set(expected_fields) | {'splices'}:
        raise ValueError('caller diagnostic provenance fields differ')
    equal({key: value[key] for key in expected_fields}, expected_fields,
          'caller diagnostic provenance scope differs')
    splices = value['splices']
    if type(splices) is not list or len(splices) != 2:
        raise ValueError('caller diagnostic splice count differs')
    entries = []
    old_end = new_end = displacement = 0
    for item in splices:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}):
            raise ValueError('caller diagnostic splice fields differ')
        old_at, new_at = item['old_offset'], item['new_offset']
        if (type(old_at) is not int or type(new_at) is not int
                or old_at < old_end or new_at < new_end
                or old_at + displacement != new_at):
            raise ValueError('caller diagnostic splice order differs')
        segments = []
        for name in ('old_hex', 'new_hex'):
            text = item[name]
            if type(text) is not str or not text:
                raise ValueError('caller diagnostic splice is not exact hexadecimal')
            try:
                part = bytes.fromhex(text)
            except ValueError as error:
                raise ValueError('caller diagnostic splice is not hexadecimal') from error
            if part.hex() != text:
                raise ValueError('caller diagnostic splice is not canonical hexadecimal')
            segments.append(part)
        before, after = segments
        if (before == after or new_at + len(after) > len(raw)
                or raw[new_at:new_at + len(after)] != after):
            raise ValueError('caller diagnostic current splice bytes differ')
        entries.append((old_at, new_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
        displacement += len(after) - len(before)
    original = raw
    for old_at, new_at, before, after in reversed(entries):
        original = original[:new_at] + before + original[new_at + len(after):]
    equal(s.bytes_pin(original), _CALLER_DIAGNOSTICS_OLD,
          'caller diagnostics did not restore the complete original source')
    replay = original
    for old_at, new_at, before, after in reversed(entries):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError('caller diagnostic original splice bytes differ')
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError('caller diagnostic forward replay differs')
    return original


def _restore_caller_journal_source(raw, provenance):
    """Read the complete pinned relation without importing any admission code."""
    if type(raw) is not bytes or type(provenance) is not bytes:
        raise ValueError('Journal preparation requires complete immutable source bytes')
    equal(s.bytes_pin(raw), _CALLER_JOURNAL_NEW, 'current complete Journal source differs')
    equal(s.bytes_pin(provenance), _CALLER_JOURNAL_FIXTURE_PIN,
          'fixed Journal preparation authority differs')
    value = s.parse(provenance)
    fields = {
        'schema': 'hepta.hia.journal-installed-resource-preparation-authority.v2',
        'preparation_id': _CALLER_JOURNAL_PREPARATION,
        'path': _CALLER_JOURNAL_PATH, 'original': _CALLER_JOURNAL_OLD,
        'current': _CALLER_JOURNAL_NEW,
        'original_archive': {'path': _CALLER_JOURNAL_ARCHIVE, **_CALLER_JOURNAL_OLD},
        'retained_source_commit': '1a4f2202a6c7ffbad373329ddcd9451cc59c9401',
        'original_method_count': 21,
        'original_build_timeout_seconds': 120,
        'original_install_timeout_seconds': 120,
        'original_probe_timeout_seconds': 30,
        'original_scope_budget_seconds': 1800,
        'original_business_assertions_and_budgets_unchanged': True,
        'setup_required_resources_unchanged': True,
        'production_source_exceptions': [],
    }
    if type(value) is not dict:
        raise ValueError('Journal preparation authority is not an object')
    equal({name: value.get(name) for name in fields}, fields,
          'Journal preparation original authority or budgets differ')
    ids = value.get('original_method_ids')
    if (type(ids) is not list or len(ids) != 21
            or any(type(name) is not str for name in ids) or len(set(ids)) != 21):
        raise ValueError('Journal preparation original complete method inventory differs')
    splices = value.get('splices')
    if type(splices) is not list or len(splices) != 2:
        raise ValueError('Journal preparation exact splice count differs')
    identifiers = ('complete-current-package-resources',
                   'staged-byte-custody-before-original-wheel-build')
    pieces = []
    old_end = new_end = delta = 0
    for index, item in enumerate(splices):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != identifiers[index]):
            raise ValueError('Journal preparation splice identity differs')
        old_at, new_at = item['old_offset'], item['new_offset']
        if (type(old_at) is not int or type(new_at) is not int
                or old_at < old_end or new_at < new_end or old_at + delta != new_at):
            raise ValueError('Journal preparation typed splice order differs')
        data = []
        for field in ('old_hex', 'new_hex'):
            text = item[field]
            if type(text) is not str or not text:
                raise ValueError('Journal preparation splice is not hexadecimal')
            try:
                segment = bytes.fromhex(text)
            except ValueError as error:
                raise ValueError('Journal preparation splice is not hexadecimal') from error
            if segment.hex() != text:
                raise ValueError('Journal preparation splice is not canonical hexadecimal')
            data.append(segment)
        before, after = data
        old_end, new_end = old_at + len(before), new_at + len(after)
        if (before == after or old_end > _CALLER_JOURNAL_OLD['bytes']
                or new_end > len(raw) or raw[new_at:new_end] != after):
            raise ValueError('Journal preparation complete source splice bytes differ')
        pieces.append((old_at, new_at, before, after))
        delta += len(after) - len(before)
    original = raw
    for old_at, new_at, before, after in reversed(pieces):
        original = original[:new_at] + before + original[new_at + len(after):]
    equal(s.bytes_pin(original), _CALLER_JOURNAL_OLD,
          'Journal preparation did not restore the entire original source')
    replay = original
    for old_at, new_at, before, after in reversed(pieces):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError('Journal preparation original splice bytes differ')
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError('Journal preparation whole current replay differs')
    return original


_SCOPED_HISTORY = 'tools/hia_scoped_caller_source_history.py'
_SCOPED_HISTORY_PIN = {"bytes":7154,"sha256":"608b2a291cfe41d5314d15da320d835c03ee5453b9987e76d383a80ce94fe773"}
_SCOPED_SOURCE_DIGESTS = {
    'tests/test_hia_agent_native_tools.py': {
        '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70',
        '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'},
    'tests/test_hia_agent_native_machine_validation.py': {
        '0c03b958462d2d2b8f7304b52bf419a9832037c3db4e51fa940053176fad0cbb'},
    'tests/test_hia_agent_native_proof_contract.py': {
        'cb958dfdac9ae83b421a55c34109247dbda64af85171525969da55ad3a6d1f03'},
    'tests/test_hia_agent_journal_native.py': {
        '97dec702780d755cc5c2ffa59e5a798c98dc48a17735f9b8983bfdb610d2f263'},
    'tests/test_hia_service_context_native.py': {
        '94bba1ba99cfeb29baa9eb34072514803af288a11d964f950c46bea431e92c1b'},
}


def _read_scoped_caller(root, capture, name, raw, expected):
    if sha256(raw).hexdigest() not in _SCOPED_SOURCE_DIGESTS.get(name, set()):
        return raw, None
    helper = capture(_SCOPED_HISTORY)
    if {'bytes': len(helper), 'sha256': sha256(helper).hexdigest()} != _SCOPED_HISTORY_PIN:
        raise ValueError('scoped caller complete source-history helper changed')
    from tools import hia_scoped_caller_source_history as history
    if Path(history.__file__).read_bytes() != helper:
        raise ValueError('scoped caller imported another source-history helper')
    saved = {name: raw, _SCOPED_HISTORY: helper}
    def take(path):
        relative = Path(path).relative_to(root).as_posix()
        if relative not in saved:
            saved[relative] = capture(relative)
        elif capture(relative) != saved[relative]:
            raise ValueError('scoped caller selected source view changed between layers')
        return saved[relative]
    return history.predecessor(root, name, raw, expected, take=take)


def _read_caller_source_admission(scope_name, declaration, inner, captured):
    """Recheck actual current callers and the optional exact successor proof."""
    if type(scope_name) is not str or scope_name not in ('ordinary', 'journal', 'context'):
        raise ValueError('undeclared caller source scope')
    if (type(inner) is not dict or type(inner.get('source_before')) is not dict
            or type(inner.get('source_after')) is not dict):
        raise ValueError('caller source captures are not complete mappings')
    consumed = {}

    def take(name, expected=None):
        raw = captured_bytes(ROOT / name, expected, captured)
        observed = s.bytes_pin(raw)
        if name in consumed and consumed[name] != observed:
            raise ValueError('caller physical source changed between layers')
        consumed[name] = observed
        return raw

    def take_path(path):
        return take(Path(path).relative_to(ROOT).as_posix())

    frozen = take(_CALLER_SCOPE_AUTHORITY, _CALLER_SCOPE_AUTHORITY_PIN)
    scope = s.parse(frozen)['scopes'][scope_name]
    equal(declaration, scope, 'caller source declaration differs from the fixed authority')
    integer(len(scope['ordered_ids']), {'ordinary': 112, 'journal': 21, 'context': 15}[scope_name])
    integer(scope['outer_seconds'], 1800)
    from tests.hia_bootstrap_caller_predecessors import bootstrap_caller_predecessor

    from tools import hia_native_cold_caller_history as native_history
    cold_histories = []
    cold_adjustments = {}
    adjustments = {}
    journal_adjustments = {}
    predecessors = {}
    for name, old_pin in scope['files'].items():
        physical = take(name)
        selected, selected_take, cold_history = physical, take_path, None
        if s.bytes_pin(physical) == native_history.KNOWN_CURRENT.get(name):
            projected, cold_history = native_history.prepare(
                ROOT, {name: physical}, take=take_path)
            selected, selected_take = projected[name], cold_history['prior_take']
            cold_histories.append(cold_history)
        def prior_take(relative):
            return selected_take(ROOT / relative)
        raw, predecessor_review = _read_scoped_caller(
            ROOT, prior_take, name, selected, old_pin)
        if predecessor_review is not None:
            predecessors[name] = (predecessor_review if cold_history is None else {
                'physical': s.bytes_pin(physical), 'predecessor': s.bytes_pin(raw),
                'historical_input': s.bytes_pin(selected),
                'prior_scope_review': predecessor_review,
                'prior_projection_is_physical_source': False})
        else:
            raw = bootstrap_caller_predecessor(ROOT, name, selected, old_pin, prior_take)
            if raw != selected:
                predecessors[name] = {'physical': s.bytes_pin(physical), 'predecessor': s.bytes_pin(raw)}
        if s.same(s.bytes_pin(raw), old_pin):
            continue
        if name == _CALLER_JOURNAL_PATH:
            if scope_name != 'journal':
                raise ValueError('Journal preparation does not authorize another scope')
            equal(old_pin, _CALLER_JOURNAL_OLD, 'Journal original scope identity differs')
            equal(s.bytes_pin(raw), _CALLER_JOURNAL_NEW, 'current complete Journal source differs')
            take(_CALLER_JOURNAL_HELPER, _CALLER_JOURNAL_HELPER_PIN)
            provenance = take(_CALLER_JOURNAL_FIXTURE, _CALLER_JOURNAL_FIXTURE_PIN)
            archive = take(_CALLER_JOURNAL_ARCHIVE, _CALLER_JOURNAL_OLD)
            if raw != physical:
                installed = take('tests/fixtures/hia_installed_distribution_sources.json')
                authoring = take('tests/fixtures/hia_component_authoring_successor_v1.json')
                equal(s.bytes_pin(installed),
                      {'bytes': 104444, 'sha256': '6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d'},
                      'Journal complete installed source authority differs')
                equal(sha256(authoring).hexdigest(),
                      '5aa32081d30e10ef29edec087c209031b21e617d9d00dcdb6338f404b01f2f5d',
                      'Journal complete authoring source authority differs')
            if _restore_caller_journal_source(raw, provenance) != archive:
                raise ValueError('Journal preparation original archive differs')
            authority = s.parse(provenance)
            equal(authority['original_method_ids'], scope['ordered_ids'],
                  'Journal preparation differs from the complete original scope')
            journal_adjustments[name] = {
                'schema': 'hepta.hia.journal-installed-resource-source-admission.v2',
                'preparation_id': _CALLER_JOURNAL_PREPARATION, 'path': name,
                'original': dict(_CALLER_JOURNAL_OLD), 'current': dict(_CALLER_JOURNAL_NEW),
                'authority': {'path': _CALLER_JOURNAL_FIXTURE, **_CALLER_JOURNAL_FIXTURE_PIN},
                'archive': {'path': _CALLER_JOURNAL_ARCHIVE, **_CALLER_JOURNAL_OLD},
                'exact_splice_count': 2, 'complete_original_inverse_verified': True,
                'complete_current_forward_replay_verified': True,
                'original_method_count': 21, 'original_method_ids': list(scope['ordered_ids']),
                'original_build_timeout_seconds': 120, 'original_install_timeout_seconds': 120,
                'original_probe_timeout_seconds': 30, 'original_scope_budget_seconds': 1800,
                'captured_files': {item: (s.bytes_pin(raw) if item == name else dict(consumed[item])) for item in
                    (_CALLER_JOURNAL_PATH, _CALLER_JOURNAL_HELPER,
                     _CALLER_JOURNAL_FIXTURE, _CALLER_JOURNAL_ARCHIVE)},
                'terminal_reread_identical': True, 'production_source_exceptions': [],
            }
            if cold_history is not None:
                view_names = (_CALLER_JOURNAL_PATH, _CALLER_JOURNAL_HELPER,
                    _CALLER_JOURNAL_FIXTURE, _CALLER_JOURNAL_ARCHIVE,
                    'tests/fixtures/hia_installed_distribution_sources.json',
                    'tests/fixtures/hia_component_authoring_successor_v1.json')
                physical_names = (*view_names, native_history.FIXTURE,
                                  native_history.PREVIOUS_FIXTURE)
                journal_adjustments[name]['native_cold_source_projection'] = {
                    'path': name, 'physical_current': s.bytes_pin(physical),
                    'declared_predecessor': s.bytes_pin(selected),
                    'actual_captured_files': {item: dict(consumed[item])
                                              for item in physical_names},
                    'historical_view_files': {item: (s.bytes_pin(selected)
                        if item == name else dict(consumed[item])) for item in view_names},
                    'terminal_reread_identical': True,
                    'whole_native_delivery_qualified': False,
                }
            continue
        if name != _CALLER_DIAGNOSTICS_PATH:
            raise ValueError('an original complete caller module changed: ' + name)
        equal(old_pin, _CALLER_DIAGNOSTICS_OLD, 'caller diagnostic original authority differs')
        take(_CALLER_DIAGNOSTICS_HELPER, _CALLER_DIAGNOSTICS_HELPER_PIN)
        provenance = take(_CALLER_DIAGNOSTICS_FIXTURE, _CALLER_DIAGNOSTICS_FIXTURE_PIN)
        _restore_caller_diagnostic_source(raw, provenance)
        adjustments[name] = {
            'path': name, 'original': dict(_CALLER_DIAGNOSTICS_OLD),
            'current': dict(_CALLER_DIAGNOSTICS_NEW),
            'provenance_path': _CALLER_DIAGNOSTICS_FIXTURE,
            'provenance_sha256': _CALLER_DIAGNOSTICS_FIXTURE_PIN['sha256'],
            'exact_splices': 2, 'complete_original_inverse_verified': True,
            'complete_current_forward_replay_verified': True,
            'original_deadline_seconds': 5, 'original_native_budget_ms': 1,
            'production_source_exception': False,
        }
    for history in cold_histories:
        native_history.verify_unchanged(history)
        for name, review in history['review']['native_cold_caller_sources'].items():
            if name in cold_adjustments and cold_adjustments[name] != review:
                raise ValueError('independent native cold source reviews disagree')
            cold_adjustments[name] = review
    proof = {
        'schema': 'hepta.hia.service-bootstrap-caller-source-admission.v1',
        'scope': scope_name,
        'authority': {'path': _CALLER_SCOPE_AUTHORITY, **_CALLER_SCOPE_AUTHORITY_PIN},
        'original_files': dict(scope['files']), 'original_modules': list(scope['modules']),
        'original_ordered_ids': list(scope['ordered_ids']),
        'original_outer_seconds': scope['outer_seconds'],
        'reviewed_diagnostic_source_adjustments': adjustments,
        'captured_files': consumed,
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }
    if cold_adjustments:
        proof['reviewed_native_cold_caller_adjustments'] = cold_adjustments
    if predecessors:
        proof['reviewed_scope_predecessors'] = predecessors
    if journal_adjustments:
        proof['reviewed_journal_installed_preparation_source_adjustments'] = journal_adjustments
    if 'caller_source_admission' in inner:
        equal(inner['caller_source_admission'], proof,
              'caller producer source proof differs from independent full-source readback')
    elif adjustments or journal_adjustments or predecessors or cold_adjustments:
        raise ValueError('a current caller successor requires its exact source proof')
    # Original unmodified callers still admit the prior v2 report with no new
    # proof field. A changed caller cannot obtain that legacy path.
    equal(inner['source_before'], inner['source_after'], 'complete caller source changed')
    for name, actual in consumed.items():
        equal(inner['source_before'].get(name), actual['sha256'],
              'caller source proof differs from its actual complete source capture')
    # All raw inputs were appended to the outer reader's custody list. Its
    # original unchanged(captured) seals them after the remaining native/cold
    # and closed-administrator receipt checks; no early PASS is returned.
    return proof


def read_callers(directory,report_pin,*,require_cold):
    directory=Path(directory);captured=[]
    report=capture(directory/"report.json",report_pin,captured)
    if report["schema"]!="hepta.hia.service-bootstrap-owned-callers.v1" or report["status"]!="PASS_COMPLETE_CALLERS":
        raise ValueError("owned complete caller command failed")
    source=s.source_snapshot()
    equal(report["source_before"],source,"caller component source changed")
    equal(report["source_after"],source,"caller final component source changed")
    integer(report["original_budget_seconds"],1800)
    command=capture(directory/"owned/command.json",report["owned_command"],captured)
    result=capture(directory/"owned/result.json",report["owned_result"],captured)
    equal(result["command"],command,"caller original command/result differ")
    equal(report["command"],command["argv"],"owned command differs from declared full command")
    integer(command["timeout_seconds"],1800);integer(command["cleanup_seconds"],5)
    integer(result["exit_code"],0);integer(result["pid"],command["pid"]);integer(command["pgid"],command["pid"])
    if (result["timed_out"] is not False or result["interruption"] is not None
            or result["owned_cleanup"]["reaped"] is not True
            or result["owned_cleanup"]["after"]!=[] or result["owned_cleanup"]["signals"]!=[]):
        raise ValueError("caller process was not a complete natural owned exit")
    argv=command["argv"]
    equal(argv[:4],[report["executable"],"-I","-B",str(ROOT/"tools/qualify_hia_service_bootstrap_callers.py")],
          "caller wrapper changed the original program")
    for name in ("stdout","stderr"):stream_identity(directory/"owned"/(name+".log"),result[name])
    inner=capture(directory/"callers/report.json",report["original_inner_report"],captured)
    scope=report["scope"]
    if scope not in ("ordinary","journal","context"):raise ValueError("undeclared caller scope")
    raw=captured_bytes(FIXTURE/"caller-scopes.json",{
        "bytes":28102,"sha256":"b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4"},captured)
    declaration=s.parse(raw)["scopes"][scope]
    if inner["schema"]!="hepta.hia.service-bootstrap-complete-callers.v2" or inner["status"]!="PASS":
        raise ValueError("full original caller inner report failed")
    equal(inner["scope"],scope,"inner caller scope differs")
    ids=declaration["ordered_ids"];integer(len(ids),{"ordinary":112,"journal":21,"context":15}[scope])
    for name in ("planned","started","stopped"):equal(inner[name],ids,"complete caller IDs missing/reordered")
    equal(inner["modules"],declaration["modules"],"complete caller module order differs")
    integer(inner["tests_run"],len(ids));integer(inner["outer_budget_seconds"],1800)
    for name in ("failures","errors","skipped","selected_retained_calls"):equal(inner[name],[],"caller rejected "+name)
    if (inner["source_unchanged"] is not True or inner["old_admin_bundles_or_clear_environment_scopes_modified"] is not False
            or inner["whole_native"] is not False or report["whole_native_stack_qualified"] is not False):
        raise ValueError("caller scope/custody claims changed")
    _read_caller_source_admission(scope,declaration,inner,captured)
    equal(inner["source_before"],inner["source_after"],"complete caller source changed")
    for name,digest in inner["source_before"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts:raise ValueError("caller source leaves root")
        raw0=captured_bytes(ROOT/name,None,captured)
        equal(s.bytes_pin(raw0)["sha256"],digest,"complete caller current source differs")
    for name in ("frames_by_mode","actual_entries_by_event"):
        if not inner[name] or sum(integer(value) for value in inner[name].values())<=0:
            raise ValueError("caller scope did not execute its actual owner")
    for row in inner["explicitly_unselected_retained_calls"]:
        if row["test"] not in ids or integer(row["mode"]) not in range(1,6):
            raise ValueError("unselected call is not in its original complete method scope")
    manifest_path=Path(inner["manifest_path"])
    manifest_raw=captured_bytes(manifest_path,None,captured);manifest=s.parse(manifest_raw)
    equal(s.bytes_pin(manifest_raw)["sha256"],inner["manifest_sha256"],"caller manifest differs")
    equal(manifest["schema"],"hepta.hia.service-bootstrap.v1","caller owner schema differs")
    if Path(manifest["image_path"]).name!=manifest["image_path"]:raise ValueError("caller image path escapes")
    image=captured_bytes(manifest_path.parent/manifest["image_path"],None,captured)
    equal(s.bytes_pin(image)["sha256"],manifest["image_sha256"],"actual caller image changed")
    equal(manifest["image_sha256"],inner["actual_image_sha256"],"caller mapped another image")
    equal(manifest["compiler_sha256"],inner["compiler_sha256"],"caller compiler identity differs")
    equal(manifest["source_sha256"],s.bytes_pin(captured_bytes(ROOT/"examples/hia_bootstrap/service_bootstrap_word.hepta",None,captured))["sha256"],
          "caller image current source differs")
    if inner["qualification_mode"]=="MATCHING_SOURCE_COLD_COMPLETE_CALLERS":
        if argv.count("--cold-report")!=1:raise ValueError("matching-cold caller command missing authority")
        cold_path=Path(argv[argv.index("--cold-report")+1])
        cold=capture(cold_path,None,captured)
        from tools.hia_native_cold_admission import SCHEMA
        if cold.get("schema")==SCHEMA:
            inputs=native_cold_inputs(cold_path,cold,captured)
            compiler=inputs.compiler_bytes
            equal(s.bytes_pin(inputs.compiler_bytes)["sha256"],inner["compiler_sha256"],
                  "actual caller native compiler differs")
            from tools.hia_selfhost_contract import file_digests
            equal(inner["source_before"],file_digests(ROOT),"complete current host observation source differs")
            observer_source={name:s.bytes_pin(captured_bytes(ROOT/name,None,captured))
                             for name in inner["source_before"]}
            native_source_custody(inputs,observer_source,captured)
            build=capture(manifest_path.parent/"build.json",None,captured)
            equal(build["manifest"],manifest,"caller actual builder output differs")
            equal(build["source_manifest"],inputs.sources,"caller builder native source differs")
            equal(build["cold_report_sha256"],s.bytes_pin(inputs.report_bytes)["sha256"],
                  "caller native cold raw identity differs")
            native_component_custody(build,inputs,captured)
            source_raw=captured_bytes(ROOT/"examples/hia_bootstrap/service_bootstrap_word.hepta",None,captured)
            verify_pack(manifest_path,manifest,build,inputs.compiler_bytes,source_raw,image,captured)
        else:
            contract_path=literal_assignment(ROOT/"tools/hia_selfhost_contract.py","CONTRACT_PATH",captured)
            contract_raw=captured_bytes(ROOT/contract_path,None,captured)
            expected_full={**inner["source_before"],contract_path:s.bytes_pin(contract_raw)["sha256"]}
            equal(cold["source_manifest"],expected_full,"caller used another complete cold source")
            required={"export_manifest_matches_qualification","isolated_python_without_site",
                "nested_full_qualification_pass","nested_process_exit_zero","no_ancestor_git_identity",
                "no_bytecode_cache_created","no_inherited_home_or_python_cache",
                "no_inherited_seed_or_successor_images","origin_hashes_preserved",
                "owned_process_tree_cleanup_confirmed","source_export_hashes_preserved"}
            if (cold["schema"]!="hepta.hia.selfhost-cold-replay.v1"
                    or cold["status"]!="COLD_SELFHOST_REPLAY_PASS"
                    or cold["profile"]!=literal_assignment(ROOT/"tools/hia_selfhost_contract.py","PROFILE",captured)
                    or set(cold["checks"])!=required or any(value is not True for value in cold["checks"].values())):
                raise ValueError("caller complete cold admission differs")
            integer(cold["returncode"],0)
            equal(cold["generation_sha256"],[inner["compiler_sha256"]]*3,"caller compiler differs from cold")
            build=capture(manifest_path.parent/"build.json",None,captured)
            equal(build["manifest"],manifest,"caller actual builder output differs")
            equal(build["source_manifest"],cold["source_manifest"],"caller builder current cold source differs")
            equal(build["cold_report_sha256"],s.bytes_pin(next(raw1 for p,raw1 in reversed(captured) if p==cold_path))["sha256"],
                  "caller cold raw identity differs")
            nested=capture(cold["nested_report"],None,captured)
            compiler=captured_bytes(Path(nested["generations"][-1]["produced_image"]),None,captured)
            equal(s.bytes_pin(compiler)["sha256"],inner["compiler_sha256"],"actual caller cold compiler differs")
            source_raw=captured_bytes(ROOT/"examples/hia_bootstrap/service_bootstrap_word.hepta",None,captured)
            verify_pack(manifest_path,manifest,build,compiler,source_raw,image,captured)
            for name,digest in build["component_inputs"].items():
                if expected_full.get(name)!=digest:raise ValueError("caller build input lacks exact cold identity")
        from tools.hia_component_cold_readback import read_component_inputs
        read_component_inputs(ROOT,build,compiler,cold_path,
            read=lambda path:captured_bytes(path,None,captured))
    elif inner["qualification_mode"]=="DEVELOPMENT_COMPLETE_CALLERS":
        if require_cold:raise ValueError("DEV caller result is not current cold qualification")
    else:raise ValueError("undeclared caller construction scope")
    closed_administrators=read_callers_original_administrator(directory,inner,ids,captured)
    unchanged(captured)
    return {"schema":"hepta.hia.service-bootstrap-readback.v1","status":"PASS_READBACK_ONLY",
            "scope":scope,"complete_methods":len(ids),"ordered_ids":ids,
            "original_closed_administrator_methods":closed_administrators,
            "all_original_methods_claimed_bootstrap_selected":False,
            "construction_scope":inner["qualification_mode"],"original_body_and_budgets_preserved":True,
            "whole_native_stack_qualified":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence",type=Path,required=True)
    parser.add_argument("--report-sha256",required=True)
    parser.add_argument("--report-bytes",type=int,required=True)
    parser.add_argument("--require-cold",action="store_true")
    parser.add_argument("--callers",action="store_true")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    pin=s.require_pin({"bytes":args.report_bytes,"sha256":args.report_sha256})
    report={"schema":"hepta.hia.service-bootstrap-readback.v1","status":"HOLD",
            "producer_report":pin,"whole_native_stack_qualified":False}
    try:
        report=(read_callers(args.evidence,pin,require_cold=args.require_cold) if args.callers
                else read_suite(args.evidence,pin,require_cold=args.require_cold))
        return 0
    except BaseException as error:
        report["failure"]={"type":type(error).__name__,"text":str(error)}
        raise
    finally:
        s.write_json(args.output,report)
if __name__=="__main__":raise SystemExit(main())
