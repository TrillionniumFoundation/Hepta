"""Fresh complete bootstrap lanes; immutable originals are admitted before candidates."""
from __future__ import annotations
import argparse
import builtins
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests import hia_service_bootstrap_oracle as oracle
from tests import hia_service_bootstrap_support as support
SCHEMA = "hepta.hia.service-bootstrap-finite-observations.v2"

class VMEntry:
    def __init__(self, program):
        self.program, self.calls = program, 0
    def __call__(self, source, size, output, capacity, state, extent):
        import ctypes
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        raw = ctypes.string_at(source, size)
        owners = [_Owner(i+1, bytearray(data)) for i, data in enumerate((
            raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)))]
        machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
        code = machine.invoke(machine.functions["f0"],
                              [_View(owner, i != 0) for i, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError("independent VM changed the read-only request")
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        self.calls += 1
        return code

class EntryCounter:
    def __init__(self, entry):
        self.entry, self.calls = entry, 0
    def __call__(self, *args):
        self.calls += 1
        return self.entry(*args)

class Backend:
    """Actual public code, explicit fixture namespace, genuine image/VM entry."""
    def __init__(self, lane, manifest):
        from hepta import hia_agent_service as api, hia_service_bootstrap_native as native
        self.api, self.native, self.lane = api, native, lane
        self.manifest = None if manifest is None else str(manifest)
        if lane == "vm":
            from hepta.hia_agent_assembly import assemble_program
            from hepta.hia_program_runtime_prepared import prepare_runtime_program
            image = object.__new__(native.NativeServiceBootstrap)
            image.image_sha256 = "independent-VM-not-executable"
            image.admitted_source_sha256 = sha256(native.SOURCE.read_bytes()).hexdigest()
            image._entry = VMEntry(prepare_runtime_program(assemble_program(native.SOURCE.read_bytes())))
        else:
            image = native.installed_service_bootstrap(str(manifest))
            image._entry = EntryCounter(image._entry)
        self.image = image
        self.captured_builtins = dict(vars(builtins))
        self.namespace = {"__name__":"hepta.hia_agent_service", "__package__":"hepta",
                          "__builtins__":self.captured_builtins}
        def clone(function):
            value = types.FunctionType(function.__code__, self.namespace, function.__name__,
                                       function.__defaults__, function.__closure__)
            value.__kwdefaults__ = None if function.__kwdefaults__ is None else dict(function.__kwdefaults__)
            return value
        self.imports = {name:clone(function) for name, function in api._SERVICE_BOOTSTRAP_IMPORT_PORTS.items()}
        self.layouts = dict(api._SERVICE_BOOTSTRAP_LOCAL_LAYOUTS)
        self.references = {mode:clone(function) for mode, function in api._SERVICE_BOOTSTRAP_REFERENCES.items()}
        for mode, method in enumerate(oracle.METHODS, 1):
            if self.references[mode].__code__.co_varnames != oracle.ORIGINALS[method].__code__.co_varnames:
                raise ValueError("candidate local layout differs from the exact original body")
        self.poison_calls = []
        def poison(*args, **kwargs):
            self.poison_calls.append("retained-body")
            raise AssertionError("selected bootstrap called a retained complete body")
        self.poison = {mode:poison for mode in self.references}
        self.selection = {"HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST":str(manifest or "independent-VM")}
        backend = self
        def frame(selected, mode, initial):
            if selected is not backend.image:
                raise AssertionError("public dispatcher changed the admitted image")
            return native.ServiceBootstrapFrame(selected, mode, initial,
                namespace=backend.namespace, global_builtins=backend.captured_builtins,
                import_ports=backend.imports, local_layouts=backend.layouts)
        def installed(path):
            if not path:
                raise ValueError("native service bootstrap selector must not be empty")
            if lane == "native" and native.installed_service_bootstrap(path) is not image:
                raise AssertionError("public loader no longer selects the same actual image")
            return image
        self.adapter_view = types.SimpleNamespace(ServiceBootstrapFrame=frame,
                                                  installed_service_bootstrap=installed)
        def loader(name):
            if name != "hepta.hia_service_bootstrap_native":
                raise AssertionError("public dispatcher requested an unrelated owner")
            return backend.adapter_view
        self.namespace.update({
            "_SERVICE_BOOTSTRAP_ITER":iter,
            "_SERVICE_BOOTSTRAP_BASE_EXCEPTION":BaseException,
            "_SERVICE_BOOTSTRAP_GLOBAL_BUILTINS":self.captured_builtins,
            "_SERVICE_BOOTSTRAP_IMPORT_PORTS":self.imports,
            "_SERVICE_BOOTSTRAP_LOCAL_LAYOUTS":self.layouts,
            "_SERVICE_BOOTSTRAP_REFERENCES":self.poison,
            "_SERVICE_BOOTSTRAP_LOADER":loader,
            "_service_bootstrap_os":types.SimpleNamespace(environ=self.selection),
        })
        self.functions = {name:clone(getattr(api.HIAAgentService, name)) for name in oracle.METHODS}
        self.public_code = {name:sha256(function.__code__.co_code).hexdigest()
                            for name, function in self.functions.items()}
        self.unselected_cases = []
    def select(self, case):
        unselected = case["method"] == "__init__" and case["scenario"] == "actual-public-unselected"
        self.namespace["_SERVICE_BOOTSTRAP_REFERENCES"] = self.references if unselected else self.poison
        if unselected:
            self.selection.pop("HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST", None)
            self.unselected_cases.append(case["id"])
        else:
            self.selection["HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST"] = str(self.manifest or "independent-VM")
        return self.functions, self.namespace, self.captured_builtins

class UnselectedBackend:
    """Actual unselected public wrappers; importing the optional owner is forbidden."""
    def __init__(self):
        from hepta import hia_agent_service as api
        owner_name = "hepta.hia_service_bootstrap_native"
        if owner_name in sys.modules:
            raise AssertionError("fresh absent-owner lane already imported its optional adapter")
        self.captured_builtins = dict(vars(builtins))
        self.namespace = {"__name__":"hepta.hia_agent_service", "__package__":"hepta",
                          "__builtins__":self.captured_builtins}
        def clone(function):
            result = types.FunctionType(function.__code__, self.namespace, function.__name__,
                                        function.__defaults__, function.__closure__)
            result.__kwdefaults__ = None if function.__kwdefaults__ is None else dict(function.__kwdefaults__)
            return result
        references = {mode:clone(fn) for mode,fn in api._SERVICE_BOOTSTRAP_REFERENCES.items()}
        def forbidden(name):
            raise AssertionError("unselected public route tried to import its optional owner")
        self.namespace.update({"_SERVICE_BOOTSTRAP_REFERENCES":references,
            "_SERVICE_BOOTSTRAP_LOADER":forbidden,
            "_service_bootstrap_os":types.SimpleNamespace(environ={})})
        self.functions = {name:clone(getattr(api.HIAAgentService,name)) for name in oracle.METHODS}
        self.public_code = {name:sha256(fn.__code__.co_code).hexdigest() for name,fn in self.functions.items()}
        self.image = types.SimpleNamespace(_entry=types.SimpleNamespace(calls=0))
        self.poison_calls, self.unselected_cases = [], []
    def select(self,case):
        self.unselected_cases.append(case["id"])
        return self.functions,self.namespace,self.captured_builtins

def audit_original(event, args):
    if (event == "import" and args and str(args[0]).startswith("hepta")
            or event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty",
                         "os.posix_spawn", "mmap.__new__", "ctypes.dlopen", "sqlite3.connect")
            or event.startswith("os.exec")):
        raise RuntimeError("original-only bootstrap lane attempted a forbidden provider: " + event)


def _relative(base, name):
    if type(name) is not str or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("authority path leaves its declared root")
    return base / name

def _terminal_integer(value, expected=None):
    if (type(value) is not int or value < 0
            or (expected is not None and value != expected)):
        raise ValueError("original process-terminal integer differs")
    return value


def _admit_process_terminal(directory, row, start, result, checkpoint, captured):
    """Admit a separately sealed natural terminal, never a checkpoint alone."""
    terminal_path = directory/"process-terminal.json"
    raw, terminal, _ = support.capture_json(terminal_path, row["terminal"])
    captured.append((terminal_path, raw))
    pid = _terminal_integer(start["pid"])
    if pid == 0:
        raise ValueError("original child PID is not positive")
    for value in (start["pgid"], result["pid"], result["pgid"],
                  checkpoint["pid"], checkpoint["pgid"], terminal["pid"], terminal["pgid"]):
        _terminal_integer(value, pid)
    for value in (start["timeout_seconds"], result["timeout_seconds"]):
        _terminal_integer(value, 600)
    for value in (start["cleanup_seconds"], result["cleanup_seconds"]):
        _terminal_integer(value, 3)
    _terminal_integer(result["returncode"], 0)
    _terminal_integer(start["started_time_ns"])
    _terminal_integer(result["started_time_ns"], start["started_time_ns"])
    _terminal_integer(result["ended_time_ns"])
    _terminal_integer(terminal["sealed_time_ns"])
    _terminal_integer(terminal["sealer_pid"])
    if (result["ended_time_ns"] < result["started_time_ns"]
            or terminal["sealed_time_ns"] < result["ended_time_ns"]
            or terminal["sealer_pid"] == 0
            or result["timeout"] is not False or result["reaped"] is not True
            or result["cleanup_error"] is not None or result["supervisor_error"] is not None
            or result["cleanup"]["reaped"] is not True or result["cleanup"]["after"] != []
            or result["cleanup"]["signals"] != []):
        raise ValueError("original terminal lacks a natural completed owned child")
    if (checkpoint["schema"] != "hepta.hia.service-bootstrap-finite-observations.v2"
            or checkpoint["status"] != "CHECKPOINT_ORIGINAL_COMPLETE"
            or checkpoint["process_terminal_required"] is not True
            or checkpoint["late_differences"] is not None
            or checkpoint["late_comparison"] != "PENDING_PROCESS_TERMINAL"):
        raise ValueError("original child report is not the required pending checkpoint")
    _terminal_integer(checkpoint["differences"], 0)
    if checkpoint["unraisables"] != []:
        raise ValueError("original checkpoint contains an unraisable failure")
    if (terminal["schema"] != "hepta.hia.service-bootstrap-process-terminal.v2"
            or terminal["status"] != "TERMINAL_COMPLETE"
            or terminal["label"] != row["label"] or terminal["lane"] != "original"
            or terminal["natural_exit"] is not True or terminal["owned_group_gone"] is not True
            or terminal["checkpoint_report"] != {"relative":"report.json", **row["report"]}
            or terminal["start"] != {"relative":row["label"]+".start.json", **row["start"]}
            or terminal["result"] != {"relative":row["label"]+".result.json", **row["result"]}
            or not support.same(terminal["checkpoint_files"], checkpoint["files"])
            or not support.same(terminal["files"], row["files"])
            or set(terminal["files"]) != set(checkpoint["files"])):
        raise ValueError("original terminal is not bound to the checkpoint/start/result chain")
    late = terminal["late"]
    checkpoint_pin = support.require_pin(checkpoint["files"]["late-events.jsonl"])
    final_pin = support.require_pin(terminal["files"]["late-events.jsonl"])
    if (late["relative"] != "late-events.jsonl"
            or not support.same(late["checkpoint"], checkpoint_pin)
            or not support.same(late["terminal"], final_pin)
            or late["checkpoint_prefix_preserved"] is not True):
        raise ValueError("original terminal late declaration differs")
    _terminal_integer(late["append_bytes"])
    if final_pin["bytes"] != checkpoint_pin["bytes"] + late["append_bytes"]:
        raise ValueError("original late size does not extend its checkpoint")
    prefix, full, count = sha256(), sha256(), 0
    with (directory/"late-events.jsonl").open("rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            if count < checkpoint_pin["bytes"]:
                prefix.update(chunk[:checkpoint_pin["bytes"]-count])
            full.update(chunk)
            count += len(chunk)
    if (count < checkpoint_pin["bytes"] or prefix.hexdigest() != checkpoint_pin["sha256"]
            or not support.same({"bytes":count,"sha256":full.hexdigest()}, final_pin)):
        raise ValueError("original late final bytes do not preserve the exact checkpoint prefix")
    expected_names = set(checkpoint["files"]) | {"report.json", "process-terminal.json"}
    if {p.name for p in directory.iterdir()} != expected_names:
        raise ValueError("original process-terminal output set differs")
    for name, expected in terminal["files"].items():
        if type(name) is not str or Path(name).name != name:
            raise ValueError("original terminal file is not an owned basename")
        support.require_pin(expected)
        if name != "late-events.jsonl" and not support.same(expected, checkpoint["files"][name]):
            raise ValueError("a nonlate original checkpoint identity was changed")
        path = directory/name
        if path.is_symlink() or not path.is_file() or not support.same(support.file_pin(path), expected):
            raise ValueError("original process-terminal raw bytes changed: " + name)
    return {**checkpoint, "files":terminal["files"],
            "checkpoint_files":checkpoint["files"], "process_terminal":row["terminal"]}


def admit_originals(authority_path, expected_pin, input_raw, source_before):
    authority_path = Path(authority_path)
    raw, authority, pin = support.capture_json(authority_path, expected_pin)
    if (authority.get("schema") != "hepta.hia.service-bootstrap-original-authority.v2"
            or authority.get("process_terminal_complete") is not True
            or authority.get("checkpoint_reports_preserved") is not True
            or authority.get("late_comparison_scope") != "NATURAL_PROCESS_EXIT"):
        raise ValueError("bootstrap requires its complete independent original authority")
    if (authority["source_before"] != source_before or authority["source_after"] != source_before
            or authority["runtime"] != sys.version
            or authority["implementation"] != sys.implementation.name
            or authority["complete_inputs"] != support.bytes_pin(input_raw)
            or authority["base_count"] != 232):
        raise ValueError("bootstrap original authority is from another runtime/input/source")
    captured = [(authority_path, raw)]
    base_path = authority_path.parent/"base-inputs.json"
    base_raw, base_value, _ = support.capture_json(base_path, authority["base_inputs"])
    complete_path = authority_path.parent/"complete-inputs.json"
    complete_raw, complete_value, _ = support.capture_json(complete_path, authority["complete_inputs"])
    freeze_path = authority_path.parent/"derived-input-freeze.json"
    freeze_raw, freeze_value, _ = support.capture_json(freeze_path, authority["derived_input_freeze"])
    captured.extend(((base_path,base_raw),(complete_path,complete_raw),(freeze_path,freeze_raw)))
    base_cases, domain_raw = oracle.cases()
    if (complete_raw != input_raw or oracle.canonical(base_value["cases"]) != oracle.canonical(base_cases)
            or base_value["basis_ids"] != list(oracle.BASIS_IDS)
            or base_value["fault_families"] != list(oracle.FAMILIES)
            or authority["base_domain"] != support.bytes_pin(domain_raw)
            or freeze_value["complete_inputs"] != authority["complete_inputs"]
            or freeze_value["ordered_ids"] != [case["id"] for case in complete_value["cases"]]):
        raise ValueError("base/derived domain is not bound to its complete immutable source")
    lanes = {}
    expected_labels = ("basis-first", "basis-second", "complete-first", "complete-second")
    if [row["label"] for row in authority["lanes"]] != list(expected_labels):
        raise ValueError("all four original lanes are required")
    for row in authority["lanes"]:
        directory = authority_path.parent / row["label"]
        start_path = authority_path.parent / (row["label"] + ".start.json")
        result_path = authority_path.parent / (row["label"] + ".result.json")
        start_raw, start, _ = support.capture_json(start_path, row["start"])
        result_raw, result, _ = support.capture_json(result_path, row["result"])
        report_raw, report, _ = support.capture_json(directory/"report.json", row["report"])
        captured.extend(((start_path,start_raw),(result_path,result_raw),(directory/"report.json",report_raw)))
        if (result["returncode"] != 0 or result["timeout"] is not False or result["reaped"] is not True
                or result["cleanup_error"] is not None or result["supervisor_error"] is not None
                or result["cleanup"]["after"] != [] or start["command"] != result["command"]
                or report["pid"] != result["pid"] or report["pgid"] != result["pgid"]
                or report["argv"] != result["command"][3:] or report["cwd"] != str(ROOT)
                or report["lane"] != "original" or report["native_or_VM_entries"] != 0
                or report["source_before"] != source_before or report["source_after"] != source_before
                or report["runtime"] != sys.version or report["status"] != "CHECKPOINT_ORIGINAL_COMPLETE"
                or result["report"] != {"relative":"report.json",**row["report"]}):
            raise ValueError("an original report is not bound to its complete real child receipt")
        if support.file_pin(authority_path.parent/(row["label"]+".stdout.log")) != result["stdout"]:
            raise ValueError("original stdout changed")
        if (support.file_pin(authority_path.parent/(row["label"]+".stderr.log")) != result["stderr"]
                or result["stderr"]["bytes"] != 0):
            raise ValueError("original stderr changed or contains an unhandled diagnostic")
        report = _admit_process_terminal(directory,row,start,result,report,captured)
        lanes[row["label"]] = (directory, report)
    for prefix in ("basis","complete"):
        left0, lp0 = lanes[prefix+"-first"]
        right0, rp0 = lanes[prefix+"-second"]
        ids0 = [case["id"] for case in (base_cases if prefix=="basis" else complete_value["cases"])]
        expected_input = authority["base_inputs"] if prefix=="basis" else authority["complete_inputs"]
        for report0 in (lp0,rp0):
            if (type(report0["count"]) is not int or report0["count"] != len(ids0)
                    or report0["ordered_ids"] != ids0 or report0["input"] != expected_input):
                raise ValueError("an original lane does not cover its entire input")
        for channel in ("observations.jsonl","late-events.jsonl","raw-tracebacks.jsonl"):
            if not support.identical_files(left0/channel,right0/channel,lp0["files"][channel],rp0["files"][channel]):
                raise ValueError("original lane channels differ: "+prefix+"/"+channel)
    basis_path,basis_report = lanes["basis-first"]
    basis_records = []
    for _,_,row0 in support.json_lines(basis_path/"observations.jsonl",basis_report["files"]["observations.jsonl"]):
        if row0["id"] in oracle.BASIS_IDS:
            basis_records.append(row0)
    regenerated = oracle.derive(base_cases,basis_records)
    if oracle.canonical(regenerated) != oracle.canonical(complete_value["cases"]):
        raise ValueError("complete fault inputs are not exactly derived from the sealed original cutpoints")
    cases = support.parse(input_raw)["cases"]
    expected_ids = [case["id"] for case in cases]
    path, report = lanes["complete-first"]
    ids = []
    for ordinal, line, value in support.json_lines(path/"observations.jsonl",report["files"]["observations.jsonl"]):
        if ordinal >= len(cases) or value["id"] != expected_ids[ordinal]:
            raise ValueError("original ordered input coverage differs")
        if any(part["unraisable"] or part["thread_errors"] for part in value["parts"]):
            raise ValueError("original observation has an unhandled provider failure")
        ids.append(value["id"])
    if ids != expected_ids or report["count"] != len(cases):
        raise ValueError("original complete ordered domain was not fully consumed")
    for path0, raw0 in captured:
        support.exact_reread(path0,raw0)
    return authority, captured, lanes["complete-first"]

_OPEN_STREAMS = []
def output_stream(path):
    stream = Path(path).open("xb", buffering=0)
    _OPEN_STREAMS.append(stream)
    return stream

def seal_record(record, sink):
    raw = oracle.canonical(record)
    frozen = support.parse(raw)
    for ordinal, (live, expected) in enumerate(zip(record["parts"], frozen["parts"])):
        for field in ("events", "unraisable", "thread_errors"):
            log = live[field]
            if type(log) is not oracle.EventLog:
                raise AssertionError("finite observation lost its append-only event log")
            log.seal(record["id"], ordinal, field, expected[field], sink)
    return raw, frozen

def _late_compare(actual_path, expected_path, expected_pin, output):
    digest, size, count = sha256(), 0, 0
    differences = output_stream(output)
    with Path(actual_path).open("rb") as actual, Path(expected_path).open("rb") as expected:
        ordinal = 0
        while True:
            left, right = expected.readline(), actual.readline()
            if not left and not right:
                break
            if left:
                digest.update(left);size += len(left)
            if left != right:
                count += 1
                differences.write(oracle.canonical({"ordinal":ordinal,
                    "expected": None if not left else support.parse(left),
                    "actual": None if not right else support.parse(right)})+b"\n")
            ordinal += 1
    if {"bytes":size,"sha256":digest.hexdigest()} != expected_pin:
        raise ValueError("late comparison consumed a different original raw channel")
    if support.file_pin(expected_path) != expected_pin:
        raise ValueError("original late channel changed during comparison")
    return count


def run(lane, inputs_path, output, *, expected=None, expected_pin=None, manifest=None):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_before = support.source_snapshot()
    support.write_json(output/"source-before.json", source_before)
    input_raw, input_value, input_pin = support.capture_json(inputs_path)
    cases = input_value["cases"]
    frozen_cases, frozen_raw = oracle.cases()
    if (type(cases) is not list or len(cases) < 232
            or oracle.canonical(cases[:232]) != oracle.canonical(frozen_cases)
            or len({case["id"] for case in cases}) != len(cases)):
        raise ValueError("the exact complete 232 input prefix is required")
    support.write_json(output/"inputs-capture.json", {"path":str(inputs_path),**input_pin,
                      "base_domain_sha256":sha256(frozen_raw).hexdigest(),
                      "count":len(cases),"ordered_ids":[case["id"] for case in cases]})
    ordering = ["source-and-inputs-captured"]
    authority = None
    captured_authority = []
    expected_directory = expected_report = None
    if lane == "original":
        if expected is not None or manifest is not None:
            raise ValueError("an original lane has no candidate authority or image")
        if any(name == "hepta" or name.startswith("hepta.") for name in sys.modules):
            raise ValueError("the original-only process already imported product code")
        sys.addaudithook(audit_original)
        backend = None
        ordering.append("original-only-provider-guard-installed")
    else:
        if expected is None or expected_pin is None:
            raise ValueError("candidate imports require a previously pinned original authority")
        authority, captured_authority, (expected_directory, expected_report) = admit_originals(
            expected, expected_pin, input_raw, source_before)
        support.write_json(output/"expected-admission.json", {
            "authority":expected_pin,"ordered_ids":authority["ordered_ids"],
            "complete_original_count":len(cases),
            "all_original_bytes_admitted_before_candidate_import":True})
        ordering.append("all-original-bytes-admitted")
        backend = UnselectedBackend() if lane == "unselected" else Backend(lane, manifest)
        ordering.append("candidate-import-and-image")
    support.write_json(output/"ordering.json", ordering)
    streams = {name:output_stream(output/name) for name in (
        "observations.jsonl","raw-tracebacks.jsonl","late-events.jsonl",
        "differences.jsonl","entry-counts.jsonl","progress.jsonl")}
    late_stream = streams["late-events.jsonl"]
    def late_sink(row):
        late_stream.write(oracle.canonical(row)+b"\n")
    unraisables = []
    def unraisable_hook(event):
        row = {"type":type(event.exc_value).__name__,
               "message":event.err_msg, "object_type":type(event.object).__name__}
        unraisables.append(row)
        sys.__stderr__.write("bootstrap unraisable: "+json.dumps(row,ensure_ascii=True)+"\n")
        sys.__stderr__.flush()
    sys.unraisablehook = unraisable_hook
    expected_stream = None if lane == "original" else (expected_directory/"observations.jsonl").open("rb")
    expected_digest, expected_size = sha256(), 0
    done, difference_count, total_entries = [], 0, 0
    current_id = None
    fatal = None
    try:
        for ordinal, case in enumerate(cases):
            current_id = case["id"]
            streams["progress.jsonl"].write(oracle.canonical({"event":"start","ordinal":ordinal,"id":current_id})+b"\n")
            before_entries = 0 if backend is None else backend.image._entry.calls
            if backend is None:
                actual, trace = oracle.observe(case)
            else:
                functions, namespace, captured_builtins = backend.select(case)
                actual, trace = oracle.observe(case, functions=functions, namespace=namespace,
                                               captured_builtins=captured_builtins)
            actual_bytes, frozen_actual = seal_record(actual,late_sink)
            streams["observations.jsonl"].write(actual_bytes+b"\n")
            streams["raw-tracebacks.jsonl"].write(oracle.canonical(trace)+b"\n")
            if expected_stream is not None:
                expected_raw = expected_stream.readline()
                if not expected_raw.endswith(b"\n"):
                    raise ValueError("candidate expected stream ended before its complete input")
                expected_digest.update(expected_raw);expected_size += len(expected_raw)
                expected_value = support.parse(expected_raw)
                if expected_value["id"] != current_id:
                    raise ValueError("candidate expected input order differs")
                if oracle.canonical(expected_value) != actual_bytes:
                    difference_count += 1
                    streams["differences.jsonl"].write(oracle.canonical({
                        "id":current_id,"ordinal":ordinal,
                        "differences":support.differences(expected_value,frozen_actual)})+b"\n")
            entries = 0 if backend is None else backend.image._entry.calls-before_entries
            total_entries += entries
            streams["entry-counts.jsonl"].write(oracle.canonical({
                "id":current_id,"entries":entries,"public_code":None if backend is None else backend.public_code,
                "explicit_unselected":lane=="unselected" or (case["method"]=="__init__" and case["scenario"]=="actual-public-unselected")})+b"\n")
            done.append(current_id)
            streams["progress.jsonl"].write(oracle.canonical({"event":"stop","ordinal":ordinal,"id":current_id})+b"\n")
            del actual, trace, frozen_actual
        if expected_stream is not None:
            if expected_stream.read(1):
                raise ValueError("candidate did not consume every original record")
            expected_identity = {"bytes":expected_size,"sha256":expected_digest.hexdigest()}
            if expected_identity != expected_report["files"]["observations.jsonl"]:
                raise ValueError("actual expected bytes consumed differ from their prior pin")
    except BaseException as error:
        fatal = {"id":current_id,"type":type(error).__name__,"text":str(error)}
        raise
    finally:
        if expected_stream is not None:
            expected_stream.close()
        support.write_json(output/"execution-progress.json", {
            "completed":len(done),"ordered_completed_ids":done,
            "expected_count":len(cases),"current_id":current_id,"fatal":fatal})
    # This process may still append destructor events during interpreter exit.
    # Preserve a pending checkpoint, never compare this prefix to a terminal.
    late_differences = None
    output_stream(output/"late-differences.jsonl")
    if lane == "unselected" and ("hepta.hia_service_bootstrap_native" in sys.modules or total_entries):
        raise AssertionError("absent-owner finite lane loaded or entered the optional owner")
    if backend is not None and backend.poison_calls:
        raise AssertionError("selected finite lane reached a retained complete method")
    source_after = support.source_snapshot()
    if source_after != source_before:
        raise ValueError("bootstrap source changed during complete finite observations")
    support.write_json(output/"source-after.json",source_after)
    support.exact_reread(inputs_path,input_raw)
    for path, raw in captured_authority:
        support.exact_reread(path,raw)
    if expected_report is not None:
        for name,pin in expected_report["files"].items():
            if support.file_pin(expected_directory/name)!=pin:
                raise ValueError("original raw file changed after candidate consumption")
    if done != [case["id"] for case in cases] or (lane in ("vm","native") and total_entries <= 0):
        raise AssertionError("complete input coverage or actual candidate entries are missing")
    files = {path.name:support.file_pin(path) for path in output.iterdir() if path.is_file()}
    passed = difference_count == 0 and not unraisables
    report = {
        "schema":SCHEMA, **support.child_identity(), "lane":lane,
        "status":("CHECKPOINT_ORIGINAL_COMPLETE" if lane=="original" else "CHECKPOINT_CANDIDATE_COMPLETE") if passed else "HOLD",
        "input":input_pin,"source_before":source_before,"source_after":source_after,
        "count":len(done),"ordered_ids":done,"differences":difference_count,
        "late_differences":late_differences,"unraisables":unraisables,
        "late_comparison":"PENDING_PROCESS_TERMINAL","process_terminal_required":True,
        "native_or_VM_entries":total_entries,"files":files,
        "expected_authority":expected_pin,
        "public_code_binding":None if backend is None else backend.public_code,
        "explicit_unselected_cases":[] if backend is None else backend.unselected_cases,
        "original_code_objects_shared_within_lane":True,
        "scope":"finite frozen original methods and explicit provider namespace; raw traceback frames are separately retained, never normalized",
        "late_scope":"checkpoint prefix only; natural process exit and separate parent terminal seal are required before complete late comparison",
        "whole_native_stack_qualified":False,
    }
    support.write_json(output/"report.json",report)
    return 0 if passed else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane",choices=("original","unselected","vm","native"),required=True)
    parser.add_argument("--inputs",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--expected",type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-bytes",type=int)
    parser.add_argument("--manifest",type=Path)
    args=parser.parse_args()
    expected_pin=None
    if args.expected is not None:
        if args.expected_sha256 is None or args.expected_bytes is None:
            parser.error("expected authority needs its prior bytes and SHA256")
        expected_pin={"bytes":args.expected_bytes,"sha256":args.expected_sha256}
    raise SystemExit(run(args.lane,args.inputs,args.output,expected=args.expected,
        expected_pin=expected_pin,manifest=args.manifest))
if __name__=="__main__":
    main()
