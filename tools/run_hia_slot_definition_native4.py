"""Actual owned original Native4 wrapper for the additional definition gate.

The original four-method class keeps its 1800-second budget and the CI step
keeps its existing 30-minute limit. Source and driver children are actual owned
processes. A missing/timeout terminal is HOLD; no old log becomes a new PASS.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
from hashlib import new as new_hash, sha256
import os
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    canonical, clean_environment, pin, read_json, regular_bytes,
    run_owned, successful_exit, write_json)
PREFIX = "HEPTA_HIA_SLOT_DEFINITION_ORIGINAL_NATIVE4"
METHODS = (
    "test_00_full_original248_derived7574_original_first_native_v5",
    "test_01_full_public84_handled12_original_first_native_v5",
    "test_02_complete_actual_admission_and_sealed_loader_controls",
    "test_03_actual_wheel_original_worker_v5_source_and_unknown_replay")
CLASS = "tests.test_hia_slot_mechanical_native.SlotMechanicalV5NativeTests"
# Verbatim already reviewed root supervision body; only CONFIG_B64 data changes.
ROOT_DRIVER_BODY = r"""import base64,hashlib,json,os,runpy,signal,sys,threading,time,traceback
from pathlib import Path
C=json.loads(base64.b64decode(CONFIG_B64,validate=True))
ROOT=Path(C['root']);REPO=Path(C['repo']);E=ROOT/C['label']
BEGIN=time.monotonic()
def pin(path):
 raw=Path(path).read_bytes()
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def write(path,value):
 with Path(path).open('x') as stream:stream.write(json.dumps(value,sort_keys=True,indent=2)+'\n')
freeze_raw=Path(C['freeze']).read_bytes()
assert {'bytes':len(freeze_raw),'sha256':hashlib.sha256(freeze_raw).hexdigest()}==C['freeze_pin']
frozen=json.loads(freeze_raw)
assert frozen['index_tree']==C['tree']
def check():
 return (Path(C['freeze']).read_bytes()==freeze_raw
  and all(Path(path).read_bytes()==raw for path,raw in authority_raw.items())
  and all(pin(REPO/name)==value for name,value in frozen['files'].items()))
authority_raw={}
for key in ('composition_readback','composition_terminal'):
 raw=Path(C[key]).read_bytes()
 assert {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}==C[key+'_pin'],key
 authority_raw[C[key]]=raw
composition=json.loads(authority_raw[C['composition_readback']])
terminal=json.loads(authority_raw[C['composition_terminal']])
assert check()
assert composition['status']=='SOURCE_FROZEN_NOT_QUALIFIED' and composition['index_tree']==C['tree']
assert terminal['returncode']==0 and terminal['observed_owned_group_gone'] and terminal['leader_reaped']
if C.get('development_compiler'):assert pin(C['development_compiler'])==C['development_compiler_pin']
assert all(pin(path)==value for path,value in C['development_origin_files'].items())
E.mkdir(mode=0o700)
sys.path.insert(0,str(REPO))
from tests.hia_slot_operations_qualification_support import group_members
assert not group_members(terminal['pid'])
for child in composition['children']:
 assert child['returncode']==0 and not child['timed_out'] and not child['signals'] and not child['remaining_owned_members']
 assert not group_members(child['command']['pid'])
import ast,re
for key in list(os.environ):
 if key.startswith(('PYTHON','HEPTA_HIA')) or key in C['clear_environment']:del os.environ[key]
os.environ.update(C['environment_additions'])
actual_ids=[]
for selector in C['selectors']:
 module_path=REPO/(selector.replace('.','/')+'.py')
 if module_path.is_file():
  module=selector;tree=ast.parse(module_path.read_bytes())
  assert not any(isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name=='load_tests' for node in tree.body)
  classes=sorted((node for node in tree.body if isinstance(node,ast.ClassDef)
   and any(isinstance(method,ast.FunctionDef) and method.name.startswith('test_') for method in node.body)),key=lambda node:node.name)
 else:
  module,classname=selector.rsplit('.',1)
  module_path=REPO/(module.replace('.','/')+'.py');tree=ast.parse(module_path.read_bytes())
  classes=[next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name==classname)]
 for cls in classes:
  actual_ids.extend(module+'.'+cls.name+'.'+name for name in sorted(node.name for node in cls.body if isinstance(node,ast.FunctionDef) and node.name.startswith('test_')))
assert actual_ids==C['expected']
component=E/'component'
assert not component.exists()
command=[sys.executable,'-I','-B',str(REPO/'tools/run_hia_unittest_gate.py'),*C['selectors']]
write(E/'plan.json',{'schema':'hepta.root.complete-reviewed-component-suite-plan.v1',
 'command':command,'complete_ordered_ids':C['expected'],'source_freeze':C['freeze_pin'],'index_tree':C['tree'],
 'original_complete_suite_timeout_seconds':1800,'root_cleanup_seconds':5,
 'original_source_controls_seconds':180,'original_installed_command_seconds':60,'original_inner_cleanup_seconds':3,
 'scope':C['scope'],'environment':C['environment_additions'],'root_pid':os.getpid(),'runtime':sys.version,
 'all_original_IDs_inputs_and_limits_preserved':True})
class DescendantMonitor:
 def __init__(self):
  self.stop_event=threading.Event();self.records={};self.errors=[];self.groups={}
  table=self.snapshot();root=table[os.getpid()]
  self.records[root['pid']]=root
  self.thread=threading.Thread(target=self.work,daemon=True)
 def snapshot(self):
  rows={}
  for path in Path('/proc').iterdir():
   if not path.name.isdecimal():continue
   try:
    value=(path/'stat').read_text();fields=value[value.rfind(')')+2:].split()
    pid=int(path.name)
    rows[pid]={'pid':pid,'parent_pid':int(fields[1]),'pgid':int(fields[2]),'sid':int(fields[3]),'start_ticks':int(fields[19]),'state':fields[0]}
   except (FileNotFoundError,ProcessLookupError,PermissionError):pass
  return rows
 def scan(self):
  rows=self.snapshot()
  active={pid for pid,item in self.records.items() if pid in rows and rows[pid]['start_ticks']==item['start_ticks']}
  changed=True
  while changed:
   changed=False
   for pid,item in rows.items():
    if pid not in active and item['parent_pid'] in active:
     if pid in self.records and self.records[pid]['start_ticks']!=item['start_ticks']:
      self.errors.append({'pid_reuse':pid});continue
     active.add(pid);self.records[pid]=item;changed=True
     if item['pgid']==item['sid'] and item['pgid']!=os.getpgrp():
      self.groups.setdefault(item['pgid'],{})[pid]=item['start_ticks']
 def work(self):
  while not self.stop_event.wait(.05):
   try:self.scan()
   except BaseException as error:
    self.errors.append({'type':type(error).__name__,'message':str(error)});return
 def start(self):
  self.scan();self.thread.start()
 def stop(self):
  self.stop_event.set();self.thread.join(timeout=1)
  if self.thread.is_alive():self.errors.append({'monitor_thread':'failed to stop'})
  self.scan()

monitor=DescendantMonitor();monitor.start()
failure=None;residual=[];commands=[];command_errors=[];owned=None;readers=[];captured={}
def capture(path):
 raw=Path(path).read_bytes()
 if str(path) in captured:assert captured[str(path)]==raw
 captured[str(path)]=raw
 return json.loads(raw)
try:
 from tests.hia_slot_operations_qualification_support import run_owned,successful_exit
 owned=run_owned(command,cwd=REPO,directory=E/'suite-owned',timeout_seconds=1800,environment=dict(os.environ))
 assert successful_exit(owned),'complete original class did not naturally pass'
 for spec in C['readbacks']:
  destination=E/'independent-readback'/spec['mode']
  destination.mkdir(mode=0o700,parents=True,exist_ok=False)
  evidence=component/spec['relative_evidence']
  receipt=evidence/spec['receipt']
  receipt_value=capture(receipt);receipt_pin=pin(receipt)
  original_reader=capture(component/spec['class_reader'])
  assert original_reader['status']=='PASS'
  argv=[sys.executable,'-I','-B',str(REPO/'tools/read_hia_worker_unknown.py'),
   '--mode',spec['mode'],'--evidence',str(evidence),
   '--expected-receipt-bytes',str(receipt_pin['bytes']),
   '--expected-receipt-sha256',receipt_pin['sha256'],'--output',str(destination/'readback.json')]
  result=run_owned(argv,cwd=REPO,directory=destination/'owned',timeout_seconds=1800,environment=dict(os.environ))
  assert successful_exit(result),'independent original worker reader did not naturally pass'
  value=capture(destination/'readback.json')
  assert value['status']=='PASS'
  if 'count' in spec:assert value['count']==spec['count']
  if 'commands' in spec:assert value['commands']==spec['commands']
  assert value==original_reader
  assert receipt.read_bytes()==captured[str(receipt)]
  readers.append({'mode':spec['mode'],'authority':receipt_pin,'report':pin(destination/'readback.json'),'result':result})
except BaseException as error:
 failure={'type':type(error).__module__+'.'+type(error).__qualname__,'message':str(error),'traceback':traceback.format_exc()}
 traceback.print_exc()
finally:
 monitor.stop()
 write(E/'observed-descendants.json',{'schema':'hepta.root.observed-descendants.v1',
  'root_pid':os.getpid(),'records':list(monitor.records.values()),'errors':monitor.errors,
  'poll_seconds':.05,'scope':'observed actual descendants only; no claim about unobserved processes'})
 command_errors.extend(monitor.errors)
 for pgid in sorted(monitor.groups):
  members=group_members(pgid)
  row={'pgid':pgid,'remaining_before':members,'signals':[]}
  if members:
   initial=monitor.groups[pgid]
   matches=[item for item in members if initial.get(item['pid'])==item['start_ticks']]
   mismatches=[item for item in members if item['pid'] in initial and initial[item['pid']]!=item['start_ticks']]
   if not matches or mismatches:row['cleanup_refused']='no unchanged independently observed process identity'
   else:
    for sig in (signal.SIGTERM,signal.SIGKILL):
     if not group_members(pgid):break
     try:os.killpg(pgid,sig);row['signals'].append(signal.Signals(sig).name)
     except ProcessLookupError:pass
     deadline=time.monotonic()+2.5
     while time.monotonic()<deadline and group_members(pgid):time.sleep(.025)
   row['remaining_after']=group_members(pgid);residual.append(row)
  commands.append(row)
 log_path=E/'suite-owned/stderr.log'
 log_raw=log_path.read_bytes() if log_path.exists() else b''
 if log_path.exists():captured[str(log_path)]=log_raw
 log=log_raw.decode('utf-8')
 stopped=[]
 for line in log.splitlines():
  match=re.fullmatch(r'(test_[A-Za-z0-9_]+) \(([^)]+)\) \.\.\. (ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)',line)
  if match:stopped.append({'id':match.group(2),'status':match.group(3)})
 counts=re.findall(r'^Ran ([0-9]+) tests? in [0-9.]+s$',log,re.MULTILINE)
 complete=([item['id'] for item in stopped]==C['expected'] and len(counts)==1 and int(counts[0])==len(C['expected']))
 stable=check()
 if C.get('development_compiler'):stable=stable and pin(C['development_compiler'])==C['development_compiler_pin']
 stable=stable and all(pin(path)==value for path,value in C['development_origin_files'].items())
 passed=(failure is None and owned is not None and successful_exit(owned) and complete
  and all(item['status']=='ok' for item in stopped) and len(readers)==len(C['readbacks'])
  and stable and not residual and not command_errors
  and all(Path(path).read_bytes()==raw for path,raw in captured.items()))
 summary={'schema':'hepta.root.complete-reviewed-component-suite-readback.v1','status':'PASS' if passed else 'HOLD',
  'scope':C['scope'],'supervisor_failure':failure,'source_freeze':C['freeze_pin'],'index_tree':C['tree'],
  'source_stable':stable,'source_file_count':len(frozen['files']),'planned':len(C['expected']),
  'expected':C['expected'],'observed_method_terminals':stopped,'complete_ordered_ids':complete,
  'actual_suite_result':owned,'independent_readbacks':readers,
  'stdout':pin(E/'suite-owned/stdout.log') if (E/'suite-owned/stdout.log').exists() else None,
  'stderr':pin(log_path) if log_path.exists() else None,'observed_owned_groups':commands,
  'residual_owned_groups':residual,'command_errors':command_errors,
  'original_suite_timeout_seconds':1800,'original_source_child_seconds':180,
  'original_installed_command_seconds':60,'original_inner_cleanup_seconds':3,
  'development_compiler':C['development_compiler_pin'],'development_origin_files':C['development_origin_files'],
  'matching_source_cold_qualified':False,'construction_scope':'EXPLICIT_DEVELOPMENT_FROM_INCOMPLETE_CURRENT_SOURCE_COLD',
  'whole_native_delivery_qualified':False,'old_stack_can_be_removed':False,
  'production_activated':False,'wall_seconds':time.monotonic()-BEGIN}
 write(E/'READBACK.json',summary)
 print('COMPLETE_COMPONENT_SUITE',C['label'],summary['status'],len(stopped),flush=True)
raise SystemExit(0 if passed else 1)
"""


def require(value, message):
    if not value:
        raise ValueError(message)


def terminal(result, before, after, started, finished):
    cleanup = result.get("owned_cleanup") or {}
    ended = ("OWNED_TIMEOUT" if result.get("timed_out") else
             "INTERRUPTED" if result.get("interruption") is not None else "NATURAL_EXIT")
    return {"schema": "hepta.root.supervised-driver-terminal.v1",
        "argv": result["command"]["argv"], "cwd": result["command"]["cwd"],
        "pid": result["pid"], "returncode": result["exit_code"], "terminal": ended,
        "leader_reaped": cleanup.get("reaped") is True,
        "observed_owned_group_gone": cleanup.get("after") == [],
        "driver_before": before, "driver_after": after,
        "stdout": result["stdout"], "stderr": result["stderr"],
        "elapsed_seconds": result["elapsed_seconds"], "started_utc": started,
        "finished_utc": finished, "inner_groups_independently_recorded": True,
        "all_unknown_descendants_or_old_groups_claimed": False}


def now():
    return datetime.now(timezone.utc).isoformat()


def freeze_sources(output):
    output.mkdir(mode=0o700)
    commands = []
    def git(label, arguments):
        result = run_owned(["git", "-C", str(ROOT), *arguments], cwd=ROOT,
            directory=output / label, timeout_seconds=30, environment=clean_environment())
        commands.append(result)
        require(successful_exit(result), "actual git source inspection failed")
        require(regular_bytes(output / label / "stderr.log") == b"", "git emitted stderr")
        return regular_bytes(output / label / "stdout.log")
    algorithm = git("object-format", ["rev-parse", "--show-object-format"]).decode("ascii").strip()
    require(algorithm in ("sha1", "sha256"), "unsupported git object format")
    tree = git("head-tree-before", ["rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    tree_rows = git("tracked-tree", ["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
    files = {}
    for row in tree_rows.split(b"\0"):
        if not row:
            continue
        header, raw_name = row.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        require(mode in ("100644", "100755") and kind == "blob", "unsupported source entry")
        require(not Path(name).is_absolute() and ".." not in Path(name).parts and name not in files,
                "unsafe or repeated source path")
        raw = regular_bytes(ROOT / name)
        blob = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        require(new_hash(algorithm, blob).hexdigest() == object_id,
                "working source differs from committed git blob: " + name)
        files[name] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    require(files, "empty actual source inventory")
    require(git("head-tree-after", ["rev-parse", "HEAD^{tree}"]).decode("ascii").strip() == tree,
            "actual source HEAD changed")
    require(all(pin(ROOT / name) == expected for name, expected in files.items()),
            "actual source changed before freeze")
    write_json(output / "FROZEN-SOURCES.json", {
        "schema": "hepta.slot.definition.ci-source-freeze.v1", "index_tree": tree,
        "files": files, "qualification_claimed": False})
    children = [{"command": result["command"], "returncode": result["exit_code"],
        "timed_out": result["timed_out"], "signals": result["owned_cleanup"]["signals"],
        "remaining_owned_members": result["owned_cleanup"]["after"]} for result in commands]
    write_json(output / "READBACK.json", {
        "schema": "hepta.slot.definition.ci-source-readback.v1",
        "status": "SOURCE_FROZEN_NOT_QUALIFIED", "index_tree": tree,
        "children": children, "source_freeze": pin(output / "FROZEN-SOURCES.json"),
        "source_file_count": len(files), "product_executed": False})
    return 0


def run_original(output, github_env=None):
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    own_path = Path(__file__).resolve(strict=True)
    own_before = pin(own_path)
    source_directory = output / "source"
    started = now()
    frozen = run_owned([sys.executable, "-I", "-B", str(own_path),
        "--freeze-sources", str(source_directory)], cwd=ROOT,
        directory=output / "source-owned", timeout_seconds=180, environment=clean_environment())
    source_terminal = terminal(frozen, own_before, pin(own_path), started, now())
    source_terminal_path = output / "source-root-terminal.json"
    write_json(source_terminal_path, source_terminal)
    require(successful_exit(frozen) and source_terminal["driver_before"] == source_terminal["driver_after"],
            "actual source freeze supervisor failed")
    source_report = read_json(source_directory / "READBACK.json")
    require(source_report["status"] == "SOURCE_FROZEN_NOT_QUALIFIED", "source capture incomplete")
    selected_cold = os.environ.get("HEPTA_HIA_SLOT_OPERATIONS_COLD_REPORT")
    selected_development = os.environ.get("HEPTA_HIA_SLOT_OPERATIONS_DEVELOPMENT_COMPILER")
    require(bool(selected_cold) != bool(selected_development), "choose exactly one original compiler input")
    environment = {name: os.environ[name] for name in (
        "PATH", "LD_LIBRARY_PATH", "CLANG", "HEPTA_CLANG", "CC", "CFLAGS",
        "CPPFLAGS", "LDSHARED", "LDFLAGS") if name in os.environ}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("HEPTA_HIA_SLOT_OPERATIONS_COLD_REPORT", "HEPTA_HIA_SLOT_OPERATIONS_DEVELOPMENT_COMPILER"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    environment["HEPTA_HIA_SLOT_OPERATIONS_EVIDENCE"] = str(output / "suite/component")
    config = {"root": str(output), "repo": str(ROOT), "label": "suite",
        "freeze": str(source_directory / "FROZEN-SOURCES.json"),
        "freeze_pin": pin(source_directory / "FROZEN-SOURCES.json"),
        "tree": source_report["index_tree"],
        "composition_readback": str(source_directory / "READBACK.json"),
        "composition_readback_pin": pin(source_directory / "READBACK.json"),
        "composition_terminal": str(source_terminal_path),
        "composition_terminal_pin": pin(source_terminal_path),
        "expected": [CLASS + "." + name for name in METHODS], "selectors": [CLASS],
        "scope": "COMPLETE_ORIGINAL_SLOT_V5_NATIVE4_ALL7822_PUBLIC84_HANDLED12_ADMISSION25_INSTALLED_EXPLICIT_OWNED_CI",
        "environment_additions": environment,
        "clear_environment": ["CPP", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
            "LD_PRELOAD", "_PYTHON_SYSCONFIGDATA_NAME", "_PYTHON_SYSCONFIGDATA_PATH",
            "_PYTHON_PROJECT_BASE", "_PYTHON_HOST_PLATFORM"],
        "readbacks": [], "development_compiler": selected_development,
        "development_compiler_pin": None if not selected_development else pin(selected_development),
        "development_origin_files": {} if not selected_cold else {selected_cold: pin(selected_cold)}}
    driver = output / "native4-root-driver.py"
    raw = ('CONFIG_B64="' + base64.b64encode(canonical(config)).decode("ascii") + '"\n'
           + ROOT_DRIVER_BODY).encode("utf-8")
    with driver.open("xb") as stream:
        stream.write(raw)
    driver_before = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    require(regular_bytes(driver) == raw, "created actual root driver differs")
    started = now()
    result = run_owned([sys.executable, "-I", "-B", str(driver)], cwd=ROOT,
        directory=output / "driver-owned", timeout_seconds=1860, environment=clean_environment())
    driver_after = pin(driver)
    end = terminal(result, driver_before, driver_after, started, now())
    end_path = output / "suite-root-terminal.json"
    write_json(end_path, end)
    bindings = {PREFIX + "_EVIDENCE": str(output / "suite/component/SlotMechanicalV5NativeTests")}
    for label, path in (("READBACK", output / "suite/READBACK.json"), ("TERMINAL", end_path)):
        if path.is_file():
            expected = pin(path)
            bindings[PREFIX + "_" + label + "_PATH"] = str(path)
            bindings[PREFIX + "_" + label + "_BYTES"] = str(expected["bytes"])
            bindings[PREFIX + "_" + label + "_SHA256"] = expected["sha256"]
    write_json(output / "environment.json", bindings)
    if github_env is not None:
        with Path(github_env).open("a", encoding="utf-8") as stream:
            for name, value in bindings.items():
                require("\n" not in value and "\r" not in value, "unsafe CI environment value")
                stream.write(name + "=" + value + "\n")
    passed = (successful_exit(result) and driver_before == driver_after
        and (output / "suite/READBACK.json").is_file()
        and read_json(output / "suite/READBACK.json")["status"] == "PASS" and pin(own_path) == own_before)
    write_json(output / "wrapper-readback.json", {
        "schema": "hepta.slot.definition.actual-native4-wrapper.v1", "status": "PASS" if passed else "HOLD",
        "source_child": frozen, "actual_driver": result, "driver_terminal": pin(end_path),
        "environment": bindings, "original_class_budget_seconds": 1800,
        "additional_driver_safety_bound_seconds": 1860, "additional_source_bound_seconds": 180,
        "existing_CI_step_timeout_minutes": 30, "CI_timeout_not_increased": True,
        "all_original_inputs_ids_methods_preserved": True, "original_native4_runs": 1,
        "qualification_claimed": False})
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence", type=Path)
    mode.add_argument("--freeze-sources", type=Path)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    if args.freeze_sources is not None:
        require(args.github_env is None, "source child cannot publish CI environment")
        return freeze_sources(args.freeze_sources)
    return run_original(args.evidence, args.github_env)


if __name__ == "__main__":
    raise SystemExit(main())
