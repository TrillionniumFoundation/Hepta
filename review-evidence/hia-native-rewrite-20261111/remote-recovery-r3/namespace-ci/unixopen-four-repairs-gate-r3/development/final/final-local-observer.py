"""Derived final local status; original receipts remain byte-for-byte unchanged."""
from pathlib import Path
import hashlib,json,stat
OUT=Path(__file__).resolve().parent
N=Path("/workspace/scratch/9acdfa9f5639/runtime-development/nine-role-local-r4")
D=Path("/dev/shm/hia-namespace-db-alpha-development-r1")
def identity(path):
 raw=path.read_bytes();st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
 return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),gitsha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),mode=stat.S_IMODE(st.st_mode))
def read(path):return json.loads(path.read_bytes())
build_path=N/"evidence/actual-unixopen-build-r1/summary.json"
group_path=N/"evidence/actual-unixopen-raw-prefix-r1/summary.json"
build=read(build_path);group=read(group_path)
build_process=read(N/"build-complete.process.json");group_process=read(N/"raw-prefix.process.json")
assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_role_compiles"]==9
assert build["packer_entries"]==len(build["packer_controls"])==45
assert build["executable"]["layout"]["relocation_count"]==0
assert build["source_pins_unchanged"] and build_process["status"]=="PASS"
assert group["status"]=="INCOMPLETE" and group["completed_cases"]==4
assert group["actual_native_entries"]==group["full_VM_entries"]==137
assert group_process["status"]=="FAIL" and group_process["returncode"]==-9
assert group_process["raw_wait_status"]==9 and not group_process["wall_timeout"]
assert group_process["kernel_limits"]==dict(address_bytes=1<<30,core_bytes=0,cpu_seconds=90)
cases=[]
for item in group["case_results"]:
 path=N/"evidence/actual-unixopen-raw-prefix-r1/cases"/item["label"]
 process=read(path/"actual-issuer-process.json")
 assert process["returncode"]==0 and process["source_unchanged"]
 assert not process["wall_watchdog_fired"] and not process["wall_kill_sent"]
 case=dict(label=item["label"],original_summary_status=item["status"],actual_ELF_returncode=0,
  actual_ELF_CPU_seconds=process["usage"]["user"]+process["usage"]["system"],actual_ELF_elapsed_ns=process["elapsed_ns"],
  original_process=identity(path/"actual-issuer-process.json"),trace=identity(path/"trace.bin"))
 if item["status"]=="PASS":
  replay=item["replay"]
  assert replay["native_entries"]==replay["VM_entries"] and replay["all_native_return_output_workspace_bytes_equal"]
  case.update(fully_compared_entries=replay["native_entries"],complete_case=True)
 else:
  frontier=path/"full-native-VM-replay/frontier.json"
  case.update(complete_case=False,last_flushed_VM_frontier=read(frontier),frontier_identity=identity(frontier))
 cases.append(case)
assert len(cases)==5 and all(x["complete_case"] for x in cases[:4]) and not cases[-1]["complete_case"]
checked=[]
for p in [N/"evidence/actual-unixopen-build-r1/source-before.json",N/"evidence/actual-unixopen-raw-prefix-r1/source-before.json"]:
 rows=read(p)
 for path,expected in rows.items():
  observed=identity(Path(path))
  fields=["bytes","sha256","mode"] if p.parent.name=="actual-unixopen-build-r1" else ["bytes","sha256","gitsha","mode"]
  assert set(expected)==set(fields)
  assert all(observed[k]==expected[k] for k in fields)
 checked.append(dict(original_inventory=identity(p),files=len(rows),readback_after_failed_child=True,original_child_finalizer_claimed=False))
db=read(D/"actual-r2/summary.json");db_process=read(D/"paired-r2.process.json")
assert db["status"]==db_process["status"]=="PASS"
assert db["controls"]==db["old_VM"]==db["new_VM"]==db["new_native"]==71
assert db["direct_steady_VM_pairs"]==7 and db["physical_OS_syscalls"]==0
assert db["all_full_return_output_workspace_steps_resources_equal"] and db["canaries_unchanged"]
report=dict(schema="namespace-nine-role-final-local-observations-v1",
 status="FRESH_BUILD_PASS_ORIGINAL_RAW_PREFIX_GROUP_CPU_FAIL",
 scope="LOCAL_DEVELOPMENT_NOT_UBUNTU_CI_NOT_FULL_GATE_QUALIFICATION",
 source_candidate=dict(CI_git="7e168881dd60687ec7aa6687d63c4d4661c21013",inputs_git="ddfcff94c9de56b762d6f4807b45de58166b022e"),
 build=dict(original=identity(build_path),process=build_process,
  fresh_role_B3=9,fresh_packer_B3=1,new_native_packer_controls=45,zero_relocations=True),
 raw_prefix=dict(original_summary=identity(group_path),original_wait4=group_process,
  planned_cases=12,completed_cases=4,complete_case_native_VM_entries=137,actual_returned_ELF_processes=5,
  final_case_VM_replay_incomplete=True,cases=cases,
  exactly_which_internal_function_consumed_total_CPU="UNKNOWN; last flushed before-VM is not a per-function cost measurement",
  native_case_CPU_total=sum(x["actual_ELF_CPU_seconds"] for x in cases)),
 independent_readback_after_failed_group=checked,
 DB_alpha=dict(original_summary=identity(D/"actual-r2/summary.json"),process=db_process,
  old_VM=71,new_VM=71,new_native=71,direct_steady_VM_pairs=7,
  new_B3_in_comparison=0,image_from_separate_fresh_twelve_build=True,physical_OS_syscalls=0),
 planned_fresh_formal_gate=dict(groups={"raw-prefix":12,"parent-refusal":8,"transport":8},
  fresh_B3=10,packer_controls=45,sourceproof=10,subject_wall_seconds=900,
  group_CPU_seconds=90,group_wall_seconds=180,address_bytes=1<<30,VM_steps=4000000,VM_arena_bytes=32<<20,VM_depth=64),
 no_old_completed_case_inheritance=True,no_budget_expansion=True,no_target_oracle_results_cached=True,
 original12_lowFD_FAILURE_preserved=True,twelve_roles_not_in_nine_gate=True,
 full_unixOpen_closed=False,ordinary_Store_SQL31_closed=False)
raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
(OUT/"observations.json").write_bytes(raw);assert (OUT/"observations.json").read_bytes()==raw
print(json.dumps(dict(status=report["status"],fresh_B3=10,packer=45,completed_raw=4,raw_planned=12,complete_pairs=137,ELF_returned=5,db_pairs=71,direct_pairs=7),sort_keys=True))
