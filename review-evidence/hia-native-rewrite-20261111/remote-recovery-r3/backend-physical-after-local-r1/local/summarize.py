"""Summarize the already completed local physical-after observations without target execution."""
from pathlib import Path
from hashlib import sha256
import json,sys
ROOT=Path("/dev/shm/hia-native-checker-physical-r1")
OUT=Path("/dev/shm/hia-native-checker-physical-local-results-r1")
def pin(p):
    b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=sha256(b).hexdigest())
def main():
    OUT.mkdir(exist_ok=False)
    monitor=json.loads((ROOT/"remaining-monitor-r1/summary.json").read_bytes())
    assert monitor["status"]=="PASS_LOCAL_GROUP_SET"
    groups=[]; totals={k:0 for k in ("cases","private_controls","native_entries","before_native_entries","actual_backend_processes_started","actual_before_processes_started","before_raw_syscalls","actual_after_raw_syscalls","complete_fixed_carrier_crosschecks","complete_full_CAS_cases","encoded_original_files")}
    byrole={};before={}
    for row in monitor["groups"]:
        d=Path(row["path"]);j=json.loads((d/"local-observation.json").read_bytes())
        s=json.loads((d/"subject/summary.json").read_bytes());r=json.loads((d/"readback/summary.json").read_bytes())
        assert j["status"]==s["status"]==r["status"]=="PASS"
        assert j["native_summary"]==s and j["readback_summary"]==r
        assert r["native_entries_executed"]==r["VM_entries_executed"]==0
        for k in ("cases","private_controls","native_entries","before_native_entries","before_raw_syscalls","actual_after_raw_syscalls","by_role","before_by_role"):
            assert s[k]==r[k],(d,k)
        assert s["complete_fixed_carrier_crosschecks"]==r["fixed_C_crosschecks"]
        assert s["complete_full_CAS_cases"]==r["full_CAS_cases"]
        assert s["source_pins_unchanged"] and r["source_pins_unchanged"]
        assert s["failures"]==r["failures"]==[]
        for k in totals:totals[k]+=r[k] if k=="encoded_original_files" else s[k]
        for m,src in ((byrole,s["by_role"]),(before,s["before_by_role"])):
            for role,n in src.items():m[role]=m.get(role,0)+n
        processes={}
        for label,disk in (("native","native"),("readback","originals")):
            p=d/"process/steps"/disk/"process.json";v=json.loads(p.read_bytes())
            assert v==j[label+"_process"] and v["status"]=="PASS" and v["returncode"]==0 and not v["timed_out"]
            assert v["child_cpu_seconds"]<90 and v["elapsed_ns"]<180000000000
            processes[label]=dict(cpu_seconds=v["child_cpu_seconds"],wall_seconds=v["elapsed_ns"]/1e9,original=pin(p))
        groups.append(dict(group=s["group"],variant=s["variant"],cases=s["cases"],private_controls=s["private_controls"],native_entries=s["native_entries"],before_native_entries=s["before_native_entries"],processes=processes,original_observation=pin(d/"local-observation.json"),original_subject=pin(d/"subject/summary.json"),original_readback=pin(d/"readback/summary.json")))
    assert len(groups)==20 and totals["cases"]==47 and totals["private_controls"]==22
    assert totals["complete_fixed_carrier_crosschecks"]==3 and totals["complete_full_CAS_cases"]==25
    assert totals["encoded_original_files"]==120
    assert sum(byrole.values())==totals["native_entries"] and sum(before.values())==totals["before_native_entries"]
    out=dict(schema="hia.local-physical-after-observation.v1",status="PASS_LOCAL_DEVELOPMENT",official_Ubuntu_qualification=False,groups=groups,totals=totals,by_role=byrole,before_by_role=before,fresh_B3=3,retained20_images_from_fully_read_artifact=13965177412,development_C_builds=2,old_semantic_cases_reexecuted=0,all_subject_and_readback_process_limits_pass=True,readback_target_entries_executed=0,source_delivery_git="43210ebe3e446f5c8864f5c6fc072abea5ea15e3",whole_public_build=False,native_public_Core_admission=False,second_compile_emission=False,publication=False,installed=False,cold=False)
    p=OUT/"summary.json";p.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(dict(status=out["status"],totals=totals,summary=pin(p)),sort_keys=True))
if __name__=="__main__":main()
