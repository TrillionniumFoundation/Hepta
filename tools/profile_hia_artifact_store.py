"""Source-bound diagnostic of the unchanged native 64-MiB store gate."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_hia_artifact_publication_native import ArtifactPublicationKernelTests

LIMIT = 60
TRACE = "read,write,open,openat,close,fsync,linkat,unlinkat,fstat,newfstatat,mmap,mremap,exit_group"
LINE = re.compile(r"^(?:\d+\s+)?(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(?:\s+.*?)?\s+<(\d+\.\d+)>\s*$")

def phases(path):
    events = [(float(m[1]), m[2], m[3], int(m[4]), float(m[5]))
              for line in path.read_text(errors="replace").splitlines()
              if (m := LINE.match(line))]
    if not events:
        return {"parsed_events":0,"status":"NO_PARSEABLE_SYSCALLS"}
    first=events[0][0]
    def stamp(i):
        e=events[i]
        return {"index":i,"seconds_since_first":e[0]+e[4]-first,"syscall":e[1],"result":e[3]}
    eof=next((i for i,e in enumerate(events)
              if e[1]=="read" and re.match(r"0(?:<[^>]*>)?,",e[2]) and e[3]==0),None)
    opened=next((i for i in range(eof+1,len(events))
                 if events[i][1] in ("open","openat") and events[i][3]>=0),None) if eof is not None else None
    syncs=[i for i,e in enumerate(events) if e[1]=="fsync"]
    linked=next((i for i,e in enumerate(events) if e[1]=="linkat"),None)
    wrote=next((i for i,e in enumerate(events)
                if e[1]=="write" and re.match(r"1(?:<[^>]*>)?,",e[2]) and e[3]>=0),None)
    anchors={"stdin_eof":eof,"first_open_after_input":opened,
             "first_fsync":syncs[0] if syncs else None,"linkat":linked,
             "second_fsync":syncs[1] if len(syncs)>1 else None,"stdout_first_write":wrote}
    gaps=sorted(((events[i][0]-events[i-1][0]-events[i-1][4],i)
                 for i in range(1,len(events))),reverse=True)
    totals={}
    for _,name,_,_,duration in events:
        row=totals.setdefault(name,{"count":0,"syscall_seconds":0.0})
        row["count"]+=1
        row["syscall_seconds"]+=duration
    return {"status":"OBSERVED_PREFIX_ONLY","parsed_events":len(events),
            "first_to_last_syscall_seconds":events[-1][0]+events[-1][4]-first,
            "boundaries":{k:stamp(i) if i is not None else None for k,i in anchors.items()},
            "syscall_totals":totals,
            "largest_userspace_or_scheduling_gaps":[
                {"seconds":gap,"after":stamp(i-1),"before":stamp(i)}
                for gap,i in gaps[:12] if gap>=0]}

def invoke(app, base, op, payload, traced):
    digest=sha256(payload).hexdigest()
    label=f"{len(payload)}-{op}-{'trace' if traced else 'direct'}"
    evidence=base/label
    evidence.mkdir()
    with tempfile.TemporaryDirectory(prefix="hia-store-phase-") as tmp:
        root=Path(tmp)/"store"
        root.mkdir(mode=0o700)
        if op=="store-get":
            p=root/digest
            p.write_bytes(payload)
            p.chmod(0o400)
        trace=evidence/"syscalls.log"
        argv=[str(app),op,str(root),digest if op=="store-get" else "-"]
        if traced:
            argv=["/usr/bin/strace","-f","-ttt","-T","-s","0","-y","-e","trace="+TRACE,
                  "-o",str(trace),*argv]
        started=time.monotonic()
        proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,env={"PATH":""},start_new_session=True)
        timed_out=False
        try:
            stdout,stderr=proc.communicate(input=b"" if op=="store-get" else payload,timeout=LIMIT)
        except subprocess.TimeoutExpired:
            timed_out=True
            try:
                os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout,stderr=proc.communicate(timeout=5)
        elapsed=time.monotonic()-started
        inventory=[]
        for p in sorted(root.iterdir()):
            st=p.lstat()
            inventory.append({"name":p.name,"size":st.st_size,"mode":oct(st.st_mode&0o777),
                              "sha256":sha256(p.read_bytes()).hexdigest()
                                if p.is_file() and not p.is_symlink() else None})
        valid=False
        if not timed_out and proc.returncode==0 and not stderr:
            try:
                if op=="store-get":
                    valid=stdout==payload
                else:
                    valid=json.loads(stdout)=={"sha256":digest,"bytes":len(payload)}
                if op=="store-put":
                    valid=valid and inventory==[{"name":digest,"size":len(payload),
                                                 "mode":"0o400","sha256":digest}]
                elif op=="store-hash":
                    valid=valid and not inventory
            except (ValueError,UnicodeError):
                pass
        row={"label":label,"operation":op,"instrumented":traced,"payload_bytes":len(payload),
             "payload_sha256":digest,"deadline_seconds":LIMIT,"elapsed_seconds":elapsed,
             "returncode":proc.returncode,"timed_out":timed_out,"stdout_bytes":len(stdout),
             "stdout_sha256":sha256(stdout).hexdigest(),"stderr_sha256":sha256(stderr).hexdigest(),
             "stderr_bytes":len(stderr),"inventory":inventory,
             "status":"PASS" if valid else "TIMEOUT" if timed_out else "FAIL"}
        if len(stdout)<=4096:
            (evidence/"stdout").write_bytes(stdout)
        (evidence/"stderr").write_bytes(stderr)
        if trace.exists():
            row["trace_sha256"]=sha256(trace.read_bytes()).hexdigest()
            row["trace"]=phases(trace)
        (evidence/"report.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
        print(json.dumps(row,sort_keys=True),flush=True)
        return row

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",required=True,type=Path)
    base=p.parse_args().output.resolve()
    base.mkdir(parents=True,exist_ok=False)
    cold=Path(os.environ["HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT"])
    cls=ArtifactPublicationKernelTests
    cls.setUpClass()
    try:
        app=cls.app
        app_hash=sha256(app.read_bytes()).hexdigest()
        rows=[]
        for size in (8<<20,64<<20):
            payload=b"x"*size
            for traced in (False,True):
                for op in ("store-hash","store-put","store-get"):
                    rows.append(invoke(app,base,op,payload,traced))
        report={"schema":"hepta.hia.store-phase-profile.v1","diagnostic_only":True,
                "acceptance_replaced":False,"app_sha256":app_hash,
                "cold_report_sha256":sha256(cold.read_bytes()).hexdigest(),
                "app_unchanged":sha256(app.read_bytes()).hexdigest()==app_hash,
                "deadline_seconds":LIMIT,"rows":rows,
                "direct_all_pass":all(r["status"]=="PASS" for r in rows if not r["instrumented"]),
                "traced_all_pass":all(r["status"]=="PASS" for r in rows if r["instrumented"])}
        (base/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        if not report["app_unchanged"] or not report["direct_all_pass"]:
            raise SystemExit(1)
    finally:
        cls.tearDownClass()

if __name__=="__main__":
    main()
