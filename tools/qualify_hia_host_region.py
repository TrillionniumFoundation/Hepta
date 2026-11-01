#!/usr/bin/env python3
"""Actual memfd/mprotect/threads/C ABI/HIA scalar integration and faults."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from hepta.hia_host_region import (HostRegion,HostRegionRejected,HostRegionUncertain,
    NativeRegionLibrary,TrustedRegionContract,retained_host_regions)
from tools.qualify_hia_native_ndu import file_identity,run_command,source_state,wire
from tools.qualify_hia_reduction_release import capture_native_commands

FIXTURES=ROOT/"benchmarks/hia_host_region"
ENTRIES=(("region_sum","read"),("region_fill","write"),("region_delayed_sum","read"),
         ("region_peak","read"),("region_fail_write","write"))


def build_fixture(output,clang,report):
    from hepta.hia_program_source import lower_source
    from hepta.hia_program_llvm import build_program_native
    ledger=report.setdefault("build_commands",[])
    core=lower_source((FIXTURES/"scalars.hepta").read_text())
    (output/"scalars.core.json").write_bytes(core.canonical_bytes+b"\n")
    with capture_native_commands(output,ledger):
        report["hia_scalar_compilation"]=build_program_native(core,output/"scalars.o",clang=str(clang),kind="object")
    target=output/"bridge.so"
    run_command([clang,"-O2","-fPIC","-shared","-std=c11","-pthread",FIXTURES/"bridge.c",output/"scalars.o","-o",target],output,ledger)
    report["artifact"]=file_identity(target)
    return target,report["artifact"]["sha256"]


def exercise(path,digest):
    report={"observations":[],"denials":[]}
    library=NativeRegionLibrary(path,digest,TrustedRegionContract(ENTRIES,True))
    region=HostRegion(4096)
    def deny(label,operation):
        try: operation()
        except (HostRegionRejected,HostRegionUncertain) as error:
            report["denials"].append({"case":label,"type":type(error).__name__,"message":str(error)})
        else: raise AssertionError("expected denial: "+label)
    def observe(label): report["observations"].append({"case":label,**region.snapshot()})
    observe("initial_no_access")
    expected=bytes((17+i)%256 for i in range(4096))
    assert region.call(library,"region_fill",generation=0,argument=17)==sum(expected)
    with region.borrow("read",generation=0) as lease: assert lease.read()==expected
    assert region.call(library,"region_sum",generation=0,offset=7,length=31)==sum(expected[7:38])
    deny("out_of_bounds",lambda:region.borrow("read",generation=0,offset=4095,length=2))
    with region.borrow("read",generation=0) as lease:
        deny("read_lease_write",lambda:lease.write(expected))
        deny("writer_while_reader",lambda:region.borrow("write",generation=0))
        observe("actual_read_mapping")
    with region.borrow("write",generation=0) as lease:
        observe("actual_write_mapping")
        deny("reader_while_writer",lambda:region.borrow("read",generation=0))
    try: os.pwrite(region._fd,b"x",0)
    except OSError as error: report["sealed_fd_write"]={"denied":True,"errno":error.errno}
    else: raise AssertionError("F_SEAL_FUTURE_WRITE failed to deny descriptor write")
    start=threading.Barrier(3);results=[];errors=[]
    def reader():
        try:
            start.wait(timeout=2)
            results.append(region.call(library,"region_delayed_sum",generation=0,argument=120,timeout=2))
        except BaseException as error: errors.append(repr(error))
    threads=[threading.Thread(target=reader) for _ in range(2)]
    for thread in threads: thread.start()
    start.wait(timeout=2)
    deadline=time.monotonic()+2
    while region.snapshot()["read_leases"]<2 and time.monotonic()<deadline:
        threading.Event().wait(.001)
    assert region.snapshot()["read_leases"]==2
    observe("two_actual_native_readers")
    deny("writer_during_native_reads",lambda:region.borrow("write",generation=0))
    deny("close_active_code",library.close)
    deny("unmap_active_region",region.close)
    for thread in threads: thread.join(3)
    assert not errors and results==[sum(expected)]*2
    peak=region.call(library,"region_peak",generation=0)
    assert peak>=2
    report["native_concurrent_reader_peak"]=peak
    deny("timeout",lambda:region.call(library,"region_delayed_sum",generation=0,argument=150,timeout=.002))
    observe("timeout_retains_data_and_worker")
    deny("reuse_quarantined",lambda:region.borrow("read",generation=1))
    deny("old_generation",lambda:region.borrow("read",generation=0))
    deny("recover_before_quiescence",lambda:region.recover(timeout=0))
    deny("unmap_uncertain",region.close)
    deny("release_uncertain_code",library.close)
    region.recover(timeout=2)
    observe("joined_zeroed_new_generation")
    generation=region.snapshot()["generation"]
    with region.borrow("read",generation=generation) as lease: assert lease.read()==bytes(4096)
    deny("stale_after_recovery",lambda:region.borrow("write",generation=0))
    deny("native_partial_write_error",lambda:region.call(library,"region_fail_write",generation=generation))
    observe("failed_write_quarantined")
    region.recover()
    generation=region.snapshot()["generation"]
    with region.borrow("read",generation=generation) as lease: assert lease.read()==bytes(4096)
    retained=region.borrow("read",generation=generation)
    deny("timeout_with_external_lease",lambda:region.call(library,"region_delayed_sum",generation=generation,argument=100,timeout=.002))
    deny("external_lease_blocks_recovery",lambda:region.recover(timeout=2))
    deny("revoked_external_lease",retained.read)
    retained.close();region.recover()
    observe("all_external_leases_released_before_recovery")
    report["library"]=library.snapshot()
    report["region_release"]=region.close();report["library_release"]=library.close()
    report["retained_after"]=retained_host_regions()
    assert not report["retained_after"]["regions"] and not report["retained_after"]["libraries"]
    return report


def fault_child(path,digest):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_CPU,(5,5))
    region=HostRegion(4096)
    library=NativeRegionLibrary(path,digest,TrustedRegionContract((("region_bad_read","read"),),True))
    print("deliberate false FFI read contract: native write must SIGSEGV",flush=True)
    region.call(library,"region_bad_read",generation=0)
    raise AssertionError("read-only native mapping accepted a write")


def bindings():
    paths=[*sorted((ROOT/"hepta").glob("*.py")),*sorted(FIXTURES.glob("*")),Path(__file__),
           ROOT/"tools/qualify_hia_reduction_release.py",ROOT/"tools/qualify_hia_native_ndu.py"]
    return {str(p.relative_to(ROOT)):file_identity(p)["sha256"] for p in paths if p.is_file()}


def run(output,clang):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns()
    report={"schema":"hepta.hia.host-region-qualification.v1","status":"running",
        "source_before":source_state(),"bindings_before":bindings(),
        "compiler_before":file_identity(clang),
        "scope":"actual Linux x86_64 hosted RAM, trusted synchronous no-escape C ABI and HIA scalar integration",
        "claims":{"arbitrary_foreign_pointers_safe":False,"mmio_dma_supported":False,"untrusted_native_code_isolated":False,"whole_language_memory_model_proved":False}}
    (output/"REGISTRATION.json").write_bytes(wire(report)+b"\n")
    try:
        path,digest=build_fixture(output,clang,report)
        report["execution"]=exercise(path,digest)
        command=[sys.executable,str(Path(__file__).resolve()),"--fault-child","--library",str(path),"--sha256",digest]
        attempted=time.monotonic_ns()
        fault=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=10)
        for name,raw in (("stdout",fault.stdout),("stderr",fault.stderr)):
            (output/("fault."+name)).write_bytes(raw)
        report["kernel_read_only_fault"]={"argv":command,"returncode":fault.returncode,"expected":-signal.SIGSEGV,
            "wall_ns":time.monotonic_ns()-attempted,"stdout":file_identity(output/"fault.stdout"),"stderr":file_identity(output/"fault.stderr")}
        assert fault.returncode==-signal.SIGSEGV
        report["status"]="completed"
    except BaseException as error:
        report.update(status="failed",error={"type":type(error).__name__,"message":str(error)})
    finally:
        report["source_after"],report["bindings_after"]=source_state(),bindings()
        report["source_unchanged"]=(report["source_before"]==report["source_after"] and report["bindings_before"]==report["bindings_after"])
        report["compiler_after"]=file_identity(clang)
        report["artifact_after"]=file_identity(report["artifact"]["path"]) if "artifact" in report else None
        report["tool_artifact_identities_unchanged"]=(report["compiler_before"]==report["compiler_after"] and report.get("artifact")==report["artifact_after"])
        report["qualification_valid"]=(report["status"]=="completed" and report["source_unchanged"] and report["tool_artifact_identities_unchanged"])
        report["whole_lifecycle_wall_ns"]=time.monotonic_ns()-started
        (output/"RESULT.json").write_bytes(wire(report)+b"\n")
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output");parser.add_argument("--clang",default=shutil.which("clang"))
    parser.add_argument("--fault-child",action="store_true");parser.add_argument("--library");parser.add_argument("--sha256")
    args=parser.parse_args()
    if args.fault_child: fault_child(args.library,args.sha256)
    if not args.output: parser.error("--output required")
    report=run(args.output,Path(args.clang).resolve())
    print(json.dumps({k:report.get(k) for k in ("status","qualification_valid","source_unchanged","whole_lifecycle_wall_ns","error")}))
    return 0 if report["qualification_valid"] else 1


if __name__=="__main__": raise SystemExit(main())
