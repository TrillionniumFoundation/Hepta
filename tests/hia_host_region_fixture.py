"""Actual HIA Core/C host-memory test fixture, without a source frontend.

C remains an independent synchronous-FFI test caller. HIA scalar functions use
the direct Core machine emitter; neither Rust, LLVM nor a source parser is used.
"""
from hashlib import sha256
import os
from pathlib import Path
import threading
import time
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_native import build_program_machine
from hepta.clang_capture import run_bounded
from hepta.native_tool_identity import digest_executable
from hepta.hia_host_region import (HostRegion,HostRegionRejected,HostRegionUncertain,
    NativeRegionLibrary,TrustedRegionContract,retained_host_regions)
ROOT=Path(__file__).resolve().parents[1]
ASSEMBLY=ROOT/'tests/fixtures/hia_host_region/scalars.hepta'
BRIDGE=ROOT/'benchmarks/hia_host_region/bridge.c'
ENTRIES=(("region_sum","read"),("region_fill","write"),("region_delayed_sum","read"),
         ("region_peak","read"),("region_fail_write","write"))

def build_fixture(output,clang,report,*,extra_sources=()):
    output=Path(output);clang=Path(clang).resolve(strict=True)
    before=digest_executable(clang)
    core=assemble_program(ASSEMBLY.read_bytes())
    # Independent mathematical observations precede native object generation.
    for acc,value in [(0,0),(1,2),((1<<64)-1,1),((1<<63),1<<63)]:
        assert execute_program(core,'hia_region_fold',[acc,value])['result']==(acc+value)&((1<<64)-1)
    for seed,index in [(0,0),(13,6),((1<<32)-1,1),(1,(1<<64)-1),(255,257)]:
        assert execute_program(core,'hia_region_byte',[seed,index])['result']==(seed+index)&255
    (output/'scalars.core.json').write_bytes(core.canonical_bytes+b'\n')
    native=build_program_machine(core,output/'scalars.o',kind='object',linker='/not/used')
    assert native['ok'] and not native['claims']['llvm_ir_used'] and not native['claims']['rust_codegen_used']
    report['hia_scalar_compilation']=native
    target=output/'bridge.so'
    command=[str(clang),'-O2','-fPIC','-shared','-std=c11','-pthread',str(BRIDGE),
             *map(str,extra_sources),str(output/'scalars.o'),'-o',str(target)]
    capture=run_bounded(command,cwd=output,timeout=30,stdout_limit=65536,stderr_limit=65536)
    report.setdefault('build_commands',[]).append({'argv':command,'returncode':capture.returncode,
            'stdout':capture.stdout,'stderr':capture.stderr})
    if capture.returncode:raise AssertionError(report['build_commands'][-1])
    assert digest_executable(clang)==before
    digest=sha256(target.read_bytes()).hexdigest()
    report['artifact']={'path':str(target),'sha256':digest,'bytes':target.stat().st_size}
    return target,digest


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
