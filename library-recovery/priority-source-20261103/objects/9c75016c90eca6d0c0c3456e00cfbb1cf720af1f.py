"""Exact uint{8,32,64} C ABI emission for side-effect-free scalar Core only."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
import ctypes
import json
import platform
import shutil
import subprocess
import time

from .core import Verified, Refused, readmit
from .runtime import run

CTYPES = {"u8":ctypes.c_uint8,"u32":ctypes.c_uint32,"u64":ctypes.c_uint64}
C_TYPES={"u8":"uint8_t","u32":"uint32_t","u64":"uint64_t"}
SUPPORTED={"const","scalar.copy","int.add.wrap","int.sub.wrap","int.xor"}

def emit_c(verified: Verified) -> str:
    verified=readmit(verified)
    fn=verified.unpack()["function"]
    if len(fn["returns"])!=1 or fn["returns"][0] not in C_TYPES:
        raise Refused("E_ABI_PROFILE","one unsigned scalar result required")
    if any(p["type"] not in C_TYPES for p in fn["params"]):
        raise Refused("E_ABI_PROFILE","only unsigned scalar parameters")
    if any(o["op"] not in SUPPORTED for o in fn["ops"]):
        raise Refused("E_ABI_PROFILE","op unsupported by C ABI scalar profile")
    if fn["end"]["op"]!="ret" or fn["effects"]:
        raise Refused("E_ABI_PROFILE","trapping or effectful functions not emitted")
    p=", ".join(f'{C_TYPES[x["type"]]} {x["name"]}' for x in fn["params"]) or "void"
    lines=["/* GENERATED FROM VERIFIED HIA PILOT SCALAR PROFILE; NOT A SAFETY CERTIFICATE. */",
           "#include <stdint.h>","#include <limits.h>",
           "_Static_assert(CHAR_BIT == 8 && sizeof(uint32_t)==4 && sizeof(uint64_t)==8, \"unsupported ABI\");",
           f'{C_TYPES[fn["returns"][0]]} {fn["name"]}({p})'+' {']
    for op in fn["ops"]:
        o=op["out"][0];t=C_TYPES.get(o["type"])
        if t is None: raise Refused("E_ABI_PROFILE","unsupported scalar type")
        name=op["op"]
        if name=="const": expr=str(op["value"])+"ULL"
        elif name=="scalar.copy": expr=op["args"][0]
        else:
            a,b=op["args"]
            symbol={"int.add.wrap":"+","int.sub.wrap":"-","int.xor":"^"}[name]
            expr=f'({a} {symbol} {b})'
        lines.append(f'  {t} {o["name"]} = ({t})({expr});')
    lines.append(f'  return {fn["end"]["args"][0]};')
    lines.append('}')
    return "\n".join(lines)+"\n"

def compile_and_probe(v: Verified, *, output: str | Path, compilers=("gcc","clang"),
                      vectors=None, iterations=1000) -> dict:
    """Compile two independently built native ELFs and compare sampled values.

    Results never certify all input values, ARM targets, source semantics, RSS,
    tail latency or C/C++ unsafe boundaries.
    """
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    source=emit_c(v);(out/"generated.c").write_text(source)
    fn=v.unpack()["function"]
    if vectors is None: vectors=[0,1,2,3,31,255,256,1024,65535,2**32-1]
    if len(fn["params"])!=1 or fn["params"][0]["type"]!="u32":
        raise Refused("E_ABI_PROFILE","probe supports one u32 parameter")
    observations=[]
    for tool in compilers:
        compiler=shutil.which(tool)
        if compiler is None:
            raise Refused("E_HOST_TOOL",f"native compiler missing: {tool}")
        target=out/(tool+".so")
        cmd=[compiler,"-std=c11","-O2","-Wall","-Wextra","-Werror","-fPIC","-shared",
             str(out/"generated.c"),"-o",str(target)]
        build_start=time.perf_counter_ns()
        x=subprocess.run(cmd,timeout=20,capture_output=True,text=True)
        build_ns=time.perf_counter_ns()-build_start
        if x.returncode:
            raise Refused("E_NATIVE_BUILD",f"{tool} returned {x.returncode}: {x.stderr[:512]}")
        lib=ctypes.CDLL(str(target.resolve()))
        f=getattr(lib,fn["name"]);f.restype=CTYPES[fn["returns"][0]]
        f.argtypes=[CTYPES[fn["params"][0]["type"]]]
        expected=[];actual=[]
        for arg in vectors:
            val=run(v,[arg])
            if val.status!="return": raise Refused("E_ABI_DIFF","source unexpectedly did not return")
            expected.append(val.results[0]); actual.append(f(arg))
        if actual!=expected:
            raise Refused("E_ABI_DIFF","compiled native output differs from verified VM")
        start=time.perf_counter_ns();z=0
        for i in range(iterations): z^=f(vectors[i%len(vectors)])
        dur=time.perf_counter_ns()-start
        observations.append({"compiler":tool,"compiler_path":compiler,
            "version":subprocess.run([compiler,"--version"],capture_output=True,text=True,timeout=3).stdout.splitlines()[0],
            "cmd":cmd,"native_build_ns":build_ns,"binary_sha256":sha256(target.read_bytes()).hexdigest(),
            "file_bytes":target.stat().st_size,"sample_count":len(vectors),
            "actual":actual,"expected":expected,"sample_call_median_not_measured":True,
            "timed_batch_ns":dur,"timed_batch_calls":iterations,"xor_sink":z})
    return {"status":"FINITE_NATIVE_DIFFERENTIAL_PASS","profile":"host-u32-one-param-scalar",
            "target_arch":platform.machine(),"core_digest":v.core_digest,
            "C_source_sha256":sha256(source.encode()).hexdigest(),"observations":observations,
            "qualified":["sampled_native_scalar_equivalence"],
            "unqualified":["whole_program_refinement","ARM64_native","physical_RSS","native_tail_latency","resource_ownership_ABI"]}

LAYOUT_SOURCE = '''
#include <stdint.h>
#include <stddef.h>
struct hia_packet { uint8_t kind; uint32_t count; uint64_t digest; };
size_t hia_packet_size(void) { return sizeof(struct hia_packet); }
size_t hia_packet_align(void) { return _Alignof(struct hia_packet); }
size_t hia_packet_kind_offset(void) { return offsetof(struct hia_packet,kind); }
size_t hia_packet_count_offset(void) { return offsetof(struct hia_packet,count); }
size_t hia_packet_digest_offset(void) { return offsetof(struct hia_packet,digest); }
'''

def probe_native_layout(output,compilers=("gcc","clang")):
    """Actual host SysV C layout only; no general cross-target ABI theorem."""
    class Packet(ctypes.Structure):
        _fields_=[("kind",ctypes.c_uint8),("count",ctypes.c_uint32),("digest",ctypes.c_uint64)]
    expected=[ctypes.sizeof(Packet),ctypes.alignment(Packet),Packet.kind.offset,
              Packet.count.offset,Packet.digest.offset]
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    source=out/'layout.c';source.write_text(LAYOUT_SOURCE)
    funcs=["size","align","kind_offset","count_offset","digest_offset"]
    rows=[]
    for tool in compilers:
        compiler=shutil.which(tool)
        if compiler is None:raise Refused("E_HOST_TOOL","compiler unavailable")
        so=out/f'layout-{tool}.so'
        cmd=[compiler,"-std=c11","-O2","-Wall","-Wextra","-Werror","-fPIC","-shared",str(source),"-o",str(so)]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
        if result.returncode:raise Refused("E_ABI_BUILD",result.stderr[:512])
        lib=ctypes.CDLL(str(so.resolve()))
        got=[]
        for f in funcs:
            fn=getattr(lib,'hia_packet_'+f);fn.restype=ctypes.c_size_t;fn.argtypes=[]
            got.append(fn())
        if got!=expected:raise Refused("E_ABI_LAYOUT","native C layout differs from ctypes")
        rows.append({"compiler":tool,"layout":got,"sha256":sha256(so.read_bytes()).hexdigest()})
    return {"profile":"host-C11-uint8-uint32-uint64-standard-layout",
            "ctypes_expected":expected,"native_observed":rows,
            "status":"FINITE_HOST_C_LAYOUT_PASS","ARM64_execution":False,
            "C_plus_plus_abi_verified":False,"production_qualified":False}

def cross_compile_aarch64_object(v: Verified, output):
    """Cross-emit *only* an AArch64 ELF relocatable from the scalar C profile.

    This is not native execution, ABI conformance, ARM RSS or machine refinement.
    Uses target predefined unsigned types without needing a foreign sysroot.
    """
    compiler=shutil.which('clang');readelf=shutil.which('readelf')
    if not compiler or not readelf:
        raise Refused('E_HOST_TOOL','Clang and readelf are required for ARM object')
    source=emit_c(v).replace('#include <stdint.h>',
        'typedef __UINT8_TYPE__ uint8_t;\ntypedef __UINT32_TYPE__ uint32_t;\ntypedef __UINT64_TYPE__ uint64_t;')
    source=source.replace('#include <limits.h>','#define CHAR_BIT __CHAR_BIT__')
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    path=out/'generated-arm64.c';path.write_text(source)
    obj=out/'generated-arm64.o'
    cmd=[compiler,'--target=aarch64-linux-gnu','-O2','-std=c11','-Wall','-Wextra','-Werror',
         '-c',str(path),'-o',str(obj)]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
    if p.returncode:raise Refused('E_ARM_OBJECT',p.stderr[:512])
    elf=subprocess.run([readelf,'-h',str(obj)],capture_output=True,text=True,timeout=10)
    if elf.returncode or 'Machine:                           AArch64' not in elf.stdout:
        raise Refused('E_ARM_OBJECT','actual ELF is not AArch64')
    return {'status':'AARCH64_CROSS_OBJECT_CREATED','source_sha256':sha256(source.encode()).hexdigest(),
            'object_sha256':sha256(obj.read_bytes()).hexdigest(),
            'object_bytes':obj.stat().st_size,'target':'aarch64-linux-gnu',
            'actual_device_execution':False,'target_ABI_qualified':False,
            'native_resource_bounds_qualified':False,'cmd':cmd}
