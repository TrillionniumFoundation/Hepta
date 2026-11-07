"""Finite real C++ C-ABI bridge probe; external C++ remains outside HIA TCB."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
import ctypes
import shutil
import subprocess
from .core import Refused

SOURCE=Path(__file__).resolve().parent.parent/"fixtures"/"cpp"/"counter_bridge.cpp"

def qualify_cpp(output, compilers=("g++","clang++")):
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    rows=[]
    for compiler in compilers:
        exe=shutil.which(compiler)
        if not exe: raise Refused("E_HOST_TOOL",f"missing {compiler}")
        for revision in (1,2):
            path=out/f'counter-{compiler}-{revision}.so'
            cmd=[exe,"-std=c++17","-O2","-Wall","-Wextra","-Werror","-fPIC","-shared",
                 f"-DHIA_CPP_RELEASE={revision}",str(SOURCE),"-o",str(path)]
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
            if p.returncode:
                raise Refused("E_CPP_BUILD",p.stderr[:600])
            lib=ctypes.CDLL(str(path.resolve()))
            lib.counter_create.argtypes=[ctypes.c_int32,ctypes.POINTER(ctypes.c_uint64)]
            lib.counter_create.restype=ctypes.c_int
            lib.counter_add.argtypes=[ctypes.c_uint64,ctypes.c_int32,ctypes.POINTER(ctypes.c_int32)]
            lib.counter_add.restype=ctypes.c_int
            lib.counter_destroy.argtypes=[ctypes.c_uint64]
            lib.counter_destroy.restype=ctypes.c_int
            lib.counter_live_count.restype=ctypes.c_int
            handle=ctypes.c_uint64(); result=ctypes.c_int32()
            assert lib.counter_create(17,ctypes.byref(handle))==0
            assert handle.value>0 and lib.counter_live_count()==1
            assert lib.counter_add(handle.value,3,ctypes.byref(result))==0 and result.value==20
            assert lib.counter_add(handle.value,2**31-1,ctypes.byref(result))==3
            assert lib.counter_destroy(handle.value)==0
            assert lib.counter_destroy(handle.value)==2
            assert lib.counter_add(handle.value,1,ctypes.byref(result))==2
            assert lib.counter_live_count()==0
            rows.append({"compiler":compiler,"synthetic_revision":revision,
                         "sha256":sha256(path.read_bytes()).hexdigest(),
                         "source_sha256":sha256(SOURCE.read_bytes()).hexdigest(),
                         "native_checks":7,"live_after":lib.counter_live_count(),
                         "unsupported":"general C++ migration, external noexcept, hardware ABI across targets"})
    return {"status":"BOUNDED_CPP_BRIDGE_PASS","rows":rows,
            "real_third_party_upstream_cycle":False,"production_qualified":False}
