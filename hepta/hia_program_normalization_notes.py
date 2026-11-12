"""Development-only fixed CPython note mechanism, not an HIA policy owner.

The HIA-produced fixed image is copied into an immutable native code mapping.
A private address table is written once, then made read-only (not executable).
The same interpreter's four exported functions remain held for this mapping.
No submitted document, JSON traversal, classification or recursion guard is
implemented here. Current development admission is exact CPython 3.14.4.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
import mmap
import os
from pathlib import Path
import struct
import sys
import sysconfig

from .hia_json_preflight_native import NativeHiaJsonImage

API_NAMES=("Py_IncRef","PyErr_SetRaisedException","PyErr_GetRaisedException","_PyErr_FormatNote")


def require_supported_interpreter():
    """Refuse unqualified interpreter ABIs before any executable mapping."""
    if (sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 14, 4)
            or sysconfig.get_config_var("Py_GIL_DISABLED")):
        raise ValueError("this development normalization requires CPython 3.14.4 with the GIL")


class _DlInfo(ctypes.Structure):
    _fields_=[("filename",ctypes.c_char_p),("base",ctypes.c_void_p),
              ("symbol",ctypes.c_char_p),("address",ctypes.c_void_p)]


class NativeCPythonNotes:
    """Explicit fixed host mechanism; native coordinator owns every use."""

    def __init__(self,image:bytes,image_sha256:str):
        require_supported_interpreter()
        self._code=self._api_map=self._entry=self._delivery=None
        self._symbols=()
        self._api_address=self._code_address=0
        self.cleanup_error=None
        self.closed=False
        self._active=0
        self.image_sha256=image_sha256
        self._expected_api=b""
        self.api_identity=()
        self.interpreter_identity={
            "executable":str(Path(sys.executable).resolve(strict=True)),
            "version":sys.version,"hexversion":sys.hexversion,
            "soabi":sysconfig.get_config_var("SOABI")}
        self.interpreter_identity["executable_sha256"]=sha256(
            Path(self.interpreter_identity["executable"]).read_bytes()).hexdigest()
        try:
            symbols=tuple(getattr(ctypes.pythonapi,name) for name in API_NAMES)
            pointers=tuple(ctypes.cast(symbol,ctypes.c_void_p).value for symbol in symbols)
            if any(type(pointer) is not int or pointer<=0 for pointer in pointers):
                raise ValueError("current interpreter note API pointer is absent")
            libc=ctypes.CDLL(None,use_errno=True)
            dladdr=libc.dladdr
            dladdr.argtypes=[ctypes.c_void_p,ctypes.POINTER(_DlInfo)]
            dladdr.restype=ctypes.c_int
            identities=[];origins={}
            for name,pointer in zip(API_NAMES,pointers):
                info=_DlInfo()
                if dladdr(pointer,ctypes.byref(info))!=1 or not info.filename or not info.symbol:
                    raise ValueError("current interpreter API has no shared-object identity")
                actual_symbol=os.fsdecode(info.symbol)
                if actual_symbol!=name or info.address!=pointer:
                    raise ValueError("current interpreter note API symbol identity differs")
                path=Path(os.fsdecode(info.filename)).resolve(strict=True)
                if str(path) not in origins:
                    origins[str(path)]=sha256(path.read_bytes()).hexdigest()
                identities.append({"name":name,"address":pointer,
                    "image":str(path),"image_sha256":origins[str(path)],
                    "image_base":info.base})
            self._symbols=symbols
            self.api_identity=tuple(identities)
            self._expected_api=struct.pack("<4Q",*pointers)
            self._code=NativeHiaJsonImage(image,image_sha256)
            self._code_address=ctypes.cast(self._code._entry,ctypes.c_void_p).value
            self._api_map=mmap.mmap(-1,len(self._expected_api),
                flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ|mmap.PROT_WRITE)
            self._api_map.write(self._expected_api)
            self._api_address=ctypes.addressof(ctypes.c_char.from_buffer(self._api_map))
            mprotect=libc.mprotect
            mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
            mprotect.restype=ctypes.c_int
            if mprotect(self._api_address,len(self._expected_api),mmap.PROT_READ)!=0:
                raise OSError(ctypes.get_errno(),"mprotect CPython API table")
            if self._api_map[:]!=self._expected_api:
                raise ValueError("CPython API table changed during admission")
            self._entry=ctypes.PYFUNCTYPE(ctypes.py_object,ctypes.c_void_p,
                ctypes.py_object,ctypes.c_uint64,ctypes.py_object,ctypes.py_object,
                ctypes.c_int64)(self._code_address)
            self._delivery=ctypes.PYFUNCTYPE(ctypes.c_void_p,ctypes.c_void_p,
                ctypes.py_object,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_void_p,
                ctypes.c_int64)(self._code_address)
            for path,digest in origins.items():
                if sha256(Path(path).read_bytes()).hexdigest()!=digest:
                    raise ValueError("interpreter code changed during API admission")
            if sha256(Path(self.interpreter_identity["executable"]).read_bytes()).hexdigest()!=self.interpreter_identity["executable_sha256"]:
                raise ValueError("interpreter executable changed during API admission")
        except BaseException:
            try:self.close()
            except BaseException:pass
            raise

    def note(self,error,kind,container,key,index):
        if self.closed or self._entry is None:
            raise RuntimeError("fixed CPython note mechanism is closed")
        if not issubclass(type(error),BaseException):
            raise TypeError("note transport requires an actual exception instance")
        if (type(kind) is not int or not 1<=kind<=3 or type(index) is not int
                or not 0<=index<=sys.maxsize or (kind!=2 and index!=0)
                or (kind in (2,3) and key is not None)):
            raise ValueError("invalid fixed exception-note transport frame")
        if self._api_map[:]!=self._expected_api:
            raise RuntimeError("immutable current-interpreter API table changed")
        result=None
        self._active+=1
        try:
            result=self._entry(self._api_address,error,kind,container,key,index)
            if self._api_map[:]!=self._expected_api:
                raise RuntimeError("fixed note mechanism changed its API table")
            if not issubclass(type(result),BaseException):
                raise RuntimeError("fixed note mechanism lost the resulting exception")
            return result
        finally:
            self._active-=1
            # A foreign repr traceback can retain this frame through f_back
            # even when the C function catches and returns its exception.
            # Release only this transport's local argument/result borrows.
            # Native error owners, parent scopes and pins are untouched.
            result=error=container=key=None

    def deliver(self,error):
        """Propagate the same raised exception without Python implicit context."""
        if self.closed or self._delivery is None:
            raise RuntimeError("fixed CPython note mechanism is closed")
        if not issubclass(type(error),BaseException):
            raise TypeError("delivery requires an actual exception instance")
        if self._api_map[:]!=self._expected_api:
            raise RuntimeError("immutable current-interpreter API table changed")
        self._active+=1
        try:
            self._delivery(self._api_address,error,4,None,None,0)
        finally:
            self._active-=1
            error=None
        raise RuntimeError("fixed exception delivery unexpectedly returned")

    def close(self):
        if self._active:
            raise RuntimeError("cannot close a currently executing CPython note mechanism")
        self.closed=True
        self._entry=self._delivery=None
        first=None
        if self._api_map is not None:
            try:self._api_map.close();self._api_map=None
            except BaseException as error:first=error
        if self._code is not None:
            try:self._code._mapping.close();self._code=None
            except BaseException as error:
                if first is None:first=error
        self.cleanup_error=first
        if first is not None:raise first
