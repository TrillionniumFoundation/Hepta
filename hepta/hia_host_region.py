"""Bounded Linux host-owned regions crossing a trusted synchronous C ABI.

This is a hosted memory boundary, not a new Core typing theorem or a device
driver. No arbitrary pointer/fd is imported or exported. Fixed-size memfd data
is borrowed under one shared-read/exclusive-write gate and kernel protections.
Native code is pinned and mapping-checked by the existing HIA native boundary.
An uncertain call retains its mapping, code and lease until its actual owned
worker is joined. Only a reviewed no-escape FFI contract makes that join a
quiescence witness. MMIO, DMA, detached native work and hostile FFI are excluded.
"""
from __future__ import annotations

from collections import deque
import copy
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import mmap
import os
from pathlib import Path
import platform
import re
import secrets
import threading
import time

from .hia_native_differential import _pin_native_artifact
from .native_mapping_identity import verify_loaded_symbols
from .hia_adaptive import _NativeRelease


PROFILE="hepta.hia.host-memfd-region-linux-x86_64.v1"
MAX_REGION_BYTES=1024*1024
MAX_REGIONS=16
MAX_LIBRARIES=16
_REGISTRY_LOCK=threading.RLock()
_REGIONS={}
_LIBRARIES={}
_IDENT=re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,127}\Z")


class HostRegionRejected(ValueError):
    pass


class HostRegionUncertain(RuntimeError):
    pass


def _reject(message):
    raise HostRegionRejected("E_HIA_HOST_REGION: "+message)


def _host():
    if (platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}
            or not hasattr(os,"memfd_create") or ctypes.sizeof(ctypes.c_void_p)!=8 or ctypes.sizeof(ctypes.c_size_t)!=8):
        _reject("actual Linux x86_64 memfd host required")


@dataclass(frozen=True)
class TrustedRegionContract:
    """Reviewed host assertion, explicitly not a proof about arbitrary C.

    Every entry has ABI int(uint8_t*,size_t,uint64_t,uint64_t*), returns zero on
    success, observes its declared region permission, stays within the supplied
    extent, and retains neither pointer after return. It creates no detached
    work using either pointer. A false assertion is outside the safety profile.
    """
    entries: tuple
    synchronous_no_escape: bool

    def admitted(self):
        if type(self) is not TrustedRegionContract or self.synchronous_no_escape is not True:
            _reject("reviewed synchronous no-escape FFI contract required; unknown retention is denied")
        if type(self.entries) is not tuple or not 1<=len(self.entries)<=16:
            _reject("bounded exact native entry inventory required")
        result={}
        for row in self.entries:
            if (type(row) is not tuple or len(row)!=2 or type(row[0]) is not str
                    or _IDENT.fullmatch(row[0]) is None or row[0] in result
                    or type(row[1]) is not str or row[1] not in {"read","write"}):
                _reject("invalid reviewed native permission inventory")
            result[row[0]]=row[1]
        return result


class NativeRegionLibrary:
    """Retained sealed code, with actual loaded-symbol identity admission."""
    def __init__(self,path,expected_sha256,contract):
        _host()
        if type(expected_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}",expected_sha256) is None:
            _reject("explicit reviewed artifact SHA-256 required")
        if type(contract) is not TrustedRegionContract: _reject("exact trusted FFI contract required")
        self._permissions=contract.admitted()
        self._lock=threading.RLock();self._active=0;self._closed=False
        self._token=secrets.token_hex(16);self._release=_NativeRelease(None,None)
        self._debts=[];self._symbols={};self._mapping=None
        self.artifact_sha256=expected_sha256
        with _REGISTRY_LOCK:
            if len(_LIBRARIES)>=MAX_LIBRARIES: _reject("native library retention budget exhausted")
            _LIBRARIES[self._token]=self

        def close_input(fd):
            release=_NativeRelease(None,fd);release.attempt()
            if not release.complete:
                self._debts.append(release)
                _reject("input descriptor close uncertain; never retry numeric descriptor")
        try:
            raw,_,fd=_pin_native_artifact(Path(path),maximum_bytes=1024*1024,close_owner=close_input)
            self._release.fd=fd
            if sha256(raw).hexdigest()!=expected_sha256: _reject("pinned native bytes differ from reviewed artifact")
            library=ctypes.CDLL("/proc/self/fd/"+str(fd),mode=os.RTLD_NOW|os.RTLD_LOCAL)
            self._release.library=library
            for name in self._permissions:
                fn=getattr(library,name)
                fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)]
                fn.restype=ctypes.c_int
                self._symbols[name]=fn
            self._release.functions=self._symbols
            self._mapping=verify_loaded_symbols(fd,self._symbols)
        except BaseException:
            self._closed=True;self._release.attempt()
            if self._release.complete and not self._debts:
                with _REGISTRY_LOCK: _LIBRARIES.pop(self._token,None)
            raise

    def _acquire(self,symbol):
        if type(symbol) is not str: _reject("built-in native symbol name required")
        with self._lock:
            if self._closed or symbol not in self._symbols: _reject("native library closed or entry not admitted")
            # The same open descriptor and loader reference remain retained.
            verify_loaded_symbols(self._release.fd,{symbol:self._symbols[symbol]})
            self._active+=1
            return self._symbols[symbol],self._permissions[symbol]

    def _finish(self):
        with self._lock:
            if self._active<=0: _reject("native call accounting underflow")
            self._active-=1

    def __copy__(self): _reject("native library owners cannot be copied")
    def __deepcopy__(self,memo): self.__copy__()

    def snapshot(self):
        with self._lock:
            return {"artifact_sha256":self.artifact_sha256,"active_calls":self._active,
                "closed":self._closed,"loaded_mapping":copy.deepcopy(self._mapping),
                "release":self._release.snapshot(),"unresolved_input_closes":len(self._debts),
                "trusted_contract":"synchronous bounded access; no pointer retention or detached native work"}

    def close(self):
        with self._lock:
            if self._active: _reject("native code retained while a region call may execute")
            self._closed=True;result=self._release.attempt()
            if not self._release.complete or self._debts: _reject("native retirement uncertain; work permanently denied")
            with _REGISTRY_LOCK: _LIBRARIES.pop(self._token,None)
            return result


@dataclass(frozen=True)
class _LeaseGrant:
    """Owner-retained authority: mutable lease fields never define access."""
    mode: str
    offset: int
    length: int
    generation: int
    internal: bool


class RegionLease:
    """An identity-checked capability; reads return copies, never a raw view."""
    def __init__(self,owner,mode,offset,length,generation,internal=False):
        self._owner=owner;self._mode=mode;self._offset=offset;self._length=length
        self._generation=generation;self._token=secrets.token_hex(16)
        self._closed=False;self._internal=internal

    def read(self): return self._owner._read(self)
    def write(self,data): return self._owner._write(self,data)
    def close(self): return self._owner._release_lease(self)
    def __enter__(self):
        with self._owner._lock: self._owner._validate_lease(self)
        return self
    def __exit__(self,*unused): self.close()
    def __copy__(self): _reject("region leases cannot be copied")
    def __deepcopy__(self,memo): self.__copy__()


class HostRegion:
    """Finite whole-region RW leases, real page protection and join recovery.

    A lock serializes admission, generation changes and host-copy operations.
    Native reads may overlap; any native/host writer excludes every other
    lease. Lease release followed by subsequent admission is the synchronization
    order. Native entries must obey the reviewed contract. C atomics or devices
    outside this region are not governed by this memory model.
    """
    def __init__(self,length,*,max_leases=16,max_native_calls=8):
        _host()
        if type(length) is not int or not 1<=length<=MAX_REGION_BYTES: _reject("region extent outside 1..1MiB")
        if type(max_leases) is not int or not 1<=max_leases<=64: _reject("lease budget outside 1..64")
        if type(max_native_calls) is not int or not 1<=max_native_calls<=max_leases: _reject("native call budget exceeds lease budget")
        self._lock=threading.RLock();self._token=secrets.token_hex(16)
        self._length=length;self._mapped=((length+mmap.PAGESIZE-1)//mmap.PAGESIZE)*mmap.PAGESIZE
        self._max_leases=max_leases;self._max_calls=max_native_calls
        self._generation=0;self._state="initializing";self._reason=None
        self._leases={};self._lease_grants={};self._jobs={};self._events=deque(maxlen=256);self._sequence=0
        self._fd=None;self._memory=None;self._address=None;self._permission="none"
        self._release_attempted=False;self._release_report={};self._unprovable_quiescence=False
        with _REGISTRY_LOCK:
            if len(_REGIONS)>=MAX_REGIONS: _reject("retained region budget exhausted, including quarantine")
            _REGIONS[self._token]=self
        try:
            import fcntl
            self._fd=os.memfd_create("hepta-host-region",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            os.ftruncate(self._fd,self._mapped)
            self._memory=mmap.mmap(self._fd,self._mapped,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
            view=ctypes.c_ubyte.from_buffer(self._memory);self._address=ctypes.addressof(view);del view
            # Existing mapping remains writable; no future fd writes/writable
            # mappings or extent changes are admitted after these actual seals.
            required=0x0001|0x0002|0x0004|0x0010
            fcntl.fcntl(self._fd,getattr(fcntl,"F_ADD_SEALS",1033),required)
            self._seals=fcntl.fcntl(self._fd,getattr(fcntl,"F_GET_SEALS",1034))
            if self._seals&required!=required: _reject("kernel refused fixed extent/future-write seals")
            info=os.fstat(self._fd);self._identity=(info.st_dev,info.st_ino,info.st_size)
            self._protect("none");self._state="ready";self._event("created")
        except BaseException:
            self._state="permanent_deny";self._close_storage_once()
            raise

    def _event(self,kind,**fields):
        self._sequence+=1
        self._events.append({"sequence":self._sequence,"kind":kind,"generation":self._generation,**fields})

    def __copy__(self): _reject("region owners cannot be copied")
    def __deepcopy__(self,memo): self.__copy__()

    def _protect(self,permission):
        flags={"none":0,"read":mmap.PROT_READ,"write":mmap.PROT_READ|mmap.PROT_WRITE}[permission]
        libc=ctypes.CDLL(None,use_errno=True);fn=libc.mprotect
        fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];fn.restype=ctypes.c_int
        if fn(self._address,self._mapped,flags)!=0:
            self._state="permanent_deny";self._reason="page permission transition unconfirmed"
            raise HostRegionRejected("E_HIA_HOST_REGION: mprotect failed errno="+str(ctypes.get_errno()))
        self._permission=permission

    def _ready(self,generation):
        if type(generation) is not int or generation!=self._generation: _reject("stale or inexact generation fence")
        if self._state!="ready": _reject("region is "+self._state)

    def _borrow(self,mode,generation,offset,length,internal):
        self._ready(generation)
        if type(mode) is not str or mode not in {"read","write"}: _reject("exact read/write permission required")
        if length is None: length=self._length-offset if type(offset) is int else None
        if (type(offset) is not int or type(length) is not int or offset<0 or length<0
                or offset>self._length or length>self._length-offset): _reject("borrow extent outside owned region")
        if len(self._leases)>=self._max_leases: _reject("lease budget exhausted")
        if self._leases and (mode=="write" or any(g.mode=="write" for g in self._lease_grants.values())):
            _reject("shared-read/exclusive-write conflict")
        # Mint the lease identity before changing kernel page permissions:
        # a failed identity source must leave no writable unowned mapping.
        lease=RegionLease(self,mode,offset,length,generation,internal)
        # The lease has not escaped to a caller. If registry or receipt
        # bookkeeping fails after mprotect, retract every partial grant
        # before returning the exception. No unowned accessible page may
        # survive a failed public or native-call admission.
        try:
            if not self._leases: self._protect(mode)
            self._leases[lease._token]=lease
            self._lease_grants[lease._token]=_LeaseGrant(mode,offset,length,generation,internal)
            self._event("borrowed",mode=mode,offset=offset,length=length)
        except BaseException:
            if self._leases.get(lease._token) is lease:
                self._leases.pop(lease._token)
                self._lease_grants.pop(lease._token,None)
            lease._closed=True
            if not self._leases:
                # A failed rollback mprotect is already permanent_deny
                # through _protect; do not certify recovery in that case.
                self._protect("none")
            raise
        return lease

    def borrow(self,mode,*,generation,offset=0,length=None):
        with self._lock: return self._borrow(mode,generation,offset,length,False)

    def _validate_lease(self,lease):
        # Registry identity alone is insufficient: the public Python handle
        # can have its mode, extent, generation or internal flag reassigned.
        # Never use those mutable fields as authority after admission.
        if (type(lease) is not RegionLease or lease._owner is not self
                or type(lease._token) is not str or lease._closed is not False
                or self._leases.get(lease._token) is not lease):
            _reject("lease is closed, forged or foreign")
        grant=self._lease_grants.get(lease._token)
        if grant is None or (type(lease._mode) is not str or type(lease._offset) is not int
                or type(lease._length) is not int or type(lease._generation) is not int
                or type(lease._internal) is not bool
                or (lease._mode,lease._offset,lease._length,lease._generation,lease._internal)
                != (grant.mode,grant.offset,grant.length,grant.generation,grant.internal)):
            _reject("lease attributes differ from the immutable owner grant")
        self._ready(grant.generation)
        return grant

    def _read(self,lease):
        with self._lock:
            grant=self._validate_lease(lease)
            return bytes(self._memory[grant.offset:grant.offset+grant.length])

    def _write(self,lease,data):
        if type(data) is not bytes: _reject("host write requires immutable bytes")
        with self._lock:
            grant=self._validate_lease(lease)
            if grant.mode!="write" or len(data)!=grant.length: _reject("write permission or exact extent missing")
            self._memory[grant.offset:grant.offset+grant.length]=data

    def _release_lease(self,lease,*,internal=False):
        with self._lock:
            if type(lease) is not RegionLease or lease._owner is not self:
                _reject("foreign lease release")
            # A presented token is mutable, unlike the owner's registered
            # object identity.  Use its fast path only after identity checks;
            # bounded identity lookup lets close()/__exit__ retire the exact
            # original grant even if the caller altered the token.  Never use
            # a spoofed token to retire any other live lease.
            token=lease._token
            if type(token) is not str or self._leases.get(token) is not lease:
                token=next((key for key,active in self._leases.items() if active is lease),None)
            if token is None:
                if lease._closed is True: return
                _reject("lease release authority missing")
            grant=self._lease_grants.get(token)
            if grant is None or grant.internal and not internal:
                _reject("lease release authority missing")
            del self._leases[token]
            del self._lease_grants[token]
            lease._closed=True
            if not self._leases: self._protect("none")
            self._event("released",mode=grant.mode)

    def _quarantine(self,reason,*,permanent=False):
        if self._state not in {"quarantined","permanent_deny"}:
            self._generation+=1
        self._state="permanent_deny" if permanent or self._state=="permanent_deny" else "quarantined"
        self._reason=reason;self._event("quarantined",reason=reason,permanent=permanent)

    def call(self,library,symbol,*,generation,argument=0,offset=0,length=None,timeout=1.0):
        if type(library) is not NativeRegionLibrary: _reject("owned reviewed native library required")
        if type(argument) is not int or not 0<=argument<2**64: _reject("exact uint64 native argument required")
        if type(timeout) not in {int,float} or not 0<timeout<=10: _reject("native join timeout outside (0,10]")
        function,mode=library._acquire(symbol)
        lease=None
        try:
            with self._lock:
                if len(self._jobs)>=self._max_calls: _reject("native call budget exhausted")
                lease=self._borrow(mode,generation,offset,length,True)
                # Before thread.start() the C entry cannot have run. Release
                # newly admitted state on a *prestart* host exception; do not
                # confuse it with an ambiguous start() outcome below.
                token=None
                try:
                    grant=self._lease_grants[lease._token]
                    native_address=self._address+grant.offset
                    native_length=grant.length
                    token=secrets.token_hex(16)
                    job={"lease":lease,"library":library,"done":threading.Event(),"uncertain":False,"result":None,"error":None,"finalized":False}
                    def worker():
                        try:
                            output=ctypes.c_uint64()
                            code=function(native_address,native_length,argument,ctypes.byref(output))
                            job["result"]=(code,output.value)
                        except BaseException as error:
                            job["error"]={"type":type(error).__name__,"message":str(error)}
                        finally: job["done"].set()
                    thread=threading.Thread(target=worker,name="hia-region-"+token[:8],daemon=False)
                    job["thread"]=thread;self._jobs[token]=job
                except BaseException:
                    # No thread.start() attempt; retire the precise internal
                    # grant and let the outer handler balance library._active.
                    if token is not None: self._jobs.pop(token,None)
                    self._release_lease(lease,internal=True)
                    lease=None
                    raise
                try: thread.start()
                except BaseException:
                    # start may have taken effect before raising. No successful
                    # call admission or guessed thread death can reclaim data.
                    job["uncertain"]=True;self._unprovable_quiescence=True
                    self._quarantine("worker launch outcome uncertain",permanent=True)
                    raise HostRegionUncertain("native worker launch uncertain; region retained permanently")
        except BaseException:
            if lease is None:
                library._finish()
            else:
                with self._lock:
                    self._quarantine("native call admission interrupted",permanent=self._unprovable_quiescence)
            raise
        try: thread.join(float(timeout))
        except BaseException as error:
            with self._lock:
                job["uncertain"]=True;self._quarantine("worker join interrupted")
            raise HostRegionUncertain("owned native join was interrupted; region quarantined") from error
        with self._lock:
            if job["finalized"]:
                # Recovery may have joined this worker while its original
                # caller was descheduled. Never revoke the recovered epoch.
                raise HostRegionUncertain("old native call was retired by recovery; result is not committed")
            if thread.is_alive() or not job["done"].is_set():
                job["uncertain"]=True;self._quarantine("native call timed out or completion unconfirmed")
                raise HostRegionUncertain("native call outcome uncertain; mapping/code/lease retained")
            uncertain=(job["uncertain"] or job["error"] is not None or job["result"] is None
                       or job["result"][0]!=0 or self._generation!=generation or self._state!="ready")
            if uncertain: self._quarantine("native call failed or its generation was revoked")
            self._finalize_job(token,job)
            if uncertain: raise HostRegionUncertain("native call did not commit; quiescent recovery required")
            self._event("native_returned",symbol=symbol)
            return job["result"][1]

    def _finalize_job(self,token,job):
        if job["finalized"]: return
        if job["thread"].is_alive() or not job["done"].is_set(): _reject("cannot retire a live or unconfirmed native worker")
        job["finalized"]=True
        self._release_lease(job["lease"],internal=True)
        job["library"]._finish()
        self._jobs.pop(token,None)
        self._event("worker_join_confirmed")

    def recover(self,*,timeout=0.0):
        if type(timeout) not in {int,float} or not 0<=timeout<=10: _reject("recovery wait outside [0,10]")
        with self._lock:
            if self._state!="quarantined" or self._unprovable_quiescence: _reject("recovery has no admissible quarantined state")
            jobs=list(self._jobs.items())
        deadline=time.monotonic()+float(timeout)
        for _,job in jobs:
            try: job["thread"].join(max(0,deadline-time.monotonic()))
            except BaseException as error:
                with self._lock: self._quarantine("recovery join unconfirmed")
                raise HostRegionUncertain("recovery could not confirm owned worker join") from error
        with self._lock:
            if self._state!="quarantined" or self._unprovable_quiescence: _reject("recovery state changed")
            if any(job["thread"].is_alive() or not job["done"].is_set() for job in self._jobs.values()):
                _reject("native worker still live; quiescence not established")
            for token,job in list(self._jobs.items()):
                job["uncertain"]=True
                self._finalize_job(token,job)
            if self._leases: _reject("external leases still retained; quiescence not established")
            self._protect("write")
            self._memory[:]=b"\0"*self._mapped
            self._protect("none")
            self._generation+=1;self._state="ready";self._reason=None
            self._event("recovered_zeroed",quiescence="all owned workers joined and no retained leases")
            return self.snapshot()

    def _observed_permissions(self):
        if self._address is None or self._release_report.get("mapping")=="closed": return None
        with open("/proc/self/maps","rb") as stream: raw=stream.read(16*1024*1024+1)
        if len(raw)>16*1024*1024: _reject("mapping inventory exceeds observation bound")
        for line in raw.splitlines():
            fields=line.split(None,5)
            low,high=(int(x,16) for x in fields[0].split(b"-"))
            if low<=self._address and self._address+self._mapped<=high:
                return fields[1].decode()
        return None

    def snapshot(self):
        with self._lock:
            return {"profile":PROFILE,"state":self._state,"reason":self._reason,"generation":self._generation,
                "length":self._length,"mapped_bytes":self._mapped,"kernel_seals":getattr(self,"_seals",None),
                "permission":self._permission,"observed_mapping_permissions":self._observed_permissions(),
                "read_leases":sum(g.mode=="read" for g in self._lease_grants.values()),
                "write_leases":sum(g.mode=="write" for g in self._lease_grants.values()),"native_jobs":len(self._jobs),
                "live_native_workers":sum(j["thread"].is_alive() for j in self._jobs.values()),
                "events":copy.deepcopy(list(self._events)),"release":dict(self._release_report),
                "claims":{"arbitrary_foreign_pointer_safe":False,"mmio_dma_supported":False,
                    "whole_language_concurrency_proved":False,"native_contract_assumed":True}}

    def _close_storage_once(self):
        if self._release_attempted: return
        self._release_attempted=True
        self._release_report={"mapping":"not_acquired" if self._memory is None else "unknown",
                              "fd":"not_acquired" if self._fd is None else "unknown"}
        if self._memory is not None:
            try: self._memory.close();self._release_report["mapping"]="closed"
            except BaseException as error: self._release_report["mapping_error"]=str(error)
        if self._fd is not None:
            try: os.close(self._fd);self._release_report["fd"]="closed"
            except BaseException as error: self._release_report["fd_error"]=str(error)
        if all(self._release_report[k] in {"closed","not_acquired"} for k in ("mapping","fd")):
            self._state="closed"
            with _REGISTRY_LOCK: _REGIONS.pop(self._token,None)
        else: self._state="permanent_deny"

    def close(self):
        with self._lock:
            if self._jobs or self._leases or self._unprovable_quiescence: _reject("unconfirmed calls or retained leases forbid unmapping")
            if self._state!="closed": self._generation+=1
            self._close_storage_once()
            if self._state!="closed": _reject("region release uncertain; no numeric handle retry")
            return dict(self._release_report)


def retained_host_regions():
    """Bounded ownership debt, without exporting a raw fd or address."""
    with _REGISTRY_LOCK:
        regions=list(_REGIONS.values());libraries=list(_LIBRARIES.values())
    return {"regions":[r.snapshot() for r in regions],"libraries":[l.snapshot() for l in libraries],
            "max_regions":MAX_REGIONS,"max_region_bytes":MAX_REGION_BYTES,"max_libraries":MAX_LIBRARIES}
