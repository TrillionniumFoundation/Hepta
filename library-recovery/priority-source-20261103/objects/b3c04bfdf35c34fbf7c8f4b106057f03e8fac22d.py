"""Disk-fsync, file-locked, generation-CAS pilot for *verified interpreter* code.

No remote attestation, signature, untrusted-host protection, running-call OSR,
process exactly-once, durable cross-node fence or production deployment claim.
"""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import fcntl
import json
import os
import tempfile

from .core import Refused, Verified, verify, readmit, canonical_bytes, decode_bytes
from .runtime import run

SCHEMA="hepta.hia.pilot.activation.v1"

@contextmanager
def locked(root: Path):
    root.mkdir(parents=True,exist_ok=True)
    fd=os.open(root/".writer.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

def _durable(root: Path, name: str, payload: bytes):
    tempname=None
    try:
        fd,tempname=tempfile.mkstemp(prefix=".staged-",dir=root)
        with os.fdopen(fd,"wb") as f:
            f.write(payload);f.flush();os.fsync(f.fileno())
        os.replace(tempname,root/name)
        d=os.open(root,os.O_DIRECTORY|os.O_RDONLY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if tempname and os.path.exists(tempname): os.unlink(tempname)

def _manifest(gen: int,active: str,baseline: str):
    body={"schema":SCHEMA,"generation":gen,"active_digest":active,"baseline_digest":baseline}
    body["checksum_sha256"]=sha256(canonical_bytes(body)).hexdigest()
    return body

class AdmissionStore:
    def __init__(self,path):
        self.root=Path(path).resolve()
        self.root.mkdir(parents=True,exist_ok=True)
        self.versions=self.root/"versions"
        self.versions.mkdir(parents=True,exist_ok=True)

    def _store_checked(self,v):
        v=readmit(v)
        dest=self.versions/(v.core_digest+".json")
        # Pre-existing file may not be overwritten by another candidate.
        if dest.exists():
            if dest.is_symlink() or dest.read_bytes()!=v.core_bytes:
                raise Refused("E_ARTIFACT","stored source differs from digest-bound Core")
            return v.core_digest
        fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(v.core_bytes);f.flush();os.fsync(f.fileno())
        d=os.open(self.versions,os.O_DIRECTORY|os.O_RDONLY)
        try: os.fsync(d)
        finally: os.close(d)
        return v.core_digest

    def initialize(self,base: Verified):
        with locked(self.root):
            if (self.root/"current.json").exists():
                raise Refused("E_ALREADY_INITIALIZED","activation store exists")
            digest=self._store_checked(base)
            _durable(self.root,"current.json",canonical_bytes(_manifest(0,digest,digest)))
        return self.read_state()

    def read_state(self):
        statefile=self.root/"current.json"
        if not statefile.exists() or statefile.is_symlink():
            raise Refused("E_MANIFEST","missing or unsafe active pointer")
        obj=decode_bytes(statefile.read_bytes())
        if set(obj)!={"schema","generation","active_digest","baseline_digest","checksum_sha256"}:
            raise Refused("E_MANIFEST","invalid pointer fields")
        if obj["schema"]!=SCHEMA or type(obj["generation"]) is not int or not 0<=obj["generation"]<2**63:
            raise Refused("E_MANIFEST","invalid schema or generation")
        if any(type(obj[key]) is not str or len(obj[key])!=64 or any(c not in '0123456789abcdef' for c in obj[key])
               for key in ("active_digest","baseline_digest","checksum_sha256")):
            raise Refused("E_MANIFEST","invalid digest")
        chk=obj.pop("checksum_sha256")
        if sha256(canonical_bytes(obj)).hexdigest()!=chk:
            raise Refused("E_MANIFEST","pointer checksum mismatch")
        obj["checksum_sha256"]=chk
        return obj

    def get_version(self,digest):
        path=self.versions/(digest+".json")
        if path.is_symlink() or not path.is_file():
            raise Refused("E_ARTIFACT","missing or unsafe program file")
        data=path.read_bytes()
        if sha256(data).hexdigest()!=digest:
            raise Refused("E_ARTIFACT","code bytes disagree with referenced identity")
        return verify(data)

    def activate(self,new: Verified,expected_generation: int,*,failure_hook=None):
        with locked(self.root):
            state=self.read_state()
            if type(expected_generation) is not int or state["generation"]!=expected_generation:
                raise Refused("E_STALE_GENERATION","CAS expected generation differs")
            digest=self._store_checked(new)
            if failure_hook=="after_store":
                raise Refused("E_INJECTED_CRASH","failure before activation pointer write")
            _durable(self.root,"current.json",canonical_bytes(_manifest(expected_generation+1,
                                     digest,state["baseline_digest"])))
        return self.read_state()

    def rollback(self,expected_generation: int):
        with locked(self.root):
            state=self.read_state()
            if type(expected_generation) is not int or state["generation"]!=expected_generation:
                raise Refused("E_STALE_GENERATION","rollback CAS mismatch")
            self.get_version(state["baseline_digest"])
            _durable(self.root,"current.json",canonical_bytes(_manifest(expected_generation+1,
                            state["baseline_digest"],state["baseline_digest"])))
        return self.read_state()

    def execute(self,inputs):
        state=self.read_state()
        active=self.get_version(state["active_digest"])
        return {"generation":state["generation"],"active_digest":state["active_digest"],
                "result":run(active,inputs).json(),"authority":"local-interpreter-only"}
