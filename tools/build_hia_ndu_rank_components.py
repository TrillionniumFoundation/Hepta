"""Reconstruct the fixed NDU rank policies using the existing native compiler.

This is a development construction boundary. It retains the original full
engine hashes and does not confer cold-release or installed qualification.
"""
from __future__ import annotations
import argparse
import ctypes as C
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import struct
import sys
import time
from tools.build_hia_ndu_evaluator import _read, _run, _sealed, _SELF as LEAF_SELF

ROOT=Path(__file__).resolve().parents[1]
SELF="tools/build_hia_ndu_rank_components.py"
SELF_BYTES=Path(__file__).read_bytes()
PINS={"main":"b67c6de037c6aa041fa60225f778f1e5f1cbb344ee319b74ec336d997b7b2d34","tasks":"0a4364fc8f886bd1e862c3cac24c7d9e5028dec670773c0cec8d3d4ac76fb88b","r1":"2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144","r2":"2b9b658fd0c5211d020b60238472119f136075b3e89f638f84ed0ad7835f4fa0","r3":"c6ab6ba1f7c89117ac687665b2c0489f27ca54740dc900bcd2501f41b99fbf64","r4":"501694a31b52ec095f31a6e650e1ca15f7c0999c1cee62c6afcbe077a838afde","r5":"f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d","r6":"18c70f0fb94c80d386b3f5eabb6accef4989c78cb4f4f76b93b27126f2aab2e1","r7":"9184c68f231af5e42a0b2a419700d0601390fbbe4942387777d80e55f012559a","r8":"ab4877e353a65a3834cf318bd02ad3ccacb16c2709aebbb669af7ed3b8a6eb2c","r9":"f6c4aa1ac0f0de5e0971456d615407d8d67954b6be58fc609e5cdbe7f441d29b","r10":"f3dfec793b05805db93a2b4b0e794201b13e495dba40a74909f2bf2117b4902e","r11":"381902ad4e92287af2491e17ac92b7baca1ac036adeaa8af01d0ef694fb9869a","r12":"d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd","r13":"e4c7125ccc6295fe7fea4188f096a5a65735923e9a8f4f70c7c482bde451271e","r14":"908e9b52943be2e477b045042147751e2e44e9ab9148c1ac40e6ceaba040d720","r15":"214aea20ce10da438d1a96e98b0a25ed1151776e1fd577047c336d57cd54ae19","r16":"531319d3fed0853e80d44fe53804a78f75ea2553888d5d3cce36eddf05f1bf88","r17":"14abdc26508e5adbdb8dbd301d305599689eb9228d7e65efdb701b2c2f177b0a","r19":"0b423516af64a25a3a682f101fba8c92fd0fbd5c724fa3681b5399f69a8d3c2e","r20":"62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f"}
ROLE_SOURCES={
"main":"ndu_rank_main","tasks":"ndu_rank_tasks","r1":"ndu_rank_json",
"r2":"ndu_rank_canonical","r3":"ndu_rank_snapshot",
"r4":"background_optimizer_structure","r5":"background_optimizer_freeze",
"r6":"ndu_rank_admission","r7":"agent_binary64","r8":"agent_binary64_format",
"r9":"ndu_rank_cost","r10":"ndu_rank_clock_budget","r11":"ndu_rank_unchanged",
"r12":"ndu_rank_binding","r13":"ndu_rank_selection","r14":"ndu_rank_report",
"r16":"ndu_rank_process","r20":"background_optimizer_json_capture"}
OWNER_SOURCES=("ndu_rank_native_owner","sha256_stream",
"ndu_rank_native_owner_identity","native_path_resolve",
"ndu_rank_native_owner_pump","ndu_rank_native_owner_json")
ADDITIONAL=("cold_sha256_stream","sha256_stream",
"ndu_rank_native_owner_packer","ndu_rank_native_owner_error",
"ndu_rank_native_owner_error_packer","ndu_rank_engine_packer",
"ndu_rank_context","ndu_rank_context_packer","ndu_rank_context_payload_packer",
"multiversion_background_payload")
ROLES=("main","tasks","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","r16","r17","r19","r20")
COMPILER="494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af"
ENGINE="8338a80a992218ca6faefea66235fd18fcfb5c5d59f2bcc1d10a184f28e294ff"
PACKER="78a2b66835ecc37c8eb13cdc6db4fabdcc8383e62c59f335801bc3d3517e3a13"

class NativeFlat:
    def __init__(self,raw):
        self.raw=raw
        self.lib=C.CDLL(None)
        self.lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long)
        self.lib.mmap.restype=C.c_void_p
        self.lib.munmap.argtypes=(C.c_void_p,C.c_size_t)
        self.lib.munmap.restype=C.c_int
        fd=_sealed(raw)
        try:self.address=self.lib.mmap(None,len(raw),5,2,fd,0)
        finally:os.close(fd)
        if self.address in (None,C.c_void_p(-1).value):raise OSError("native mapping failed")
        self.entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(self.address)
    def call(self,data,cap,wn=512):
        s=C.create_string_buffer(data)
        o=C.create_string_buffer(b"Q"*(cap+32),cap+32)
        w=C.create_string_buffer(b"V"*(wn+32),wn+32)
        if wn:C.memset(C.addressof(w)+16,0,wn)
        rc=self.entry(s,len(data),C.addressof(o)+16,cap,C.addressof(w)+16,wn)
        if o.raw[:16]+o.raw[-16:]!=b"Q"*32 or w.raw[:16]+w.raw[-16:]!=b"V"*32:
            raise ValueError("native packer changed guards")
        return rc,o.raw[16:-16]
    def close(self):
        if self.address is not None:
            if self.lib.munmap(self.address,len(self.raw))!=0:raise OSError("native unmap failed")
            self.address=None
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def build(output,source_builder,*,root=ROOT,observe_current=False):
    root=Path(root).resolve(strict=True);output=Path(output)
    source_builder=Path(source_builder).resolve(strict=True)
    if sys.platform!="linux" or os.uname().machine!="x86_64":raise ValueError("Linux x86_64 required")
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    names=sorted(set(ROLE_SOURCES.values())|set(OWNER_SOURCES)|set(ADDITIONAL))
    paths={name:"examples/hia_bootstrap/"+name+".hepta" for name in names}
    captured={name:_read(root/path) for name,path in paths.items()}
    own=_read(root/SELF);leaf=_read(root/"tools/build_hia_ndu_evaluator.py")
    if own!=SELF_BYTES or leaf!=LEAF_SELF or _read(Path(__file__))!=SELF_BYTES:
        raise ValueError("executed constructor differs from selected root")
    compiler=_read(source_builder)
    if sha256(compiler).hexdigest()!=COMPILER:raise ValueError("fixed native compiler differs")
    before={paths[k]:{"bytes":len(v),"sha256":sha256(v).hexdigest()} for k,v in captured.items()}
    before.update({SELF:{"bytes":len(own),"sha256":sha256(own).hexdigest()},
        "tools/build_hia_ndu_evaluator.py":{"bytes":len(leaf),"sha256":sha256(leaf).hexdigest()}})
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,indent=2)+"\n")
    def unchanged():
        if any(_read(root/paths[k])!=v for k,v in captured.items()) or _read(root/SELF)!=own or _read(root/"tools/build_hia_ndu_evaluator.py")!=leaf or _read(Path(__file__))!=SELF_BYTES or _read(source_builder)!=compiler:
            raise ValueError("native rank construction source changed")
    start=time.monotonic()
    flats={};compile_rows=[]
    for name in names:
        raw,record=_run(output,name,[source_builder,"compile"],captured[name],executable=compiler)
        flats[name]=raw
        (output/(name+".flat")).write_bytes(raw)
        compile_rows.append({"name":name,"bytes":len(raw),"sha256":sha256(raw).hexdigest()})
        (output/"compiled.json").write_text(json.dumps(compile_rows,indent=2)+"\n")
        print("COMPILED",name,len(raw),sha256(raw).hexdigest(),flush=True)
    unchanged()
    roles={role:flats[name] for role,name in ROLE_SOURCES.items()}
    # Discovery is restricted to two actual stream implementations; the selected
    # original flat must have the fixed full hash before it can enter any image.
    matches=[name for name in ("sha256_stream","cold_sha256_stream") if sha256(flats[name]).hexdigest()==PINS["r15"]]
    if not observe_current and len(matches)!=1:raise ValueError("original exact SHA role is not uniquely reconstructed: "+repr(matches))
    sha_name="sha256_stream" if observe_current else matches[0];roles["r15"]=flats[sha_name]
    owner_parts=[flats[name] if name!="sha256_stream" else flats[sha_name] for name in OWNER_SOURCES]
    frame=b"HIANOP02"+struct.pack("<7Q",*(len(x) for x in owner_parts),1)+b"".join(owner_parts)
    with NativeFlat(flats["ndu_rank_native_owner_packer"]) as pk:
        rc,body=pk.call(frame,8<<20)
        if rc>=0xfffffffd:raise ValueError("native owner pack refused: "+str(rc))
        roles["r17"]=body[:rc]
    error=flats["ndu_rank_native_owner_error"]
    frame=b"HIAERR01"+struct.pack("<Q",len(error))+error
    with NativeFlat(flats["ndu_rank_native_owner_error_packer"]) as pk:
        rc,body=pk.call(frame,2<<20)
        if rc>=0xfffffffd:raise ValueError("native error pack refused: "+str(rc))
        roles["r19"]=body[:rc]
    for role in ROLES:
        raw=roles[role];actual=sha256(raw).hexdigest()
        (output/(role+".flat")).write_bytes(raw)
        if not observe_current and actual!=PINS[role]:raise ValueError("original native role differs: "+role+" "+actual)
    if not observe_current and sha256(flats["ndu_rank_engine_packer"]).hexdigest()!=PACKER:raise ValueError("original rank packer differs")
    with NativeFlat(flats["ndu_rank_engine_packer"]) as pk:
        body=b"".join(roles[k] for k in ROLES)
        prefix=b"HIANEP02"+struct.pack("<Q",21)+struct.pack("<21Q",*(len(roles[k]) for k in ROLES))
        products=[]
        for mode in (0,1):
            request=prefix+struct.pack("<Q",mode)+body
            rc,raw=pk.call(request,(16<<20)+4096)
            if rc>=0xfffffffd:raise ValueError("native engine pack refused")
            product=raw[:rc]
            again_rc,again=pk.call(request,(16<<20)+4096)
            if again_rc!=rc or again[:rc]!=product:raise ValueError("two native constructions differ")
            (output/("rank-engine.o" if mode==0 else "rank-engine.flat")).write_bytes(product)
            products.append({"mode":mode,"bytes":rc,"sha256":sha256(product).hexdigest()})
    if not observe_current and (products[1]["bytes"]!=4461559 or products[1]["sha256"]!=ENGINE):raise ValueError("original full engine differs")
    unchanged()
    (output/"source-after.json").write_text(json.dumps(before,indent=2)+"\n")
    report={"schema":"hepta.hia.ndu-rank-reconstruction.v1","passed":not observe_current,"construction_completed":True,"historical_domain":not observe_current,"source_unchanged":True,
        "compile_rows":compile_rows,"roles":[{"role":k,"bytes":len(roles[k]),"sha256":sha256(roles[k]).hexdigest()} for k in ROLES],
        "products":products,"stream_source":sha_name,"wall_seconds":time.monotonic()-start,
        "matching_cold":False,"whole_installed_rebuild":False}
    (output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
    print("CURRENT_CONSTRUCTION_OBSERVED" if observe_current else "EXACT_RANK_COMPONENTS_PASS",len(ROLES),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",required=True,type=Path);p.add_argument("--source-builder",required=True,type=Path)
    p.add_argument("--observe-current",action="store_true")
    a=p.parse_args();build(a.output,a.source_builder,observe_current=a.observe_current)
