"""Deliberately narrow Clang AST -> checked HIA migration oracle.

Only one unsigned-int scalar function with one return expression in the whole
unit. All unsupported input is a full-unit refusal, never partial migration.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import ctypes
import json
import os
import re
import stat
import shutil
import subprocess
import tempfile

from .builders import op,scalar
from .core import Refused, Verified, verify, canonical_bytes

@dataclass(frozen=True)
class Migration:
    verified: Verified
    original_sha256: str
    clang_ast_sha256: str
    clang_version: str
    semantic_scope: str = "strict single-function unsigned int expression"

    def evidence(self):
        return {"original_sha256":self.original_sha256,
                "clang_ast_sha256":self.clang_ast_sha256,
                "clang_version":self.clang_version,
                "core_digest":self.verified.core_digest,
                "scope":self.semantic_scope,"general_c_migration":False}

def _bounded_ast(source: bytes, compiler: str):
    # Output goes to a temporary regular file rather than unbounded parent RAM.
    def bounds():
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU,(6,6))
        resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
        cmd=[compiler,"-x","c","-std=c11","-nostdinc","-Werror",
             "-fsyntax-only","-Xclang","-ast-dump=json","-"]
        try:
            p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,
                             preexec_fn=bounds if os.name=="posix" else None)
            p.communicate(input=source,timeout=10)
        except (subprocess.TimeoutExpired,OSError) as exc:
            if "p" in locals() and p.poll() is None:
                p.kill();p.communicate()
            raise Refused("E_C_CLANG","bounded compiler invocation failed") from exc
        stdout.seek(0);raw=stdout.read(2*1024*1024+1)
        stderr.seek(0);err=stderr.read(1024).decode("utf-8","replace")
        if p.returncode!=0:
            raise Refused("E_C_CLANG",f"Clang rejected bounded translation unit: {err[:128]}")
        if len(raw)>2*1024*1024:
            raise Refused("E_C_AST_BUDGET","AST output exceeded 2MiB")
    try:
        root=json.loads(raw)
    except ValueError as exc:
        raise Refused("E_C_AST","malformed clang JSON") from exc
    # Iterative preflight caps both width and depth, independently of recursive translation.
    stack=[(root,0)]; nodes=0
    while stack:
        n,depth=stack.pop();nodes+=1
        if nodes>4096 or depth>64:
            raise Refused("E_C_AST_BUDGET","AST nodes/depth exceeded")
        if type(n) is dict:
            stack.extend((v,depth+1) for v in n.values())
        elif type(n) is list:
            stack.extend((v,depth+1) for v in n)
    return root, sha256(raw).hexdigest()

def migrate(path: str | Path, *, clang="clang") -> Migration:
    # Open by O_NOFOLLOW, then compile the frozen bytes on stdin. Clang cannot
    # subsequently observe a different source pathname during this request.
    path=Path(path).absolute()
    try:
        first=path.lstat()
        if not stat.S_ISREG(first.st_mode) or first.st_size>4096:
            raise Refused("E_C_SOURCE_BUDGET","require <=4KiB regular source")
        fd=os.open(path,os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0))
        try:
            file_stat=os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode) or (file_stat.st_dev,file_stat.st_ino)!=(first.st_dev,first.st_ino):
                raise Refused("E_C_SOURCE_RACE","input identity changed before read")
            raw=os.read(fd,4097)
            if len(raw)>4096: raise Refused("E_C_SOURCE_BUDGET","source exceeds 4KiB")
            after_read=os.fstat(fd)
            if (file_stat.st_size,file_stat.st_mtime_ns)!=(after_read.st_size,after_read.st_mtime_ns):
                raise Refused("E_C_SOURCE_RACE","source changed during snapshot")
        finally: os.close(fd)
    except OSError as exc:
        raise Refused("E_C_SOURCE","unsafe or unavailable input") from exc
    if re.search(rb"(?m)^\s*#",raw):
        raise Refused("E_C_PREPROCESSOR","macros and includes unsupported")
    before=sha256(raw).hexdigest()
    if ctypes.sizeof(ctypes.c_uint)!=4:
        raise Refused("E_C_ABI","host unsigned int must be exactly 32 bits")
    binary=shutil.which(clang)
    if not binary:
        raise Refused("E_HOST_TOOL","Clang required")
    root,ast_sha=_bounded_ast(raw,binary)
    try:
        after=path.lstat()
        if (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_size) != (first.st_dev,first.st_ino,first.st_mtime_ns,first.st_size):
            raise Refused("E_C_SOURCE_RACE","source identity/freshness changed during translation")
    except OSError as exc:
        raise Refused("E_C_SOURCE_RACE","source disappeared during translation") from exc
    top=[]
    for child in root.get("inner",[]):
        if child.get("isImplicit") is True: continue
        if child.get("loc",{}).get("file")!="<stdin>" and child.get("kind")!="FunctionDecl":
            # Unknown non-main declarations from compiler are not promoted to user declarations.
            if child.get("loc",{}).get("file") is not None: continue
        if child.get("kind")=="FunctionDecl" and child.get("loc",{}).get("file") == "<stdin>":
            top.append(child)
        elif child.get("loc",{}).get("file")=="<stdin>":
            raise Refused("E_C_TOPLEVEL","unsupported user top-level declaration")
    if len(top)!=1:
        raise Refused("E_C_UNIT","require exactly one user function")
    fn=top[0]
    if fn.get("type",{}).get("qualType")!="unsigned int (unsigned int)":
        raise Refused("E_C_SIGNATURE","only u32(u32) C signature")
    parts=fn.get("inner",[])
    if (len(parts)!=2 or parts[0].get("kind")!="ParmVarDecl"
        or parts[0].get("type",{}).get("qualType")!="unsigned int"
        or parts[1].get("kind")!="CompoundStmt"):
        raise Refused("E_C_PROFILE","one named scalar argument and compound body required")
    name=fn.get("name"); arg=parts[0].get("name")
    body=parts[1].get("inner",[])
    if len(body)!=1 or body[0].get("kind")!="ReturnStmt" or len(body[0].get("inner",[]))!=1:
        raise Refused("E_C_BODY","single return expression only")
    operations=[]
    count=0
    def emit(node,depth=0):
        nonlocal count
        if depth>32:
            raise Refused("E_C_DEPTH","expression depth exceeded")
        kind=node.get("kind")
        if kind=="ImplicitCastExpr":
            if (node.get("castKind")!="LValueToRValue"
                or node.get("type",{}).get("qualType")!="unsigned int"
                or len(node.get("inner",[]))!=1):
                raise Refused("E_C_CAST","unsupported implicit C conversion")
            return emit(node["inner"][0],depth+1)
        if kind=="ParenExpr":
            if len(node.get("inner",[]))!=1: raise Refused("E_C_AST","malformed parenthesized expression")
            return emit(node["inner"][0],depth+1)
        if kind=="DeclRefExpr":
            ref=node.get("referencedDecl",{})
            if ref.get("name")!=arg or ref.get("type",{}).get("qualType")!="unsigned int":
                raise Refused("E_C_REFERENCE","only named scalar parameter may be read")
            return arg
        if kind=="IntegerLiteral":
            if node.get("type",{}).get("qualType")!="unsigned int":
                raise Refused("E_C_LITERAL","integer literal must be unsigned")
            try: number=int(node["value"])
            except (KeyError,TypeError,ValueError) as exc: raise Refused("E_C_LITERAL","invalid literal") from exc
            if not 0<=number<2**32: raise Refused("E_C_LITERAL","constant out of range")
            count+=1;n=f"t{count}"
            operations.append(op("const",results=[(n,"u32")],value=number))
            return n
        if kind=="BinaryOperator":
            if (node.get("type",{}).get("qualType")!="unsigned int"
                or node.get("opcode") not in {"+","-","^"} or len(node.get("inner",[]))!=2):
                raise Refused("E_C_EXPR","unsupported expression operator")
            a=emit(node["inner"][0],depth+1);b=emit(node["inner"][1],depth+1)
            count+=1;n=f"t{count}"
            ins={"+":"int.add.wrap","-":"int.sub.wrap","^":"int.xor"}[node["opcode"]]
            operations.append(op(ins,[a,b],[(n,"u32")]))
            return n
        raise Refused("E_C_EXPR",f"unsupported C AST expression: {kind}")
    result=emit(body[0]["inner"][0])
    core=scalar(name=name,args=[(arg,"u32")],ops=operations,results=["u32"],returns=[result])
    checked=verify(core)
    version=subprocess.run([binary,"--version"],capture_output=True,text=True,timeout=3).stdout.splitlines()[0]
    return Migration(checked,before,ast_sha,version)
