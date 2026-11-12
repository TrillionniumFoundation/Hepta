"""Read the complete submitted Git tree and the retained original 4157-case failure.

Read-only static inventory and original byte custody. This does not execute an
inspected source, regenerate HIA, compile, rerun a suite, activate, or delete.
"""
from __future__ import annotations
import ast
import base64
from collections import Counter, defaultdict
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import traceback

PREFIX = "review-evidence/hia-native-rewrite-20261111/"
ARCHIVE = PREFIX + "reconstructed-components-r12/qualification/raw-originals.tar.xz"
CUSTODY = PREFIX + "reconstructed-components-r12/qualification/custody.json"
READBACK = PREFIX + "reconstructed-components-r12/qualification/independent-readback.json"
PINS = {
    ARCHIVE: ("2aae1a9fc536d476cf02f32d40b7c3a34335cf34",666816,"5595532d3fc1d8e8b5021236b30217b85ec53a1452d4b23a98b378996e67cee5"),
    CUSTODY: ("4af6da4be51458e1a34aa033658740344f9fdcb4",52786,""),
    READBACK: ("4d0d2547ab43a21b808ca10e180a7b5038eacdbb",9813,""),
}
FROZEN = "0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
SELECTED_ORIGINALS = {
    "qualification/QUALIFICATION.json",
    "qualification/full-retained-regression.json",
    "qualification/full-retained-regression.owner.json",
    "qualification/full-retained-regression.stdout.log",
    "qualification/full-retained-regression.stderr.log",
    "original-control/full-launch-control.json",
    "original-control/preparation/preparation.json",
    "original-control/cargo-recheck-before-full.json",
    "derived/retained-diagnostic.json",
}
# The complete archives/reports remain in the artifact. Keep stdout bounded
# to the full prerequisite controls and a compact complete production index.
STDOUT_ORIGINALS = SELECTED_ORIGINALS - {
    "qualification/QUALIFICATION.json",
    "qualification/full-retained-regression.json",
    "qualification/full-retained-regression.stderr.log",
}
START = time.monotonic_ns()

def ident(raw):
    return dict(bytes=len(raw),gitsha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
                sha256=hashlib.sha256(raw).hexdigest())

def save(root, name, raw, mode=None):
    p = PurePosixPath(name)
    assert not p.is_absolute() and ".." not in p.parts and str(p)==name
    target=root.joinpath(*p.parts)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if mode is not None:
        assert type(mode) is int and 0 <= mode <= 0o777
        target.chmod(mode)
        assert stat.S_IMODE(target.stat().st_mode)==mode
    assert target.read_bytes()==raw
    return dict(path=name,mode=stat.S_IMODE(target.stat().st_mode),**ident(raw))

def json_bytes(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()

def emit(tag,name,raw):
    pin=ident(raw)
    if not raw:
        print(tag+" "+json.dumps(dict(path=name,offset=0,part_bytes=0,base64="",**pin),sort_keys=True),flush=True)
    for off in range(0,len(raw),12288):
        part=raw[off:off+12288]
        print(tag+" "+json.dumps(dict(path=name,offset=off,part_bytes=len(part),
              base64=base64.b64encode(part).decode("ascii"),**pin),sort_keys=True),flush=True)

def git(root,*args):
    return subprocess.check_output(["git","--no-replace-objects","-C",str(root),*args],timeout=20)

def state_tuple(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def read_checked(root,name,expected,retain=False):
    rel=PurePosixPath(name)
    assert not rel.is_absolute() and ".." not in rel.parts and str(rel)==name
    current=root
    for item in rel.parts:
        current=current/item
        assert not current.is_symlink(), name
    fd=os.open(current,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    parts=[];digest=hashlib.sha256()
    try:
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        mode="100755" if before.st_mode&0o111 else "100644"
        assert mode==expected["mode"]
        h=hashlib.sha1(b"blob "+str(before.st_size).encode()+b"\0")
        count=0
        while True:
            raw=os.read(fd,1<<20)
            if not raw:
                break
            h.update(raw);digest.update(raw);count+=len(raw)
            if retain:
                parts.append(raw)
        after=os.fstat(fd)
    finally:
        os.close(fd)
    assert state_tuple(before)==state_tuple(after)==state_tuple(current.lstat()),name
    assert count==before.st_size and h.hexdigest()==expected["gitsha"],name
    return dict(path=name,mode=mode,bytes=count,gitsha=h.hexdigest(),sha256=digest.hexdigest()),b"".join(parts)

def module_name(path):
    return path.removesuffix(".py").replace("/",".").removesuffix(".__init__")

def python_record(path,raw):
    module=module_name(path);package=module.rpartition(".")[0]
    if path.endswith("/__init__.py"):
        package=module
    result=dict(path=path,module=module,syntax="UNPARSED",imports=[],definitions=[],
                literal_native_selectors=[],literal_HIA_sources=[],syntax_error=None)
    try:
        tree=ast.parse(raw,filename=path)
    except SyntaxError as exc:
        result.update(syntax="SYNTAX_ERROR",syntax_error=dict(error=str(exc),lineno=exc.lineno,offset=exc.offset,end_lineno=exc.end_lineno))
        return result
    imports=set();strings=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            imports.update(a.name for a in node.names)
        elif isinstance(node,ast.ImportFrom):
            target=node.module or ""
            if node.level:
                parents=package.split(".")
                target=".".join(parents[:len(parents)-node.level+1]+([target] if target else []))
            if target:
                imports.add(target)
                imports.update(target+"."+a.name for a in node.names if a.name!="*")
        elif isinstance(node,ast.Constant) and isinstance(node.value,str):
            strings.add(node.value)
    def definitions(nodes,prefix=""):
        values=[]
        for node in nodes:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                name=prefix+node.name
                values.append(dict(name=name,kind=type(node).__name__,line=node.lineno,end_line=node.end_lineno,
                                   public=not node.name.startswith("_")))
                if isinstance(node,ast.ClassDef):
                    values.extend(definitions(node.body,name+"."))
        return values
    result.update(syntax="PARSED",imports=sorted(imports),definitions=definitions(tree.body),
        purpose=(ast.get_docstring(tree) or "").split("\n\n",1)[0],
        literal_native_selectors=sorted(s for s in strings if s.startswith(("HEPTA_HIA_","HEPTA_NDU_")) and "\n" not in s),
        literal_HIA_sources=sorted(s for s in strings if s.endswith((".hia",".hiaasm",".hepta")) and "\n" not in s),
        lines=len(raw.splitlines()),ast_nodes=sum(1 for _ in ast.walk(tree)))
    return result

def read_originals(root,out,source_rows):
    inputs={}
    for path,(sha,size,digest) in PINS.items():
        row,raw=read_checked(root,path,source_rows[path],True)
        assert row["gitsha"]==sha and row["bytes"]==size
        if digest:
            assert row["sha256"]==digest
        inputs[path]=raw
    custody=json.loads(inputs[CUSTODY]);prior=json.loads(inputs[READBACK])
    assert custody["head"]==FROZEN and prior["head"]==FROZEN
    assert custody["original_files"]==123 and custody["original_bytes"]==8688721
    expected={r["name"]:r for r in custody["members"]}
    assert len(expected)==123
    seen=set();rows=[];selected=[];reports={};extra=[]
    with tarfile.open(fileobj=io.BytesIO(inputs[ARCHIVE]),mode="r:xz") as archive:
        for member in archive:
            name=member.name;p=PurePosixPath(name)
            assert not p.is_absolute() and ".." not in p.parts and str(p)==name and name not in seen
            assert member.isfile() and not member.issym() and not member.islnk()
            assert 0<=member.size<=32<<20
            raw=archive.extractfile(member).read()
            assert len(raw)==member.size
            pin=ident(raw);seen.add(name)
            if name in expected:
                old=expected[name]
                assert pin["bytes"]==old["bytes"] and pin["sha256"]==old["sha256"]
                assert member.mode==old["mode"]
            else:
                # Only the embedded exact custody document may be additional.
                assert raw==inputs[CUSTODY],name
                extra.append(name)
            target="original-4157/"+name
            saved=save(out,target,raw,member.mode);saved["original_mode"]=member.mode
            rows.append(saved)
            if name in SELECTED_ORIGINALS:
                selected.append(saved)
                if name in STDOUT_ORIGINALS:
                    emit("HIA_FULL_AUDIT_ORIGINAL",target,raw)
            if name in ("qualification/QUALIFICATION.json","qualification/full-retained-regression.json",
                        "qualification/full-retained-regression.owner.json",
                        "original-control/full-launch-control.json","original-control/preparation/preparation.json"):
                reports[name]=json.loads(raw)
    assert set(expected).issubset(seen) and len(seen)==124 and len(extra)==1
    assert sum(r["bytes"] for r in rows if r["path"].removeprefix("original-4157/") in expected)==8688721
    assert {r["path"].removeprefix("original-4157/") for r in selected}==SELECTED_ORIGINALS
    retained=reports["qualification/full-retained-regression.json"]
    actual=dict(tests_run=retained["tests_run"],errors=len(retained["errors"]),
        failures=len(retained["failures"]),skips=len(retained["skipped"]),
        expected_failures=len(retained["expected_failures"]),unexpected_successes=len(retained["unexpected_successes"]))
    assert actual==dict(tests_run=4157,errors=187,failures=1,skips=18,expected_failures=0,unexpected_successes=0)
    result=dict(status="PASS_ORIGINAL_READBACK_ONLY",source_commit=FROZEN,members=124,
        original_files=123,original_bytes=8688721,embedded_custody=extra,
        retained_status="FAIL_HOLD",counts=actual,source_files=prior["source_files"],
        all_originals_preserved=True,selected_originals=selected,files=rows,
        old_failure_relabelled=False,new_tests=0,new_native=0,new_B3=0,
        prerequisite_deletion_actor="UNKNOWN")
    save(out,"original-readback.json",json_bytes(result))
    emit("HIA_FULL_AUDIT_ORIGINAL","original-readback.json",json_bytes(result))
    return result

def main():
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    affinity=os.sched_getaffinity(0);assert affinity
    os.sched_setaffinity(0,{min(affinity)})
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("original180secondreadbacklimit")))
    signal.alarm(180)
    root=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    out=Path(os.environ["HIA_CI_OUTPUT"]).resolve()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False)
    summary=dict(status="INCOMPLETE",new_AST=0,new_HIA=0,new_B3=0,new_VM=0,new_native=0,
        whole_stack_closed=False,installed_activation=False,deleted_files=0,
        limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,cores=1))
    try:
        head=git(root,"rev-parse","HEAD").decode().strip()
        tree_sha=git(root,"rev-parse","HEAD^{tree}").decode().strip()
        assert head==os.environ["GITHUB_SHA"]
        clean_before=git(root,"status","--porcelain=v1","--untracked-files=all")
        assert not clean_before,clean_before
        entries={}
        for raw in git(root,"ls-tree","-rz","--full-tree","HEAD").split(b"\0"):
            if not raw:continue
            meta,name=raw.split(b"\t",1);mode,kind,sha=meta.decode().split()
            assert kind=="blob" and mode in ("100644","100755")
            path=name.decode("utf-8");assert path not in entries
            entries[path]=dict(mode=mode,gitsha=sha)
        ledger=[];python={};pyproject=None;file_kinds=Counter()
        for name,expected in sorted(entries.items()):
            retain=name.endswith(".py") or name=="pyproject.toml"
            row,raw=read_checked(root,name,expected,retain)
            row["extension"]=PurePosixPath(name).suffix or "extensionless"
            row["area"]=("production" if name.startswith("hepta/") else "tools" if name.startswith("tools/") else
                "tests" if name.startswith("tests/") else "retained-evidence" if name.startswith(("review-evidence/","experiments/","benchmarks/")) else "other")
            file_kinds[row["extension"]]+=1;ledger.append(row)
            if name.endswith(".py"):
                python[name]=python_record(name,raw)
                if python[name]["syntax"]=="PARSED":
                    summary["new_AST"]+=1
            elif name=="pyproject.toml":
                pyproject=tomllib.loads(raw.decode())
        modules={r["module"]:name for name,r in python.items()}
        callers=defaultdict(set)
        for name,r in python.items():
            for imported in r["imports"]:
                parts=imported.split(".")
                while parts:
                    match=modules.get(".".join(parts))
                    if match:
                        if match!=name:callers[match].add(name)
                        break
                    parts.pop()
        for name,r in python.items():
            r["repository_static_callers"]=sorted(callers[name])
        package=[r for name,r in sorted(python.items()) if name.startswith("hepta/")]
        syntax_errors=[dict(path=name,**r["syntax_error"]) for name,r in python.items() if r["syntax_error"]]
        inventory=dict(schema="hia.complete-submitted-source-static-audit.v1",
            status="STATIC_INVENTORY_NOT_NATIVE_DELIVERY_ACCEPTANCE",
            git_head=head,git_tree=tree_sha,files=ledger,package_modules=package,
            hosted_tools=[r for name,r in sorted(python.items()) if name.startswith("tools/")],
            all_python=python,syntax_errors=syntax_errors,
            counts=dict(files=len(ledger),bytes=sum(x["bytes"] for x in ledger),
                Python=len(python),parsed_Python=sum(r["syntax"]=="PARSED" for r in python.values()),
                production_Python=len(package),extensions=dict(sorted(file_kinds.items()))),
            installation=dict(build_system=pyproject.get("build-system"),scripts=pyproject.get("project",{}).get("scripts"),
                requires_python=pyproject.get("project",{}).get("requires-python")),
            scope=dict(all_Git_blob_bytes_and_modes_verified=True,all_Python_attempted_AST=True,
                historical_invalid_sources_retained_and_reported=True,dynamic_callers_complete=False,
                every_function_semantically_audited=False,whole_native_replacement_qualified=False,
                deletion_authorized_by_inventory=False,whole_stack_closed=False))
        summary["counts"]=inventory["counts"]
        summary["syntax_errors"]=syntax_errors
        invraw=json_bytes(inventory);save(out,"complete-source-inventory.json",invraw)
        # The complete inventory is unabridged in its own artifact file.
        # This derived projection covers every production module without
        # repeating the full retained-evidence AST inventory in the job log.
        projection=dict(schema="hia.complete-production-module-projection.v1",
            source_inventory_identity=ident(invraw),head=head,tree=tree_sha,
            counts=inventory["counts"],installation=inventory["installation"],
            modules=[dict(path=r["path"],module=r["module"],purpose=r.get("purpose",""),
                syntax=r["syntax"],lines=r.get("lines"),ast_nodes=r.get("ast_nodes"),
                public_definitions=[d["name"] for d in r.get("definitions",[]) if d["public"]],
                all_definition_count=len(r.get("definitions",[])),
                imports=r["imports"],native_selectors=r.get("literal_native_selectors",[]),
                HIA_sources=r.get("literal_HIA_sources",[]),
                production_callers=[p for p in r["repository_static_callers"] if p.startswith("hepta/")],
                all_static_caller_count=len(r["repository_static_callers"])) for r in package],
            scope=inventory["scope"])
        projected=json.dumps(projection,sort_keys=True,ensure_ascii=True,separators=(",",":")).encode()+bytes([10])
        save(out,"complete-production-module-projection.json",projected)
        emit("HIA_FULL_AUDIT_ORIGINAL","complete-production-module-projection.json",projected)
        original=read_originals(root,out,entries)
        for row in ledger:
            after,_=read_checked(root,row["path"],entries[row["path"]])
            assert all(after[k]==row[k] for k in ("path","mode","bytes","gitsha","sha256")),row["path"]
        assert git(root,"rev-parse","HEAD").decode().strip()==head
        assert git(root,"rev-parse","HEAD^{tree}").decode().strip()==tree_sha
        assert not git(root,"status","--porcelain=v1","--untracked-files=all")
        assert all(x["syntax"]=="PARSED" for x in package)
        summary.update(status="PASS_STATIC_AND_ORIGINAL_READBACK_ONLY",head=head,tree=tree_sha,
            new_AST=inventory["counts"]["parsed_Python"],counts=inventory["counts"],
            syntax_errors=syntax_errors,installation=inventory["installation"],
            inventory_identity=ident(invraw),all_source_bytes_modes_before_after_equal=True,
            original_retained_status=original["retained_status"],original_retained_counts=original["counts"],
            original_members=124,original_bytes=8688721)
    except BaseException as exc:
        summary.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        signal.alarm(0);summary["elapsed_ns"]=time.monotonic_ns()-START
        save(out,"summary.json",json_bytes(summary))
        print("HIA_FULL_AUDIT_SUMMARY "+json.dumps(summary,sort_keys=True),flush=True)
    return 0 if summary["status"]=="PASS_STATIC_AND_ORIGINAL_READBACK_ONLY" else 1

if __name__=="__main__":
    raise SystemExit(main())
