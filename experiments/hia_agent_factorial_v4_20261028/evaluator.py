"""Finite generated-source admission and actual native/owner observations.

The model cannot supply commands, filenames, harnesses or compiler flags. This
is a closed source profile, not a general operating-system sandbox.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import time

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import _Machine
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity
from experiments.hia_agent_factorial_v4_20261028 import fixtures


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def rust_type(typ):
    return "Vec<u8>" if typ == "buffer" else typ


def _primitive_parameter_into(source):
    """A narrow syntax witness; actual target conversion is still rustc's job.

    Only an unshadowed declared scalar parameter may receive .into(). Neither
    container receivers, closures, complex binding patterns nor custom traits
    enter through this optional study profile. No source bytes are rewritten.
    """
    # The old lexical macro scan recognizes calls, but macro_rules definitions
    # place a name between '!' and '{'. Reject definitions/metavariables before
    # inspecting literal method sites so expansion cannot hide the receiver.
    if "$" in source or re.search(r"\bmacro_rules\b", source):
        raise ValueError("E_FACTORIAL_PRIMITIVE_INTO: macro definitions and metavariables are outside this profile")
    sites = list(re.finditer(r"\.\s*into\s*\(", source))
    if not sites:
        return
    declaration = re.search(r"\bfn\s+[A-Za-z_][A-Za-z_0-9]*\s*\(([^()]*)\)", source)
    if declaration is None or "|" in source:
        raise ValueError("E_FACTORIAL_PRIMITIVE_INTO: closed function header and no closure/bar syntax required")
    scalars = set()
    for parameter in declaration[1].split(","):
        found = re.fullmatch(r"\s*(?:mut\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*:\s*(u8|u16|u32|u64|usize|bool)\s*", parameter)
        if found:
            scalars.add(found[1])
    receivers = set()
    for site in sites:
        before = source[:site.start()]
        receiver = re.search(r"([A-Za-z_][A-Za-z_0-9]*)\s*$", before)
        if (receiver is None or receiver[1] not in scalars
                or before[:receiver.start()].rstrip().endswith(".")):
            raise ValueError("E_FACTORIAL_PRIMITIVE_INTO: receiver must be a declared scalar parameter")
        if re.match(r"\s*\)", source[site.end():]) is None:
            raise ValueError("E_FACTORIAL_PRIMITIVE_INTO: into takes no arguments")
        receivers.add(receiver[1])
    for binding in re.finditer(r"\blet\b", source):
        match = re.match(r"\s+(?:mut\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*(?=[:=;])", source[binding.end():])
        if match is None or match[1] in receivers:
            raise ValueError("E_FACTORIAL_PRIMITIVE_INTO: simple bindings only and receiver parameters may not be shadowed")


def rust_admit(task, files, enforce_contract=True, *, primitive_parameter_into=False):
    """Exact disclosed finite syntax, followed by real rustc type checking."""
    if type(primitive_parameter_into) is not bool:
        raise ValueError("E_FACTORIAL_RUST_PROFILE")
    owned = task["provider"] in {"touch", "replace"}
    normalized = {}
    for name, source in files.items():
        if type(source) is not str or not source.isascii() or len(source.encode()) > 16384:
            raise ValueError("E_FACTORIAL_RUST_SOURCE")
        if any(c in source for c in ('#', '"', "'", '`', '\\')) or any(c in source for c in ("//", "/*", "*/", "..")):
            raise ValueError("E_FACTORIAL_RUST_LEXICAL_PROFILE")
        if not owned and any(c in source for c in "[]"):
            raise ValueError("E_FACTORIAL_RUST_OWNER_OUTSIDE_TASK")
        if re.search(r"\b(unsafe|extern|mod|struct|enum|impl|trait|static|const|type|async|await|loop|while|for|match|move|dyn|std|core|alloc|super)\b", source):
            raise ValueError("E_FACTORIAL_RUST_DECLARATION_OR_EFFECT")
        if len(re.findall(r"\bfn\b", source)) != 1 or source.count("{") > 12:
            raise ValueError("E_FACTORIAL_RUST_FUNCTION_COUNT")
        if re.search(r"\b(provider_call|maximum_word|vector_macro)\b", source):
            raise ValueError("E_FACTORIAL_RUST_RESERVED_NAME")
        type_part = re.sub(r"\bVec\s*<\s*u8\s*>", "", source) if owned else source
        if any(word != "MAX" for word in re.findall(r"\b[A-Z][A-Za-z_0-9]*\b", type_part)):
            raise ValueError("E_FACTORIAL_RUST_TYPE_PROFILE")
        macros = re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*!\s*[([{]", source)
        if any(word != "vec" or not owned for word in macros):
            raise ValueError("E_FACTORIAL_RUST_MACRO_PROFILE")
        text = re.sub(r"\s*::\s*", "::", source)
        body, imports = re.subn(r"\buse\s+crate::api\s*;", "", text)
        if imports != (1 if name == "client.rs" else 0) or re.search(r"\b(use|crate)\b", body):
            raise ValueError("E_FACTORIAL_RUST_IMPORT")
        path = "api::" + task["provider"]
        calls = len(re.findall(r"\b" + re.escape(path) + r"\s*\(", body))
        mentions = len(re.findall(r"\b" + re.escape(path) + r"\b", body))
        if calls != mentions or calls != (1 if name == "client.rs" else 0):
            raise ValueError("E_FACTORIAL_RUST_PROVIDER_CALL_COUNT")
        body = re.sub(r"\b" + re.escape(path) + r"\b", "provider_call", body)
        body = re.sub(r"\bu(?:32|64)::MAX\b", "maximum_word", body)
        body = re.sub(r"\bvec\s*!\s*\[", "vector_macro[", body)
        if "::" in body or re.search(r"[)}\]]\s*\(|\.\s*[0-9]+\s*\(", body):
            raise ValueError("E_FACTORIAL_RUST_PATH_OR_CALLABLE")
        if primitive_parameter_into:
            _primitive_parameter_into(text)
        methods = set(fixtures.RUST_METHODS) | ({"into"} if primitive_parameter_into else set())
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", body):
            word, prefix = match[1], body[:match.start()].rstrip()
            if re.search(r"\bfn$", prefix):
                continue
            if prefix.endswith("."):
                if word not in methods or (word == "len" and not owned):
                    raise ValueError("E_FACTORIAL_RUST_METHOD: " + word)
            elif word not in {"provider_call", "if", "return", "let"} | ({"drop"} if owned else set()):
                raise ValueError("E_FACTORIAL_RUST_CALL: " + word)
        normalized[name] = text
    if enforce_contract:
        compact = re.sub(r"\s+", "", normalized["api.rs"])
        # Parameter mutability does not change the callable interface.
        compact = re.sub(r"\bmut(?=[a-z_])", "", compact)
        compact = compact.replace("(mut", "(").replace(",mut", ",")
        params = ",".join(n + ":" + rust_type(t) for n, t in task["provider_params"])
        returned = rust_type(task["provider_returns"][0])
        if not compact.startswith("pubfn" + task["provider"] + "(" + params + ")->" + returned + "{"):
            raise ValueError("E_FACTORIAL_PROVIDER_INTERFACE")
        client = re.sub(r"\s+", "", normalized["client.rs"]).replace("usecrate::api;", "")
        if not client.startswith("pubfnentrypoint(a:u32,b:u32,c:u32)->u64{"):
            raise ValueError("E_FACTORIAL_ENTRY_INTERFACE")


def parse_files(task, language, text, *, enforce_contract=True, primitive_parameter_into=False):
    if type(text) is not str or len(text.encode()) > 65536:
        raise ValueError("E_FACTORIAL_RESPONSE_SIZE")
    decoded = decode_json(text)
    if type(decoded) is not dict or set(decoded) != {"files"} or type(decoded["files"]) is not dict:
        raise ValueError("E_FACTORIAL_RESPONSE_ENVELOPE")
    files = decoded["files"]
    if set(files) != set(fixtures.EDITABLE[language]):
        raise ValueError("E_FACTORIAL_FILES")
    receipt = {"operation": "atomic_replace_two_functions", "editable_files": sorted(files),
               "original_sha256": hashlib.sha256(canonical(task["original_" + language])).hexdigest(),
               "replacement_sha256": hashlib.sha256(canonical(files)).hexdigest(),
               "unchanged_files_sha256": hashlib.sha256(canonical(task["unchanged_" + language])).hexdigest()}
    if language == "rust":
        rust_admit(task, files, enforce_contract, primitive_parameter_into=primitive_parameter_into)
        if primitive_parameter_into:
            receipt["rust_conversion_profile"] = "unshadowed_declared_scalar_parameter_into_v1"
        return copy.deepcopy(files), receipt
    if any(type(value) is not dict for value in files.values()):
        raise ValueError("E_FACTORIAL_HIA_FUNCTION_OBJECT")
    provider, client = files["api.hia.json"], files["client.hia.json"]
    if provider.get("name") != task["provider"] or client.get("name") != "entrypoint":
        raise ValueError("E_FACTORIAL_FUNCTION_NAMES")
    if client.get("params") != task["original_hia"]["client.hia.json"]["params"] or client.get("returns") != ["u64"]:
        raise ValueError("E_FACTORIAL_ENTRY_INTERFACE")
    if enforce_contract and ([[p["name"], p["type"]] for p in provider.get("params", [])] != task["provider_params"]
                             or provider.get("returns") != task["provider_returns"]):
        raise ValueError("E_FACTORIAL_PROVIDER_INTERFACE")
    program = verify_program(fixtures.document(task, files, probe_contract=enforce_contract))
    allowed_types = {"bool", "u8", "u16", "u32", "u64", "usize", "buffer", "mutbuf", "readbuf"}
    calls = []
    for function in program.as_dict()["functions"]:
        if set(function["effects"]) - {"alloc", "read", "write", "trap"}:
            raise ValueError("E_FACTORIAL_HIA_EFFECT")
        blocks = {block["id"]: block for block in function["blocks"]}
        if len(blocks) > 16 or sum(len(b["ops"]) for b in blocks.values()) > 128:
            raise ValueError("E_FACTORIAL_HIA_SIZE")
        types = list(function["returns"]) + [p["type"] for p in function["params"]]
        for block in blocks.values():
            types += [p["type"] for p in block["params"]]
            for operation in block["ops"]:
                types += [out["type"] for out in operation["out"]]
                kind = operation["op"]
                if not (kind in {"const", "select", "call", "int.cast", "buffer.new", "buffer.len", "buffer.load", "buffer.store", "borrow.read", "borrow.mut", "loan.end", "owner.drop", "owner.move"}
                        or kind.startswith(("int.", "bit.", "compare."))):
                    raise ValueError("E_FACTORIAL_HIA_OPERATION")
                if kind == "call":
                    calls.append((function["name"], operation["attrs"]["function"]))
        if set(types) - allowed_types:
            raise ValueError("E_FACTORIAL_HIA_TYPE")
        active, seen = set(), set()
        def visit(name):
            if name in active:
                raise ValueError("E_FACTORIAL_HIA_LOOP")
            if name in seen:
                return
            active.add(name)
            term = blocks[name]["term"]
            edges = [term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []
            for edge in edges:
                visit(edge["target"])
            active.remove(name); seen.add(name)
        visit(function["entry"])
    if calls != [("entrypoint", task["provider"]), ("provider_probe", task["provider"])]:
        raise ValueError("E_FACTORIAL_HIA_CALL_GRAPH")
    return program, receipt


C_DRIVER = r'''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t entrypoint(uint32_t,uint32_t,uint32_t);
extern uint64_t provider_probe(uint32_t,uint32_t,uint32_t);
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void*);
static int active=0; static uint64_t na,nf,live,peak,bad;
static void *ptrs[128]; static size_t sizes[128];
static void add(void*p,size_t n){if(!active||!p)return; for(int i=0;i<128;i++)if(!ptrs[i]){ptrs[i]=p;sizes[i]=n;na++;live+=n;if(live>peak)peak=live;return;}bad=1;}
void *__wrap_malloc(size_t n){void*p=__real_malloc(n);add(p,n);return p;}
void *__wrap_calloc(size_t a,size_t b){void*p=__real_calloc(a,b);add(p,a*b);return p;}
void __wrap_free(void*p){if(p)for(int i=0;i<128;i++)if(ptrs[i]==p){nf++;live-=sizes[i];ptrs[i]=0;break;}__real_free(p);}
static void reset(void){na=nf=peak=bad=0;if(live)bad=1;active=1;}
int main(void){uint32_t a,b,c;setbuf(stdout,0);while(scanf("%"SCNu32" %"SCNu32" %"SCNu32,&a,&b,&c)==3){
reset();uint64_t e=entrypoint(a,b,c);active=0;uint64_t ea=na,ef=nf,el=live,ep=peak,eb=bad;
reset();uint64_t p=provider_probe(a,b,c);active=0;
printf("%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"\n",e,p,ea,ef,el,ep,eb,na,nf,live,peak,bad);
}return 0;}
'''


RUST_ALLOCATOR = r'''
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicBool,AtomicU64,Ordering};
struct Counted;
static ACTIVE:AtomicBool=AtomicBool::new(false);
static ALLOCS:AtomicU64=AtomicU64::new(0);static FREES:AtomicU64=AtomicU64::new(0);
static LIVE:AtomicU64=AtomicU64::new(0);static PEAK:AtomicU64=AtomicU64::new(0);
fn account(n:usize){if ACTIVE.load(Ordering::SeqCst){ALLOCS.fetch_add(1,Ordering::SeqCst);let now=LIVE.fetch_add(n as u64,Ordering::SeqCst)+n as u64;PEAK.fetch_max(now,Ordering::SeqCst);}}
unsafe impl GlobalAlloc for Counted {
unsafe fn alloc(&self,l:Layout)->*mut u8{let p=System.alloc(l);if !p.is_null(){account(l.size());}p}
unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8{let p=System.alloc_zeroed(l);if !p.is_null(){account(l.size());}p}
unsafe fn dealloc(&self,p:*mut u8,l:Layout){if ACTIVE.load(Ordering::SeqCst){FREES.fetch_add(1,Ordering::SeqCst);LIVE.fetch_sub(l.size() as u64,Ordering::SeqCst);}System.dealloc(p,l);}
}
#[global_allocator] static A:Counted=Counted;
fn reset(){ALLOCS.store(0,Ordering::SeqCst);FREES.store(0,Ordering::SeqCst);LIVE.store(0,Ordering::SeqCst);PEAK.store(0,Ordering::SeqCst);ACTIVE.store(true,Ordering::SeqCst);}
fn capture()->[u64;4]{ACTIVE.store(false,Ordering::SeqCst);[ALLOCS.load(Ordering::SeqCst),FREES.load(Ordering::SeqCst),LIVE.load(Ordering::SeqCst),PEAK.load(Ordering::SeqCst)]}
'''


def rust_driver(task, *, enforce_contract=True):
    name = task["provider"]
    params, returns = task["provider_params"], task["provider_returns"]
    if not enforce_contract and name == "span":
        params, returns = [["a", "u16"], ["b", "u16"]], ["u32"]
    signature = ",".join(n + ":" + rust_type(t) for n, t in params)
    arguments = ",".join(n for n, _ in params)
    observed = "a as u64,b as u64" if name in {"span", "saturating_sum"} else "buf.len() as u64," + ("x as u64" if name == "touch" else "n as u64")
    expected = "v[0] as u64,v[1] as u64" if name in {"span", "saturating_sum"} else "((v[0]&7)+1) as u64," + ("(v[1]&255) as u64" if name == "touch" else "((v[2]&7)+1) as u64")
    identity_before = "let address=buf.as_ptr();" if name == "touch" else ""
    identity_after = "if value.as_ptr()!=address{BAD.store(1,Ordering::SeqCst);}" if name == "touch" else ""
    return RUST_ALLOCATOR + f'''
mod api_original {{#![forbid(unsafe_code)] include!("api.rs");}}
mod client {{#![forbid(unsafe_code)] include!("client.rs");}}
mod audit;mod utility;mod probe;
mod api {{
use std::sync::atomic::{{AtomicU64,Ordering}};
static CALLS:AtomicU64=AtomicU64::new(0);static ARG0:AtomicU64=AtomicU64::new(0);static ARG1:AtomicU64=AtomicU64::new(0);static BAD:AtomicU64=AtomicU64::new(0);
pub fn reset(a:u64,b:u64){{CALLS.store(0,Ordering::SeqCst);BAD.store(0,Ordering::SeqCst);ARG0.store(a,Ordering::SeqCst);ARG1.store(b,Ordering::SeqCst);}}
pub fn result()->(u64,u64){{(CALLS.load(Ordering::SeqCst),BAD.load(Ordering::SeqCst))}}
pub fn {name}({signature})->{rust_type(returns[0])}{{
CALLS.fetch_add(1,Ordering::SeqCst);let (a0,a1)=({observed});if a0!=ARG0.load(Ordering::SeqCst)||a1!=ARG1.load(Ordering::SeqCst){{BAD.store(1,Ordering::SeqCst);}}
{identity_before}let value=super::api_original::{name}({arguments});{identity_after}value
}}
}}
use std::io::{{self,BufRead}};
fn main(){{for line in io::stdin().lock().lines(){{let line=line.unwrap();let v:Vec<u32>=line.split_whitespace().map(|x|x.parse().unwrap()).collect();
api::reset({expected});reset();let e=client::entrypoint(v[0],v[1],v[2]);let er=capture();let ec=api::result();
api::reset({expected});reset();let p=probe::provider_probe(v[0],v[1],v[2]);let pr=capture();let pc=api::result();
println!("{{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}} {{}}",e,p,er[0],er[1],er[2],er[3],ec.1,pr[0],pr[1],pr[2],pr[3],pc.1,ec.0,pc.0);
}}}}
'''


def build(task, language, text, folder, clang, rustc, *, enforce_contract=True, primitive_parameter_into=False):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    record = {"language": language, "task": task["id"], "folder": str(folder), "native_built": False, "status": "response_rejected"}
    try:
        parsed, receipt = parse_files(task, language, text, enforce_contract=enforce_contract, primitive_parameter_into=primitive_parameter_into)
        record.update(receipt=receipt, status="compile_rejected")
        binary = folder / "candidate"
        compiler = file_identity(clang if language == "hia" else rustc)
        record["compiler"] = compiler
        if language == "hia":
            (folder / "candidate.hia.json").write_bytes(parsed.canonical_bytes)
            record.update(core_path=str(folder / "candidate.hia.json"), core_sha256=parsed.sha256)
            decoded = decode_json(text)["files"]
            for name, value in {**task["unchanged_hia"], **decoded}.items():
                (folder / name).write_bytes(canonical(value) + b"\n")
            record["native_compile"] = build_program_native(parsed, folder / "candidate.o", clang=clang, kind="object")
            (folder / "driver.c").write_text(C_DRIVER)
            argv = [clang, "-O2", str(folder / "driver.c"), str(folder / "candidate.o"), "-Wl,--wrap=malloc,--wrap=calloc,--wrap=free", "-o", str(binary)]
        else:
            for name, source in {**task["unchanged_rust"], **parsed}.items():
                (folder / name).write_text(source)
            probe = task["probe_rust"]
            if not enforce_contract and task["provider"] == "span":
                probe = probe.replace("api::span(a,b)", "api::span(a as u16,b as u16)")
            (folder / "probe.rs").write_text(probe)
            (folder / "main.rs").write_text(rust_driver(task, enforce_contract=enforce_contract))
            argv = [rustc, "--edition=2021", "-Copt-level=2", "-Coverflow-checks=on", str(folder / "main.rs"), "-o", str(binary)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        record["compile"] = {"argv": argv, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        if proc.returncode == 0:
            record.update(status="compiled", native_built=True, artifact=file_identity(binary))
        if file_identity(compiler["path"]) != compiler:
            raise RuntimeError("E_FACTORIAL_COMPILER_CHANGED")
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, (OSError, subprocess.TimeoutExpired, RuntimeError)):
            record["status"] = "infrastructure_failure"
    record["build_ns"] = time.monotonic_ns() - started
    save(folder / "BUILD.json", record)
    return record


def vm_observations(built, task, cases):
    checked = verify_program(Path(built["core_path"]).read_bytes())
    if checked.sha256 != built["core_sha256"]:
        raise RuntimeError("E_FACTORIAL_CORE_DRIFT")
    def snapshot(value):
        if hasattr(value, "data") and hasattr(value, "ident"):
            return {"owner": value.ident, "length": len(value.data), "first": int(value.data[0]) if value.data else None}
        return value
    class Observed(_Machine):
        def __init__(self):
            super().__init__(checked, 10000, 256, None, 16); self.calls = []
        def invoke(self, function, arguments, depth=0):
            event = {"function": function["name"], "arguments": [snapshot(v) for v in arguments]}
            self.calls.append(event)
            result = super().invoke(function, arguments, depth)
            event["values"] = [snapshot(v) for v in result]
            return result
    rows = []
    for case in cases:
        pair = []
        for entry in ("entrypoint", "provider_probe"):
            machine = Observed()
            try:
                values = machine.invoke(machine.functions[entry], list(case))
                row = {"status": "returned", "values": values}
            except Exception as error:
                row = {"status": "refused_or_trapped", "error": {"type": type(error).__name__, "message": str(error)}}
            row.update(resources=machine.resources(), calls=machine.calls)
            calls = [event for event in machine.calls if event["function"] == task["provider"]]
            expected = fixtures.provider_arguments(task, case)
            actual = copy.deepcopy(calls[0]["arguments"]) if len(calls) == 1 else None
            if actual and type(actual[0]) is dict:
                actual[0].pop("owner", None)
            row["provider_contract"] = len(calls) == 1 and actual == expected
            if task["provider"] == "touch" and len(calls) == 1:
                row["provider_contract"] &= bool(calls[0].get("values") and calls[0]["values"][0].get("owner") == calls[0]["arguments"][0].get("owner"))
            pair.append(row)
        rows.append(pair)
    return rows


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))


def execute(built, task, cases, expected):
    started = time.monotonic_ns()
    artifact = built["artifact"]
    if file_identity(artifact["path"]) != artifact:
        raise RuntimeError("E_FACTORIAL_BINARY_DRIFT")
    descriptor = os.memfd_create("hepta-factorial-native", os.MFD_ALLOW_SEALING)
    try:
        data = Path(artifact["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise RuntimeError("E_FACTORIAL_BINARY_DRIFT")
        with os.fdopen(os.dup(descriptor), "wb") as output:
            output.write(data); output.flush()
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        payload = "".join(" ".join(str(v) for v in case) + "\n" for case in cases)
        try:
            proc = subprocess.run(["/proc/self/fd/" + str(descriptor)], pass_fds=(descriptor,), input=payload,
                                  capture_output=True, text=True, timeout=5, preexec_fn=limits)
            execution = {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "timeout": False}
        except subprocess.TimeoutExpired as error:
            text = lambda v: v.decode(errors="replace") if isinstance(v, bytes) else v
            execution = {"returncode": None, "stdout": text(error.stdout), "stderr": text(error.stderr), "timeout": True}
    finally:
        os.close(descriptor)
    values = []
    for line in (execution["stdout"] or "").splitlines():
        if re.fullmatch(r"[0-9]+(?: [0-9]+){11,13}", line) is None:
            values = []; break
        values.append([int(word) for word in line.split()])
    native_complete = execution["returncode"] == 0 and len(values) == len(cases)
    logical_allocations = 1 if task["provider"] == "touch" else 3 if task["provider"] == "replace" else 0
    peak_limit = 8 if task["provider"] == "touch" else 17 if task["provider"] == "replace" else 0
    resource_ok = native_complete
    for row in values:
        resource_ok &= all(row[start] == row[start+1] and row[start] <= logical_allocations
                           and row[start+2] == 0 and row[start+3] <= peak_limit and row[start+4] == 0 for start in (2, 7))
        if built["language"] == "rust":
            resource_ok &= len(row) == 14 and row[12:] == [1, 1]
    vm = vm_observations(built, task, cases) if built["language"] == "hia" else None
    vm_ok = True
    if vm is not None:
        for index, pair in enumerate(vm):
            for part, observed in enumerate(pair):
                resources = observed["resources"]
                vm_ok &= bool(observed["status"] == "returned" and observed.get("values") == [values[index][part]] if native_complete else False)
                vm_ok &= observed["provider_contract"] and resources["allocations"] == resources["frees"] == logical_allocations
                vm_ok &= resources["live_owners"] == 0 and resources["live_bytes"] == 0 and resources["live_local_loans"] == 0 and resources["peak_bytes"] <= peak_limit
    correct = native_complete and [row[:2] for row in values] == expected and resource_ok and vm_ok
    return {"status": "correct" if correct else "native_budget_or_trap" if not native_complete else "observable_wrong",
            "native_executed": native_complete, "execution": execution, "observations": values, "expected": expected,
            "resource_contract_passed": resource_ok, "vm_contract_passed": vm_ok, "hia_vm": vm,
            "artifact_unchanged": file_identity(artifact["path"]) == artifact, "evaluation_ns": time.monotonic_ns() - started}


def feedback(built, observed):
    return {"build_status": built["status"], "diagnostic": built.get("error") or built.get("compile", {}).get("stderr", "")[:4000],
            "public_status": observed["status"] if observed else None,
            "public_observed": [r[:2] for r in observed["observations"]] if observed else None,
            "public_expected": observed["expected"] if observed else None,
            "public_resource_contract": observed["resource_contract_passed"] if observed else None,
            "public_vm_contract": observed["vm_contract_passed"] if observed else None}
