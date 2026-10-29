#!/usr/bin/env python3
"""Source-bound upstream C record/view migration through independent HIA/LLVM.

The inherited command recorder and artifact checker are shared with filecheck;
this trial has a separate prospective protocol and never replaces old samples.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.c_project import verify_capture
from hepta.elf_shared_abi import inspect_owned_shared_elf
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_source import lower_c_project_views
from hepta.native_tool_identity import update_stable_regular_hash
from tools.qualify_hia_filecheck import (Trial, RESOURCE_HARNESS, cases, checksum,
    corpus, digest, identity, order, quantile, require, update, write)
from tools.qualify_c_ring_buffer import verify_upstream as verify_ring
from tools.qualify_c_musl_compare import verify_upstream as verify_compare

FIXTURE = ROOT / "examples/hia_legacy_queue"
PROTOCOL_PATH = ROOT / "experiments/hia_legacy_queue/PROTOCOL_20261028.json"
PROTOCOL = json.loads(PROTOCOL_PATH.read_text())
SOURCES = ("ring/ringbuffer.c", "compare/memcmp.c", "compare/bcmp.c", "checksum.c")
ENTRY = "legacy_checksum_chunk"


def source_bindings():
    paths = [Path(__file__), PROTOCOL_PATH,
             ROOT / "tools/qualify_hia_filecheck.py",
             ROOT / "experiments/hia_filecheck/PROTOCOL_20261028.json",
             ROOT / "tools/qualify_c_ring_buffer.py",
             ROOT / "tools/qualify_c_musl_compare.py",
             *FIXTURE.iterdir(), *sorted((ROOT / "hepta").glob("*.py")),
             *sorted((ROOT / "examples/hia_filecheck").glob("*"))]
    for name in ("ring_buffer", "musl_compare"):
        paths.extend((ROOT / "tests/fixtures/c_migration" / name).rglob("*"))
    return {str(p.relative_to(ROOT)): digest(p) for p in paths if p.is_file()}


def populate_project(project):
    """Copy exact upstream inputs; authored glue is inventoried separately."""
    verify_ring(); verify_compare()
    project.mkdir()
    for source, dest in (("ring_buffer", "ring"), ("musl_compare", "compare")):
        shutil.copytree(ROOT / "tests/fixtures/c_migration" / source, project / dest)
    for path in FIXTURE.iterdir():
        if path.is_file():
            shutil.copyfile(path, project / path.name)
    for name in ("checksum.c", "app_driver.c", "rss_supervisor.c"):
        shutil.copyfile(ROOT / "examples/hia_filecheck" / name, project / name)
    contracts = json.loads((project / "ring/contracts.json").read_text())
    contracts["functions"].update(json.loads((project / "compare/contracts.json").read_text())["functions"])
    contracts["functions"]["checksum_byte"] = {"records": {}, "slices": {}}
    write(project / "contracts.json", contracts)
    return contracts


def compile_database(project, directory, sources=SOURCES):
    directory.mkdir()
    database = directory / "compile_commands.json"
    write(database, [{"directory": str(project), "file": name,
        "arguments": ["clang", "-std=c11", "-DNDEBUG", "-funsigned-char", "-fno-builtin",
                      "-Icompare/platform", "-O3", "-c", name, "-o", name + ".o"]}
        for name in sources])
    return database


def generated_program_identity(core, directory):
    """Bind consumed generated files to this exact independently verified Core.

    These are trusted-host build checks, not a sealed compiler-input or native
    refinement certificate. The existing stable reader rejects path drift,
    nonregular files and sizes larger than the regenerated expected bytes.
    """
    expected = {"core": ("program.hia.json", core.canonical_bytes),
                "llvm": ("program.ll", emit_program_llvm(core).text.encode("utf-8"))}
    observed = {}
    for label, (name, content) in expected.items():
        path = Path(directory) / name
        actual = sha256()
        update_stable_regular_hash(actual, path, max_bytes=len(content))
        require(actual.hexdigest() == sha256(content).hexdigest(),
                "generated " + label + " differs from the same verified Core")
        observed[label] = {"path": str(path.absolute()), "bytes": len(content),
                           "sha256": actual.hexdigest()}
    return observed


class LegacyTrial(Trial):
    protocol = PROTOCOL
    protocol_path = PROTOCOL_PATH
    schema = "hepta.hia.legacy-queue.qualification.v1"
    performance_arm = "hia_native_lto"
    source_bindings = staticmethod(source_bindings)

    def __init__(self, directory, *, clang, clangxx, rustc, profdata, linker):
        initialization_started = time.perf_counter_ns()
        self.out = Path(directory).absolute()
        require(not self.out.exists(), "new evidence directory required")
        self.out.mkdir(parents=True)
        self.tools = {key: str(Path(shutil.which(value) or value).absolute())
                      for key, value in dict(clang=clang, clangxx=clangxx, rustc=rustc,
                                             profdata=profdata, linker=linker).items()}
        self.report = {"schema": self.schema, "ok": False,
            "protocol": self.protocol, "protocol_sha256": digest(self.protocol_path),
            "source_bindings": self.source_bindings(), "commands": [], "builds": {},
            "resource_cases": [], "samples": [], "claims": dict(self.protocol["claims"])}
        self.project = self.out / "project"
        self.contracts = populate_project(self.project)
        self.libraries, self.runtime_images = {}, {}
        self.application_serial = 0
        self.report["initialization_wall_ns"] = time.perf_counter_ns() - initialization_started

    def capture(self, project, directory, sources=SOURCES, *, contracts=None):
        begin = time.perf_counter_ns()
        database = compile_database(project, directory, sources)
        migrated = lower_c_project_views(database, contracts=self.contracts if contracts is None else contracts,
            clang=self.tools["clang"], client_source=(project / "client.hepta").read_text(), retain_asts=True)
        core = migrated.pop("program")
        asts = migrated.pop("raw_asts")
        write(directory / "capture.json", migrated["capture"])
        (directory / "source.hepta").write_text(migrated["source"])
        (directory / "client.hepta").write_text(migrated["client_source"])
        (directory / "program.hia.json").write_bytes(core.canonical_bytes)
        (directory / "program.ll").write_text(emit_program_llvm(core).text)
        ast_records = []
        for index, text in asts.items():
            path = directory / f"clang-ast-{index}.json"
            path.write_text(text)
            ast_records.append({"configuration_index": index, **identity(path)})
        verify_capture(migrated["capture"])
        write(directory / "migration.json", migrated)
        check_begin = time.perf_counter_ns()
        verify_program(core.canonical_bytes)
        admission = time.perf_counter_ns() - check_begin
        return core, {"source_tus": len(sources), "translated_implementation_bodies": len(migrated["functions"]),
            "upstream_function_bodies": 11, "authored_migrated_function_bodies": len(migrated["functions"])-11,
            "authored_client_function_bodies": migrated["authored_client_function_bodies"],
            "raw_clang_ast_stdout_retained": True, "asts": ast_records,
            "upstream_ring": verify_ring(), "upstream_compare": verify_compare(),
            "declaration_inventory_complete": migrated["declaration_inventory_complete"],
            "program_sha256": core.sha256, "capture": identity(directory / "capture.json"),
            "migration": identity(directory / "migration.json"),
            "generated_program": generated_program_identity(core, directory),
            "wall_ns": time.perf_counter_ns()-begin, "fresh_admission_wall_ns": admission,
            "manual_migrated_body_edits": 0, "human_effort_measured": False,
            "claims": migrated["claims"]}

    def application(self, arm, algorithm, file="held-out.bin", *, env=None, alternate=None, stage="application"):
        library = self.libraries[arm]
        require(identity(library) == self.runtime_images[str(library)], "library changed before load")
        require(identity(self.out / "filecheck") == self.driver_identity, "host changed")
        require(identity(self.out / "rss-supervisor") == self.supervisor_identity, "supervisor changed")
        expected = self.report["inputs"][file]
        require(identity(self.out / file) == {k: expected[k] for k in ("path", "bytes", "sha256")}, "input changed")
        receipt = self.out / f"rss-{self.application_serial:04}.json"
        self.application_serial += 1
        argv = [self.out / "rss-supervisor", receipt, self.out / "filecheck", library, ENTRY,
                self.out / file, str(self.protocol["algorithms"][algorithm])]
        if alternate is not None:
            argv.append(alternate)
        row = self.command(argv, stage, env=env)
        observed, memory = json.loads(row["stdout"]), json.loads(receipt.read_text())
        require(observed["checksum"] == expected["checksums"][algorithm] and observed["bytes"] == expected["bytes"], "application output mismatch")
        require(observed["calls"] == (expected["bytes"]+7)//8 and len(observed["batch_ns"]) == (expected["bytes"]+4095)//4096, "missing work")
        require(memory["child_exit_code"] == 0 and memory["child_signal"] == 0, "child failed")
        require(identity(library) == self.runtime_images[str(library)], "library changed during load")
        return {"observation": observed, "memory": memory, "memory_receipt": identity(receipt),
                "process_wall_ns": row["wall_ns"], "command_index": len(self.report["commands"])-1}

    def build(self):
        for name, path in self.tools.items():
            version = self.command([path, "--version"], "tool_identity")
            self.report.setdefault("tools", {})[name] = {**identity(path), "version": version["stdout"]}
        self.report["host"] = {"platform": platform.platform(), "machine": platform.machine(),
            "exclusive_host": False, "dot_status": "LOCAL_RUNTIME_NOT_OBSERVABLE"}
        self.report["python"] = {**identity(sys.executable), "version": sys.version}
        self.report["git"] = self.command(["git", "-C", ROOT, "rev-parse", "HEAD"], "source_identity")["stdout"].strip()
        self.report["git_status"] = self.command(["git", "-C", ROOT, "status", "--porcelain"], "source_identity")["stdout"]
        tracked = set(self.command(["git", "-C", ROOT, "ls-files"], "source_identity")["stdout"].splitlines())
        self.report["source_files_tracked"] = set(self.report["source_bindings"]).issubset(tracked)
        self.report["inputs"] = {}
        for name, spec in (("training.bin", self.protocol["training"]), ("held-out.bin", self.protocol["held_out"])):
            data = corpus(spec["seed"], spec["bytes"]); (self.out/name).write_bytes(data)
            self.report["inputs"][name] = {**identity(self.out/name), "checksums": {key: checksum(data, poly) for key, poly in self.protocol["algorithms"].items()}}
        for source, output, extra in (("app_driver.c", "filecheck", ["-ldl"]), ("rss_supervisor.c", "rss-supervisor", [])):
            self.command([self.tools["clang"], "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
                          self.project/source, *extra, "-o", self.out/output], "host_build")
        self.driver_identity = identity(self.out/"filecheck")
        self.supervisor_identity = identity(self.out/"rss-supervisor")
        self.report["supervisor"] = self.supervisor_identity
        self.core, self.report["migration"] = self.capture(self.project, self.out/"migration")
        self.libraries = {name: self.out/(name+".so") for name in self.protocol["arms"]}
        begin = time.perf_counter_ns()
        receipt = build_program_native(self.core, self.libraries["hia_default"], clang=self.tools["clang"])
        self.report["builds"]["hia_default"] = {"wall_ns": time.perf_counter_ns()-begin, "receipt": receipt}
        self.flags = ["-O3", "-flto=full", "-fuse-ld="+self.tools["linker"], "-march=native", "-fPIC", "-shared", "-Wl,-Bsymbolic-functions"]
        begin = time.perf_counter_ns()
        generated = self.require_core_ir()
        row = self.command([self.tools["clang"], *self.flags, self.out/"migration/program.ll", "-o", self.libraries["hia_native_lto"]], "hia_research_native_build")
        self.require_core_ir()
        inventory = inspect_owned_shared_elf(self.libraries["hia_native_lto"].read_bytes(), emit_program_llvm(self.core).exports)
        self.report["builds"]["hia_native_lto"] = {"wall_ns": time.perf_counter_ns()-begin,
            "compiler_wall_ns": row["wall_ns"], "default_backend_receipt": False,
            "generated_program": generated, "binary_inventory": inventory}
        self.rust_flags = ["--edition=2021", "--crate-type=cdylib", "-Copt-level=3", "-Clto=fat", "-Ccodegen-units=1", "-Cpanic=abort", "-Ctarget-cpu=native"]
        for label in ("c", "cpp", "rust"):
            self.baseline(label, pgo=False); self.baseline(label, pgo=True)
        self.extra_builds()
        self.report["artifacts"] = {name: identity(path) for name, path in self.libraries.items()}
        self.report["artifacts"]["host_driver"] = self.driver_identity
        self.runtime_images.update({str(path): identity(path) for path in self.libraries.values()})

    def extra_builds(self):
        """A separately registered trial may add arms before the artifact seal."""

    def require_core_ir(self):
        observed = generated_program_identity(self.core, self.out / "migration")
        require(observed == self.report["migration"]["generated_program"],
                "generated Core/LLVM identity changed after capture")
        return observed

    def verify_artifacts(self):
        super().verify_artifacts()
        self.require_core_ir()

    def build_reference(self, label, output, extra, stage):
        if label == "rust":
            self.command([self.tools["rustc"], *self.rust_flags, *extra, self.project/"reference.rs", "-o", output], stage)
            return
        cflags = ["-std=c11", "-DNDEBUG", "-funsigned-char", "-fno-semantic-interposition"]
        if label == "c":
            self.command([self.tools["clang"], *cflags, *self.flags, *extra,
                          *[self.project/name for name in SOURCES], self.project/"client.c", "-o", output], stage)
        else:
            objects=[]
            for number, name in enumerate(SOURCES):
                obj=self.out/(output.name+f"-{number}.o"); objects.append(obj)
                self.command([self.tools["clang"], *cflags, "-O3", "-flto=full", "-march=native", "-fPIC", *extra,
                              "-c", self.project/name, "-o", obj], stage+"_c_object")
            self.command([self.tools["clangxx"], "-std=c++20", "-DNDEBUG", "-funsigned-char", "-fno-semantic-interposition",
                          *self.flags, *extra, self.project/"reference.cpp", *objects, "-o", output], stage)

    def baseline(self, label, *, pgo):
        arm=label+("_native_pgo" if pgo else "_native_lto")
        begin=time.perf_counter_ns(); record={}; self.report["builds"][arm]=record
        if not pgo:
            self.build_reference(label,self.libraries[arm],[],"baseline_build")
        else:
            profiles=self.out/(label+"_profiles"); profiles.mkdir()
            instrumented=self.out/(label+"_instrumented.so")
            flags=["-Cprofile-generate="+str(profiles)] if label=="rust" else ["-fprofile-instr-generate"]
            self.build_reference(label,instrumented,flags,"profile_build")
            self.runtime_images[str(instrumented)]=identity(instrumented)
            final=self.libraries[arm]; self.libraries[arm]=instrumented
            try:
                record["training"]=[self.application(arm,algo,"training.bin",env=dict(os.environ,LLVM_PROFILE_FILE=str(profiles/(algo+"-%p.profraw"))),stage="profile_training") for algo in self.protocol["algorithms"]]
            finally:
                self.libraries[arm]=final
            raw=sorted(profiles.glob("*.profraw")); require(len(raw)==2,"two actual profiles required")
            merged=profiles/"training.profdata"
            self.command([self.tools["profdata"],"merge","-o",merged,*raw],"profile_merge")
            flags=["-Cprofile-use="+str(merged),"-Cllvm-args=-pgo-warn-missing-function"] if label=="rust" else ["-fprofile-instr-use="+str(merged),"-Werror=profile-instr-out-of-date","-Werror=profile-instr-unprofiled"]
            self.build_reference(label,final,flags,"profile_use_build")
            record["profiles"]=[identity(p) for p in raw]; record["merged_profile"]=identity(merged)
        record["wall_ns"]=time.perf_counter_ns()-begin

    def differential(self):
        functions={}
        for arm,path in self.libraries.items():
            fn=getattr(ctypes.CDLL(str(path)),ENTRY)
            fn.argtypes=[ctypes.c_size_t,ctypes.c_ulonglong,ctypes.c_uint,ctypes.c_uint]; fn.restype=ctypes.c_ulonglong
            functions[arm]=fn
        rows=[]
        with (self.out/"differential.jsonl").open("x") as stream:
            for case in cases():
                row={**case,"observed":{arm:int(fn(*case["arguments"])) for arm,fn in functions.items()}}
                stream.write(json.dumps(row)+"\n"); rows.append(row)
                require(all(value==case["expected"] for value in row["observed"].values()),"ABI differential mismatch")
        self.report["differential"]={"cases":len(rows),"routes":len(functions),"native_calls":len(rows)*len(functions),"ledger":identity(self.out/"differential.jsonl")}

    def resources(self):
        (self.out/"resource_harness.c").write_text(RESOURCE_HARNESS)
        obj=self.out/"resource_hia.o"
        self.report["resource_native_build"]=build_program_native(self.core,obj,kind="object",clang=self.tools["clang"])
        wrap=["-Wl,--wrap=malloc","-Wl,--wrap=calloc","-Wl,--wrap=free"]
        for label in ("c","hia"):
            inputs=[obj] if label=="hia" else [*[self.project/name for name in SOURCES],self.project/"client.c"]
            self.command([self.tools["clang"],"-std=c11","-DNDEBUG","-funsigned-char","-O2","-fno-builtin","-DENTRY="+ENTRY,
                          self.out/"resource_harness.c",*inputs,*wrap,"-o",self.out/("resource_"+label)],"resource_observer_build")
        for case in list(cases())[:self.protocol["resource_cases"]]:
            for refusal in self.protocol["allocation_refusal_indices"]:
                vm=execute_program(self.core,ENTRY,case["arguments"],allocation_fail_at=refusal or None)
                stats=vm["resources"]
                expected=dict(result=vm["result"],attempts=stats["allocation_attempts"],allocations=stats["allocations"],frees=stats["frees"],live=0)
                native={label:json.loads(self.command([self.out/("resource_"+label),*case["arguments"],refusal],"resource_execution")["stdout"]) for label in ("c","hia")}
                self.report["resource_cases"].append({**case,"refuse_at":refusal,"vm":vm,"native":native})
                require(stats["live_owners"]==0 and all(row==expected for row in native.values()),"allocation/refusal/cleanup mismatch")

    def maintenance(self):
        begin=time.perf_counter_ns(); project=self.out/"maintained-project"; shutil.copytree(self.project,project)
        (project/"checksum_v2.c").write_text('#include "checksum.h"\nunsigned int checksum_byte_v2(unsigned int state,unsigned char byte,unsigned int algorithm) {\n if(algorithm==1)return checksum_byte(state,byte,0xedb88320U);\n if(algorithm==2)return checksum_byte(state,byte,0x82f63b78U);\n return state;\n}\n')
        header=project/"checksum.h"; header.write_text(header.read_text()+"\nunsigned int checksum_byte_v2(unsigned int state,unsigned char byte,unsigned int algorithm);\n")
        contracts=json.loads(json.dumps(self.contracts)); contracts["functions"]["checksum_byte_v2"]={"records":{},"slices":{}}
        core,migration=self.capture(project,self.out/"maintenance",(*SOURCES,"checksum_v2.c"),contracts=contracts)
        native=self.out/"maintenance.so"; build=build_program_native(core,native,clang=self.tools["clang"])
        original=self.out/"maintenance-c.so"
        self.command([self.tools["clang"],"-O3","-shared","-fPIC",project/"checksum.c",project/"checksum_v2.c","-o",original],"maintenance_original_build")
        rows=[]
        for algorithm in (0,1,2,3):
            for state,byte in ((0,0),(0xffffffff,255),(12345,49)):
                expected=state if algorithm not in (1,2) else update(state,bytes([byte]),self.protocol["algorithms"]["ieee" if algorithm==1 else "castagnoli"])
                values={}
                for label,path,symbol in (("c",original,"checksum_byte_v2"),("hia",native,"c_checksum_byte_v2")):
                    fn=getattr(ctypes.CDLL(str(path)),symbol);fn.argtypes=[ctypes.c_uint,ctypes.c_ubyte,ctypes.c_uint];fn.restype=ctypes.c_uint
                    values[label]=int(fn(state,byte,algorithm))
                rows.append({"arguments":[state,byte,algorithm],"expected":expected,"values":values})
                require(all(v==expected for v in values.values()),"maintenance output mismatch")
        write(self.out/"maintenance-cases.json",rows)
        self.report["maintenance"]={"migration":migration,"build":build,"cases":rows,"wall_ns":time.perf_counter_ns()-begin,
            "authored_source_files_added":1,"authored_source_files_modified":1,"manual_migrated_body_edits":0,"human_effort_measured":False}

    def measure(self):
        require(not self.report["git_status"] and self.report["source_files_tracked"],"formal measurement requires clean committed source")
        require(self.source_bindings()==self.report["source_bindings"],"source drift before measurement")
        self.verify_artifacts()
        for group,algorithm,arm in self.sample_order():
            self.report["samples"].append({"group":group,"algorithm":algorithm,"arm":arm,**self.application(arm,algorithm,stage="measured_application")})
        alternate=self.out/"hia-switch-copy.so";shutil.copyfile(self.libraries["hia_default"],alternate)
        self.report["switch_recovery"]={}
        for name,path in (("successful_switch",alternate),("rejected_switch",self.out/"absent-candidate.so")):
            row=self.application("hia_default","ieee",alternate=path,stage=name)
            require(row["observation"]["switches"]==int(name=="successful_switch") and row["observation"]["refused_switches"]==int(name=="rejected_switch"),"switch path missing")
            self.report["switch_recovery"][name]=row
        summary={}
        for algorithm in self.protocol["algorithms"]:
            table={}
            for arm in self.protocol["arms"]:
                rows=[r for r in self.report["samples"] if r["algorithm"]==algorithm and r["arm"]==arm]
                require(len(rows)==self.protocol["paired_groups"],"incomplete sample matrix")
                runtime=statistics.median(r["process_wall_ns"] for r in rows)
                batches=[ns for r in rows for ns in r["observation"]["batch_ns"]]
                table[arm]={"median_process_wall_ns":runtime,"mib_per_second":self.protocol["held_out"]["bytes"]*1e9/runtime/2**20,
                    "batch_p95_ns":quantile(batches,.95),"batch_p99_ns":quantile(batches,.99),
                    "child_wait4_peak_rss_kib_median":statistics.median(r["memory"]["child_wait4_ru_maxrss_kib"] for r in rows),"samples":len(rows)}
            strong=min((a for a in table if not a.startswith("hia")),key=lambda a:table[a]["median_process_wall_ns"])
            summary[algorithm]={"arms":table,"fastest_strong_reference":strong,
                "hia_runtime_ratio":table[self.performance_arm]["median_process_wall_ns"]/table[strong]["median_process_wall_ns"],
                "hia_p99_ratio":table[self.performance_arm]["batch_p99_ns"]/table[strong]["batch_p99_ns"]}
        self.report["summary"]=summary
        self.report["performance_advantage_gate"]=all(r["hia_runtime_ratio"]<=1 and r["hia_p99_ratio"]<=1 for r in summary.values())
        self.report["samples_excluded"]=0

    def sample_order(self):
        # Original sampler remains bound to the original registered matrix.
        from tools.qualify_hia_filecheck import PROTOCOL as old
        require(all(self.protocol[k]==old[k] for k in ("arms","algorithms","paired_groups")),"shared sampler protocol mismatch")
        return order()

    def run(self, *, prepare_only=False):
        begin=time.perf_counter_ns()
        try:
            # Shared corpus/ordering helpers are admitted only when the two
            # independently registered protocol fields are exactly the same.
            from tools.qualify_hia_filecheck import PROTOCOL as old
            require(all(self.protocol[k]==old[k] for k in ("algorithms","differential_cases")),"shared oracle protocol mismatch")
            self.build();self.differential();self.resources();self.maintenance()
            if not prepare_only:self.measure()
            self.verify_artifacts()
            require(self.source_bindings()==self.report["source_bindings"],"source changed during qualification")
            require(identity(self.out/"rss-supervisor")==self.supervisor_identity,"supervisor changed")
            require(identity(sys.executable)=={k:self.report["python"][k] for k in ("path","bytes","sha256")},"Python changed")
            self.report.update(ok=True,status="prepared_not_measured" if prepare_only else "completed",prepare_only=prepare_only)
        except Exception as error:
            self.report.update(ok=False,status="failed",error={"type":type(error).__name__,"message":str(error)})
        finally:
            self.report["run_wall_ns"]=time.perf_counter_ns()-begin
            self.report["whole_qualification_wall_ns"]=(self.report["initialization_wall_ns"]
                                                         + self.report["run_wall_ns"])
            for row in self.report["commands"]:row.pop("stdout",None);row.pop("stderr",None)
            if (self.out/"processes.jsonl").exists():self.report["process_ledger"]=identity(self.out/"processes.jsonl")
            write(self.out/"qualification.json",self.report)
        return self.report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",required=True)
    for name,default in (("clang",os.environ.get("CLANG","clang")),("clangxx",os.environ.get("CLANGXX","clang++")),("rustc",os.environ.get("RUSTC","rustc")),("profdata","llvm-profdata"),("linker","ld.lld")):p.add_argument("--"+name,default=default)
    p.add_argument("--prepare-only",action="store_true");a=p.parse_args(argv)
    report=LegacyTrial(a.output,clang=a.clang,clangxx=a.clangxx,rustc=a.rustc,profdata=a.profdata,linker=a.linker).run(prepare_only=a.prepare_only)
    print(json.dumps({key:report[key] for key in ("ok","status","error","summary","performance_advantage_gate") if key in report},sort_keys=True))
    return 0 if report["ok"] else 1

if __name__=="__main__":raise SystemExit(main())
