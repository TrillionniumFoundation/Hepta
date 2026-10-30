#!/usr/bin/env python3
"""Capture C inline-array implementations and emit checked Hepta plus a C ABI.

The existing source/declarator capture and frontend checker remain admission
requirements. The independent C backend is selected explicitly so original C
clients need not initialize unread inline-array payload for Rust references.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.ast import HeptaError
from hepta.c_backend import CEmitter, compile_c
from hepta.c_inline_record_views import CInlineRecordViewTranslator, snapshot_inline_contracts
from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project, verify_capture
from hepta.checker import check
from hepta.hia_json_preflight import preflight_hia_json
from hepta.parser import parse
from hepta.hia_program_tools import read_bounded, HIAEditRejected


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_contract(path):
    try:
        raw = read_bounded(path, limit=1048576).decode("utf-8")
        preflight_hia_json(raw, max_nodes=32768, max_depth=32)
        return snapshot_inline_contracts(json.loads(raw))
    except MigrationRejected:
        raise
    except (HIAEditRejected, UnicodeError, ValueError, OverflowError, RecursionError) as error:
        raise MigrationRejected("E_C_INLINE_CONTRACT", "Invalid bounded inline contract input: " + str(error)) from error


def migrate_inline_project(database, destination, *, contracts, clang="clang-20", cc="gcc", verify_native=False):
    destination = Path(destination).absolute()
    began = time.perf_counter_ns()
    report = {"schema":"hepta.c-inline-record-migration.v1", "ok":False,
              "status":"not_completed", "backend":"checked_hepta_to_independent_c",
              "diagnostics":[], "claims":{"source_equivalence_proved":False,
                  "whole_language_soundness_proved":False, "arbitrary_c_cpp_supported":False,
                  "rust_codegen_used":False, "original_implementation_linked":False,
                  "payload_zero_initialized_by_bridge":False, "pointer_provenance_inferred":False},
              "costs":{"machine_wall_ns":None, "human_engineering_seconds":None,
                       "human_review_seconds":None, "agent_input_tokens":None,
                       "agent_output_tokens":None, "agent_reasoning_tokens":None}}
    translator = None
    try:
        if destination.exists() or destination.is_symlink():
            raise MigrationRejected("E_C_PROJECT_EXISTS", "Migration output must be a new directory")
        frozen = snapshot_inline_contracts(contracts)
        report["contracts"] = frozen
        report["contract_identity"] = {"sha256":digest(json.dumps(frozen,sort_keys=True,separators=(",",":")).encode()),
                                       "origin":"explicit_caller_contract_not_inferred"}
        capture = capture_project(database, clang=clang)
        translator = CInlineRecordViewTranslator(capture, frozen)
        translator.retained_asts = {}
        source, _, functions = translator.emit()
        program = parse(source, str(destination / "source.hepta"))
        checked = check(program)
        if not checked.ok:
            report["diagnostics"] = [x.to_dict() for x in checked.diagnostics]
            raise MigrationRejected("E_C_PROJECT_FRONTEND", "Generated Hepta failed the existing frontend checker")
        emitter = CEmitter(program, checked, "cdylib")
        core_c = emitter.emit()
        bridge = translator.c_bridge(emitter, program)
        generated = core_c + "\n" + bridge
        report.update(capture=capture, functions=functions,
                      source_type_admission=translator.original_type_receipts,
                      declaration_inventory_complete=translator.inventory_complete,
                      declarations=translator.inventory, profile=translator.view_report(),
                      frontend_validation="passed", c_backend_borrow_validation="passed")
        if any(row["status"] in {"pending","rejected","prototype_pending","record_forward_pending"} for row in translator.inventory):
            raise MigrationRejected("E_C_INVENTORY", "Incomplete captured declaration coverage")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".inline-project-",dir=destination.parent) as tmp:
            stage = Path(tmp)
            contents = {"source.hepta":source,"bridge.c":bridge,"generated.c":generated}
            for index, ast in translator.retained_asts.items():
                contents[f"clang-ast-{index}.json"] = ast
            if verify_native:
                native = compile_c(generated,cc=cc,crate_type="cdylib",output=stage/"libtranslated.so")
                report["native_build"] = native
                if not native["ok"]:
                    raise MigrationRejected("E_C_PROJECT_NATIVE", "Generated C backend failed native compilation")
                native["artifact"] = str(destination/"libtranslated.so")
                report["native_validation"] = "compiled_not_executed"
            else:
                report["native_validation"] = "not_requested"
            verify_capture(capture)
            report["artifacts"] = {}
            for name, data in contents.items():
                raw = data.encode()
                (stage/name).write_bytes(raw)
                report["artifacts"][name] = {"bytes":len(raw),"sha256":digest(raw)}
            if verify_native:
                raw = (stage/"libtranslated.so").read_bytes()
                report["artifacts"]["libtranslated.so"] = {"bytes":len(raw),"sha256":digest(raw)}
            report["costs"]["machine_wall_ns"] = time.perf_counter_ns()-began
            report.update(ok=True,status="captured_checked_built_not_equivalence_proved")
            (stage/"migration.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
            destination.mkdir()
            for path in sorted(stage.iterdir(),key=lambda p:p.name=="migration.json"):
                os.link(path,destination/path.name)
        return report
    except (MigrationRejected,HeptaError,OSError,ValueError,KeyError,TypeError,RecursionError) as error:
        report.update(ok=False,status="rejected")
        report["diagnostics"].append({"code":getattr(error,"code","E_C_INLINE_PROJECT"),"message":str(error)})
        if translator is not None:
            report["declarations"] = translator.inventory
            report["declaration_inventory_complete"] = translator.inventory_complete
        report["costs"]["machine_wall_ns"] = time.perf_counter_ns()-began
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--contracts",required=True)
    parser.add_argument("--clang",default="clang-20")
    parser.add_argument("--cc",default="gcc")
    parser.add_argument("--verify-native",action="store_true")
    args=parser.parse_args()
    report=migrate_inline_project(args.database,args.output,contracts=load_contract(args.contracts),
                                  clang=args.clang,cc=args.cc,verify_native=args.verify_native)
    print(json.dumps(report,sort_keys=True))
    return 0 if report["ok"] else 1


if __name__=="__main__":
    raise SystemExit(main())
