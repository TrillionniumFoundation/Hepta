"""Exact current P16 public fixtures selected for the raw verify prefix.

This is test-only orchestration. Published fixture function ASTs and their
original public oracle execute before any target call. Tree1 and render-mode
rows are retained in a selection record, not relabelled as raw-prefix tests.
Native text/catalog bytes never replace the original public expected output.
"""
from __future__ import annotations
import ast,copy,importlib.util,json,sys,traceback
from hashlib import sha256
from pathlib import Path

PINS={
 "test_worker_program_service_r4.py":(27251,"d10d9b4f2289a4e770a6680a2a10a81975d941bcec387cfd4fb59f3f23c37937"),
 "test_worker_type_context_program_r2.py":(20269,"a2f453a67c7b5f7a9575c86087f521f1849e2d73ce3847ee6518bcd95e2200a4"),
 "type_context_original_corpus_r1.py":(11863,"110f96c2f8a1744d4c65e6487bde8d214d76987a3f9e50afebdecb4199188206"),
 "type_context_public_plans_r2.py":(3973,"1896ec7c44225df0c0acc0e6bdca54e5dcd7ea8e461870b4190995e2b59b8474"),
}
GROUPS={
 "fixed-errors":("public-fixed",62,34),
 "type-context":("public-context",4,4),
 "type-names":("public-type-names",48,24),
 "type-shapes":("public-type-shapes",18,9),
 "type-order":("public-type-order",34,17),
 "helper-budget":("public-helper-budget",1,1),
 "late-inventory":("public-late-inventory",1,1),
}
def raw_cases(project,group,bundle,pin,cas,save,out):
    from hepta.hia_program import verify_program,HIAProgramRejected
    from hepta.hia_agent_assembly import render_assembly,assemble_program,diagnose_assembly,HIAAssemblyRejected
    assert group in GROUPS
    project=Path(project);out=Path(out)
    out.mkdir(parents=True,exist_ok=False)
    def exact(name):
        path=project/"reference_fixtures"/name
        raw=pin(path)
        assert (len(raw),sha256(raw).hexdigest())==PINS[name],name
        return path,raw
    def functions(name,selected,namespace):
        path,raw=exact(name);tree=ast.parse(raw,filename=str(path))
        rows=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in selected]
        assert len(rows)==len(selected) and {row.name for row in rows}==set(selected)
        exec(compile(ast.Module(body=rows,type_ignores=[]),str(path)+":exact-selected-fixtures","exec"),namespace)
        return [dict(name=row.name,AST_sha256=sha256(ast.dump(row,include_attributes=False).encode()).hexdigest())
                for row in rows]
    catalog=json.loads(pin(bundle["current_diagnostic_catalog"]))
    assert catalog["groups"]==[1,2,3,4,5] and len(catalog["entries"])==181
    namespace=dict(json=json,copy=copy,traceback=traceback,Path=Path,
        verify_program=verify_program,HIAProgramRejected=HIAProgramRejected,
        render_assembly=render_assembly,assemble_program=assemble_program,
        diagnose_assembly=diagnose_assembly,HIAAssemblyRejected=HIAAssemblyRejected,
        PLAN=[],cas=cas,pin=pin,save=save,OUT=out,
        bundle={"native_type_context_reader_inventory":bundle["current_type_context_inventory"]},
        FIXED={(r["group"],r["error"]):(r["code"]+": "+r["message"]).encode("utf-8") for r in catalog["entries"]})
    exact_methods=functions("test_worker_program_service_r4.py",
        {"primitive","composite","transport","canonical","receipt_expected","reference","add"},namespace)
    exact_methods+=functions("test_worker_type_context_program_r2.py",
        {"reference_trace","add_fixed","public_fixed_plan","public_context_plan",
         "public_helper_budget_plan","public_late_inventory_plan"},namespace)
    original_group,total,selected_count=GROUPS[group]
    old_modules={};module_proof=[]
    try:
        if group.startswith("type-") and group!="type-context":
            for module_name in ("type_context_original_corpus_r1","type_context_public_plans_r2"):
                path,raw=exact(module_name+".py")
                old_modules[module_name]=sys.modules.get(module_name)
                spec=importlib.util.spec_from_file_location(module_name,path)
                module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module
                spec.loader.exec_module(module)
                assert Path(module.__file__).resolve()==path.resolve()
                assert pin(path)==raw
                module_proof.append(dict(module=module_name,bytes=len(raw),sha256=sha256(raw).hexdigest()))
            sys.modules["type_context_public_plans_r2"].plan(namespace,original_group)
        else:
            selected={
                "fixed-errors":"public_fixed_plan","type-context":"public_context_plan",
                "helper-budget":"public_helper_budget_plan","late-inventory":"public_late_inventory_plan",
            }[group]
            namespace[selected]()
    finally:
        for name,old in reversed(tuple(old_modules.items())):
            if old is None:sys.modules.pop(name,None)
            else:sys.modules[name]=old
    rows=namespace["PLAN"];assert len(rows)==total
    selected=[row for row in rows if row["mode"]==1 and row["tree"]==0]
    assert len(selected)==selected_count
    assert len({row["label"] for row in selected})==selected_count
    evidence=[]
    for row in rows:
        value=dict(label=row["label"],mode=row["mode"],tree=row["tree"],
            raw_input=cas(row["source"]),expected_payload=cas(row["expected"]["payload"]),
            expected_kind=row["expected"]["kind"],
            selected_for_actual_raw_verify=(row["mode"]==1 and row["tree"]==0))
        if row["expected"]["kind"]==4:value["expected_code"]=row["expected"]["code"]
        evidence.append(value)
    save(out/"exact-current-fixture-selection.json",dict(
        schema="hia-current-P16-raw-prefix-fixture-selection-v1",original_group=original_group,
        published_fixture_rows=total,actual_selected_rows=selected_count,rows=evidence,
        exact_fixture_function_AST=exact_methods,explicit_sibling_modules=module_proof,
        all_original_public_oracles_before_target=True,native_catalog_is_not_oracle=True,
        excluded_modes_not_counted_as_executed=True,original_target_executions=0))
    return selected
