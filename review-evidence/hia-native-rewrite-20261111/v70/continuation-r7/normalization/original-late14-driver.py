"""Original r7 late-integer and items-shape boundary observations, no edits."""
from __future__ import annotations
import ast,gc,hashlib,json,os,sys,time,traceback,weakref
from pathlib import Path
from unittest.mock import patch
ROOT=Path("/home/qq/hia-native-self-rewrite-20261111-dda7/normalization-v70-r1")
SOURCE=ROOT/"source-notes-coordinator-r7"
ORIGINAL=ROOT/"evidence"/"notes-coordinator-r7"
CASE=ROOT/"evidence"/"late-errors-r7-original-r1"
CASE.mkdir(mode=0o700,exist_ok=False)
started=time.monotonic_ns()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
    with path.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def encoded(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,indent=2)+"\n").encode("ascii")
def check(expected):
    for path,row in expected.items():
        raw=(SOURCE/path).read_bytes()
        assert {"bytes":len(raw),"sha256":digest(raw)}==row,("source changed",path)
def load_defs(path,wanted,names,extra=None):
    raw=path.read_bytes();assert digest(raw)==wanted
    input_files[str(path)]=wanted
    tree=ast.parse(raw,filename=str(path))
    nodes=[node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name in names]
    assert sorted(node.name for node in nodes)==sorted(names)
    ns={"__name__":"__main__","sys":sys,"digest":digest,"weakref":weakref}
    if extra:ns.update(extra)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),ns)
    return ns
def fixture(name,trace):
    if name.startswith("late_integer"):
        if name=="late_integer_subclass_700":
            class Number(int):
                def __repr__(self):trace.append("forbidden int repr override");raise AssertionError("int repr override")
            value=Number(10**699)
        elif name=="late_integer_early_bits_1100":value=10**1099
        elif name=="late_integer_negative_700":value=-(10**699)
        else:value=10**699
        if name=="late_integer_key_700":
            class Mapping(dict):
                def items(self):trace.append("items");return [(value,0)]
            value=Mapping(physical=0)
        return original_defs["late"](value,trace)
    class BadItem:
        @property
        def __class__(self):trace.append("forbidden tuple type callback");raise AssertionError("tuple type callback")
        def __del__(self):trace.append("bad_item_del")
    class Pair(tuple):
        def __len__(self):trace.append("forbidden tuple len override");raise AssertionError("tuple len override")
    class Mapping(dict):
        def items(self):
            trace.append("items")
            if name=="items_non_tuple_none":return [None]
            if name=="items_non_tuple_list":return [["key",0]]
            if name=="items_one_tuple":return [("key",)]
            if name=="items_three_tuple":return [("key",0,1)]
            if name=="items_bad_destructor":return [BadItem()]
            if name=="items_tuple_subclass":return [Pair(("key",0))]
            if name=="items_tuple_container":return (("key",0),)
            if name=="items_generator_container":return iter((("key",0),))
            raise AssertionError(name)
    return original_defs["late"](Mapping(physical=0),trace)
def observe(call,name):
    trace=[]
    value=fixture(name,trace)
    outcome=original_defs["outcome"](call,value)
    value=None
    return {"outcome":outcome,"trace":trace}
report={"schema":"hia.normalization.v70.r7-late-error-original-observations.v1",
    "scope":"Fresh bounded observations on unchanged r7 source and actual machine images; no compilation or repair.",
    "full_owner_qualified":False,"physical_recursion_qualified":False,
    "observations":[],"differences":[],"failures":[],"new_compile_count":0}
input_files={};source_before=None;image_before=None
try:
    raw=(ORIGINAL/"RESULT.json").read_bytes()
    assert digest(raw)=="c1e551d57825926a826af70383af92849f59ab1e5e087ee70a2870c296e65f0b"
    prior=json.loads(raw)
    raw=(ORIGINAL/"SOURCE_IDENTITY.json").read_bytes()
    assert digest(raw)==prior["source_identity"]["sha256"]
    source_before=json.loads(raw);check(source_before)
    path=ORIGINAL/"native"/"manifest.json"
    manifest=json.loads(path.read_bytes())
    paths=[path]+[path.parent/row["image_path"] for row in manifest["images"].values()]
    paths += [path.parent/row["image_path"] for row in manifest["hosted_mechanisms"].values()]
    image_before={str(p):digest(p.read_bytes()) for p in paths}
    for key in list(os.environ):
        if key.startswith("HEPTA_HIA_"):del os.environ[key]
    sys.dont_write_bytecode=True;os.chdir(SOURCE);sys.path.insert(0,str(SOURCE))
    from hepta.hia_program import _decode
    from hepta.hia_program_normalization_native import installed_program_normalization
    owner=installed_program_normalization(path)
    original_defs=load_defs(ROOT/"helpers"/"cause_terminal_r4.py",
        "59a7476b576550737528b0d5d34d779971e4b43c3700406f91400e49dd4b698d",
        {"safe_value","error_state","outcome","late"})
    names=("late_integer_700","late_integer_negative_700","late_integer_early_bits_1100",
        "late_integer_subclass_700","late_integer_key_700","late_integer_disabled_limit",
        "items_non_tuple_none","items_non_tuple_list","items_one_tuple","items_three_tuple",
        "items_bad_destructor","items_tuple_subclass","items_tuple_container","items_generator_container")
    saved=sys.get_int_max_str_digits();enabled=gc.isenabled();gc.disable()
    try:
        for name in names:
            limit=0 if name=="late_integer_disabled_limit" else 640
            sys.set_int_max_str_digits(limit)
            original=observe(_decode,name)
            sys.set_int_max_str_digits(limit)
            with patch("json.dumps",side_effect=AssertionError("hosted full serializer entered")),\
                 patch("json.loads",side_effect=AssertionError("hosted full parser entered")):
                actual=observe(owner.normalize_program,name)
            row={"case":name,"original":original,"native":actual,"equal":original==actual}
            report["observations"].append(row)
            if not row["equal"]:report["differences"].append(name)
    finally:
        sys.set_int_max_str_digits(saved)
        if enabled:gc.enable()
    assert len(report["observations"])==14
    report["status"]="ORIGINAL_DIFFERENCES_CONFIRMED" if report["differences"] else "ALL_OBSERVATIONS_MATCH"
except BaseException:
    report["status"]="HARNESS_OR_CANDIDATE_FAILURE";report["failures"].append(traceback.format_exc())
finally:
    try:
        if source_before is not None:check(source_before);report["source_unchanged"]=True
        if image_before is not None:
            assert {p:digest(Path(p).read_bytes()) for p in image_before}==image_before
            report["images_unchanged"]=True
        for p,sha in input_files.items():assert digest(Path(p).read_bytes())==sha
        report["fixture_sources_unchanged"]=True
    except BaseException:
        report["status"]="HARNESS_OR_CANDIDATE_FAILURE";report["failures"].append(traceback.format_exc())
    report["image_inputs"]=image_before
    report["script_sha256"]=digest(Path(__file__).read_bytes())
    report["elapsed_ns"]=time.monotonic_ns()-started
    raw=encoded(report);put(CASE/"RESULT.json",raw)
    print(json.dumps({"status":report["status"],"result":str(CASE/"RESULT.json"),
        "bytes":len(raw),"sha256":digest(raw),"observations":len(report["observations"]),
        "matches":sum(row["equal"] for row in report["observations"]),
        "differences":report["differences"]},sort_keys=True))
if report["status"]!="ALL_OBSERVATIONS_MATCH":raise SystemExit(1)
