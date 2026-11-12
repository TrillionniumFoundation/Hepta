"""Read exact restored original candidate authors; zero generation or execution."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,os,sys,traceback
sys.dont_write_bytecode=True
COMMON=Path(os.environ["HIA_CI_COMMON"]).resolve();raw=COMMON.read_bytes()
assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
spec=importlib.util.spec_from_file_location("patch_originals_common",COMMON)
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
common.PINS[COMMON]=raw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
status="FAIL";out=None
details=dict(scope="COMPLETE_ORIGINAL_CANDIDATE_AUTHOR_READBACK_ONLY",
    generation=0,AST_checks=0,B3_compiles=0,VM_entries=0,native_entries=0,
    whole_stack_closed=False,original_failures_unchanged=True)
def identity(raw):
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),
        gitsha=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
try:
    context=common.prepare();workspace=Path(context["workspace"])
    out=common.BASE/"patch-original-source-readback";out.mkdir()
    relative=(
        "native-edit-candidate-next/development/core_patch_candidate_limit.authoring.py",
        "native-edit-candidate-next/development/agent_edit_apply_candidate_limit.authoring.py",
        "native-edit-candidate-next/development/source-r1.json")
    rows=[]
    for rel in relative:
        path=workspace/rel;raw=path.read_bytes();common.PINS[path.resolve()]=raw
        row=dict(relative_path=rel,mode=path.stat().st_mode&0o777,**identity(raw))
        target=out/"originals"/rel;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(row["mode"])
        assert target.read_bytes()==raw
        for offset in range(0,len(raw),12000):
            part=raw[offset:offset+12000]
            print("HIA_PATCH_ORIGINAL_SOURCE "+json.dumps(dict(**row,offset=offset,
                part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
        rows.append(row)
    assert rows[1]["gitsha"]=="a9d390e13f2d414aded2f25c8b4462382eec23ee"
    assert rows[2]["gitsha"]=="fec9eefec86b608c7ec35e805818940a5c8caab6"
    # Inventory is read-only discovery for the complete program child. It does
    # not infer semantics from filenames or execute any discovered author.
    inventory=[]
    for path in sorted(workspace.rglob("*.py")):
        rel=path.relative_to(workspace).as_posix()
        if "program" in path.name and ("admission" in path.name or "prefix" in path.name or "driver" in path.name):
            raw=path.read_bytes();common.PINS[path.resolve()]=raw
            inventory.append(dict(relative_path=rel,mode=path.stat().st_mode&0o777,**identity(raw)))
    (out/"program-author-inventory.json").write_text(json.dumps(inventory,sort_keys=True,indent=2)+"\n")
    details.update(originals=rows,program_author_inventory=inventory);status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc))
    common.OUTPUT.mkdir(parents=True,exist_ok=True)
    (common.OUTPUT/"reader-failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    print("HIA_PATCH_ORIGINAL_SOURCE_READBACK "+json.dumps(details,sort_keys=True),flush=True)
    common.finish("patch-original-source-reader",status,details,
        {"patch-originals":out} if out is not None else {})
if status!="PASS":raise SystemExit(1)
