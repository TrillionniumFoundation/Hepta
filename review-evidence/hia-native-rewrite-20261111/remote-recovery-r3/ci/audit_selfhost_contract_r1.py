"""Read-only diagnosis of the current bounded Selfhost-Core source contract.
Successful completion means the diagnostic evidence was captured, not that the
contract or cold qualification passed. The checked-in contract is never changed.
"""
import argparse,copy,json,os,stat,sys,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path.cwd().resolve()
sys.path.insert(0,str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH,support_contract
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def identity(raw):return dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),git_blob=gitsha(raw))
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
OUT=a.output.resolve();assert not OUT.exists();OUT.mkdir(parents=True)
pins={};summary=dict(schema="hia-selfhost-contract-readonly-diagnosis-v1",
 status="DIAGNOSTIC_INCOMPLETE",whole_stack_closed=False,cold_qualification_executed=False,
 checked_in_contract_updated=False,source_commit=os.environ.get("GITHUB_SHA"),python=sys.version)
try:
    declared_path=ROOT/CONTRACT_PATH
    original=declared_path.read_bytes();pins[declared_path]=original
    expected=support_contract(ROOT)
    raw=(json.dumps(expected,indent=2,sort_keys=True)+"\n").encode()
    declared=json.loads(original)
    old=declared["source_identity"]["files"];new=expected["source_identity"]["files"]
    different=[dict(path=name,declared_sha256=old.get(name),actual_sha256=new.get(name))
      for name in sorted(set(old)|set(new)) if old.get(name)!=new.get(name)]
    declared_structure=copy.deepcopy(declared);actual_structure=copy.deepcopy(expected)
    del declared_structure["source_identity"]["files"]
    del actual_structure["source_identity"]["files"]
    inventory=[]
    for name,digest in sorted(new.items()):
        path=ROOT/name
        assert path.is_relative_to(ROOT) and not path.is_symlink() and path.is_file(),name
        content=path.read_bytes();pins[path]=content
        assert sha256(content).hexdigest()==digest
        inventory.append(dict(path=name,mode=stat.S_IMODE(path.stat().st_mode),**identity(content)))
    (OUT/"original-contract.json").write_bytes(original)
    (OUT/"expected-current-contract.json").write_bytes(raw)
    save(OUT/"source-inventory.json",inventory)
    summary.update(status="DIAGNOSTIC_CAPTURED",
      source_contract_equal=declared==expected,
      declaration_except_source_identity_equal=declared_structure==actual_structure,
      differing_source_files=different,source_files=len(inventory),
      original_contract=identity(original),expected_current_contract=identity(raw))
    print("HIA_CONTRACT_DIAGNOSIS "+json.dumps(summary,sort_keys=True),flush=True)
    print("HIA_EXPECTED_CONTRACT "+json.dumps(dict(**identity(raw),text=raw.decode()),sort_keys=True),flush=True)
except BaseException as e:
    summary.update(status="DIAGNOSTIC_FAILED",error_class=type(e).__name__,error=str(e))
    (OUT/"failure.txt").write_text(traceback.format_exc())
    traceback.print_exc()
finally:
    unchanged=all(p.read_bytes()==raw for p,raw in pins.items())
    summary["all_original_source_bytes_unchanged"]=unchanged
    if not unchanged:summary["status"]="DIAGNOSTIC_FAILED"
    save(OUT/"summary.json",summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary["status"]!="DIAGNOSTIC_CAPTURED":raise SystemExit(1)
