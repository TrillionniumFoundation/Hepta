"""Create a fresh private final-v66 controller and exec the reviewed guardian."""
from hashlib import sha256
import json,os,stat,sys
from pathlib import Path
os.umask(0o077)
payload=json.loads(sys.stdin.read())
root=Path("/home/qian-qi/he26v66r2")
control=root/"control";guard=root/"guard"
python=Path("/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python")
SOURCE_COUNT=0  # Final published source count, never a runtime override.
assert SOURCE_COUNT>634
assert len(payload["head"])==40 and all(c in "0123456789abcdef" for c in payload["head"])
assert len(payload["tree"])==40 and all(c in "0123456789abcdef" for c in payload["tree"])
assert payload["head"]=="__FROZEN_HEAD_PENDING__"
assert payload["tree"]=="__FROZEN_TREE_PENDING__"
assert not any(p.is_symlink() for p in (root,*root.parents))
assert not os.path.lexists(root)
capacity=os.statvfs(root.parent)
assert capacity.f_bavail*capacity.f_frsize >= 8 << 30
assert capacity.f_favail >= 100000
assert sha256(python.read_bytes()).hexdigest()=="b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
python_report=Path("/home/qian-qi/hia-e26e-python314-linux-completion-r2/python-linux-preparation.json")
python_guard=Path("/home/qian-qi/hia-e26e-python314-linux-completion-r2/guard/guardian.json")
assert sha256(python_report.read_bytes()).hexdigest()=="f834e072227ed59f06d347772b8db126c1910c574e660d66f9d15c1c1ec43967"
assert sha256(python_guard.read_bytes()).hexdigest()=="f4115e59f8a6eb22db8a002960fbca83e248e071e5694d89e93371b2262b036d"
ORIGINAL_PINS={
 "/home/qian-qi/he26v65r2/q/QUALIFICATION.json":"d91d279d192a9fe6b6a7521d8732197bdc37f4af3a03a694cfccb15929748b60",
 "/home/qian-qi/he26v65r2/q/cold.json":"938b9331e28e53442a21796acb319f3c9683fc26748cad49893b56873bf02ad4",
 "/home/qian-qi/he26v65r2/q/source-tests.json":"a2a84183bbca9df57ee352524e874420c446cb472bba34a5abd04551556593de",
 "/home/qian-qi/he26v65r2/guard/guardian.json":"ae721abf9b428acedb43fe99d5b072fed1de3299fd331b457410fdb5858519f1",
 "/home/qian-qi/he26v66r1/guard/guardian.json":"c843ea8a9c841ebc0d9fa3102056dc061709a1dd9ae81282f54116b810303077",
 "/home/qian-qi/hia-native-closure-evidence/4161e8d12d87906fde144f039da07908ad52d98a/desktop-full-hold-r2-preservation-r3/PRESERVATION.json":"6edd6d762f9ca2f95c1b3c0b40d1cd543c83e030fa0ecba1a72a2c26507644de",
}
for name,expected in ORIGINAL_PINS.items():
 assert sha256(Path(name).read_bytes()).hexdigest()==expected
root.mkdir(mode=0o700);control.mkdir(mode=0o700);guard.mkdir(mode=0o700)
def create(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as stream:
  stream.write(raw);stream.flush();os.fsync(stream.fileno())
identities={str(python):"b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493",
 str(python_report):"f834e072227ed59f06d347772b8db126c1910c574e660d66f9d15c1c1ec43967",str(python_guard):"f4115e59f8a6eb22db8a002960fbca83e248e071e5694d89e93371b2262b036d"}
identities.update(ORIGINAL_PINS)
for name,item in payload["files"].items():
 assert Path(name).name==name and name not in (".","..")
 raw=item["source"].encode()
 assert sha256(raw).hexdigest()==item["sha256"],name
 path=control/name;create(path,raw)
 assert path.read_bytes()==raw
 identities[str(path)]=item["sha256"]
config={"schema":"hia-external-guardian-request.v1","controller_seconds":10800,
 "command":[str(python),"-B",str(control/"desktop_v66r2_fetch_prepare_full.py")],
 "cwd":str(root),"source_identities":identities,
 "expected_qualification":{"path":str(root/"q/QUALIFICATION.json"),
   "head":payload["head"],"tree":payload["tree"],"cold_source_count":SOURCE_COUNT+1,
   "contract_sha256":"__FROZEN_CONTRACT_PENDING__"}}
raw=(json.dumps(config,indent=2,sort_keys=True)+"\n").encode()
create(guard/"request.json",raw)
create(root/"launch-intent.json",(json.dumps({"schema":"hia.desktop-v66-launch-intent.v1",
 "head":payload["head"],"tree":payload["tree"],"stable_key":payload["stable_key"],
 "raw_source_identity_checks_required":True,"full_execution_requested":True,
 "original_cold_180_seconds_unchanged":True,"whole_native_delivery_qualified":False,
 "control_files":{name:item["sha256"] for name,item in payload["files"].items()}},
 indent=2,sort_keys=True)+"\n").encode())
for directory in (control,guard,root,root.parent):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
print(json.dumps({"stage":"EXACT_V66_FULL_GUARDIAN_LAUNCH","head":payload["head"],
 "root":str(root),"guard":str(guard),"controller_seconds":10800}),flush=True)
os.execv(sys.executable,[sys.executable,"-B",str(control/"guardian.py"),
 "--config",str(guard/"request.json"),"--config-sha256",sha256(raw).hexdigest(),
 "--implementation",str(control/"process_owner_impl.py")])
