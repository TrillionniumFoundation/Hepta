"""Materialize and statically verify one exact new custody control namespace.
No controls, tests, project imports, network calls or owners are executed.
"""
from pathlib import Path
import ast, difflib, hashlib, json, os, stat
ROOT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-ci-a2-diagnostics-only-r1")
BUNDLE = ROOT / "STATIC-INPUTS.bundle.json"
EXPECTED = "eb6c778ed5d41af72dbf7303066edb2a0d50a5ed8d8112c92980a285d9562a93"
raw = BUNDLE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED
bundle = json.loads(raw)
assert bundle["root"] == str(ROOT)
pins = []
for row in bundle["files"]:
    p = ROOT / row["relative"]
    assert not p.is_absolute() or p.is_relative_to(ROOT)
    assert ".." not in p.relative_to(ROOT).parts
    p.parent.mkdir(parents=True, exist_ok=True)
    assert not any(x.is_symlink() for x in (p.parent, *p.parents))
    data = row["raw"].encode()
    assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
    assert hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest() == row["git_blob_sha1"]
    fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd,"wb") as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    assert p.read_bytes() == data
    pins.append({k:row[k] for k in ("relative","bytes","sha256","git_blob_sha1","mode")})
changes = json.loads((ROOT/"reference/MECHANICAL-REPLACEMENTS.json").read_bytes())
checks = []
diff = []
for name, replacements in changes.items():
    old=(ROOT/"reference"/("original-r2-"+name)).read_text()
    new=(ROOT/name).read_text()
    if name != "workflow-template.yml":
        inverse=new
        for a,b in reversed(replacements):
            assert inverse.count(b)==1
            inverse=inverse.replace(b,a)
        assert inverse==old
    else:
        import re
        mapping={b:a for a,b in replacements}
        pattern="|".join(re.escape(k) for k in sorted(mapping,key=len,reverse=True))
        assert re.sub(pattern,lambda m:mapping[m.group()],new)==old
    if name.endswith(".py"):
        ast.parse(old,filename="reference/"+name)
        ast.parse(new,filename=name)
    diff.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),"old/"+name,"new/"+name))
    checks.append({"file":name,"whole_file_exact_inverse":True})
for name in ("guardian.py","process_owner_impl.py","original_receiver.py","diagnostics.py"):
    ast.parse((ROOT/name).read_text(),filename=name)
new_policy=json.loads((ROOT/"policy.json").read_bytes())
old_policy=json.loads((ROOT/"reference/original-r2-policy.json").read_bytes())
assert new_policy["limits"]==old_policy["limits"]
assert new_policy["diagnostics"]==old_policy["diagnostics"]
assert new_policy["parts"]==[] and new_policy["partition_files_created"] is False
assert new_policy["artifact"]["run_attempt"]==2
assert new_policy["source"]["cold_source_count"]==892
source=(ROOT/"reference/CURRENT-COLD-SOURCE-MANIFEST.json").read_bytes()
assert len(json.loads(source))==892 and hashlib.sha256(source).hexdigest()==new_policy["source"]["source_manifest_canonical_sha256"]
assert json.loads(source)["docs/HIA_SELFHOST_CORE_SUPPORT.json"]==new_policy["source"]["contract_sha256"]
assert "os.environ.get('GITHUB_RUN_ATTEMPT') == '1'" in (ROOT/"controller.py").read_text()
assert "github.run_attempt == '1'" in (ROOT/"workflow-template.yml").read_text()
assert (ROOT/"workflow-template.yml").read_text().count("CONTROL_COMMIT_PLACEHOLDER")==4
assert (ROOT/"workflow-template.yml").read_text().count("POLICY_SHA256_PLACEHOLDER")==3
assert (ROOT/"workflow-template.yml").read_text().count("actions/upload-artifact@")==1
request=json.loads((ROOT/"REQUEST.json").read_bytes())
assert request["policy"]=={"bytes":len((ROOT/"policy.json").read_bytes()),"sha256":hashlib.sha256((ROOT/"policy.json").read_bytes()).hexdigest()}
assert request["control_files"]==new_policy["control_files"]
for name,pin in new_policy["control_files"].items():
    data=(ROOT/name).read_bytes()
    assert len(data)==pin["bytes"] and hashlib.sha256(data).hexdigest()==pin["sha256"]
def recursive_delta(a,b,p=""):
    if type(a) is not type(b): return [{"path":p,"before":a,"after":b}]
    if isinstance(a,dict):
        out=[]
        for k in sorted(set(a)|set(b)):
            if k not in a or k not in b: out.append({"path":p+"/"+k,"before":a.get(k),"after":b.get(k)})
            else: out.extend(recursive_delta(a[k],b[k],p+"/"+k))
        return out
    if a!=b: return [{"path":p,"before":a,"after":b}]
    return []
policy_delta=recursive_delta(old_policy,new_policy)
diff.extend(difflib.unified_diff((ROOT/"reference/original-r2-policy.json").read_text().splitlines(True),(ROOT/"policy.json").read_text().splitlines(True),"old/policy.json","new/policy.json"))
def create(name,data):
    if not isinstance(data,bytes): data=(json.dumps(data,indent=2,sort_keys=True)+"\n").encode()
    p=ROOT/name
    with p.open("xb") as out: out.write(data);out.flush();os.fsync(out.fileno())
    assert p.read_bytes()==data
    return {"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"git_blob_sha1":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()}
patch=create("CONTROL-DELTA.patch","".join(diff).encode())
pdelta=create("POLICY-DELTA.json",policy_delta)
report={"schema":"hia.pc-attempt2-diagnostics-static-authoring.v1","status":"STATIC_ONLY_FULL_BYTES_AND_AST_PASS","files":pins,"whole_file_inverse":checks,"unchanged_algorithms":["guardian.py","process_owner_impl.py","original_receiver.py","diagnostics.py"],"original_transport_owner":[900,3],"worker_seconds":720,"current_original_attempt":2,"new_recovery_attempt":1,"current_cold_sources":892,"declared_sources_without_contract":891,"current_population_unknown_until_ZIP_read":True,"product_or_native_or_control_test_executions":0,"network_calls":0,"patch":patch,"policy_delta":pdelta,"new_protocol_NOT_ACTUAL":True}
pin=create("STATIC-READBACK.json",report)
print(json.dumps({"status":report["status"],"files":len(pins),"bytes":sum(p["bytes"] for p in pins),"report":pin,"patch":patch,"policy_delta_leaves":len(policy_delta)}))
