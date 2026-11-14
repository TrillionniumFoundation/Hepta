from pathlib import Path
import hashlib,json,stat,os
B=Path("/tmp/hia-u32-r8-post-reset-r3-dda7")
OUT=Path("/tmp/hia-progress-v148-20261114-dda7")
SURFACE=Path("/tmp/hia-r8-r3-surface-static-review-r3-dda7")
def pin(b):return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def fixed(p,identity=None,expected=None):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 raw=p.read_bytes();assert seven(p.lstat())==seven(s)
 actual={**pin(raw),"mode":stat.S_IMODE(s.st_mode),"git_mode":"100755" if s.st_mode&0o111 else "100644"}
 if identity:assert all(actual[k]==v for k,v in identity.items()),str(p)
 if expected is not None:assert seven(s)==expected,str(p)
 return raw
hraw=fixed(B/"HANDOFF.json");assert pin(hraw)["git_blob"]=="83be8e3d15f59b90cf12b0f602b39227b6251190"
handoff=json.loads(hraw)
for row in handoff["files"].values():fixed(row["path"],{k:row[k] for k in ("bytes","sha256","git_blob","mode")})
lraw=fixed(B/"PREPARATION-LAUNCH.json");assert pin(lraw)["git_blob"]=="665a8cda8c4b3eb9e20ae936aa7f44953b6eaf28"
launch=json.loads(lraw);prep=json.loads(fixed(B/"PREPARATION-PLAN.json"));assert pin(fixed(B/"prepare_input_view.py"))["git_blob"]=="cf49f169f344e630b76e50cba67094833bf84c5e"
for group in ("controlled_files","authority_files"):
 for d in prep[group].values():fixed(d["path"],d["identity"],d["new_seven_stats"])
for name in ("run_controls.py","r8_common.py","restore_oracles.py","r8_private_reference.py"):
 assert fixed(B/name)==fixed(Path("/tmp/hia-r8-source-recovery-20261114-r1/frozen-author-r2")/name)
sraw=fixed(SURFACE/"RESULT.json");s=json.loads(sraw);assert s["status"]=="PASS_STATIC_REVIEW_ONLY" and s["failures"]==[]
assert s["binder"]==s["products"]==s["project_imports"]==s["source_or_payload_copies"]==0
assert all(x["status"]=="PASS" for x in s["checks"])
fixed(SURFACE/"DETAILS.json",s["details"])
assert all(not Path(p).exists() for p in prep["must_be_absent"])
v=os.statvfs("/dev/shm");block=v.f_frsize
required=sum((r["identity"]["bytes"]+block-1)//block*block for r in prep["copy_files"]+prep["future_oracle_files"])+prep["product_floor_bytes"]+prep["reserve_bytes"]+prep["metadata_allowance_bytes"]
assert required==4076843008 and v.f_bavail*block>=required and not v.f_flag&getattr(os,"ST_NOEXEC",8)
report={"schema":"hia.root.r8.r3.author-review.v1","status":"PASS_R3_AUTHORING_AND_MAPPING_ONLY","root_review":["Complete preparer code read; writes confined to new input view and records; no project import or subprocess.","Three complete launch descriptors read; original product and restore owner budgets remain separate.","All handoff files and 70 controls/15 authorities freshly read by Root with exact pins and new seven stats.","Four original runner/common/restore/private files compared byte-for-byte by Root.","Independent Surface full forward/inverse and strict whitelist review accepted; complete DETAILS bytes matched."],"handoff":pin(hraw),"launch":pin(lraw),"surface_result":pin(sraw),"surface_details":s["details"],"surface_validation_checks":s["checks"],"root_full_GET_R3_recipe":"36766cd7f37f741280990d5b0d58b5c0176c5155","root_full_GET_R3_leaves":25,"free_bytes":v.f_bavail*block,"required_bytes":required,"all_four_future_roots_absent":True,"binder":0,"products":0,"whole_native":False}
raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
rpath=OUT/"R8-ROOT-AUTHOR-REVIEW.json"
with rpath.open("xb") as f:f.write(raw)
auth={"schema":"hia.root.r8.input-preparation.authorization.v1","authorized":True,"scope":"R8_808_INPUT_VIEW_ONLY_NO_ORACLE_OR_PRODUCTS","maximum_attempts":1,"outer_seconds":180,"cleanup_seconds":3,"root_review":{"path":str(rpath),"identity":pin(raw)},"launch_identity":pin(lraw),"products_authorized":0,"oracle_owner_authorized":False,"user_goal_authorizes_reversible_implementation_and_verification":True}
with (OUT/"R8-PREPARATION-AUTHORIZATION.json").open("x") as f:f.write(json.dumps(auth,sort_keys=True,indent=2)+"\n")
print(json.dumps({"review":pin(raw),"authorization":pin((OUT/"R8-PREPARATION-AUTHORIZATION.json").read_bytes()),"status":report["status"],"copy_executions":0},sort_keys=True))
