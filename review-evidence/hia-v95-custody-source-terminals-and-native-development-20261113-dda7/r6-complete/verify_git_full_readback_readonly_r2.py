"""Read-only successor to the preserved R6 outer directory-set assertion failure."""
from pathlib import Path, PurePosixPath
import hashlib,json,os,stat,time
ROOT=Path(__file__).resolve().parent
TARGET=ROOT/"git-full-readback-restore-r1/restored"
OUT=ROOT/"git-full-readback-readonly-r2"
def identity(b):
 return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
def verify(b,pin):
 assert identity(b)=={k:pin[k] for k in ("bytes","sha256","git_blob")}
def write(name,obj):
 with (OUT/name).open("x") as f:json.dump(obj,f,sort_keys=True,indent=2);f.write("\n")
def main():
 OUT.mkdir()
 started=time.monotonic_ns()
 transport=json.loads((ROOT/"TRANSPORT.json").read_bytes())
 manifest_raw=(ROOT/"MANIFEST.json").read_bytes();verify(manifest_raw,transport["manifest"])
 manifest=json.loads(manifest_raw)
 prior_stdout=(ROOT/"git-full-readback-restore-r1/stdout").read_bytes()
 prior_child_stderr=(ROOT/"git-full-readback-restore-r1/stderr").read_bytes()
 prior_outer_stderr=(ROOT/"root-full-get-restore.stderr.log").read_bytes()
 observed=json.loads(prior_stdout)
 assert not prior_child_stderr
 assert observed["status"]=="RESTORED_FULLY"
 assert observed["logical_files"]==10060 and observed["logical_bytes"]==787835354
 assert observed["directories"]==1570 and observed["all_bytes_sha256_git_and_modes_verified"] is True
 assert observed["complete_gzip_crc_isize"] is True
 assert observed["archive_sha256"]==transport["archive"]["sha256"]
 assert b"assert actual_dirs==set(manifest['directories'])" in prior_outer_stderr
 assert b"AssertionError" in prior_outer_stderr
 assert not (ROOT/"git-full-readback-restore-r1/REPORT.json").exists()
 write("REQUEST.json",{"schema":"hia.r6.readonly-successor-request.v1","original_outer_failure_preserved":True,
  "original_decoder_stdout":identity(prior_stdout),"original_outer_stderr":identity(prior_outer_stderr),
  "target":str(TARGET),"product_execution":False,"git_mutations":0,"restore_replayed":False})
 by={row["file"]:row for row in transport["chunks"]}
 assert len(by)==434
 for file,row in by.items():
  receipt=json.loads((ROOT/"GIT-CUSTODY"/(file+".receipt.json")).read_bytes())
  assert receipt["full_get_verified"] is True
  for k in ("bytes","sha256","git_blob"):assert receipt[k]==row[k]
  for k,original in (("full_get_bytes","bytes"),("full_get_sha256","sha256"),("full_get_blob","git_blob")):assert receipt[k]==row[original]
  verify((ROOT/"GIT-CUSTODY/readback"/file).read_bytes(),row)
 expected_members=set(manifest["logical_files"])
 expected_recorded_dirs=set(manifest["directories"])
 required_parents=set()
 for name in expected_members|expected_recorded_dirs:
  for parent in PurePosixPath(name).parents:
   if str(parent)!=".":required_parents.add(str(parent))
 synthetic=required_parents-expected_recorded_dirs
 assert synthetic=={"independent-source","product-core"}
 actual_dirs={};actual_members=set()
 for p in TARGET.rglob("*"):
  name=p.relative_to(TARGET).as_posix();info=p.lstat()
  if stat.S_ISDIR(info.st_mode):actual_dirs[name]=stat.S_IMODE(info.st_mode)
  else:actual_members.add(name)
 assert set(actual_dirs)==expected_recorded_dirs|required_parents
 assert actual_members==expected_members and len(actual_members)==10060
 total=0;kinds={}
 for name,row in manifest["logical_files"].items():
  p=TARGET/name;info=p.lstat()
  assert stat.S_IMODE(info.st_mode)==int(row["mode"],8),name
  if row["kind"]=="file":
   assert stat.S_ISREG(info.st_mode);raw=p.read_bytes()
  elif row["kind"]=="symlink":
   assert stat.S_ISLNK(info.st_mode);raw=os.fsencode(os.readlink(p))
  else:raise AssertionError((name,row["kind"]))
  verify(raw,row);total+=len(raw);kinds[row["kind"]]=kinds.get(row["kind"],0)+1
 assert total==manifest["logical_bytes"]==787835354
 for name,row in manifest["directories"].items():
  assert actual_dirs[name]==int(row["mode"],8),name
 assert len(expected_recorded_dirs)==1570 and len(actual_dirs)==1572
 report={"schema":"hepta.custody.full-get-readonly-successor.v2",
  "status":"ALL_FIXED_R6_LOGICAL_GIT_GET_ORIGINALS_RESTORED",
  "original_decoder_status":"RESTORED_FULLY","original_outer_wrapper_status":"FAIL",
  "original_outer_failure":"Exact directory-set assertion omitted two required synthetic mount parents.",
  "original_outer_failure_bytes":identity(prior_outer_stderr),
  "original_decoder_stdout":identity(prior_stdout),"original_decoder_stderr":identity(prior_child_stderr),
  "original_manifest":identity(manifest_raw),"transport":identity((ROOT/"TRANSPORT.json").read_bytes()),
  "git_full_readback_chunks":434,"all_wrapper_bytes_sha256_git_checked_again":True,
  "logical_files":len(expected_members),"logical_bytes":total,"logical_kinds":kinds,
  "recorded_original_directory_count":1570,"all_recorded_original_directory_modes_verified":True,
  "synthetic_parent_count":2,"synthetic_parent_modes_observed":{p:oct(actual_dirs[p]) for p in sorted(synthetic)},
  "synthetic_parent_original_modes_claimed":False,"actual_total_directories":len(actual_dirs),
  "exact_logical_member_and_required_directory_sets_verified":True,
  "all_logical_file_symlink_bytes_sha256_git_modes_verified_again":True,
  "complete_gzip_crc_isize_checked_by_original_decoder":True,
  "archive":transport["archive"],"outer_zip_original_bytes_retained_not_in_this_archive":transport["outer_zip_original_bytes_retained_not_in_archive"],
  "source_tree":"78155bac080168d2946116ede1607e48b221ec1b",
  "readonly_successor_elapsed_ns":time.monotonic_ns()-started,"restored_root":str(TARGET),
  "restore_replayed":False,"source_modified":False,"new_product_execution":False,"extra_git_posts":0,"whole_native":False}
 write("REPORT.json",report)
 print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
