"""Read the exact FOLLOW45 unixOpen failure; no HIA/VM/compiler/native execution."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,importlib.util,json,os,resource,signal,traceback
from pathlib import Path
HELPER="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/namespace-ci/issued-fs-follow42-readback/read_issued_fs_follow42.py"
HELPER_SHA="a2d0b36d9c739afc202785b2fc3acc488c55c126dac53b78e0a9f41c998b9866"
PIN=dict(artifact=13935987059,run=43201563676,job=131126031828,
 ZIP_bytes=58378569,ZIP_sha256="32be8415df27b414d445f9399449891cdfe4611794bca01a0002b99ffbdf6509",
 archive_bytes=5178304,archive_sha256="6a65af7281419e20edbba5f60ba21e1dcedaaf80c84ed65605ee6dd42dfffab9",
 index_bytes=15033,index_sha256="1a8db9bfeb5c5b9fc933b6e4c2232e58da8af0d621ef20bcb6d39482fc446764",
 members=47,raw_bytes=39092043)
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def alarm(*_):raise TimeoutError("FOLLOW45 exact original reader wall180")
 signal.signal(signal.SIGALRM,alarm);signal.alarm(180)
 repo=Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
 helper_path=repo/HELPER;helper_raw=helper_path.read_bytes()
 assert hashlib.sha256(helper_raw).hexdigest()==HELPER_SHA
 spec=importlib.util.spec_from_file_location("unixopen45_exact_reader_helpers",helper_path)
 helper=importlib.util.module_from_spec(spec);sys.modules[spec.name]=helper
 exec(compile(helper_raw,str(helper_path),"exec"),helper.__dict__)
 helper.PIN=PIN
 src=Path(os.environ["HIA_NAMESPACE_UNIXOPEN45_ORIGINALS"]).resolve(strict=True)
 out=Path(os.environ["HIA_NAMESPACE_UNIXOPEN45_READBACK_OUTPUT"]).absolute()
 out.mkdir(parents=True,exist_ok=False);payload=out/"payload";payload.mkdir()
 work=out.parent/(out.name+"-expanded-47");work.mkdir(exist_ok=False)
 report=dict(schema="hia.namespace.unixopen.follow45.original-readback.v1",
  status="INCOMPLETE",source=PIN,original_target_status="FAIL",
  B3_entries=0,VM_entries=0,native_entries=0,no_target_reexecution=True,
  ZIP_scope="actions/download-artifact transport; only inner archive and member bytes independently replayed",
  all_members_verified=False,raw_original_copies_complete=False,after_check_errors=[])
 originals=[];primary=None
 try:
  archive,ap=helper.locate(src,"evidence.tar.xz",PIN["archive_bytes"],PIN["archive_sha256"])
  index,ip=helper.locate(src,"evidence-members.json",PIN["index_bytes"],PIN["index_sha256"])
  originals.extend([(archive,ap),(index,ip),(helper_path,helper.pin(helper_path))])
  helper.copy(archive,payload/"original"/"evidence.tar.xz",ap)
  helper.copy(index,payload/"original"/"evidence-members.json",ip)
  report["raw_original_copies_complete"]=True
  helper.save(out/"summary.json",report)
  checked=helper.extract(archive,index,work)
  report["all_members_verified"]=True
  helper.save(payload/"all-47-members-readback.json",checked)
  exact=[row for row in checked if row["name"].endswith("/unixopen-native-parent-r1/build/summary.json")]
  assert len(exact)==1,[r["name"] for r in checked]
  row=exact[0];summary=work/row["name"];raw=summary.read_bytes()
  assert len(raw)==4954 and hashlib.sha256(raw).hexdigest()=="06a811f886313934d0f0a5cac9728707dda2772adaa273562d54a81e004b46cb"
  assert helper.git(raw)=="4300ac70db9b724d811e637e570e7cc267dd8697"
  helper.copy(summary,payload/"exports"/"original-build-summary.json",helper.pin(summary))
  report["original_complete_summary"]=dict(member=row["name"],**helper.pin(summary))
  # Emit exact original bytes before interpreting any semantic report keys.
  print("HIA_UNIXOPEN45_RAW_SUMMARY "+json.dumps(dict(bytes=len(raw),
   sha256=hashlib.sha256(raw).hexdigest(),git=helper.git(raw),
   base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
  selected=[]
  for item in checked:
   name=item["name"]
   if ("unixopen-parent-fresh-HIA-B3-and-original-six-body-C" in name
       and (name.endswith(".json") or name.endswith(".log"))):
    path=work/name;target=payload/"exports"/name
    helper.copy(path,target,helper.pin(path));selected.append(dict(member=name,**helper.pin(path)))
    if path.name in ("stderr.log","stdout.log"):
     data=path.read_bytes()
     expected_streams={"stdout.log":(4557,"495090faceba9e800b7abdf7b95321eaff60e54bf75d117f790c09f5f2a37db6"),
      "stderr.log":(1668,"909c84247e193f967f3bc6afe40a3633b32dccbf58c1dbdd279910a8fb0f0237")}
     assert (len(data),hashlib.sha256(data).hexdigest())==expected_streams[path.name]
     print("HIA_UNIXOPEN45_RAW_STREAM "+json.dumps(dict(member=name,
      bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
      git=helper.git(data),base64=base64.b64encode(data).decode("ascii")),sort_keys=True),flush=True)
  report["original_build_process_and_streams"]=selected
  body=json.loads(raw)
  assert body["status"]=="FAIL" and body["error_class"]=="ValueError" and body["error"]=="Break()"
  assert body["mode"]=="build" and body["source_pins_unchanged"] is True
  for key in ("VM_entries","native_entries","C_cases","protocol_controls","fresh_B3_compiles"):
   assert body[key]==0,(key,body[key])
  assert body["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
  report["original_complete_summary_json"]=body
  report["status"]="PASS_READBACK_ONLY"
 except BaseException as error:
  primary=error;report.update(status="FAIL_READBACK",error=repr(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  for path,before in originals:
   try:assert helper.pin(path)==before
   except BaseException as error:
    report["after_check_errors"].append(dict(path=str(path),error=repr(error)))
  if report["after_check_errors"]:report["status"]="FAIL_READBACK"
  report["all_inputs_unchanged"]=bool(originals) and not report["after_check_errors"]
  helper.save(out/"summary.json",report)
  helper.save(payload/"readback-summary.json",report)
  try:
   seal=helper.seal(out);helper.save(out/"custody.json",seal)
  except BaseException as error:
   report["seal_error"]=repr(error);report["status"]="FAIL_READBACK"
   helper.save(out/"summary.json",report)
   if primary is not None:primary.add_note("seal: "+repr(error))
   else:traceback.print_exc()
  print("HIA_UNIXOPEN45_ORIGINAL_READBACK "+json.dumps(report,sort_keys=True),flush=True)
 return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
