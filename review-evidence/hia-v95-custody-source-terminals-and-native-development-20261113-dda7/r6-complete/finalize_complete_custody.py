"""Freeze complete R6 CAS transport provenance and prepare an exact mount inventory."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
ROOT=Path(__file__).resolve().parent
def pin(raw):
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def write(name,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
 with (ROOT/name).open("xb") as f:f.write(raw)
 return {"file":name,"local_file":str(ROOT/name),**pin(raw)}
def main():
 original=json.loads((ROOT/"PUBLISH-LIST.json").read_bytes())
 transport=json.loads((ROOT/"TRANSPORT.json").read_bytes())
 assert len(original)==467 and len(transport["chunks"])==434
 all_receipts={}
 for p in (ROOT/"GIT-CUSTODY").rglob("*.receipt.json"):
  rel=p.relative_to(ROOT/"GIT-CUSTODY")
  if any(x in ("readback","staging") for x in rel.parts):continue
  value=json.loads(p.read_bytes());name=value["file"]
  assert name not in all_receipts and value["full_get_verified"] is True
  all_receipts[name]=value
 for row in original:
  receipt=all_receipts[row["file"]]
  for k in ("bytes","sha256","git_blob"):assert receipt[k]==row[k]
  assert pin((ROOT/"GIT-CUSTODY/readback"/row["file"]).read_bytes())=={k:row[k] for k in ("bytes","sha256","git_blob")}
 assert all(row["file"] in all_receipts for row in transport["chunks"])
 proof_path="git-full-readback-readonly-r2/REPORT.json"
 proof=json.loads((ROOT/proof_path).read_bytes())
 assert proof["status"]=="ALL_FIXED_R6_LOGICAL_GIT_GET_ORIGINALS_RESTORED"
 assert proof["git_full_readback_chunks"]==434 and proof["logical_files"]==10060
 original_names={row["file"] for row in original}
 excluded_large={"COMPLETE.tar.gz","MANIFEST.json","METADATA-CAPSULE.json","INPUTS-FROZEN.json"}
 selected=[]
 for p in ROOT.iterdir():
  if p.is_file() and p.name not in original_names and p.name not in excluded_large and not p.name.startswith("FINAL-"):
   selected.append(p)
 for p in (ROOT/"GIT-CUSTODY").rglob("*"):
  if p.is_file() and not any(x in ("readback","staging") for x in p.relative_to(ROOT/"GIT-CUSTODY").parts):
   selected.append(p)
 for directory in ("git-full-readback-restore-r1","git-full-readback-readonly-r2"):
  for p in (ROOT/directory).iterdir():
   if p.is_file():selected.append(p)
 records={}
 for p in sorted(set(selected)):
  assert not p.is_symlink()
  raw=p.read_bytes();name=p.relative_to(ROOT).as_posix()
  records[name]={**pin(raw),"mode":format(stat.S_IMODE(p.stat().st_mode),"04o"),"text":raw.decode("utf-8")}
 payload={"schema":"hepta.r6.all-completed-cas-provenance.v1","files":records,
  "records":len(records),"whole_native":False,"snapshot_cut":"after complete 434-chunk and original metadata readback plus read-only successor; before publishing this final capsule",
  "excluded_payload_readbacks":"All 467 original payload objects remain separate Git blobs; not duplicated in this provenance capsule.",
  "original_large_metadata_custody":"MANIFEST.json and INPUTS-FROZEN.json are preserved by the verified original archive and exact metadata fragment mechanism.",
  "transport_gaps_retained":"The earlier original first GET error body for part 091 was not recoverable; its retained summary and successor readback remain. No reconstruction is claimed."}
 raw=(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode()
 compressed=zlib.compress(raw,9)
 capsule={"schema":"hia.lossless-zlib-utf8-record-capsule.v1","decoded":pin(raw),"records":len(records),
  "encoding":"base64(zlib(exact UTF-8 JSON bytes))","payload":base64.b64encode(compressed).decode(),"whole_native":False}
 capsule_pin=write("FINAL-TRANSPORT-CAPSULE.json",capsule)
 assert zlib.decompress(base64.b64decode(capsule["payload"],validate=True))==raw
 index={"schema":"hepta.r6.complete-original-git-custody-index.v1",
  "status":"ALL_434_CHUNKS_AND_33_ORIGINAL_METADATA_OBJECTS_FULL_GET_AND_LOGICAL_RESTORE_COMPLETE",
  "original_payload_entries":original,"original_payload_count":len(original),"raw_chunk_wrappers":434,"original_metadata_entries":33,
  "all_original_payload_receipts":{row["file"]:all_receipts[row["file"]] for row in original},
  "additional_completed_transport_receipts":{k:v for k,v in all_receipts.items() if k not in original_names},
  "complete_transport_provenance":capsule_pin,
  "original_gzip":transport["archive"],"archive_recoverable_via_immutable_utf8_wrappers":True,
  "raw_binary_archive_git_blob_uploaded":False,
  "logical_readonly_restore_report":{"file":proof_path,**pin((ROOT/proof_path).read_bytes())},
  "logical_files":10060,"logical_bytes":787835354,"recorded_directory_count":1570,
  "synthetic_required_mount_parents":["independent-source","product-core"],"synthetic_original_modes_claimed":False,
  "original_decoder_success_retained":True,"original_outer_directory_assertion_failure_retained":True,
  "readonly_successor_does_not_overwrite_original_failure":True,
  "part331_unknown_then404_then_exact_retry_preserved":True,
  "parts340_341_original_post_ack_local_persistence_disconnect_then_readonly_recovery_preserved":True,
  "first_part091_get_error_body_unavailable_gap_preserved":True,
  "outer_zip_wrapper_bytes_not_in_this_archive":transport["outer_zip_original_bytes_retained_not_in_archive"],
  "source_tree":"78155bac080168d2946116ede1607e48b221ec1b",
  "new_product_execution":False,"default_changed":False,"product_ref_changed":False,"whole_native":False}
 index_pin=write("FINAL-INDEX.json",index)
 additions=json.loads((ROOT/"FINAL-SUCCESSOR-FILE-PINS.json").read_bytes())
 for name in ("PUBLICATION-HELPER-R3.js","RECOVER-INCOMPLETE-UPLOAD-R2.js","PUBLICATION-TWO-CHUNK-SCHEDULER.js","finalize_complete_custody.py","FINAL-SUCCESSOR-FILE-PINS.json"):
  raw=(ROOT/name).read_bytes();additions.append({"file":name,"local_file":str(ROOT/name),**pin(raw)})
 rows={row["file"]:row for row in [*original,*additions,capsule_pin,index_pin]}
 assert len(rows)==len(original)+len(additions)+2
 publish=write("FINAL-PUBLISH-LIST.json",list(rows.values()))
 missing=[row for row in rows.values() if row["file"] not in all_receipts]
 print(json.dumps({"status":index["status"],"all_receipts":len(all_receipts),"provenance_records":len(records),
  "capsule":capsule_pin,"index":index_pin,"publish":publish,"final_mount_entry_count":len(rows),"missing_publications":missing},sort_keys=True),flush=True)
if __name__=="__main__":main()
