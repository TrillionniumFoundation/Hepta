import hashlib,json,os,pathlib
base=pathlib.Path("/tmp/hia-e26e-package-prepare-terminal-r2")
rows=json.loads("[{\"path\":\"preparation.json\",\"chars\":12166,\"sha256\":\"51eabb5fd13572cf981c70cf60b1da1ade05b389651350c031ad715aa798b6dd\"},{\"path\":\"guard/guardian.json\",\"chars\":9201,\"sha256\":\"8e9ffe07b423f20538efea124f7e1666e6ed8823bd0076ec985eaf4a4be2f060\"},{\"path\":\"guard/child.stdout.log\",\"chars\":432,\"sha256\":\"7c30b165189e8337d9fc9d97dc8583fd9b0700b0375fa80eac800d376aa6aa10\"},{\"path\":\"guard/child.stderr.log\",\"chars\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"},{\"path\":\"guard/request.json\",\"chars\":3884,\"sha256\":\"ff85e498c67223540ccbf59ec39d64a3838ae2cf999cff0cc82d58816d6a1564\"},{\"path\":\"launch-intent.json\",\"chars\":2236,\"sha256\":\"d70ba40c26bf5c092eccf58adce4f6e6c985648d4ebcbfb8e5f6efed84ed1578\"},{\"path\":\"expected-source-identities.json\",\"chars\":3519,\"sha256\":null},{\"path\":\"authoritative-status.json\",\"chars\":729,\"sha256\":null},{\"path\":\"h-stdout.log\",\"chars\":631,\"sha256\":null},{\"path\":\"h-stderr.log\",\"chars\":0,\"sha256\":null}]")
for row in rows:
 p=base/row["path"];raw=p.read_bytes();n=len(raw.decode())
 assert n in (row["chars"],row["chars"]+1),(row["path"],n)
 if n==row["chars"]+1:
  assert raw.endswith(b"\n");raw=raw[:-1]
  with p.open("wb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==raw
 d=hashlib.sha256(raw).hexdigest()
 if row["sha256"]:assert row["sha256"]==d
 row.update(bytes=len(raw),sha256=d)
p=json.loads((base/"preparation.json").read_bytes())
g=json.loads((base/"guard/guardian.json").read_bytes())
c=json.loads((base/"guard/request.json").read_bytes())
i=json.loads((base/"launch-intent.json").read_bytes())
h=json.loads((base/"authoritative-status.json").read_bytes())
expected=json.loads((base/"expected-source-identities.json").read_bytes())
assert h["state"]=="succeeded" and h["exit_code"]==0 and h["output_complete"] is True and h["output_durable"] is True and not h["timed_out"]
assert h["log_errors"]=={"stderr":None,"stdout":None} and h["log_truncated"]=={"stderr":False,"stdout":False}
assert p["status"]=="DEVELOPMENT_SOURCE_MATERIALIZED_PENDING_OUTER_GUARDIAN"
assert p["canonical_commit"]=="e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6" and p["canonical_tree"]=="bfcbb39e22371cbb2292c89a2fa1ca010353a56f"
assert p["source_manifest_sha256"]=="7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af"
assert p["source_population"]=={"declared_source_count":661,"decoded_bytes":30794542,"members":1666,"non_experimental_members":1642}
assert p["old_inputs_before"]==p["old_inputs_after"] and len(p["old_inputs_before"])==12
assert all(expected[x["path"]]==x["sha256"] for x in p["old_inputs_before"])
assert p["compiler_original_before"]==p["compiler_original_after"] and p["compiler_copy"]["sha256"]==p["compiler_original_before"]["sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
assert p["python"]["sha256"]=="b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
assert {k:v["version"] for k,v in p["dependencies"].items()}=={"jsonschema":"4.25.1","setuptools":"78.1.1","wheel":"0.46.3","z3-solver":"4.15.4.0","zstandard":"0.25.0"}
assert all(v["imported"] is True for v in p["dependencies"].values())
assert set(p["candidate_sources"])=={"wire-r7","cli"}
for name,s in list(p["candidate_sources"].items())+[("published_before_seal",p["published_before_seal"]),("published_after_seal",p["published_after_seal"])]:
 assert s["member_count"]==1666 and s["all_canonical_bytes_modes_verified"] is True and s["complete_git_object_closure"] is False
 assert s["read_only"]==(name=="published_after_seal")
for k in ["complete_git_object_closure","source_contract_checked_document_current","tests_requested","qualification_requested","whole_native_delivery_qualified","cold_180_second_gate_modified","old_source_checkouts_accessed","network_or_git_requested"]:
 assert p[k] is False,k
assert i["capacity_before"]["available_bytes"]>=8<<30 and i["capacity_before"]["free_inodes"]>=100000 and i["final_full_root_touched"] is False
assert g["status"]=="EXTERNAL_OWNED_PROCESS_COMPLETED" and g["input_identity_preserved"] is True
assert g["source_identities_before"]==g["source_identities_after"]==c["source_identities"]==expected and len(expected)==26
assert g["external_controller_seconds"]==c["controller_seconds"]==1800
assert g["command"]==c["command"]==["/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python","-B","/home/qian-qi/he26v66devr2/control/prepare_development_package.py"]
assert g["cwd"]==c["cwd"]=="/home/qian-qi/he26v66devr2"
assert g["lifecycle_implementation_sha256"]=="36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
life=g["lifecycle"];clean=life["cleanup"]
assert life["status"]=="OWNED_PROCESS_COMPLETED" and life["returncode"]==0 and life["exit_observed_before_deadline"] is True and life["timed_out"] is False
assert life["interrupted_signals"]==[] and not life.get("owner_error") and life["event_overflow"] is False
assert all(e["kind"] in {"qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"} for e in life["events"])
assert clean["complete"] is True and clean["observed_echild"] is True and clean["leader_reaped"] is True and clean["errors"]==[] and clean["remaining_direct_children"]==[] and clean["deadline_exceeded"] is False
for name in ["guard/child.stdout.log","guard/child.stderr.log"]:
 assert g["logs"]["/home/qian-qi/he26v66devr2/"+name]==hashlib.sha256((base/name).read_bytes()).hexdigest()
result={"schema":"hia.desktop-package-preparation-independent-terminal-acceptance.v1","status":"DEVELOPMENT_SOURCE_READY","host":"desktop","job_id":"1a1cae7294a-2564-8fc","stable_key":"hia-e26e-desktop-e09-package-development-prepare-r2","canonical_commit":p["canonical_commit"],"canonical_tree":p["canonical_tree"],"input_identities_before_after":26,"original_old_pins":12,"source_members":1666,"declared_source_members":661,"immutable_baseline":True,"independent_wire_cli_copies":True,"natural_guardian_cleanup":True,"whole_native_delivery_qualified":False,"complete_git_object_closure":False,"source_contract_checked_document_current":False,"tests_run":False,"originals":rows}
raw=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode()
f=base/"ACCEPTANCE.json"
with f.open("xb") as out:out.write(raw);out.flush();os.fsync(out.fileno())
print(json.dumps({"status":result["status"],"acceptance_path":str(f),"acceptance_bytes":len(raw),"acceptance_sha256":hashlib.sha256(raw).hexdigest(),"originals":rows}))
