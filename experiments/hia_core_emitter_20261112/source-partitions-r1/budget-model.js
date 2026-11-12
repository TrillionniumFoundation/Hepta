return function calculatePartitionBudget(originals, policy, plan, H) {
 const parse=raw=>JSON.parse(raw,(_k,v,c)=>typeof v==="number"&&!Number.isSafeInteger(v)&&/^-?(?:0|[1-9][0-9]*)$/.test(c?.source||"")?BigInt(c.source):v);
 const quote=s=>JSON.stringify(s).replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"));
 function pretty(v,depth=0){
  if(typeof v==="bigint")return v.toString();
  if(v===null)return "null";
  if(typeof v==="string")return quote(v);
  if(typeof v==="number"||typeof v==="boolean")return String(v);
  const pad=" ".repeat(depth),child=" ".repeat(depth+2);
  if(Array.isArray(v))return v.length?"[\n"+v.map(x=>child+pretty(x,depth+2)).join(",\n")+"\n"+pad+"]":"[]";
  const keys=Object.keys(v).sort();
  return keys.length?"{\n"+keys.map(k=>child+quote(k)+": "+pretty(v[k],depth+2)).join(",\n")+"\n"+pad+"}":"{}";
 }
 const wire=v=>pretty(v)+"\n",copy=v=>parse(wire(v));
 const compact=v=>{
  const raw=pretty(v);let out="",quoted=false,escaped=false;
  for(const c of raw){
   if(quoted){out+=c;if(escaped)escaped=false;else if(c==="\\")escaped=true;else if(c==='"')quoted=false;}
   else if(c==='"'){quoted=true;out+=c;}
   else if(!" \t\r\n".includes(c))out+=c;
  }
  return out+"\n";
 };

 const prior={setup:parse(originals.setup),guardian:parse(originals.guardian),report:parse(originals.report)};
 for(const k of Object.keys(prior))if((k==="guardian"?compact(prior[k]):wire(prior[k]))!==originals[k])throw Error("reference Python wire mismatch: "+k);
 const max=18446744073709551615n;
 const oldRoot=prior.setup.context.root;
 const temp=oldRoot.slice(0,oldRoot.lastIndexOf("/"));
 const checkout=Object.keys(prior.setup.context.control_sources).find(x=>x.endsWith("/.github/workflows/hia-core.yml")).slice(0,-"/.github/workflows/hia-core.yml".length);
 const sha=v=>H.sha256(H.utf8(typeof v==="string"?v:wire(v)));
 const controls=[];
 function rewrite(v,root){if(typeof v==="string")return v.replaceAll(oldRoot,root);if(Array.isArray(v))return v.map(x=>rewrite(x,root));if(v&&typeof v==="object")return Object.fromEntries(Object.entries(v).map(([k,x])=>[k.replaceAll(oldRoot,root),rewrite(x,root)]));return v;}
 for(const group of plan.partitions){
  const root=temp+"/"+policy.work_root_name+"-"+group.partition_id;
  const publicRoot=temp+"/"+policy.public_root_name+"-"+group.partition_id;
  const context=copy(prior.setup.context);
  Object.assign(context,{schema:"hia.actions.core-source-partition-context.v1",
    root,public_root:publicRoot,run_id:max,run_number:max,
    actual_control_checkout:"f".repeat(40),actual_workflow_commit:"e".repeat(40),
    policy_sha256:sha(policy),event_ref:policy.trigger_branch,
    partition_id:group.partition_id,partition_count:20,partition_source_bytes:group.source_bytes,
    selected_source_indices:group.files.map(x=>x.index)});
  context.control_sources={};
  for(const [name,pin]of Object.entries(policy.control_files))context.control_sources[checkout+"/"+policy.control_prefix+"/"+name]=pin.sha256;
  context.control_sources[checkout+"/"+policy.control_prefix+"/policy.json"]=sha(policy);
  for(const [name,pin]of Object.entries(policy.unchanged_original_workflows))context.control_sources[checkout+"/"+name]=pin.sha256;
  context.python.binary.identity=context.python.binary.identity.map(()=>max);
  const identities={...context.control_sources};
  for(const [name,pin]of Object.entries(policy.control_files))identities[root+"/control/"+name]=pin.sha256;
  identities[root+"/control/policy.json"]=sha(policy);
  identities[root+"/context.json"]=sha(context);
  identities[context.python.resolved]=context.python.binary.sha256;
  const command=[context.python.resolved,"-I","-S","-B",root+"/control/worker.py","--root",root,"--policy-sha256",sha(policy),"--partition-id",String(group.partition_id)];
  const config={schema:"hia-external-guardian-request.v1",controller_seconds:900,command,cwd:root,source_identities:identities};
  const setup={...copy(prior.setup),context,source_identities:identities,command,
    schema:"hia.actions.core-source-partition-setup.v1",guardian_config_sha256:sha(config),
    capacity_before:{free_bytes:max,free_inodes:max}};
  const report={schema:"hia.actions.core-source-partition-worker.v1",status:"SOURCE_PARTITION_VERIFIED_PENDING_NATURAL_GUARDIAN",
    root,policy_sha256:sha(policy),partition_id:group.partition_id,partition_count:20,
    external_pins_sha256:policy.control_files["asset-pins.json"].sha256,
    partition_plan_sha256:policy.control_files["partitions.json"].sha256,
    API_attempts:rewrite(prior.report.API_attempts,root),GET_attempts:rewrite(prior.report.GET_attempts,root),
    source_artifact:policy.source_artifact,
    project_code_executed:false,qualification_executed:false,original_product_statuses_reclassified:false,
    original_failure_reclassified:false,source_generated_again:false,native_compiler_executed:false,
    Core_VM_executed:false,product_tests_executed:false,token_or_signed_URL_recorded:false,
    official_metadata:rewrite(prior.report.official_metadata,root),
    artifact_before:rewrite(prior.report.artifact_before,root),artifact_after:rewrite(prior.report.artifact_after,root),
    archive_inventory:copy(prior.report.archive_inventory),archive_member_count:60,archive_uncompressed_bytes:7374535,
    all_members_fully_read_and_CRC_verified:true,all_54_historical_pins_verified:true,
    original_source_file_count:40,original_source_total_bytes:7089249,
    selected_source_indices:group.files.map(x=>x.index),selected_source_bytes:group.source_bytes,
    frame_files:group.files.map(x=>({source_index:x.index,logical_path:x.logical_path,archive_path:x.archive_member,
      origin:"sealed original source member "+x.archive_member,
      record:{path:root+"/selected/"+String(x.index).padStart(3,"0")+".original",bytes:x.bytes,sha256:x.sha256,identity:Array(9).fill(max)}})),
    all_selected_source_originals_fully_read:true,original_failed_run:copy(prior.report.original_failed_run),
    original_run_conclusion:"failure",elapsed_ns:900000000000};
  const stdoutObject={status:report.status,partition_id:group.partition_id,source_files:2,source_bytes:group.source_bytes,original_run_conclusion:"failure",qualification_executed:false};
  const stdout="{"+Object.entries(stdoutObject).map(([k,v])=>quote(k)+": "+pretty(v)).join(", ")+"}\n";
  const guardian=rewrite(prior.guardian,root);
  Object.assign(guardian,{command,cwd:root,source_identities_before:identities,source_identities_after:identities});
  guardian.logs={[root+"/guard/child.stdout.log"]:sha(stdout),[root+"/guard/child.stderr.log"]:sha("")};
  const sizes={guardian:H.utf8(compact(guardian)).length,stdout:H.utf8(stdout).length,stderr:0,worker_report:H.utf8(wire(report)).length,setup:H.utf8(wire(setup)).length};
  const total=Object.values(sizes).reduce((n,x)=>n+x,0);
  controls.push({partition_id:group.partition_id,source_bytes:group.source_bytes,current_control_bytes:sizes,control_total:total,combined_raw:group.source_bytes+total,headroom:524288-group.source_bytes-total,identities:Object.keys(identities).length,within_control_reserve:total<=131072});
 }
 return {schema:"hia.core-source-partition-reference-wire-budget-model.v1",
  status:controls.every(x=>x.within_control_reserve)?"MODEL_WITHIN_RESERVED_BUDGET":"MODEL_EXCEEDS_RESERVED_BUDGET",
  scope:"Static V8 byte-count model derived from actual run43157292390 originals. This is not a future runtime receipt or Python execution; every new job independently enforces the real byte limits and may HOLD.",
  reference_wire_renderer_matches_all_three_actual_python_originals:true,
  reference_wire_formats:{guardian:"compact sorted JSON plus newline",setup:"sorted indent2 JSON plus newline",report:"sorted indent2 JSON plus newline"},
  conservative_substitutions:["Run ID and run number use full 20-decimal unsigned64 width","Python binary identity and selected-file identities use 20-decimal widths","Capacity counters use 20-decimal widths","Worker elapsed time uses full900-second decimal width"],
  assumptions:["Original runner path and Python version-string lengths are the actual observed reference; future changes are handled by the runtime caps, not assumed equivalent","Natural stdout is modeled from the exact new print fields; nonempty stderr still consumes the same combined128KiB cap"],
  maximum_control_total:Math.max(...controls.map(x=>x.control_total)),
  maximum_combined_raw:Math.max(...controls.map(x=>x.combined_raw)),
  minimum_headroom:Math.min(...controls.map(x=>x.headroom)),controls};
};