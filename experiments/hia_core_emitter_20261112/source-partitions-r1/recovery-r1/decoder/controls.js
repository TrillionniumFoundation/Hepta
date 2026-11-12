/* V8-only finite negative controls. Real raw logs remain immutable.
 * Mutations are in-memory readback fixtures; no provider request, source generation or product execution.
 */
function checkCorePartitionRecovery(make,H,expected,frozen,inputs) {
  const d=make(H),base=inputs.partitions.find(x=>x.partition_id===1);
  const exp={...expected,partition_id:1,job_id:base.job_id},out=d.decode(base.log_raw,exp,frozen);
  const rows=[];
  const assert=(x,m)=>{if(!x)throw new Error(m);};
  function run(name,accept,fn) {
    let ok=false,error=null;try{fn();ok=true;}catch(e){error=String(e);}
    const pass=ok===accept;rows.push({name,expected_accept:accept,observed_accept:ok,pass,error});
    if(!pass)throw new Error("decoder control failed: "+name+" / "+error);
  }
  const strip=line=>line.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"").replace(/\r$/,"");
  const markers={manifest:"HIA_CORE_SOURCE_PARTITION_MANIFEST_V1",frame:"HIA_CORE_SOURCE_PARTITION_FRAME_V1",end:"HIA_CORE_SOURCE_PARTITION_END_V1",failure:"HIA_CORE_SOURCE_PARTITION_FAILURE_V1"};
  function changeLine(log,type,fn) {
    const lines=log.split("\n"),idx=lines.findIndex(line=>strip(line).startsWith(markers[type]+" "));
    assert(idx>=0,"fixture marker absent");
    const original=strip(lines[idx]),payload=JSON.parse(original.slice(markers[type].length+1));
    const updated=fn(payload,original);
    if(updated===null)lines.splice(idx,1);
    else lines[idx]=typeof updated==="string"?updated:markers[type]+" "+JSON.stringify(updated);
    return lines.join("\n");
  }
  function b64(bytes){
    const abc="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let text="";
    for(let i=0;i<bytes.length;i+=3){
      const n=(bytes[i]<<16)|((bytes[i+1]||0)<<8)|(bytes[i+2]||0);
      text+=abc[(n>>>18)&63]+abc[(n>>>12)&63]+(i+1<bytes.length?abc[(n>>>6)&63]:"=")+(i+2<bytes.length?abc[n&63]:"=");
    }
    return text;
  }
  function reframed(mutator) {
    const manifest=d.parse(out.manifest_raw),files=out.files.map(x=>({...x})),terminal={...out.terminal};
    mutator(manifest,files,terminal);
    manifest.files=files.map(x=>({path:x.path,bytes:H.utf8(x.raw).length,sha256:H.sha256(H.utf8(x.raw)),origin:x.origin}));
    manifest.total_raw_bytes=manifest.files.reduce((n,x)=>n+x.bytes,0);
    manifest.frame_count=manifest.files.reduce((n,x)=>n+Math.ceil(x.bytes/8192),0);
    const mr=d.pythonWire(manifest)+"\n",mb=H.utf8(mr),sha=H.sha256(mb),lines=[];
    lines.push(markers.manifest+" "+JSON.stringify({bytes:mb.length,sha256:sha,base64:b64(mb)}));
    for(const x of files){
      const raw=new Uint8Array(H.utf8(x.raw));
      for(let offset=0;offset<raw.length;offset+=8192){
        const bytes=raw.slice(offset,offset+8192);
        lines.push(markers.frame+" "+JSON.stringify({manifest_sha256:sha,path:x.path,offset,length:bytes.length,sha256:H.sha256(bytes),base64:b64(bytes)}));
      }
    }
    Object.assign(terminal,{manifest_sha256:sha,files:files.length,frames:manifest.frame_count,raw_bytes:manifest.total_raw_bytes});
    lines.push(markers.end+" "+JSON.stringify(terminal));
    return lines.join("\n")+"\n";
  }
  const validate=log=>d.audit(d.decode(log,exp,frozen),exp,frozen);
  run("actual_part1_seven_originals",true,()=>validate(base.log_raw));
  run("missing_late_END",false,()=>validate(changeLine(base.log_raw,"end",()=>null)));
  run("duplicate_frame",false,()=>validate(changeLine(base.log_raw,"frame",(_,line)=>line+"\n"+line)));
  run("noncontiguous_frame_offset",false,()=>validate(changeLine(base.log_raw,"frame",f=>({...f,offset:f.offset+1}))));
  run("changed_frame_bytes_old_hash",false,()=>validate(changeLine(base.log_raw,"frame",f=>({...f,base64:(f.base64[0]==="A"?"B":"A")+f.base64.slice(1)}))));
  run("deleted_frame",false,()=>validate(changeLine(base.log_raw,"frame",()=>null)));
  run("foreign_source_path",false,()=>validate(changeLine(base.log_raw,"frame",f=>({...f,path:"source/examples/hia_bootstrap/not-selected.hiaasm"}))));
  run("other_partition_context",false,()=>d.decode(base.log_raw,{...exp,partition_id:0},frozen));
  run("other_workflow_context",false,()=>d.decode(base.log_raw,{...exp,workflow_commit:"0".repeat(40)},frozen));
  run("old_failure_upgraded",false,()=>validate(changeLine(base.log_raw,"end",f=>({...f,original_failure_reclassified:true}))));
  run("per_job_claims_whole_matrix",false,()=>validate(changeLine(base.log_raw,"end",f=>({...f,all_20_partitions_complete_claimed:true}))));
  run("HOLD_cannot_enter_complete_audit",false,()=>validate(changeLine(base.log_raw,"end",f=>({...f,status:"PARTITION_HOLD"}))));
  run("failure_marker_after_END",false,()=>validate(base.log_raw+"\n"+markers.failure+' {"status":"PARTITION_HOLD"}\n'));
  run("self_consistent_frames_changed_original_source",false,()=>validate(reframed((m,files)=>{files[0].raw="!"+files[0].raw.slice(1);})));
  run("complete_stream_missing_one_control",false,()=>validate(reframed((m,files)=>{files.splice(files.findIndex(x=>x.path==="partition-reader/setup.json"),1);})));
  run("self_consistent_frames_changed_input_after",false,()=>validate(reframed((m,files)=>{
    const x=files.find(x=>x.path==="partition-reader/guard/guardian.json"),g=d.parse(x.raw);
    const name=Object.keys(g.source_identities_after)[0];g.source_identities_after[name]="0".repeat(64);x.raw=d.pythonWire(g)+"\n";
  })));
  run("self_consistent_frames_incomplete_cleanup",false,()=>validate(reframed((m,files)=>{
    const x=files.find(x=>x.path==="partition-reader/guard/guardian.json"),g=d.parse(x.raw);g.lifecycle.cleanup.complete=false;x.raw=d.pythonWire(g)+"\n";
  })));
  function cloneProvider() { return {run_raw:inputs.run_raw,jobs_raw:inputs.jobs_raw,partitions:inputs.partitions.map(x=>({...x}))}; }
  run("aggregate_missing_partition",false,()=>d.aggregate({...inputs,partitions:inputs.partitions.slice(0,19)},expected,frozen));
  run("aggregate_duplicate_provider_job",false,()=>{
    const x=cloneProvider(),j=JSON.parse(x.jobs_raw);j.jobs[1].id=j.jobs[0].id;x.jobs_raw=JSON.stringify(j);d.aggregate(x,expected,frozen);
  });
  run("aggregate_other_run",false,()=>{
    const x=cloneProvider(),r=JSON.parse(x.run_raw);r.id++;x.run_raw=JSON.stringify(r);d.aggregate(x,expected,frozen);
  });
  run("aggregate_other_attempt",false,()=>{
    const x=cloneProvider(),r=JSON.parse(x.run_raw);r.run_attempt=2;x.run_raw=JSON.stringify(r);d.aggregate(x,expected,frozen);
  });
  run("aggregate_failed_provider_job",false,()=>{
    const x=cloneProvider(),j=JSON.parse(x.jobs_raw);j.jobs[0].conclusion="failure";x.jobs_raw=JSON.stringify(j);d.aggregate(x,expected,frozen);
  });
  run("aggregate_job_id_not_from_provider",false,()=>{
    const x=cloneProvider();x.partitions[0].job_id++;d.aggregate(x,expected,frozen);
  });
  run("aggregate_swapped_partition_logs",false,()=>{
    const x=cloneProvider();[x.partitions[0].log_raw,x.partitions[1].log_raw]=[x.partitions[1].log_raw,x.partitions[0].log_raw];d.aggregate(x,expected,frozen);
  });
  run("aggregate_missing_guardian_step",false,()=>{
    const x=cloneProvider(),j=JSON.parse(x.jobs_raw);j.jobs[0].steps=j.jobs[0].steps.filter(s=>s.name!=="Read one fixed original source partition under its independent 900-second guardian");
    x.jobs_raw=JSON.stringify(j);d.aggregate(x,expected,frozen);
  });
  return {schema:"hia.core-partition-V8-reader-controls.v1",status:"PASS",control_count:rows.length,
    controls:rows,positive_actual_part1_log:d.seal(base.log_raw),actual_full_twenty_group_baseline_required_separately:true,
    source_generated_again:false,Python_executed:false,native_compiler_executed:false,product_executed:false,
    mutations_only_to_in_memory_log_fixtures:true,original_provider_logs_unchanged:true};
}
