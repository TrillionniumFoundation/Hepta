return function decodeCoreEmitterDiagnostics(rawLog, api) {
  const {utf8, sha256, base64Bytes, bytesBase64, utf8Text} = api;
  function require(ok, text) { if (!ok) throw new Error("HIA diagnostic custody: " + text); }
  function integer(x, max=Number.MAX_SAFE_INTEGER) { return Number.isSafeInteger(x) && x >= 0 && x <= max; }
  function sha(x) { return typeof x === "string" && /^[0-9a-f]{64}$/.test(x); }
  const names=[];
  for (const stage of ["prepare","run","finalize"]) for (const channel of ["stdout","stderr"]) names.push("stage/"+stage+"."+channel+".log");
  names.push("setup.json","context.json","guard/request.json","FINAL.json","guard/guardian.json","evidence/report.json","guard/child.stdout.log","guard/child.stderr.log");
  const gated=new Set(["guard/guardian.json","evidence/report.json","guard/child.stdout.log","guard/child.stderr.log"]);
  const markers=[], unknown=[];
  for (const [lineIndex,line] of rawLog.split(/\r?\n/).entries()) {
    const stripped=line.replace(/^\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s+/,"");
    if(!stripped.startsWith("HIA_CORE_EMITTER_")) continue;
    const match=/^HIA_CORE_EMITTER_([A-Z_]+) (\{.*\})$/.exec(stripped);
    require(match,"malformed marker at original line "+(lineIndex+1));
    let value; try { value=JSON.parse(match[2]); } catch(_) { throw new Error("malformed marker JSON at original line "+(lineIndex+1)); }
    markers.push({kind:match[1],value,line:lineIndex+1});
  }
  require(markers.length>0,"no diagnostic markers");
  require(markers[0].kind==="DIAGNOSTIC_BEGIN","missing initial boundary");
  const begin=markers[0].value;
  require(begin.schema==="hia.core-emitter-actions-diagnostic.v1" &&
    begin.control_commit==="9473e0fca206dc27ed87122f4a5d45a905d8b35c" &&
    begin.workflow_commit==="4d508b8e7b66d8f2801e76f6b6bb4794eb4bdac7" &&
    begin.run_id===43131161021 && begin.run_attempt===1 &&
    begin.policy_sha256==="0cf91131f947850badb125537249c94229f5cf0590653363702b378913a84dcf" &&
    begin.maximum_original_raw_bytes===4194304 && begin.fixed_file_count===14 &&
    begin.directory_scans===0 && begin.product_execution===false &&
    begin.original_exit_status_modified===false && begin.frames_are_original_bytes===true,
    "fixed current operation identity differs");
  require(markers[1]?.kind==="DIAGNOSTIC_BOUNDARY","missing closure boundary");
  const boundary=markers[1].value;
  require(typeof boundary.closed_current_operation_ECHILD==="boolean" &&
    boundary.natural_success_inferred===false,"invalid closure record");
  const files=[], unavailable=[]; let at=2, printed=0,totalFrames=0;
  for(const name of names) {
    const start=markers[at++];
    require(start && start.value.name===name,"fixed ordered name missing: "+name);
    if(start.kind==="ORIGINAL_UNAVAILABLE") {
      require(["CLOSED_CURRENT_OPERATION_NOT_PROVEN","OMITTED_RAW_BUDGET","MISSING","READ_REFUSED"].includes(start.value.status),
        "invalid unavailable status: "+name);
      if(gated.has(name) && !boundary.closed_current_operation_ECHILD)
        require(start.value.status==="CLOSED_CURRENT_OPERATION_NOT_PROVEN" && start.value.original_bytes_printed===0,"unclosed original disclosed");
      unavailable.push({name,...start.value});continue;
    }
    require(start.kind==="ORIGINAL_BEGIN","expected original start: "+name);
    require(!gated.has(name) || boundary.closed_current_operation_ECHILD,"closed operation missing");
    const item=start.value;
    require(integer(item.bytes,4194304) && sha(item.sha256) && item.frame_bytes===8192 &&
      item.frame_count===Math.ceil(item.bytes/8192),"bad original denominator: "+name);
    const joined=new Uint8Array(item.bytes);let offset=0;
    for(let index=0; index<item.frame_count; index++) {
      const frame=markers[at++]; require(frame?.kind==="ORIGINAL_FRAME","missing original frame");
      const value=frame.value;
      require(value.name===name && value.index===index && value.offset===offset &&
        value.bytes===Math.min(8192,item.bytes-offset) && sha(value.sha256) &&
        typeof value.base64==="string","frame identity or length differs");
      const bytes=base64Bytes(value.base64);
      require(bytes.length===value.bytes && bytesBase64(bytes)===value.base64 &&
        sha256(bytes)===value.sha256,"frame bytes differ");
      joined.set(bytes,offset); offset+=bytes.length; totalFrames++;
    }
    const finish=markers[at++];
    require(finish?.kind==="ORIGINAL_END" && finish.value.name===name &&
      finish.value.bytes===item.bytes && finish.value.sha256===item.sha256 &&
      finish.value.frame_count===item.frame_count && offset===item.bytes &&
      sha256(joined)===item.sha256,"whole original or END differs");
    printed+=item.bytes;
    require(printed<=4194304,"total raw budget exceeded");
    files.push({name,bytes:item.bytes,sha256:item.sha256,frame_count:item.frame_count,
      base64:bytesBase64(joined)});
  }
  const terminal=markers[at++];
  require(terminal?.kind==="DIAGNOSTIC_END" && at===markers.length,"missing or repeated final boundary");
  const end=terminal.value;
  require(end.maximum_raw_bytes===4194304 && end.closed_current_operation_ECHILD===boundary.closed_current_operation_ECHILD &&
    end.original_raw_bytes_printed===printed && integer(end.original_raw_byte_budget_reserved,4194304) &&
    integer(end.verified_original_bytes_read,end.original_raw_byte_budget_reserved) &&
    printed<=end.verified_original_bytes_read && end.original_exit_status_modified===false &&
    end.qualification_claimed===false,"final raw denominator differs");
  require(end.fixed_file_observations && typeof end.fixed_file_observations==="object" &&
    !Array.isArray(end.fixed_file_observations),"missing original observations");
  let observedRead=0;
  for(const [name,observation] of Object.entries(end.fixed_file_observations)){
    require(names.includes(name),"unexpected observed name");
    require(["COMPLETE_ORIGINAL_READ","OMITTED_RAW_BUDGET","MISSING","READ_REFUSED"].includes(observation.status),"unknown observation");
    if(observation.status==="COMPLETE_ORIGINAL_READ"){
      require(integer(observation.bytes,4194304)&&sha(observation.sha256),"bad observed original");
      observedRead+=observation.bytes;
      const recovered=files.find(x=>x.name===name);
      if(recovered)require(recovered.bytes===observation.bytes&&recovered.sha256===observation.sha256,"original observation mismatch");
      else require(gated.has(name)&&!boundary.closed_current_operation_ECHILD,"complete original omitted without boundary");
    }
  }
  require(observedRead===end.verified_original_bytes_read,"independent read denominator differs");
  for(const file of files)require(end.fixed_file_observations[file.name]?.status==="COMPLETE_ORIGINAL_READ","missing successful observation");
  for(const file of unavailable)if(file.status!=="CLOSED_CURRENT_OPERATION_NOT_PROVEN")
    require(end.fixed_file_observations[file.name]?.status===file.status,"missing refusal observation");
  return {schema:"hia.core-emitter-diagnostic-frame-readback.v1",
    status:"COMPLETE_DIAGNOSTIC_FRAMES_RECOVERED_NOT_QUALIFICATION",
    run_id:43131161021,run_attempt:1,job_id:130895354218,
    log:{bytes:utf8(rawLog).length,sha256:sha256(utf8(rawLog))},
    begin,boundary,end,files,unavailable,fixed_files:14,frames:totalFrames,original_bytes:printed,
    original_statuses_reclassified:false,product_execution:false,qualification_claimed:false};
};