return function runDecoderControls(decoder, pins, policy, H) {
  const enc = H.utf8;
  const b64 = bytes => {
    const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out="";
    for(let i=0;i<bytes.length;i+=3){
      const a=bytes[i],b=i+1<bytes.length?bytes[i+1]:0,c=i+2<bytes.length?bytes[i+2]:0,n=(a<<16)|(b<<8)|c;
      out+=chars[(n>>>18)&63]+chars[(n>>>12)&63]+(i+1<bytes.length?chars[(n>>>6)&63]:"=")+(i+2<bytes.length?chars[n&63]:"=");
    }
    return out;
  };
  const expected={run_id:900000001,control_commit:"25d75b425814943e2409f4538a024541b8731ac0",
    workflow_commit:"edde83a69f5863d2ac6f17b033af11ec35d21d0e",
    policy_sha256:"1ed146aeb3081d6cc6b023d0da3ca7a018969f730277522f24c8ab5c1e58267b",
    branch:policy.trigger_branch};
  const originals=[...pins.historical_targets.filter(x=>x.role==="original").map(x=>x.logical_path),
    ...pins.reader_targets.map(x=>x.logical_path),pins.frame_result.logical_path];
  const names=["guard/guardian.json","guard/child.stdout.log","guard/child.stderr.log","recovery-terminal.json","setup.json"];
  const rawBodies=[
    '{"synthetic":true,"nanoseconds":18446744073709551615,"text":"雪𐐷"}\n',
    "synthetic stdout\n","",
    '{"synthetic":true,"actual_product_executed":false}\n',
    '{"synthetic":true,"context":"frame decoding only"}\n'
  ];
  function fixture(hold=false){
    const files=names.map((name,i)=>{
      const bytes=enc(rawBodies[i]);
      return {path:"diagnostic-reader/"+name,bytes:bytes.length,sha256:H.sha256(bytes),origin:"synthetic decoder control"};
    });
    const manifest={
      schema:"hia.core-failed-reader-diagnostic-frame-manifest.v1",
      context:{schema:"hia.actions.core-failed-reader-diagnostic-context.v1",
        repository:"TrillionniumFoundation/Hepta",event:"create",event_ref_type:"branch",run_attempt:1,
        run_id:expected.run_id,actual_control_checkout:expected.control_commit,actual_workflow_commit:expected.workflow_commit,
        policy_sha256:expected.policy_sha256,event_ref:expected.branch,
        original_product_commit:"80ec04ae7489209b122c874531d194c67b30dfed",
        original_product_tree:"963e980c2486e1f7c74fa42bc8132ef6b1b8b690",
        token_or_signed_URL_in_context:false,qualification_executed:false},
      files,frame_bytes:8192,maximum_raw_bytes:524288,maximum_stdout_bytes:1048576,
      original_run_conclusion:"failure",original_failed_run_id:43152508792,
      original_failure_reclassified:false,qualification_executed:false,assembly_body_bytes_output:0,
      failed_artifact:policy.source_artifact,missing_diagnostic_targets:originals,
      diagnostics_accepted:!hold,errors:hold?[{stage:"SYNTHETIC",type:"Refusal"}]:[],
      total_raw_bytes:files.reduce((n,x)=>n+x.bytes,0),
      frame_count:files.reduce((n,x)=>n+Math.ceil(x.bytes/8192),0)};
    const frameRecords=[];
    for(let i=0;i<files.length;i++){
      const bytes=enc(rawBodies[i]);
      for(let offset=0;offset<bytes.length;offset+=8192){
        const part=bytes.slice(offset,offset+8192);
        frameRecords.push({path:files[i].path,offset,length:part.length,sha256:H.sha256(part),base64:b64(part)});
      }
    }
    const end={schema:"hia.core-failed-reader-diagnostic-frame-terminal.v1",
      status:hold?"DIAGNOSTIC_HOLD":"DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED",
      result_sha256:"a".repeat(64),diagnostic_bytes_complete:true,files:files.length,
      frames:manifest.frame_count,raw_bytes:manifest.total_raw_bytes,
      original_run_conclusion:"failure",original_failure_reclassified:false,assembly_body_bytes_output:0,
      qualification_executed:false,missing_diagnostic_targets:originals};
    return {manifest,frameRecords,end};
  }
  function render(f,omitEnd=false){
    const raw=enc(JSON.stringify(f.manifest)),sha=H.sha256(raw);
    const records=[
      "HIA_CORE_READER_DIAGNOSTIC_MANIFEST_V1 "+JSON.stringify({bytes:raw.length,sha256:sha,base64:b64(raw)}),
      ...f.frameRecords.map(x=>"HIA_CORE_READER_DIAGNOSTIC_FRAME_V1 "+JSON.stringify({...x,manifest_sha256:sha}))
    ];
    if(!omitEnd)records.push("HIA_CORE_READER_DIAGNOSTIC_END_V1 "+JSON.stringify({...f.end,manifest_sha256:sha}));
    return "unrelated workflow line\n"+records.map(x=>"2026-11-12T00:00:00.0000000Z "+x).join("\n")+"\n";
  }
  const rows=[],fixtures=[];
  function run(name,f,expect,mutateLog){
    let log=render(f,name==="missing_end");
    if(mutateLog)log=mutateLog(log);
    let observation,error=null,rawPreserved=null;
    try{
      const result=decoder(log,expected,pins,H);
      observation=result.terminal.status;
      const body=result.files.find(x=>x.path==="diagnostic-reader/guard/guardian.json");
      rawPreserved=body?result.decodeUTF8(body.bytes)===rawBodies[0]:null;
    }catch(e){observation="REJECTED";error=e.message;}
    const pass=observation===expect&&(expect==="REJECTED"||rawPreserved===true);
    rows.push({name,expected:expect,observed:observation,pass,error,
      raw_unicode_and_unsigned_64bit_decimal_preserved:rawPreserved,
      log_bytes:enc(log).length,log_sha256:H.sha256(enc(log))});
    fixtures.push({name,log});
  }
  run("complete_small_diagnostics",fixture(),"DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED");
  run("explicit_hold_preserved",fixture(true),"DIAGNOSTIC_HOLD");
  run("missing_end",fixture(),"REJECTED");
  {const f=fixture();f.frameRecords[0].sha256="0".repeat(64);run("frame_hash_tampered",f,"REJECTED");}
  {const f=fixture();f.frameRecords[0].offset=1;run("frame_offset_gap",f,"REJECTED");}
  {const f=fixture();f.frameRecords.splice(1,0,{...f.frameRecords[0]});run("duplicate_frame",f,"REJECTED");}
  {const f=fixture();f.manifest.files[0].path="source/examples/hia_bootstrap/forbidden.hiaasm";
    f.frameRecords[0].path=f.manifest.files[0].path;run("source_body_forbidden",f,"REJECTED");}
  {const f=fixture();f.manifest.context.actual_workflow_commit="0".repeat(40);run("wrong_operation_identity",f,"REJECTED");}
  {const f=fixture();f.manifest.original_failure_reclassified=true;run("old_failure_cannot_be_upgraded",f,"REJECTED");}
  {const f=fixture();f.manifest.files[0].bytes=524289;run("raw_budget_exceeded",f,"REJECTED");}
  {const f=fixture();f.manifest.diagnostics_accepted=null;run("ambiguous_acceptance_rejected",f,"REJECTED");}
  {const f=fixture();const x=pins.historical_targets.find(x=>x.logical_path==="original/setup.json");
    f.manifest.files[0].path=x.logical_path;f.manifest.missing_diagnostic_targets=originals.filter(p=>p!==x.logical_path);
    f.frameRecords[0].path=x.logical_path;f.end.missing_diagnostic_targets=f.manifest.missing_diagnostic_targets;
    run("historical_raw_identity_differs",f,"REJECTED");}
  return {schema:"hia.core-failed-reader-V8-decoder-controls.v1",status:rows.every(x=>x.pass)?"PASS":"FAIL",
    runtime:"functions V8 isolate only",cases:rows.length,passed:rows.filter(x=>x.pass).length,rows,fixtures,
    scope:{synthetic_framing_only:true,actual_Actions_log_decoded:false,Python_parse_executed:false,
      network_or_h_used:false,native_or_product_tests_executed:false,original_failed_run_reclassified:false}};
};