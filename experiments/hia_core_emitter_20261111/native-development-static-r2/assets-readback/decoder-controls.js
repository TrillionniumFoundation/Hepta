function runCoreAssetDecoderControls(decode, actualPins, H) {
  const pinset=JSON.parse(JSON.stringify(actualPins));
  const expected={run_id:43138417048,control_commit:"8b10b000a43e57cdaa27f60d425b6625e4b2209a",
    workflow_commit:"0753cae7150e2c8d01b0d5cbec41264e831b5d3e",
    policy_sha256:"23084b55ea9fae4c7e8696064f3ee98635622922994182c11d872fc6751044196fd",
    branch:"codex/hia-core-emitter-generated-assets-run-r1-20261112-e26e",
    product_commit:"80ec04ae7489209b122c874531d194c67b30dfed",
    product_tree:"963e980c2486e1f7c74fa42bc8132ef6b1b8b690"};
  // Synthetic seals are local fixture data, not a claim about any original.
  expected.policy_sha256="a".repeat(64);
  const controls=["reader/guard/guardian.json","reader/guard/child.stdout.log",
    "reader/guard/child.stderr.log","reader/recovery-terminal.json","reader/setup.json"];
  const inputs=[], payloads=[];
  function blob(raw){const prefix=H.utf8("blob "+raw.length+String.fromCharCode(0));
    const combined=new Uint8Array(prefix.length+raw.length);combined.set(prefix);combined.set(raw,prefix.length);
    return H.sha1(combined);}
  for(const pin of pinset.archive_members.filter(x=>x.logical_path)){
    const raw=new Uint8Array(pin.bytes);raw.fill(65+(inputs.length%26));
    pin.sha256=H.sha256(raw);pin.git_blob_sha1=blob(raw);
    inputs.push({path:pin.logical_path,bytes:raw.length,sha256:pin.sha256,origin:"synthetic exact-size original fixture"});
    const frames=[];
    for(let at=0;at<raw.length;at+=24576){const block=raw.slice(at,at+24576);
      frames.push({path:pin.logical_path,offset:at,length:block.length,sha256:H.sha256(block),base64:H.b64(block)});}
    payloads.push(frames);
  }
  for(const name of controls){const raw=H.utf8("synthetic control "+name+"\n");
    inputs.push({path:name,bytes:raw.length,sha256:H.sha256(raw),origin:"synthetic current control"});
    payloads.push([{path:name,offset:0,length:raw.length,sha256:H.sha256(raw),base64:H.b64(raw)}]);}
  const ctx={schema:"hia.actions.core-emitter-assets-context.v1",
    repository:"TrillionniumFoundation/Hepta",event:"create",event_ref_type:"branch",
    run_attempt:1,run_id:expected.run_id,actual_control_checkout:expected.control_commit,
    actual_workflow_commit:expected.workflow_commit,policy_sha256:expected.policy_sha256,
    event_ref:expected.branch,original_product_commit:expected.product_commit,
    original_product_tree:expected.product_tree,token_or_signed_URL_in_context:false,qualification_executed:false};
  function records(selected,accepted){
    const files=selected.map(i=>inputs[i]);
    const manifest={schema:"hia.original-log-frame-manifest.v1",context:ctx,files,frame_bytes:24576,
      frame_count:selected.reduce((n,i)=>n+payloads[i].length,0),
      total_raw_bytes:files.reduce((n,x)=>n+x.bytes,0),maximum_raw_bytes:8388608,maximum_stdout_bytes:12582912,
      original_product_statuses_reclassified:false,qualification_executed:false,
      original_source_artifact:{id:13907470026,bytes:12049642,
        sha256:"e6d54cec5c3788221827bf25a3189838dbc884211d89c3ef86afa129117319d8",
        run_id:43131161021,run_attempt:1,head_sha:"4d508b8e7b66d8f2801e76f6b6bb4794eb4bdac7"},
      source_originals_accepted:accepted,original_custody_status:accepted?"SOURCE_ONLY_CORE_EMITTER_V2_AUTHORING_PASS":null,
      missing_frame_targets:[],errors:accepted?[]:[{stage:"SOURCE_ACCEPTANCE",type:"SyntheticRefusal"}]};
    const raw=H.utf8(JSON.stringify(manifest)),digest=H.sha256(raw);
    const out=[{tag:"HIA_ORIGINAL_FRAME_MANIFEST_V1",value:{bytes:raw.length,sha256:digest,base64:H.b64(raw)}}];
    for(const i of selected)for(const f of payloads[i])out.push({tag:"HIA_ORIGINAL_FRAME_V1",value:{manifest_sha256:digest,...f}});
    out.push({tag:"HIA_ORIGINAL_FRAME_END_V1",value:{schema:"hia.original-log-frame-terminal.v1",
      status:accepted?"ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION":"FRAMING_HOLD",manifest_sha256:digest,
      files:files.length,frames:manifest.frame_count,raw_bytes:manifest.total_raw_bytes,source_bytes_complete:true,
      original_custody_status:manifest.original_custody_status,missing_frame_targets:[],
      original_product_statuses_reclassified:false,qualification_executed:false,result_sha256:"b".repeat(64)}});
    return out;
  }
  const full=records(inputs.map((_,i)=>i),true);
  function log(items){return "2026-11-12T00:00:00Z HIA_CORE_EMITTER_WORKFLOW_SHA: ignored-environment-example\n"+
    items.map(x=>"2026-11-12T00:00:01Z "+x.tag+" "+JSON.stringify(x.value)).join("\n")+"\n";}
  const observations=[];
  function test(name,items,wanted,exp=expected,pins=pinset){
    try{const result=decode(log(items),exp,pins,H);
      if(wanted==="REFUSE")throw Error("control unexpectedly accepted");
      if(wanted==="COMPLETE"&&(result.files.length!==59||result.terminal.status!=="ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION"))throw Error("full result differs");
      if(wanted==="HOLD"&&(result.files.length!==5||result.terminal.status!=="FRAMING_HOLD"||result.unaccounted_original_targets.length!==54))throw Error("HOLD custody differs");
      observations.push({name,status:"PASS",observed:wanted,files:result.files.length});
    }catch(error){if(wanted!=="REFUSE"||error.message==="control unexpectedly accepted")throw error;
      observations.push({name,status:"PASS",observed:"REFUSED",reason:error.message});}}
  test("complete54-plus-five-controls-with-independent-synthetic-hashes",full,"COMPLETE");
  test("source-rejected-HOLD-preserves-five-controls-without-promoting54",records(controls.map((_,i)=>54+i),false),"HOLD");
  test("missing-END",full.slice(0,-1),"REFUSE");
  test("wrong-workflow-binding",full,"REFUSE",{...expected,workflow_commit:"f".repeat(40)});
  const badFrame=full.slice();badFrame[1]={...badFrame[1],value:{...badFrame[1].value,sha256:"0".repeat(64)}};
  test("frame-byte-SHA-mismatch",badFrame,"REFUSE");
  const gap=full.slice();gap[1]={...gap[1],value:{...gap[1].value,offset:1}};
  test("first-frame-gap",gap,"REFUSE");
  const doubled=full.slice();doubled.splice(2,0,full[1]);test("duplicate-frame",doubled,"REFUSE");
  const wrongPin=JSON.parse(JSON.stringify(pinset));wrongPin.archive_members.find(x=>x.logical_path).sha256="0".repeat(64);
  test("fixed-original-SHA-mismatch",full,"REFUSE",expected,wrongPin);
  const badEnd=full.slice();badEnd[badEnd.length-1]={...badEnd.at(-1),value:{...badEnd.at(-1).value,frames:badEnd.at(-1).value.frames+1}};
  test("terminal-frame-count-mismatch",badEnd,"REFUSE");
  test("success-missing-one-current-control",records(inputs.map((_,i)=>i).slice(0,-1),true),"REFUSE");
  return {schema:"hia.core-emitter-generated-assets-decoder-controls.v1",status:"PASS",
    executed_controls:observations.length,observations,synthetic_selected_original_bytes:7251108,
    exact_real_product_or_artifact_bytes_used:false,actual_artifact_decoded:false,
    product_execution:false,native_execution:false,qualification:false};
}