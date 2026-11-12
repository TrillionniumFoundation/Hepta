function decodeCoreFailedReaderDiagnostics(log, expected, pins, H) {
  const fail = message => { throw new Error(message); };
  const require = (value, message) => { if (!value) fail(message); };
  const isUint = value => Number.isSafeInteger(value) && value >= 0;
  const hex = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  function unbase64(value) {
    require(typeof value === "string" && value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), "invalid canonical base64");
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const pad = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
    const bytes = new Uint8Array(value.length / 4 * 3 - pad);
    let offset = 0;
    for (let i=0;i<value.length;i+=4) {
      const a=chars.indexOf(value[i]), b=chars.indexOf(value[i+1]);
      const c=value[i+2] === "=" ? 0 : chars.indexOf(value[i+2]);
      const d=value[i+3] === "=" ? 0 : chars.indexOf(value[i+3]);
      if (i + 4 === value.length && pad === 2) require((b & 15) === 0, "nonzero base64 padding");
      if (i + 4 === value.length && pad === 1) require((c & 3) === 0, "nonzero base64 padding");
      const n=(a<<18)|(b<<12)|(c<<6)|d;
      if (offset<bytes.length) bytes[offset++]=(n>>>16)&255;
      if (offset<bytes.length) bytes[offset++]=(n>>>8)&255;
      if (offset<bytes.length) bytes[offset++]=n&255;
    }
    return bytes;
  }
  function utf8(bytes) {
    let result = "";
    for (let i=0;i<bytes.length;) {
      const a=bytes[i++]; let n, remain, min;
      if (a<128) { result+=String.fromCharCode(a); continue; }
      if(a>=194&&a<=223){n=a&31;remain=1;min=128;}
      else if(a>=224&&a<=239){n=a&15;remain=2;min=2048;}
      else if(a>=240&&a<=244){n=a&7;remain=3;min=65536;}
      else fail("invalid UTF8 leading byte");
      require(i+remain<=bytes.length,"truncated UTF8");
      for(let j=0;j<remain;j++){const c=bytes[i++];require((c&192)===128,"invalid UTF8 continuation");n=(n<<6)|(c&63);}
      require(n>=min&&n<=0x10ffff&&!(n>=0xd800&&n<=0xdfff),"invalid UTF8 codepoint");
      result+=String.fromCodePoint(n);
    }
    return result;
  }
  const statuses = new Set(["DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED","DIAGNOSTIC_HOLD"]);
  const prefixes = ["HIA_CORE_READER_DIAGNOSTIC_MANIFEST_V1","HIA_CORE_READER_DIAGNOSTIC_FRAME_V1",
                    "HIA_CORE_READER_DIAGNOSTIC_END_V1","HIA_CORE_READER_DIAGNOSTIC_FAILURE_V1"];
  const records=[];
  for(const raw of log.split("\n")){
    let line=raw.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"");
    if(line.endsWith("\r"))line=line.slice(0,-1);
    const p=prefixes.find(x=>line.startsWith(x+" "));
    if(p)records.push({prefix:p,value:JSON.parse(line.slice(p.length+1)),raw_line:line});
  }
  require(records.length>=2 && records[0].prefix===prefixes[0] &&
          records.at(-1).prefix===prefixes[2],"missing first manifest or final END");
  require(records.filter(x=>x.prefix===prefixes[0]).length===1 &&
          records.filter(x=>x.prefix===prefixes[2]).length===1 &&
          records.every(x=>x.prefix!==prefixes[3]),"duplicate or failed frame stream");
  const sealed=records[0].value;
  require(isUint(sealed.bytes)&&sealed.bytes<=65536&&hex(sealed.sha256),"manifest seal shape");
  const manifestBytes=unbase64(sealed.base64);
  require(manifestBytes.length===sealed.bytes&&H.sha256(manifestBytes)===sealed.sha256,"manifest bytes/hash");
  const manifest=JSON.parse(utf8(manifestBytes));
  require(manifest.schema==="hia.core-failed-reader-diagnostic-frame-manifest.v1"
          && manifest.frame_bytes===8192 && manifest.maximum_raw_bytes===524288
          && manifest.maximum_stdout_bytes===1048576,"fixed diagnostic framing limits");
  require(manifest.original_run_conclusion==="failure" && manifest.original_failed_run_id===43152508792
          && manifest.original_failure_reclassified===false && manifest.qualification_executed===false
          && manifest.assembly_body_bytes_output===0,"original failure or no-body scope changed");
  require(typeof manifest.diagnostics_accepted==="boolean" && Array.isArray(manifest.errors),
          "diagnostic acceptance and errors shape");
  const context=manifest.context;
  require(context && context.schema==="hia.actions.core-failed-reader-diagnostic-context.v1"
          && context.repository==="TrillionniumFoundation/Hepta" && context.event==="create"
          && context.run_attempt===1 && context.run_id===expected.run_id
          && context.actual_control_checkout===expected.control_commit
          && context.actual_workflow_commit===expected.workflow_commit
          && context.policy_sha256===expected.policy_sha256 && context.event_ref===expected.branch
          && context.event_ref_type==="branch" && context.token_or_signed_URL_in_context===false
          && context.qualification_executed===false
          && context.original_product_commit==="80ec04ae7489209b122c874531d194c67b30dfed"
          && context.original_product_tree==="963e980c2486e1f7c74fa42bc8132ef6b1b8b690",
          "exact new diagnostic operation binding");
  require(manifest.failed_artifact?.id===13915070523
          && manifest.failed_artifact?.bytes===7381515
          && manifest.failed_artifact?.sha256==="57e3f0db194d961e64dd4773b04dddf373fe5ca02ea2763924d0ec5040d2a2f8"
          && manifest.failed_artifact?.run_id===43152508792
          && manifest.failed_artifact?.run_attempt===1
          && manifest.failed_artifact?.head_sha==="6049861e92f0f68dacaf3101bfdb0f98f06c9930"
          && manifest.failed_artifact?.name==="hia-core-emitter-generated-assets-43152508792-1",
          "exact failed original artifact binding");
  require(pins?.schema==="hia.core-failed-reader-diagnostic-pins.v1"
          && Array.isArray(pins.historical_targets) && pins.historical_targets.length===54
          && pins.assembly_output===false && pins.original_failure_reclassified===false,
          "frozen diagnostic target policy");
  const historical=new Map(pins.historical_targets.filter(x=>x.role==="original")
      .map(x=>[x.logical_path,x]));
  require(historical.size===14 && [...historical.values()].reduce((n,x)=>n+x.bytes,0)===161859,
          "fixed fourteen historical control originals");
  const original=new Set([...historical.keys(),...pins.reader_targets.map(x=>x.logical_path),
                          pins.frame_result.logical_path]);
  require(original.size===20 && [...original].every(p=>!p.startsWith("source/")),
          "twenty fixed diagnostic targets; no assembly body");
  const controls=new Set(["diagnostic-reader/guard/guardian.json","diagnostic-reader/guard/child.stdout.log",
      "diagnostic-reader/guard/child.stderr.log","diagnostic-reader/recovery-terminal.json",
      "diagnostic-reader/setup.json"]);
  require(Array.isArray(manifest.files)&&manifest.files.length<=25,"diagnostic file denominator");
  const missing=manifest.missing_diagnostic_targets;
  require(Array.isArray(missing)&&new Set(missing).size===missing.length
          && missing.every(x=>original.has(x)),"missing target ledger");
  const files=new Map();
  let rawCount=0,expectedFrames=0;
  for(const pin of manifest.files){
    require(pin && typeof pin.path==="string" && !files.has(pin.path)
            && (original.has(pin.path)||controls.has(pin.path)) && isUint(pin.bytes)
            && pin.bytes<=524288 && hex(pin.sha256) && !missing.includes(pin.path),
            "diagnostic file pin/path/duplicate");
    if(historical.has(pin.path)){const frozen=historical.get(pin.path);
      require(pin.bytes===frozen.bytes&&pin.sha256===frozen.sha256,
              "historical diagnostic differs from independent frozen bytes");}
    rawCount+=pin.bytes;expectedFrames+=Math.ceil(pin.bytes/8192);
    require(rawCount<=524288,"raw diagnostic budget");
    files.set(pin.path,{pin,bytes:new Uint8Array(pin.bytes),offset:0,frames:0});
  }
  const unaccounted=[...original].filter(x=>!files.has(x)&&!missing.includes(x));
  if(manifest.diagnostics_accepted===true)require(unaccounted.length===0,"unaccounted diagnostic original");
  require(rawCount===manifest.total_raw_bytes&&expectedFrames===manifest.frame_count
          && isUint(manifest.frame_count),"manifest aggregate counts");
  let frames=0,bytesCount=0,currentFile=0;
  const ordered=[...files.values()];
  for(const record of records.slice(1,-1)){
    require(record.prefix===prefixes[1],"non-frame between manifest and END");
    const f=record.value;
    require(f.manifest_sha256===sealed.sha256&&files.has(f.path)&&isUint(f.offset)
            &&isUint(f.length)&&f.length>0&&f.length<=8192&&hex(f.sha256),"frame header");
    while(currentFile<ordered.length&&ordered[currentFile].offset===ordered[currentFile].pin.bytes)currentFile++;
    const target=files.get(f.path);
    require(ordered[currentFile]===target&&f.offset===target.offset
            &&f.length===Math.min(8192,target.pin.bytes-target.offset),"frame order/gap/overlap");
    const bytes=unbase64(f.base64);
    require(bytes.length===f.length&&H.sha256(bytes)===f.sha256,"frame complete bytes/hash");
    target.bytes.set(bytes,target.offset);target.offset+=bytes.length;target.frames++;frames++;bytesCount+=bytes.length;
  }
  for(const f of files.values())require(f.offset===f.pin.bytes&&H.sha256(f.bytes)===f.pin.sha256,
                                      "complete diagnostic original bytes/hash");
  const end=records.at(-1).value;
  require(end.schema==="hia.core-failed-reader-diagnostic-frame-terminal.v1"&&statuses.has(end.status)
          &&hex(end.result_sha256)&&end.diagnostic_bytes_complete===true,"complete diagnostic END");
  require(end.manifest_sha256===sealed.sha256&&end.files===files.size&&end.frames===frames
          &&end.raw_bytes===bytesCount&&frames===expectedFrames&&bytesCount===rawCount,
          "diagnostic END aggregate binding");
  require(end.original_run_conclusion==="failure"&&end.original_failure_reclassified===false
          &&end.assembly_body_bytes_output===0&&end.qualification_executed===false
          &&JSON.stringify(end.missing_diagnostic_targets)===JSON.stringify(missing),"END failure scope");
  if(end.status==="DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED"){
    require(manifest.diagnostics_accepted===true&&Array.isArray(manifest.errors)&&manifest.errors.length===0
            &&unaccounted.length===0&&[...controls].every(x=>files.has(x)),
            "complete diagnostic stream lacks bound originals/current controls");
    const expectedOrder=[...original].filter(x=>!missing.includes(x));
    require(JSON.stringify(manifest.files.slice(0,expectedOrder.length).map(x=>x.path))===
            JSON.stringify(expectedOrder),"fixed original diagnostic output order");
  }else if(manifest.diagnostics_accepted===false){
    require([...files.keys()].every(x=>controls.has(x)),"rejected diagnostics claim accepted original files");
  }
  for(const [path,f]of files){
    if(!historical.has(path))continue;
    const prefix=H.utf8("blob "+f.bytes.length+String.fromCharCode(0));
    const object=new Uint8Array(prefix.length+f.bytes.length);object.set(prefix);object.set(f.bytes,prefix.length);
    require(H.sha1(object)===historical.get(path).git_blob_sha1,"historical Git blob identity");
  }
  const framedBytes=records.reduce((n,r)=>n+H.utf8(r.raw_line+"\n").length,0);
  require(framedBytes<=1048576,"actual bounded diagnostic stdout");
  return {manifest_raw:manifestBytes,manifest,terminal:end,unaccounted_original_targets:unaccounted,
    files:[...files].map(([path,f])=>({path,bytes:f.bytes,sha256:f.pin.sha256,origin:f.pin.origin})),
    records:records.length,framed_bytes:framedBytes,decodeUTF8:utf8};
}
