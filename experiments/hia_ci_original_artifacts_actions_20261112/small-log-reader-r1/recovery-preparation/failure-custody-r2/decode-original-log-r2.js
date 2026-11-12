function decodeOriginalLog(log, expected, H) {
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
  const statuses = new Set(["ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION","FRAMING_HOLD"]);
  const prefixes = ["HIA_ORIGINAL_FRAME_MANIFEST_V1","HIA_ORIGINAL_FRAME_V1","HIA_ORIGINAL_FRAME_END_V1","HIA_ORIGINAL_FRAME_FAILURE_V1"];
  const records=[];
  for (const raw of log.split("\n")) {
    let line=raw.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"");
    if(line.endsWith("\r"))line=line.slice(0,-1);
    const p=prefixes.find(x=>line.startsWith(x+" "));
    if(p) records.push({prefix:p,value:JSON.parse(line.slice(p.length+1))});
  }
  require(records.length>=2,"no complete manifest/terminal");
  require(records[0].prefix===prefixes[0]&&records.at(-1).prefix===prefixes[2],"frames missing first manifest or final END");
  require(records.filter(x=>x.prefix===prefixes[0]).length===1&&records.filter(x=>x.prefix===prefixes[2]).length===1&&records.every(x=>x.prefix!==prefixes[3]),"duplicate or failed frame stream");
  const sealed=records[0].value;
  require(isUint(sealed.bytes)&&sealed.bytes<=131072&&hex(sealed.sha256),"manifest seal shape");
  const manifestBytes=unbase64(sealed.base64);
  require(manifestBytes.length===sealed.bytes&&H.sha256(manifestBytes)===sealed.sha256,"manifest bytes/hash");
  const manifest=JSON.parse(utf8(manifestBytes));
  require(manifest.schema==="hia.original-log-frame-manifest.v1"&&manifest.frame_bytes===24576&&manifest.maximum_raw_bytes===8388608&&manifest.maximum_stdout_bytes===12582912,"manifest schema/budgets");
  require(manifest.qualification_executed===false&&manifest.original_product_statuses_reclassified===false,"false qualification/reclassification");
  const context=manifest.context;
  require(context&&context.repository==="TrillionniumFoundation/Hepta"&&context.event==="create"&&context.run_attempt===1&&context.run_id===expected.run_id,"run binding");
  require(context.actual_control_checkout===expected.control_commit&&context.actual_workflow_commit===expected.workflow_commit&&context.policy_sha256===expected.policy_sha256,"frozen code/policy binding");
  require(context.event_ref===expected.branch&&context.event_ref_type==="branch"&&context.original_product_commit===expected.product_commit&&context.original_product_tree===expected.product_tree,"source/branch binding");
  require(manifest.original_small_artifact?.id===13905131691&&manifest.original_small_artifact?.bytes===35868688&&manifest.original_small_artifact?.sha256==="0bdd2c0eb471e21cee980e00c397f5fa2e2e681dcdc16cadec2174798bf2412d","small artifact binding");
  const original=new Set(["small/FINAL.json"]);
  for(const id of ["13901601239","13900618647"]){
    for(const p of ["CUSTODY.json","SELECTED.json","OBSERVATIONS.json","hia-machine-elf-caller-gate.json","hia-machine-elf-callers-evidence/report.json","hia-machine-elf-callers-owner/run-result.json","hia-machine-elf-callers-owner/process-owner.json","hia-machine-elf-callers-owner/stdout.log","hia-machine-elf-callers-owner/stderr.log","hia-machine-elf-callers-owner/process-owner.json.stdout.log","hia-machine-elf-callers-owner/process-owner.json.stderr.log"])original.add("original/"+id+"/"+p);
  }
  const controls=new Set(["reader/guard/guardian.json","reader/guard/child.stdout.log","reader/guard/child.stderr.log","reader/recovery-terminal.json","reader/setup.json"]);
  require(original.size===23&&Array.isArray(manifest.files)&&manifest.files.length<=28,"fixed frame file denominator");
  const missing=manifest.missing_frame_targets;
  require(Array.isArray(missing)&&new Set(missing).size===missing.length&&missing.every(x=>original.has(x)),"missing fixed target ledger");
  const files=new Map();
  let rawCount=0, expectedFrames=0;
  for(const pin of manifest.files) {
    require(pin&&typeof pin.path==="string"&&!files.has(pin.path)&&(original.has(pin.path)||controls.has(pin.path))&&isUint(pin.bytes)&&pin.bytes<=8388608&&hex(pin.sha256),"file pin/path/duplicate");
    require(!missing.includes(pin.path),"present target also missing");
    rawCount+=pin.bytes;expectedFrames+=Math.ceil(pin.bytes/24576);
    require(rawCount<=8388608,"raw output bound");
    files.set(pin.path,{pin,bytes:new Uint8Array(pin.bytes),offset:0,frames:0});
  }
  const unaccounted=[...original].filter(x=>!files.has(x)&&!missing.includes(x));
  if(manifest.source_originals_accepted===true)require(unaccounted.length===0,"unaccounted original target");
  require(rawCount===manifest.total_raw_bytes&&expectedFrames===manifest.frame_count&&isUint(manifest.frame_count),"manifest aggregate denominator");
  let frames=0,bytesCount=0,currentFile=0;
  const ordered=[...files.values()];
  for(const record of records.slice(1,-1)){
    require(record.prefix===prefixes[1],"non-frame between manifest/END");
    const f=record.value;
    require(f.manifest_sha256===sealed.sha256&&files.has(f.path)&&isUint(f.offset)&&isUint(f.length)&&f.length>0&&f.length<=24576&&hex(f.sha256),"frame header");
    while(currentFile<ordered.length&&ordered[currentFile].offset===ordered[currentFile].pin.bytes)currentFile++;
    const target=files.get(f.path);
    require(ordered[currentFile]===target&&f.offset===target.offset&&f.length===Math.min(24576,target.pin.bytes-target.offset),"frame ordering/gap/overlap/length");
    const bytes=unbase64(f.base64);
    require(bytes.length===f.length&&H.sha256(bytes)===f.sha256,"frame exact bytes/hash");
    target.bytes.set(bytes,target.offset);target.offset+=bytes.length;target.frames++;frames++;bytesCount+=bytes.length;
  }
  for(const file of files.values())require(file.offset===file.pin.bytes&&H.sha256(file.bytes)===file.pin.sha256,"complete raw file bytes/hash");
  const end=records.at(-1).value;
  require(end.schema==="hia.original-log-frame-terminal.v1"&&statuses.has(end.status)&&hex(end.result_sha256)&&end.source_bytes_complete===true,"complete terminal marker");
  require(end.manifest_sha256===sealed.sha256&&end.files===files.size&&end.frames===frames&&end.raw_bytes===bytesCount&&frames===expectedFrames&&bytesCount===rawCount,"END aggregate binding");
  require(end.qualification_executed===false&&end.original_product_statuses_reclassified===false&&end.original_custody_status===manifest.original_custody_status&&JSON.stringify(end.missing_frame_targets)===JSON.stringify(missing),"END scope/original status");
  if(end.status==="ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION")require(manifest.source_originals_accepted===true&&Array.isArray(manifest.errors)&&manifest.errors.length===0,"complete stream has source errors");
  const final=files.get("small/FINAL.json");
  if(final)require(final.pin.sha256==="a0c87bc6fee4dec1bf8acf995aab6634e56b8f8afa5cdd19638d3329ff0a0fef","original FINAL external log seal");
  return {manifest_raw:manifestBytes,manifest,terminal:end,unaccounted_original_targets:unaccounted,files:[...files].map(([path,f])=>({path,bytes:f.bytes,sha256:f.pin.sha256,origin:f.pin.origin})),records:records.length,decodeUTF8:utf8};
}
