function decode970OriginalLog(log, expected, H) {
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
  let framedStdoutBytes=0;
  for (const raw of log.split("\n")) {
    let line=raw.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"");
    if(line.endsWith("\r"))line=line.slice(0,-1);
    const p=prefixes.find(x=>line.startsWith(x+" "));
    if(p){
      require([...line].every(c=>c.charCodeAt(0)<128),"non-ASCII frame line");
      framedStdoutBytes+=line.length+1;
      require(framedStdoutBytes<=25165824,"actual framed stdout exceeds24MiB");
      records.push({prefix:p,value:JSON.parse(line.slice(p.length+1))});
    }
  }
  require(records.length>=2,"no complete manifest/terminal");
  require(records[0].prefix===prefixes[0]&&records.at(-1).prefix===prefixes[2],"frames missing first manifest or final END");
  require(records.filter(x=>x.prefix===prefixes[0]).length===1&&records.filter(x=>x.prefix===prefixes[2]).length===1&&records.every(x=>x.prefix!==prefixes[3]),"duplicate or failed frame stream");
  const sealed=records[0].value;
  require(isUint(sealed.bytes)&&sealed.bytes<=131072&&hex(sealed.sha256),"manifest seal shape");
  const manifestBytes=unbase64(sealed.base64);
  require(manifestBytes.length===sealed.bytes&&H.sha256(manifestBytes)===sealed.sha256,"manifest bytes/hash");
  const manifest=JSON.parse(utf8(manifestBytes));
  require(manifest.schema==="hia.original-log-frame-manifest.v1"&&manifest.frame_bytes===24576&&manifest.maximum_raw_bytes===16777216&&manifest.maximum_stdout_bytes===25165824,"manifest schema/budgets");
  require(manifest.qualification_executed===false&&manifest.original_product_statuses_reclassified===false,"false qualification/reclassification");
  const context=manifest.context;
  require(context&&context.repository==="TrillionniumFoundation/Hepta"&&context.event==="create"&&context.run_attempt===1&&context.run_id===expected.run_id,"run binding");
  require(context.actual_control_checkout===expected.control_commit&&context.actual_workflow_commit===expected.workflow_commit&&context.policy_sha256===expected.policy_sha256,"frozen code/policy binding");
  require(context.event_ref===expected.branch&&context.event_ref_type==="branch"&&context.original_product_commit===expected.product_commit&&context.original_product_tree===expected.product_tree,"source/branch binding");
  require(manifest.original_artifact?.id===13911977275
    &&manifest.original_artifact?.bytes===599427251
    &&manifest.original_artifact?.sha256==="40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580"
    &&manifest.original_artifact?.run_id===43140734709
    &&manifest.original_artifact?.checkout_commit==="9704596acc4470bd0042838586602e26bac7b3d1"
    &&manifest.original_artifact?.checkout_tree==="c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b","original970 artifact binding");
  require(manifest.maximum_original_download_GETs===1&&manifest.additional_artifact_downloads_for_framing===0,"single-GET framing scope");
  const selected=[
  "hia-machine-state-gate.json",
  "hia-machine-state-callers-evidence/report.json",
  "hia-machine-state-owner/run-result.json",
  "hia-machine-state-owner/process-owner.json",
  "hia-machine-state-owner/process-owner.json.request.json",
  "hia-machine-state-owner/stdout.log",
  "hia-machine-state-owner/stderr.log",
  "hia-machine-state-owner/process-owner.json.stdout.log",
  "hia-machine-state-owner/process-owner.json.stderr.log",
  "hia-machine-state-callers-evidence/component.unittest.log",
  "hia-machine-state-callers-evidence/original-callers.unittest.log",
  "hia-machine-instructions-gate.json",
  "hia-machine-instructions-callers-evidence/report.json",
  "hia-machine-instructions-owner/run-result.json",
  "hia-machine-instructions-owner/process-owner.json",
  "hia-machine-instructions-owner/process-owner.json.request.json",
  "hia-machine-instructions-owner/stdout.log",
  "hia-machine-instructions-owner/stderr.log",
  "hia-machine-instructions-owner/process-owner.json.stdout.log",
  "hia-machine-instructions-owner/process-owner.json.stderr.log",
  "hia-machine-instructions-callers-evidence/component.unittest.log",
  "hia-machine-instructions-callers-evidence/original-callers.unittest.log",
  "hia-core-lowering-gate.json",
  "hia-core-lowering-callers-evidence/report.json",
  "hia-core-lowering-owner/run-result.json",
  "hia-core-lowering-owner/process-owner.json",
  "hia-core-lowering-owner/process-owner.json.request.json",
  "hia-core-lowering-owner/stdout.log",
  "hia-core-lowering-owner/stderr.log",
  "hia-core-lowering-owner/process-owner.json.stdout.log",
  "hia-core-lowering-owner/process-owner.json.stderr.log",
  "hia-core-lowering-callers-evidence/component.unittest.log",
  "hia-core-lowering-callers-evidence/original-machine.unittest.log",
  "hia-core-lowering-callers-evidence/original-core.unittest.log",
  "hia-machine-elf-component-gate.json",
  "hia-machine-elf-component-evidence/report.json",
  "hia-machine-elf-component-owner/run-result.json",
  "hia-machine-elf-component-owner/process-owner.json",
  "hia-machine-elf-component-owner/process-owner.json.request.json",
  "hia-machine-elf-component-owner/stdout.log",
  "hia-machine-elf-component-owner/stderr.log",
  "hia-machine-elf-component-owner/process-owner.json.stdout.log",
  "hia-machine-elf-component-owner/process-owner.json.stderr.log",
  "hia-machine-elf-component-evidence/unittest.log",
  "hia-machine-elf-component-owner/component-child-gate.json",
  "hia-machine-elf-caller-gate.json",
  "hia-machine-elf-callers-evidence/report.json",
  "hia-machine-elf-callers-owner/run-result.json",
  "hia-machine-elf-callers-owner/process-owner.json",
  "hia-machine-elf-callers-owner/process-owner.json.request.json",
  "hia-machine-elf-callers-owner/stdout.log",
  "hia-machine-elf-callers-owner/stderr.log",
  "hia-machine-elf-callers-owner/process-owner.json.stdout.log",
  "hia-machine-elf-callers-owner/process-owner.json.stderr.log",
  "hia-cold.json",
  "hia-cold.cold/request.json",
  "hia-cold.cold/process-owner.json",
  "hia-cold.cold/process-owner.json.request.json",
  "hia-cold.cold/stdout.log",
  "hia-cold.cold/stderr.log",
  "hia-cold.cold/process-owner.json.stdout.log",
  "hia-cold.cold/process-owner.json.stderr.log",
  "hia-cold.cold/qualification.json",
  "hia-cold.cold/qualification.evidence/phase-index.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-original.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-capacity-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-capacity-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-modified.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-capacity-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-capacity-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-cfg-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-original.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-cfg-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-cfg-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-modified.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-cfg-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-cfg-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-elf-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-elf-original.json",
  "hia-cold.cold/qualification.evidence/phase-elf-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-elf-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-elf-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-elf-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-elf-modified.json",
  "hia-cold.cold/qualification.evidence/phase-elf-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-elf-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-elf-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-chain-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-chain-original.json",
  "hia-cold.cold/qualification.evidence/phase-chain-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-chain-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-chain-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-chain-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-chain-modified.json",
  "hia-cold.cold/qualification.evidence/phase-chain-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-chain-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-chain-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-owned-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-owned-original.json",
  "hia-cold.cold/qualification.evidence/phase-owned-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-owned-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-owned-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-owned-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-owned-modified.json",
  "hia-cold.cold/qualification.evidence/phase-owned-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-owned-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-owned-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-bulk-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-original.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-bulk-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-bulk-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-modified.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-bulk-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-bulk-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-loan-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-loan-original.json",
  "hia-cold.cold/qualification.evidence/phase-loan-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-loan-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-loan-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-loan-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-loan-modified.json",
  "hia-cold.cold/qualification.evidence/phase-loan-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-loan-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-loan-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-resource-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-resource-original.json",
  "hia-cold.cold/qualification.evidence/phase-resource-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-resource-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-resource-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-resource-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-resource-modified.json",
  "hia-cold.cold/qualification.evidence/phase-resource-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-resource-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-resource-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-tail-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-tail-original.json",
  "hia-cold.cold/qualification.evidence/phase-tail-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-tail-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-tail-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-tail-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-tail-modified.json",
  "hia-cold.cold/qualification.evidence/phase-tail-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-tail-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-tail-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-select-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-select-original.json",
  "hia-cold.cold/qualification.evidence/phase-select-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-select-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-select-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-select-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-select-modified.json",
  "hia-cold.cold/qualification.evidence/phase-select-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-select-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-select-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-effects-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-effects-original.json",
  "hia-cold.cold/qualification.evidence/phase-effects-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-effects-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-effects-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-effects-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-effects-modified.json",
  "hia-cold.cold/qualification.evidence/phase-effects-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-effects-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-effects-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-multi-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-multi-original.json",
  "hia-cold.cold/qualification.evidence/phase-multi-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-multi-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-multi-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-multi-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-multi-modified.json",
  "hia-cold.cold/qualification.evidence/phase-multi-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-multi-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-multi-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-keyword-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-original.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-keyword-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-keyword-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-modified.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-keyword-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-keyword-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-signed-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-signed-original.json",
  "hia-cold.cold/qualification.evidence/phase-signed-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-signed-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-signed-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-signed-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-signed-modified.json",
  "hia-cold.cold/qualification.evidence/phase-signed-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-signed-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-signed-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-original.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-original.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-cli-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-cli-original.json",
  "hia-cold.cold/qualification.evidence/phase-cli-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-cli-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-cli-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-cli-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-cli-modified.json",
  "hia-cold.cold/qualification.evidence/phase-cli-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-cli-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-cli-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-names-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-names-original.json",
  "hia-cold.cold/qualification.evidence/phase-names-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-names-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-names-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-names-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-names-modified.json",
  "hia-cold.cold/qualification.evidence/phase-names-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-names-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-names-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-exports-original.request.json",
  "hia-cold.cold/qualification.evidence/phase-exports-original.json",
  "hia-cold.cold/qualification.evidence/phase-exports-original.process.json",
  "hia-cold.cold/qualification.evidence/phase-exports-original.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-exports-original.stderr.log",
  "hia-cold.cold/qualification.evidence/phase-exports-modified.request.json",
  "hia-cold.cold/qualification.evidence/phase-exports-modified.json",
  "hia-cold.cold/qualification.evidence/phase-exports-modified.process.json",
  "hia-cold.cold/qualification.evidence/phase-exports-modified.stdout.log",
  "hia-cold.cold/qualification.evidence/phase-exports-modified.stderr.log",
  "hia-cold.cold/qualification.evidence/B0.receipt.json",
  "hia-cold.cold/qualification.evidence/B1.receipt.json",
  "hia-cold.cold/qualification.evidence/B1.request.json",
  "hia-cold.cold/qualification.evidence/B1.stdout.log",
  "hia-cold.cold/qualification.evidence/B1.stderr.log",
  "hia-cold.cold/qualification.evidence/B2.receipt.json",
  "hia-cold.cold/qualification.evidence/B2.request.json",
  "hia-cold.cold/qualification.evidence/B2.stdout.log",
  "hia-cold.cold/qualification.evidence/B2.stderr.log",
  "hia-cold.cold/qualification.evidence/B3.receipt.json",
  "hia-cold.cold/qualification.evidence/B3.request.json",
  "hia-cold.cold/qualification.evidence/B3.stdout.log",
  "hia-cold.cold/qualification.evidence/B3.stderr.log",
  "hia-cold.cold/qualification.evidence/M1.receipt.json",
  "hia-cold.cold/qualification.evidence/M1.request.json",
  "hia-cold.cold/qualification.evidence/M1.stdout.log",
  "hia-cold.cold/qualification.evidence/M1.stderr.log",
  "hia-cold.cold/qualification.evidence/M2.receipt.json",
  "hia-cold.cold/qualification.evidence/M2.request.json",
  "hia-cold.cold/qualification.evidence/M2.stdout.log",
  "hia-cold.cold/qualification.evidence/M2.stderr.log",
  "hia-cold.cold/qualification.evidence/M3.receipt.json",
  "hia-cold.cold/qualification.evidence/M3.request.json",
  "hia-cold.cold/qualification.evidence/M3.stdout.log",
  "hia-cold.cold/qualification.evidence/M3.stderr.log",
  "hia-cold.cold/qualification.evidence/native-observer-build.json",
  "hia-cold.cold/qualification.evidence/linked-observer-build.json",
  "hia-cold.cold/qualification.evidence/independent-native-observer-reference.json",
  "hia-cold.cold/qualification.evidence/independent-linked-observer-reference.json",
  "hia-cold.cold/qualification.evidence/native-observer-packer.receipt.json",
  "hia-cold.cold/qualification.evidence/native-observer-packer.request.json",
  "hia-cold.cold/qualification.evidence/native-observer-packer.stdout.log",
  "hia-cold.cold/qualification.evidence/native-observer-packer.stderr.log",
  "hia-cold.cold/qualification.evidence/native-observer-emit.receipt.json",
  "hia-cold.cold/qualification.evidence/native-observer-emit.request.json",
  "hia-cold.cold/qualification.evidence/native-observer-emit.stdout.log",
  "hia-cold.cold/qualification.evidence/native-observer-emit.stderr.log",
  "hia-cold.cold/qualification.evidence/linked-observer-policy.receipt.json",
  "hia-cold.cold/qualification.evidence/linked-observer-policy.request.json",
  "hia-cold.cold/qualification.evidence/linked-observer-policy.stdout.log",
  "hia-cold.cold/qualification.evidence/linked-observer-policy.stderr.log",
  "hia-cold.cold/qualification.evidence/linked-observer-packer.receipt.json",
  "hia-cold.cold/qualification.evidence/linked-observer-packer.request.json",
  "hia-cold.cold/qualification.evidence/linked-observer-packer.stdout.log",
  "hia-cold.cold/qualification.evidence/linked-observer-packer.stderr.log",
  "hia-cold.cold/qualification.evidence/linked-observer-emit.receipt.json",
  "hia-cold.cold/qualification.evidence/linked-observer-emit.request.json",
  "hia-cold.cold/qualification.evidence/linked-observer-emit.stdout.log",
  "hia-cold.cold/qualification.evidence/linked-observer-emit.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-exports.worker.json",
  "hia-cold.cold/qualification.evidence/reference-exports.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-exports.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-names.worker.json",
  "hia-cold.cold/qualification.evidence/reference-names.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-names.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-cli.worker.json",
  "hia-cold.cold/qualification.evidence/reference-cli.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-cli.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-explicit-traps.worker.json",
  "hia-cold.cold/qualification.evidence/reference-explicit-traps.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-explicit-traps.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-resource.worker.json",
  "hia-cold.cold/qualification.evidence/reference-resource.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-resource.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-bulk.worker.json",
  "hia-cold.cold/qualification.evidence/reference-bulk.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-bulk.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-loan.worker.json",
  "hia-cold.cold/qualification.evidence/reference-loan.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-loan.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-cfg.worker.json",
  "hia-cold.cold/qualification.evidence/reference-cfg.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-cfg.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-capacity.worker.json",
  "hia-cold.cold/qualification.evidence/reference-capacity.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-capacity.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-tail.worker.json",
  "hia-cold.cold/qualification.evidence/reference-tail.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-tail.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-select.worker.json",
  "hia-cold.cold/qualification.evidence/reference-select.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-select.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-effects.worker.json",
  "hia-cold.cold/qualification.evidence/reference-effects.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-effects.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-multi.worker.json",
  "hia-cold.cold/qualification.evidence/reference-multi.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-multi.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-keyword.worker.json",
  "hia-cold.cold/qualification.evidence/reference-keyword.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-keyword.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-signed.worker.json",
  "hia-cold.cold/qualification.evidence/reference-signed.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-signed.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-scalar-casts.worker.json",
  "hia-cold.cold/qualification.evidence/reference-scalar-casts.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-scalar-casts.stderr.log",
  "hia-cold.cold/qualification.evidence/reference-core.worker.json",
  "hia-cold.cold/qualification.evidence/reference-core.stdout.log",
  "hia-cold.cold/qualification.evidence/reference-core.stderr.log"
];
  const original=new Set(selected.map(x=>"original/"+x));
  const controls=new Set(["custody/guard/guardian.json","custody/guard/child.stdout.log","custody/guard/child.stderr.log","custody/recovery-terminal.json","custody/setup.json","custody/FINAL.json"]);
  require(original.size===354&&Array.isArray(manifest.files)&&manifest.files.length<=360,"fixed354+6 frame file denominator");
  const missing=manifest.missing_frame_targets;
  require(Array.isArray(missing)&&new Set(missing).size===missing.length&&missing.every(x=>selected.includes(x))
    &&JSON.stringify(missing)===JSON.stringify(selected.filter(x=>missing.includes(x))),"ordered missing fixed target ledger");
  const logicalMissing=new Set(missing.map(x=>"original/"+x));
  const files=new Map();
  let rawCount=0, expectedFrames=0;
  for(const pin of manifest.files) {
    require(pin&&typeof pin.path==="string"&&!files.has(pin.path)&&(original.has(pin.path)||controls.has(pin.path))&&isUint(pin.bytes)&&pin.bytes<=16777216&&hex(pin.sha256),"file pin/path/duplicate");
    require(!logicalMissing.has(pin.path),"present target also missing");
    rawCount+=pin.bytes;expectedFrames+=Math.ceil(pin.bytes/24576);
    require(rawCount<=16777216,"raw output bound");
    files.set(pin.path,{pin,bytes:new Uint8Array(pin.bytes),offset:0,frames:0});
  }
  const unaccounted=[...original].filter(x=>!files.has(x)&&!logicalMissing.has(x));
  require(unaccounted.length===0,"unaccounted original target");
  if(manifest.source_originals_accepted===true)require(missing.length===0&&[...controls].every(x=>files.has(x))&&files.size===360,"complete custody omitted original/control");
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
  const final=files.get("custody/FINAL.json");
  if(final){
    const value=JSON.parse(utf8(final.bytes));
    require(value.schema==="hia.actions.970-original-custody-final.v1"
      &&value.context.actual_control_checkout===expected.control_commit
      &&value.context.actual_workflow_commit===expected.workflow_commit
      &&value.context.policy_sha256===expected.policy_sha256
      &&value.context.run_id===expected.run_id
      &&value.status===manifest.original_custody_status
      &&value.qualification_executed===false
      &&value.original_product_statuses_reclassified===false
      &&value.original_CI_rerun===false,"actual current FINAL identity/scope");
    if(end.status==="ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION")require(
      value.status==="EXACT970_ORIGINAL_CI_SMALL_CUSTODY_READY_NOT_QUALIFICATION"
      &&value.capture_complete===true&&value.source_bound_originals_and_natural_owner_accepted===true
      &&Array.isArray(value.errors)&&value.errors.length===0,"complete FINAL original custody");
  }
  return {manifest_raw:manifestBytes,manifest,terminal:end,unaccounted_original_targets:unaccounted,files:[...files].map(([path,f])=>({path,bytes:f.bytes,sha256:f.pin.sha256,origin:f.pin.origin})),records:records.length,decodeUTF8:utf8};
}
