function decode970SmallRecoveryLog(log, expected, H) {
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
  require(expected && isUint(expected.run_id) && expected.run_id > 0,
    "actual unique run ID must be externally bound");
  const statuses = new Set(["ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION","FRAMING_HOLD"]);
  const prefixes = ["HIA_ORIGINAL_FRAME_MANIFEST_V1","HIA_ORIGINAL_FRAME_V1","HIA_ORIGINAL_FRAME_END_V1","HIA_ORIGINAL_FRAME_FAILURE_V1"];
  const records=[];
  let framedStdoutBytes=0;
  for(const raw of log.split("\n")){
    let line=raw.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"");
    if(line.endsWith("\r"))line=line.slice(0,-1);
    const prefix=prefixes.find(x=>line.startsWith(x+" "));
    if(prefix){
      for(let i=0;i<line.length;i++)require(line.charCodeAt(i)<128,"non-ASCII frame line");
      framedStdoutBytes+=line.length+1;
      require(framedStdoutBytes<=50331648,"actual framed stdout exceeds48MiB");
      records.push({prefix,value:JSON.parse(line.slice(prefix.length+1))});
    }
  }
  require(records.length>=2,"no complete manifest/terminal");
  require(records[0].prefix===prefixes[0]&&records.at(-1).prefix===prefixes[2],
    "frames missing first manifest or final END");
  require(records.filter(x=>x.prefix===prefixes[0]).length===1
    &&records.filter(x=>x.prefix===prefixes[2]).length===1
    &&records.every(x=>x.prefix!==prefixes[3]),"duplicate or failed frame stream");
  const sealed=records[0].value;
  require(isUint(sealed.bytes)&&sealed.bytes<=262144&&hex(sealed.sha256),"manifest seal shape");
  const manifestBytes=unbase64(sealed.base64);
  require(manifestBytes.length===sealed.bytes&&H.sha256(manifestBytes)===sealed.sha256,
    "manifest bytes/hash");
  const manifest=JSON.parse(utf8(manifestBytes)),context=manifest.context;
  require(manifest.schema==="hia.original-log-frame-manifest.v1"
    &&manifest.frame_bytes===24576&&manifest.maximum_raw_bytes===33554432
    &&manifest.maximum_stdout_bytes===50331648,"manifest schema/budgets");
  require(manifest.qualification_executed===false&&manifest.original_product_statuses_reclassified===false,
    "false qualification/reclassification");
  require(context&&context.schema==="hia.actions.970-small-recovery-context.v1"
    &&context.repository==="TrillionniumFoundation/Hepta"
    &&context.event==="create"&&context.run_attempt===1&&context.run_id===expected.run_id,
    "actual unique run binding");
  require(context.actual_control_checkout===expected.control_commit
    &&context.actual_workflow_commit===expected.workflow_commit
    &&context.policy_sha256===expected.policy_sha256,"frozen code/policy binding");
  require(context.event_ref===expected.branch&&context.event_ref_type==="branch"
    &&context.original_product_commit==="9704596acc4470bd0042838586602e26bac7b3d1"
    &&context.original_product_tree==="c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b",
    "original970 source/branch binding");
  require(manifest.original_small_artifact?.id===13913382201
    &&manifest.original_small_artifact?.bytes===22390611
    &&manifest.original_small_artifact?.sha256==="58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d"
    &&manifest.original_small_artifact?.run_id===43150215535
    &&manifest.original_small_artifact?.checkout_commit==="896cb5ceaf8a34c9263b26e8131886285042cea6",
    "one actual small artifact identity");
  require(manifest.original_custody_run_id===43150215535
    &&manifest.original_final_sha256==="afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345"
    &&manifest.original_custody_status==="CUSTODY_HOLD"
    &&manifest.additional_large_artifact_downloads===0
    &&manifest.expected_historical_target_count===371
    &&manifest.maximum_reader_control_count===5,"historical HOLD and recovery scope");
  const historicalOrder=[
  "custody/FINAL.json",
  "custody/FRAME-RESULT.json",
  "custody/context.json",
  "custody/setup.json",
  "custody/recovery.json",
  "custody/recovery-terminal.json",
  "custody/supervisor.stdout.log",
  "custody/supervisor.stderr.log",
  "custody/guard/request.json",
  "custody/guard/guardian.json",
  "custody/guard/child.stdout.log",
  "custody/guard/child.stderr.log",
  "custody/api/artifact-13911977275.metadata.original.json",
  "custody/selected/13911977275/DIRECTORY.json",
  "custody/selected/13911977275/SELECTED.json",
  "custody/selected/13911977275/CUSTODY.json",
  "custody/selected/13911977275/OBSERVATIONS.json",
  "original/hia-machine-state-gate.json",
  "original/hia-machine-state-callers-evidence/report.json",
  "original/hia-machine-state-owner/run-result.json",
  "original/hia-machine-state-owner/process-owner.json",
  "original/hia-machine-state-owner/process-owner.json.request.json",
  "original/hia-machine-state-owner/stdout.log",
  "original/hia-machine-state-owner/stderr.log",
  "original/hia-machine-state-owner/process-owner.json.stdout.log",
  "original/hia-machine-state-owner/process-owner.json.stderr.log",
  "original/hia-machine-state-callers-evidence/component.unittest.log",
  "original/hia-machine-state-callers-evidence/original-callers.unittest.log",
  "original/hia-machine-instructions-gate.json",
  "original/hia-machine-instructions-callers-evidence/report.json",
  "original/hia-machine-instructions-owner/run-result.json",
  "original/hia-machine-instructions-owner/process-owner.json",
  "original/hia-machine-instructions-owner/process-owner.json.request.json",
  "original/hia-machine-instructions-owner/stdout.log",
  "original/hia-machine-instructions-owner/stderr.log",
  "original/hia-machine-instructions-owner/process-owner.json.stdout.log",
  "original/hia-machine-instructions-owner/process-owner.json.stderr.log",
  "original/hia-machine-instructions-callers-evidence/component.unittest.log",
  "original/hia-machine-instructions-callers-evidence/original-callers.unittest.log",
  "original/hia-core-lowering-gate.json",
  "original/hia-core-lowering-callers-evidence/report.json",
  "original/hia-core-lowering-owner/run-result.json",
  "original/hia-core-lowering-owner/process-owner.json",
  "original/hia-core-lowering-owner/process-owner.json.request.json",
  "original/hia-core-lowering-owner/stdout.log",
  "original/hia-core-lowering-owner/stderr.log",
  "original/hia-core-lowering-owner/process-owner.json.stdout.log",
  "original/hia-core-lowering-owner/process-owner.json.stderr.log",
  "original/hia-core-lowering-callers-evidence/component.unittest.log",
  "original/hia-core-lowering-callers-evidence/original-machine.unittest.log",
  "original/hia-core-lowering-callers-evidence/original-core.unittest.log",
  "original/hia-machine-elf-component-gate.json",
  "original/hia-machine-elf-component-evidence/report.json",
  "original/hia-machine-elf-component-owner/run-result.json",
  "original/hia-machine-elf-component-owner/process-owner.json",
  "original/hia-machine-elf-component-owner/process-owner.json.request.json",
  "original/hia-machine-elf-component-owner/stdout.log",
  "original/hia-machine-elf-component-owner/stderr.log",
  "original/hia-machine-elf-component-owner/process-owner.json.stdout.log",
  "original/hia-machine-elf-component-owner/process-owner.json.stderr.log",
  "original/hia-machine-elf-component-evidence/unittest.log",
  "original/hia-machine-elf-component-owner/component-child-gate.json",
  "original/hia-machine-elf-caller-gate.json",
  "original/hia-machine-elf-callers-evidence/report.json",
  "original/hia-machine-elf-callers-owner/run-result.json",
  "original/hia-machine-elf-callers-owner/process-owner.json",
  "original/hia-machine-elf-callers-owner/process-owner.json.request.json",
  "original/hia-machine-elf-callers-owner/stdout.log",
  "original/hia-machine-elf-callers-owner/stderr.log",
  "original/hia-machine-elf-callers-owner/process-owner.json.stdout.log",
  "original/hia-machine-elf-callers-owner/process-owner.json.stderr.log",
  "original/hia-cold.json",
  "original/hia-cold.cold/request.json",
  "original/hia-cold.cold/process-owner.json",
  "original/hia-cold.cold/process-owner.json.request.json",
  "original/hia-cold.cold/stdout.log",
  "original/hia-cold.cold/stderr.log",
  "original/hia-cold.cold/process-owner.json.stdout.log",
  "original/hia-cold.cold/process-owner.json.stderr.log",
  "original/hia-cold.cold/qualification.json",
  "original/hia-cold.cold/qualification.evidence/phase-index.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-capacity-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-cfg-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-elf-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-elf-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-elf-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-elf-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-elf-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-chain-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-chain-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-chain-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-chain-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-chain-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-owned-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-owned-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-owned-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-owned-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-owned-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-bulk-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-loan-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-loan-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-loan-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-loan-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-loan-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-resource-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-resource-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-resource-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-resource-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-resource-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-tail-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-tail-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-tail-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-tail-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-tail-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-select-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-select-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-select-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-select-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-select-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-effects-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-effects-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-effects-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-effects-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-effects-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-multi-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-multi-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-multi-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-multi-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-multi-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-keyword-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-signed-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-signed-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-signed-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-signed-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-signed-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-scalar-casts-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-explicit-traps-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-cli-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-cli-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-cli-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-cli-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-cli-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-names-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-names-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-names-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-names-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-names-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-exports-original.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-original.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-original.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-original.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-exports-original.stderr.log",
  "original/hia-cold.cold/qualification.evidence/phase-exports-modified.request.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-modified.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-modified.process.json",
  "original/hia-cold.cold/qualification.evidence/phase-exports-modified.stdout.log",
  "original/hia-cold.cold/qualification.evidence/phase-exports-modified.stderr.log",
  "original/hia-cold.cold/qualification.evidence/B0.receipt.json",
  "original/hia-cold.cold/qualification.evidence/B1.receipt.json",
  "original/hia-cold.cold/qualification.evidence/B1.request.json",
  "original/hia-cold.cold/qualification.evidence/B1.stdout.log",
  "original/hia-cold.cold/qualification.evidence/B1.stderr.log",
  "original/hia-cold.cold/qualification.evidence/B2.receipt.json",
  "original/hia-cold.cold/qualification.evidence/B2.request.json",
  "original/hia-cold.cold/qualification.evidence/B2.stdout.log",
  "original/hia-cold.cold/qualification.evidence/B2.stderr.log",
  "original/hia-cold.cold/qualification.evidence/B3.receipt.json",
  "original/hia-cold.cold/qualification.evidence/B3.request.json",
  "original/hia-cold.cold/qualification.evidence/B3.stdout.log",
  "original/hia-cold.cold/qualification.evidence/B3.stderr.log",
  "original/hia-cold.cold/qualification.evidence/M1.receipt.json",
  "original/hia-cold.cold/qualification.evidence/M1.request.json",
  "original/hia-cold.cold/qualification.evidence/M1.stdout.log",
  "original/hia-cold.cold/qualification.evidence/M1.stderr.log",
  "original/hia-cold.cold/qualification.evidence/M2.receipt.json",
  "original/hia-cold.cold/qualification.evidence/M2.request.json",
  "original/hia-cold.cold/qualification.evidence/M2.stdout.log",
  "original/hia-cold.cold/qualification.evidence/M2.stderr.log",
  "original/hia-cold.cold/qualification.evidence/M3.receipt.json",
  "original/hia-cold.cold/qualification.evidence/M3.request.json",
  "original/hia-cold.cold/qualification.evidence/M3.stdout.log",
  "original/hia-cold.cold/qualification.evidence/M3.stderr.log",
  "original/hia-cold.cold/qualification.evidence/native-observer-build.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-build.json",
  "original/hia-cold.cold/qualification.evidence/independent-native-observer-reference.json",
  "original/hia-cold.cold/qualification.evidence/independent-linked-observer-reference.json",
  "original/hia-cold.cold/qualification.evidence/native-observer-packer.receipt.json",
  "original/hia-cold.cold/qualification.evidence/native-observer-packer.request.json",
  "original/hia-cold.cold/qualification.evidence/native-observer-packer.stdout.log",
  "original/hia-cold.cold/qualification.evidence/native-observer-packer.stderr.log",
  "original/hia-cold.cold/qualification.evidence/native-observer-emit.receipt.json",
  "original/hia-cold.cold/qualification.evidence/native-observer-emit.request.json",
  "original/hia-cold.cold/qualification.evidence/native-observer-emit.stdout.log",
  "original/hia-cold.cold/qualification.evidence/native-observer-emit.stderr.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-policy.receipt.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-policy.request.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-policy.stdout.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-policy.stderr.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-packer.receipt.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-packer.request.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-packer.stdout.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-packer.stderr.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-emit.receipt.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-emit.request.json",
  "original/hia-cold.cold/qualification.evidence/linked-observer-emit.stdout.log",
  "original/hia-cold.cold/qualification.evidence/linked-observer-emit.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-exports.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-exports.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-exports.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-names.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-names.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-names.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-cli.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-cli.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-cli.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-explicit-traps.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-explicit-traps.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-explicit-traps.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-resource.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-resource.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-resource.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-bulk.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-bulk.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-bulk.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-loan.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-loan.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-loan.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-cfg.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-cfg.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-cfg.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-capacity.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-capacity.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-capacity.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-tail.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-tail.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-tail.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-select.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-select.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-select.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-effects.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-effects.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-effects.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-multi.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-multi.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-multi.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-keyword.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-keyword.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-keyword.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-signed.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-signed.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-signed.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-scalar-casts.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-scalar-casts.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-scalar-casts.stderr.log",
  "original/hia-cold.cold/qualification.evidence/reference-core.worker.json",
  "original/hia-cold.cold/qualification.evidence/reference-core.stdout.log",
  "original/hia-cold.cold/qualification.evidence/reference-core.stderr.log"
];
  const controlOrder=["reader/guard/guardian.json","reader/guard/child.stdout.log","reader/guard/child.stderr.log","reader/recovery-terminal.json","reader/setup.json"];
  const historical=new Set(historicalOrder),controls=new Set(controlOrder);
  const order=[...controlOrder,...historicalOrder],rank=new Map(order.map((x,i)=>[x,i]));
  require(historical.size===371&&controls.size===5
    &&Array.isArray(manifest.files)&&manifest.files.length<=376,"fixed371+5 file denominator");
  const sourceMissing=manifest.source_missing_targets,omitted=manifest.budget_omitted_targets,
    missing=manifest.missing_frame_targets;
  require(Array.isArray(sourceMissing)&&Array.isArray(omitted)&&Array.isArray(missing)
    &&new Set(sourceMissing).size===sourceMissing.length
    &&new Set(omitted).size===omitted.length&&new Set(missing).size===missing.length
    &&sourceMissing.every(x=>historical.has(x))&&omitted.every(x=>rank.has(x))
    &&!sourceMissing.some(x=>omitted.includes(x))
    &&JSON.stringify(missing)===JSON.stringify([...sourceMissing,...omitted]),
    "exact source-missing and budget-omitted partition");
  const files=new Map();
  let rawCount=0,expectedFrames=0,previousRank=-1;
  for(const pin of manifest.files){
    require(pin&&typeof pin.path==="string"&&rank.has(pin.path)&&!files.has(pin.path)
      &&isUint(pin.bytes)&&pin.bytes<=33554432&&hex(pin.sha256)
      &&typeof pin.origin==="string","file pin/path/duplicate");
    require(rank.get(pin.path)>previousRank&&!missing.includes(pin.path),
      "frame fixed priority or present/missing collision");
    previousRank=rank.get(pin.path);
    rawCount+=pin.bytes;expectedFrames+=Math.ceil(pin.bytes/24576);
    require(rawCount<=33554432,"raw output bound");
    files.set(pin.path,{pin,bytes:new Uint8Array(pin.bytes),offset:0,frames:0});
  }
  const unaccounted=[...historical].filter(x=>!files.has(x)&&!missing.includes(x));
  require(unaccounted.length===0,"unaccounted historical target");
  require(rawCount===manifest.total_raw_bytes&&expectedFrames===manifest.frame_count
    &&isUint(manifest.frame_count),"manifest byte/frame denominator");
  let frames=0,bytesCount=0,currentFile=0;
  const ordered=[...files.values()];
  for(const record of records.slice(1,-1)){
    require(record.prefix===prefixes[1],"non-frame between manifest/END");
    const f=record.value;
    require(f.manifest_sha256===sealed.sha256&&files.has(f.path)&&isUint(f.offset)
      &&isUint(f.length)&&f.length>0&&f.length<=24576&&hex(f.sha256),"frame header");
    while(currentFile<ordered.length&&ordered[currentFile].offset===ordered[currentFile].pin.bytes)currentFile++;
    const target=files.get(f.path);
    require(ordered[currentFile]===target&&f.offset===target.offset
      &&f.length===Math.min(24576,target.pin.bytes-target.offset),
      "frame ordering/gap/overlap/length");
    const bytes=unbase64(f.base64);
    require(bytes.length===f.length&&H.sha256(bytes)===f.sha256,"frame exact bytes/hash");
    target.bytes.set(bytes,target.offset);target.offset+=bytes.length;
    target.frames++;frames++;bytesCount+=bytes.length;
  }
  for(const file of files.values())require(file.offset===file.pin.bytes
    &&H.sha256(file.bytes)===file.pin.sha256,"complete raw file bytes/hash");
  const end=records.at(-1).value;
  require(end.schema==="hia.original-log-frame-terminal.v1"&&statuses.has(end.status)
    &&hex(end.result_sha256)&&end.source_bytes_complete===true,"complete terminal marker");
  require(end.manifest_sha256===sealed.sha256&&end.files===files.size
    &&end.frames===frames&&end.raw_bytes===bytesCount
    &&frames===expectedFrames&&bytesCount===rawCount,"END aggregate binding");
  require(end.qualification_executed===false&&end.original_product_statuses_reclassified===false
    &&end.original_custody_status==="CUSTODY_HOLD"
    &&JSON.stringify(end.missing_frame_targets)===JSON.stringify(missing),
    "END exact historical HOLD and missing ledger");
  require(Array.isArray(manifest.errors),"error ledger required");
  if(end.status==="ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION"){
    require(manifest.source_originals_accepted===true&&manifest.all_historical_targets_framed===true
      &&missing.length===0&&manifest.errors.length===0&&files.size===376
      &&controlOrder.every(x=>files.has(x)),"complete new recovery has missing data/errors");
  }else{
    require(manifest.all_historical_targets_framed===false,"HOLD cannot claim full target closure");
  }
  const final=files.get("custody/FINAL.json");
  if(final){
    require(final.pin.sha256===manifest.original_final_sha256,"original FINAL external SHA");
    const value=JSON.parse(utf8(final.bytes));
    require(value.schema==="hia.actions.970-original-custody-final.v1"
      &&value.context.run_id===43150215535
      &&value.context.actual_control_checkout==="1e45e6b02c28b388cd78ff3ca1ef62d6155d1925"
      &&value.context.actual_workflow_commit==="896cb5ceaf8a34c9263b26e8131886285042cea6"
      &&value.status==="CUSTODY_HOLD"&&value.qualification_executed===false
      &&value.original_product_statuses_reclassified===false,"actual historical FINAL identity");
  }
  return {manifest_raw:manifestBytes,manifest,terminal:end,
    unaccounted_historical_targets:unaccounted,
    files:[...files].map(([path,f])=>({path,bytes:f.bytes,sha256:f.pin.sha256,origin:f.pin.origin})),
    records:records.length,framed_stdout_bytes:framedStdoutBytes,decodeUTF8:utf8};
}
