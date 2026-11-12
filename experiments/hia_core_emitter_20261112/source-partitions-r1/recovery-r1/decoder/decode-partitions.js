/* Independent V8 byte recovery; no project import, regeneration, compiler, or product execution.
 * Frozen inputs are complete raw policy/pins/plan bytes. Original JSON bytes are retained;
 * unsafe integer tokens are parsed as BigInt only for equality, never rounded and re-emitted.
 * A complete per-job END is not a twenty-job closure. RESULT bodies are not in this stream.
 */
function makeCorePartitionRecovery(H) {
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

  const parse = raw => JSON.parse(raw, (_key,value,context) => {
    if (typeof value === "number" && !Number.isSafeInteger(value) &&
        /^-?(?:0|[1-9][0-9]*)$/.test(context?.source || "")) return BigInt(context.source);
    return value;
  });
  const stringify = value => {
    if (typeof value === "bigint") return value.toString();
    if (Array.isArray(value)) return "[" + value.map(stringify).join(",") + "]";
    if (value && typeof value === "object")
      return "{" + Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+stringify(value[k])).join(",") + "}";
    return JSON.stringify(value);
  };
  const same = (a,b) => stringify(a) === stringify(b);
  function pythonWire(value,depth=0) {
    const indent = n => "  ".repeat(n);
    const quote = s => JSON.stringify(s).replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"));
    if (typeof value === "string") return quote(value);
    if (typeof value === "bigint") return value.toString();
    if (Array.isArray(value)) return value.length ? "[\n"+value.map(x=>indent(depth+1)+pythonWire(x,depth+1)).join(",\n")+"\n"+indent(depth)+"]" : "[]";
    if (value && typeof value === "object") {
      const keys=Object.keys(value).sort();
      return keys.length ? "{\n"+keys.map(k=>indent(depth+1)+quote(k)+": "+pythonWire(value[k],depth+1)).join(",\n")+"\n"+indent(depth)+"}" : "{}";
    }
    require(value===null||typeof value==="boolean"||(typeof value==="number"&&Number.isFinite(value)),"unsupported Python wire primitive");
    return JSON.stringify(value);
  }
  function gitBlob(bytes) {
    const prefix=H.utf8("blob "+bytes.length+"\0"), all=new Uint8Array(prefix.length+bytes.length);
    all.set(prefix);all.set(bytes,prefix.length);return H.sha1(all);
  }
  function seal(raw) { const b=H.utf8(raw); return {bytes:b.length,sha256:H.sha256(b),git_blob_sha1:gitBlob(b)}; }
  const controlNames=["guard/guardian.json","guard/child.stdout.log","guard/child.stderr.log","recovery-terminal.json","setup.json"];
  const controlPaths=controlNames.map(n=>"partition-reader/"+n);
  const marks=["HIA_CORE_SOURCE_PARTITION_MANIFEST_V1","HIA_CORE_SOURCE_PARTITION_FRAME_V1",
               "HIA_CORE_SOURCE_PARTITION_END_V1","HIA_CORE_SOURCE_PARTITION_FAILURE_V1"];
  function frozen(raw,expected) {
    require(typeof raw.policy==="string"&&typeof raw.pins==="string"&&typeof raw.plan==="string","frozen raw inputs required");
    const policy=parse(raw.policy),pins=parse(raw.pins),plan=parse(raw.plan);
    require(seal(raw.policy).sha256===expected.policy_sha256,"frozen policy digest differs");
    for(const [name,key] of [["asset-pins.json","pins"],["partitions.json","plan"]])
      require(same(seal(raw[key]),policy.control_files[name]),"frozen complete "+name+" identity differs");
    require(policy.schema==="hia.actions.core-source-partition-policy.v1"&&policy.repository==="TrillionniumFoundation/Hepta"
            &&policy.trigger_branch===expected.branch&&policy.matrix.partition_count===20
            &&same(policy.matrix.partition_ids,Array.from({length:20},(_,i)=>i))&&policy.matrix.max_parallel===2
            &&policy.matrix.fail_fast===false,"fixed matrix policy differs");
    require(plan.schema==="hia.core-original-assets-fixed-partition-plan.v1"&&plan.partition_count===20
            &&plan.source_files===40&&plan.source_total_bytes===7089249&&plan.max_parallel===2
            &&plan.source_raw_cap_per_job===393216&&plan.control_raw_reserve===131072
            &&plan.total_raw_cap_per_job===524288&&plan.stdout_cap_per_job===1048576
            &&plan.independent_owner_seconds===900&&plan.cleanup_seconds===3
            &&plan.re_generated===false&&plan.native_executed===false,"fixed partition plan differs");
    require(pins.schema==="hia.core-original-asset-partition-pins.v1"&&pins.source_file_count===40
            &&pins.source_total_bytes===7089249&&pins.original_failure_reclassified===false
            &&pins.source_generated_again===false&&pins.historical_targets.length===54
            &&pins.archive_inventory.length===60,"fixed full archive pins differ");
    require(same(plan.artifact,policy.source_artifact)&&same(pins.artifact,policy.source_artifact)
            &&policy.source_artifact.id===13915070523&&policy.source_artifact.bytes===7381515
            &&policy.source_artifact.sha256==="57e3f0db194d961e64dd4773b04dddf373fe5ca02ea2763924d0ec5040d2a2f8"
            &&policy.source_artifact.run_id===43152508792&&policy.source_artifact.run_attempt===1
            &&policy.source_artifact.head_sha==="6049861e92f0f68dacaf3101bfdb0f98f06c9930"
            &&policy.source_artifact.name==="hia-core-emitter-generated-assets-43152508792-1","sealed failed artifact differs");
    const seen=new Set(), paths=new Set();
    let total=0;
    require(Array.isArray(plan.partitions)&&plan.partitions.length===20,"twenty fixed groups required");
    for(const [id,g]of plan.partitions.entries()){
      require(g.partition_id===id&&Array.isArray(g.files)&&g.files.length===2&&isUint(g.source_bytes)&&g.source_bytes<=393216,"fixed group denominator/limit");
      let sum=0,last=-1;
      for(const f of g.files){
        require(isUint(f.index)&&f.index<40&&!seen.has(f.index)&&f.index>last&&!paths.has(f.logical_path),"fixed source ordinal/path uniqueness/order");
        const p=pins.historical_targets[f.index];
        for(const key of ["logical_path","role","bytes","sha256","git_blob_sha1"])require(f[key]===p[key],"fixed source pin differs: "+key);
        require(f.archive_member===String(f.index).padStart(3,"0")+".original"&&["assembly","abi"].includes(f.role)
                &&isUint(f.bytes)&&f.bytes>0&&f.bytes<=393216&&hex(f.sha256)&&/^[0-9a-f]{40}$/.test(f.git_blob_sha1),"source pin shape");
        last=f.index;seen.add(f.index);paths.add(f.logical_path);sum+=f.bytes;
      }
      require(sum===g.source_bytes,"group source byte sum");total+=sum;
    }
    require(seen.size===40&&total===7089249,"all forty exact original sources required");
    return {policy,pins,plan,raw};
  }
  function contextCheck(context,expected,f) {
    const {policy,plan}=f,group=plan.partitions[expected.partition_id];
    require(context&&context.schema==="hia.actions.core-source-partition-context.v1"&&context.repository===policy.repository
            &&context.event==="create"&&context.event_ref===expected.branch&&context.event_ref_type==="branch"
            &&context.run_id===expected.run_id&&context.run_attempt===1&&isUint(context.run_number)
            &&context.actual_control_checkout===expected.control_commit&&context.actual_workflow_commit===expected.workflow_commit
            &&context.policy_sha256===expected.policy_sha256&&hex(context.event_sha256)
            &&context.original_product_commit===policy.source.head&&context.original_product_tree===policy.source.tree
            &&context.token_or_signed_URL_in_context===false&&context.qualification_executed===false,
            "exact source partition operation binding");
    require(context.partition_id===expected.partition_id&&context.partition_count===20
            &&context.partition_source_bytes===group.source_bytes
            &&same(context.selected_source_indices,group.files.map(x=>x.index)),"context partition binding");
    const suffix="/"+policy.work_root_name+"-"+expected.partition_id;
    require(typeof context.root==="string"&&context.root.startsWith("/")&&context.root.endsWith(suffix)
            &&!context.root.split("/").includes(".."),"fixed private root");
    const parent=context.root.slice(0,-suffix.length);
    require(context.public_root===parent+"/"+policy.public_root_name+"-"+expected.partition_id,"fixed public partition root");
    require(context.python&&typeof context.python.resolved==="string"&&context.python.resolved.startsWith("/")
            &&typeof context.python.version==="string"&&context.python.version.startsWith("3.14.4 ")
            &&hex(context.python.binary?.sha256)&&context.python.binary.path===context.python.resolved
            &&isUint(context.python.binary.bytes)&&context.python.binary.bytes>0,"actual fixed-version interpreter identity");
    return context;
  }
  function decode(log,expected,raw) {
    require(typeof log==="string"&&isUint(expected.partition_id)&&expected.partition_id<20
            &&isUint(expected.job_id)&&expected.job_id>0&&isUint(expected.run_id)&&expected.run_id>0,"expected real job binding");
    const f=frozen(raw,expected),group=f.plan.partitions[expected.partition_id],records=[];
    for(const originalLine of log.split("\n")){
      let line=originalLine.replace(/^\uFEFF/,"").replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /,"");
      if(line.endsWith("\r"))line=line.slice(0,-1);
      const marker=marks.find(x=>line.startsWith(x+" "));
      if(marker)records.push({marker,value:parse(line.slice(marker.length+1)),raw_line:line});
    }
    require(records.length>=2&&records[0].marker===marks[0]&&records.at(-1).marker===marks[2],
            "missing partition manifest or complete late END");
    require(records.filter(x=>x.marker===marks[0]).length===1&&records.filter(x=>x.marker===marks[2]).length===1
            &&records.every(x=>x.marker!==marks[3]),"duplicate or failed frame stream");
    const sealed=records[0].value;
    require(isUint(sealed.bytes)&&sealed.bytes<=65536&&hex(sealed.sha256)&&typeof sealed.base64==="string"
            &&sealed.base64.length<=87384,"bounded manifest seal shape");
    const mb=unbase64(sealed.base64);
    require(mb.length===sealed.bytes&&H.sha256(mb)===sealed.sha256,"manifest complete bytes/hash");
    const manifestRaw=utf8(mb),manifest=parse(manifestRaw);
    require(manifest.schema==="hia.core-source-partition-frame-manifest.v1"&&manifest.frame_bytes===8192
            &&manifest.maximum_source_raw_bytes===393216&&manifest.maximum_control_raw_bytes===131072
            &&manifest.maximum_raw_bytes===524288&&manifest.maximum_stdout_bytes===1048576,"fixed partition frame limits");
    for(const name of ["original_failure_reclassified","qualification_executed","source_generated_again","all_20_partitions_complete_claimed"])
      require(manifest[name]===false,"per-partition scope changed: "+name);
    require(manifest.original_run_conclusion==="failure"&&typeof manifest.partition_accepted==="boolean"
            &&Array.isArray(manifest.errors)&&same(manifest.source_artifact,f.policy.source_artifact)
            &&manifest.partition_id===expected.partition_id&&manifest.partition_count===20
            &&manifest.partition_plan_sha256===f.policy.control_files["partitions.json"].sha256
            &&same(manifest.selected_source_indices,group.files.map(x=>x.index))
            &&manifest.source_bytes===(manifest.partition_accepted?group.source_bytes:0),"manifest partition/provenance binding");
    contextCheck(manifest.context,expected,f);
    const sourceMap=new Map(group.files.map(x=>[x.logical_path,x])), controls=new Set(controlPaths),files=new Map();
    require(Array.isArray(manifest.files)&&manifest.files.length<=7,"maximum seven exact partition originals");
    let rawCount=0,sourceCount=0,controlCount=0,expectedFrames=0;
    for(const pin of manifest.files){
      require(pin&&typeof pin.path==="string"&&!files.has(pin.path)&&(sourceMap.has(pin.path)||controls.has(pin.path))
              &&isUint(pin.bytes)&&pin.bytes<=524288&&hex(pin.sha256)&&typeof pin.origin==="string","partition file pin/path/duplicate");
      if(sourceMap.has(pin.path)){
        const target=sourceMap.get(pin.path);
        require(manifest.partition_accepted&&pin.bytes===target.bytes&&pin.sha256===target.sha256,"unselected or differing source original");
        const member=f.pins.archive_inventory.find(x=>x.normalized_path===target.archive_member);
        require(member&&pin.origin==="sealed original source member "+member.archive_path,"fixed source archive provenance");
        sourceCount+=pin.bytes;
      }else{
        require(pin.origin==="current independent partition read raw control record","fixed control provenance");
        controlCount+=pin.bytes;
      }
      rawCount+=pin.bytes;expectedFrames+=Math.ceil(pin.bytes/8192);
      require(rawCount<=524288&&sourceCount<=393216&&controlCount<=131072,"partition raw byte budgets");
      files.set(pin.path,{pin,bytes:new Uint8Array(pin.bytes),offset:0,frames:0});
    }
    require(sourceCount===manifest.source_bytes&&rawCount===manifest.total_raw_bytes
            &&expectedFrames===manifest.frame_count&&isUint(manifest.frame_count)&&manifest.frame_count<=70,"manifest byte/frame denominators");
    const prescribed=[...(manifest.partition_accepted?group.files.map(x=>x.logical_path):[]),...controlPaths].filter(x=>files.has(x));
    require(same([...files.keys()],prescribed),"fixed source/control output order");
    let frames=0,bytesCount=0,current=0;
    const ordered=[...files.values()];
    for(const record of records.slice(1,-1)){
      require(record.marker===marks[1],"non-frame between manifest and END");
      const frame=record.value;
      require(frame.manifest_sha256===sealed.sha256&&files.has(frame.path)&&isUint(frame.offset)
              &&isUint(frame.length)&&frame.length>0&&frame.length<=8192&&hex(frame.sha256)
              &&typeof frame.base64==="string"&&frame.base64.length<=10924,"bounded frame header");
      while(current<ordered.length&&ordered[current].offset===ordered[current].pin.bytes)current++;
      const target=files.get(frame.path);
      require(ordered[current]===target&&frame.offset===target.offset
              &&frame.length===Math.min(8192,target.pin.bytes-target.offset),"frame order/gap/overlap");
      const bytes=unbase64(frame.base64);
      require(bytes.length===frame.length&&H.sha256(bytes)===frame.sha256,"frame complete bytes/hash");
      target.bytes.set(bytes,target.offset);target.offset+=bytes.length;target.frames++;frames++;bytesCount+=bytes.length;
    }
    const decoded=[];
    for(const [path,item]of files){
      require(item.offset===item.pin.bytes&&H.sha256(item.bytes)===item.pin.sha256,"complete original bytes/hash");
      const blob=gitBlob(item.bytes);
      if(sourceMap.has(path))require(blob===sourceMap.get(path).git_blob_sha1,"original source Git blob differs");
      const text=utf8(item.bytes);
      require(H.utf8(text).length===item.bytes.length&&H.sha256(H.utf8(text))===item.pin.sha256,"UTF8 original roundtrip");
      decoded.push({path,bytes:item.pin.bytes,sha256:item.pin.sha256,git_blob_sha1:blob,raw:text,origin:item.pin.origin});
    }
    const end=records.at(-1).value;
    require(end.schema==="hia.core-source-partition-frame-terminal.v1"
            &&["SOURCE_PARTITION_COMPLETE_NOT_QUALIFICATION","PARTITION_HOLD"].includes(end.status)
            &&hex(end.result_sha256)&&end.partition_bytes_complete===true,"complete partition late END");
    require(end.manifest_sha256===sealed.sha256&&end.partition_id===expected.partition_id&&end.partition_count===20
            &&same(end.selected_source_indices,manifest.selected_source_indices)&&end.source_bytes===manifest.source_bytes
            &&end.files===files.size&&end.frames===frames&&end.raw_bytes===bytesCount
            &&frames===expectedFrames&&bytesCount===rawCount&&end.original_run_conclusion==="failure","END exact denominators/provenance");
    for(const name of ["original_failure_reclassified","qualification_executed","source_generated_again","all_20_partitions_complete_claimed"])
      require(end[name]===false,"END scope changed: "+name);
    if(end.status==="SOURCE_PARTITION_COMPLETE_NOT_QUALIFICATION")
      require(manifest.partition_accepted&&manifest.errors.length===0&&files.size===7
              &&controlPaths.every(x=>files.has(x))&&group.files.every(x=>files.has(x.logical_path)),"complete partition lacks exact originals");
    else require(!manifest.partition_accepted&&[...files.keys()].every(x=>controls.has(x)),"HOLD cannot include accepted source originals");
    const stdout=records.reduce((n,x)=>n+H.utf8(x.raw_line+"\n").length,0);
    require(stdout<=1048576,"actual application frame stdout cap");
    return {schema:"hia.core-source-partition-decoded.v1",partition_id:expected.partition_id,job_id:expected.job_id,
      run_id:expected.run_id,manifest_raw:manifestRaw,manifest_sha256:sealed.sha256,manifest,terminal:end,files:decoded,
      source_bytes:sourceCount,control_bytes:controlCount,raw_bytes:rawCount,frame_count:frames,
      framed_stdout_bytes:stdout,raw_log:seal(log),result_body_observed:false};
  }

  function audit(decoded,expected,raw) {
    const f=frozen(raw,expected),{policy,pins,plan}=f,group=plan.partitions[expected.partition_id];
    require(decoded.terminal.status==="SOURCE_PARTITION_COMPLETE_NOT_QUALIFICATION","HOLD has no complete custody audit");
    const rows=new Map(decoded.files.map(x=>[x.path,x]));
    require(rows.size===7&&controlPaths.every(p=>rows.has(p)),"all seven actual originals required");
    const get=name=>parse(rows.get("partition-reader/"+name).raw);
    const setup=get("setup.json"),guard=get("guard/guardian.json"),report=get("recovery-terminal.json");
    const ctx=contextCheck(decoded.manifest.context,expected,f),root=ctx.root;
    require(same(setup.context,ctx)&&setup.schema==="hia.actions.core-source-partition-setup.v1"
            &&setup.status==="PREPARED_NOT_EXECUTED"&&setup.controller_seconds===900&&setup.cleanup_seconds===3
            &&setup.token_received===false&&setup.project_code_executed===false
            &&setup.capacity_before.free_bytes>=8589934592&&setup.capacity_before.free_inodes>=100000,"actual setup and storage contract");
    const workerCommand=[ctx.python.resolved,"-I","-S","-B",root+"/control/worker.py","--root",root,
                         "--policy-sha256",expected.policy_sha256,"--partition-id",String(expected.partition_id)];
    require(same(setup.command,workerCommand),"actual isolated worker command");
    const controllerSuffix="/"+policy.control_prefix+"/controller.py";
    const controllerMatches=Object.keys(ctx.control_sources).filter(p=>p.endsWith(controllerSuffix));
    require(controllerMatches.length===1,"one exact checkout control root");
    const checkout=controllerMatches[0].slice(0,-controllerSuffix.length);
    const controlSources={};
    for(const [name,pin] of Object.entries(policy.control_files))
      controlSources[checkout+"/"+policy.control_prefix+"/"+name]=pin.sha256;
    controlSources[checkout+"/"+policy.control_prefix+"/policy.json"]=expected.policy_sha256;
    for(const [name,pin] of Object.entries(policy.unchanged_original_workflows))
      controlSources[checkout+"/"+name]=pin.sha256;
    require(same(ctx.control_sources,controlSources)&&Object.keys(controlSources).length===11,"all eleven exact checkout control/workflow pins");
    const ids={...controlSources};
    for(const [name,pin] of Object.entries(policy.control_files))ids[root+"/control/"+name]=pin.sha256;
    ids[root+"/control/policy.json"]=expected.policy_sha256;
    ids[root+"/context.json"]=H.sha256(H.utf8(pythonWire(ctx)+"\n"));
    ids[ctx.python.resolved]=ctx.python.binary.sha256;
    require(Object.keys(ids).length===21&&same(setup.source_identities,ids),"all twenty-one independently rederived input identities");
    const request={schema:"hia-external-guardian-request.v1",controller_seconds:900,
                   command:workerCommand,cwd:root,source_identities:ids};
    require(setup.guardian_config_sha256===H.sha256(H.utf8(pythonWire(request)+"\n")),"actual guardian request raw digest");
    require(guard.schema==="hepta.hia.external-qualification-guardian.v1"
            &&guard.status==="EXTERNAL_OWNED_PROCESS_COMPLETED"&&same(guard.command,workerCommand)&&guard.cwd===root
            &&guard.external_controller_seconds===900&&guard.cold_180_second_gate_modified===false
            &&guard.lifecycle_implementation_sha256===policy.control_files["process_owner_impl.py"].sha256
            &&same(guard.source_identities_before,ids)&&same(guard.source_identities_after,ids)
            &&guard.input_identity_preserved===true&&guard.whole_native_delivery_qualified===false,"actual guardian operation and before/after identities");
    const life=guard.lifecycle,cleanup=life?.cleanup;
    require(life?.schema==="hepta.hia.external-qualification-guardian.v1.lifecycle"
            &&life.status==="OWNED_PROCESS_COMPLETED"&&life.returncode===0
            &&life.subreaper_enabled===true&&life.qualification_started===true
            &&life.qualification_seconds===900&&life.cleanup_seconds===3
            &&life.timed_out===false&&life.exit_observed_before_deadline===true
            &&life.event_overflow===false&&same(life.interrupted_signals,[])
            &&(life.owner_error===undefined||life.owner_error===null),"actual natural owner termination");
    require(cleanup?.attempted===true&&cleanup.complete===true&&cleanup.observed_echild===true
            &&cleanup.leader_reaped===true&&cleanup.deadline_exceeded===false
            &&same(cleanup.errors,[])&&same(cleanup.remaining_direct_children,[]),"actual ECHILD/reap complete cleanup");
    const allowedEvents=new Set(["qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"]);
    require(Array.isArray(life.events)&&life.events.length>=3&&life.events.every(x=>allowedEvents.has(x.kind))
            &&["qualification_started","qualification_exit_observed","owned_child_reaped"].every(k=>life.events.some(x=>x.kind===k)),
            "natural event ledger with no forced cleanup");
    const logs={};
    for(const name of ["child.stdout.log","child.stderr.log"])logs[root+"/guard/"+name]=rows.get("partition-reader/guard/"+name).sha256;
    require(same(guard.logs,logs),"actual complete original child logs bound to guardian");
    const child=parse(rows.get("partition-reader/guard/child.stdout.log").raw.trim());
    require(child.status==="SOURCE_PARTITION_VERIFIED_PENDING_NATURAL_GUARDIAN"
            &&child.partition_id===expected.partition_id&&child.source_files===2&&child.source_bytes===group.source_bytes
            &&child.original_run_conclusion==="failure"&&child.qualification_executed===false,"actual worker stdout result");
    require(report.schema==="hia.actions.core-source-partition-worker.v1"
            &&report.status==="SOURCE_PARTITION_VERIFIED_PENDING_NATURAL_GUARDIAN"&&report.root===root
            &&report.policy_sha256===expected.policy_sha256
            &&report.external_pins_sha256===policy.control_files["asset-pins.json"].sha256
            &&report.partition_plan_sha256===policy.control_files["partitions.json"].sha256
            &&same(report.source_artifact,policy.source_artifact)&&report.partition_id===expected.partition_id
            &&report.partition_count===20&&report.original_run_conclusion==="failure"
            &&same(report.original_failed_run,pins.original_failed_reader)
            &&report.original_source_file_count===40&&report.original_source_total_bytes===7089249
            &&(report.error_type===undefined||report.error_type===null),"actual worker final source contract");
    for(const name of ["project_code_executed","qualification_executed","original_product_statuses_reclassified",
                      "original_failure_reclassified","source_generated_again","native_compiler_executed",
                      "Core_VM_executed","product_tests_executed","token_or_signed_URL_recorded"])
      require(report[name]===false,"actual worker scope "+name);
    const calls=report.API_attempts,gets=report.GET_attempts,artifact=policy.source_artifact;
    const metadataPath="/repos/"+policy.repository+"/actions/artifacts/"+artifact.id;
    require(Array.isArray(calls)&&calls.length===2&&Array.isArray(gets)&&gets.length===1
            &&same(calls.map(x=>x.role),["official_metadata","official_download_redirect"])
            &&same(calls.map(x=>x.path),[metadataPath,metadataPath+"/zip"])
            &&calls.every(x=>x.artifact_id===artifact.id&&x.method==="GET"&&x.attempt===1&&x.retries===0
                       &&x.host==="api.github.com"&&x.credential_sent_only_to_official_API===true)
            &&calls[0].status===200&&calls[1].status===302&&calls[1].automatic_redirects===0
            &&calls[1].authorization_forwarded===false&&calls[1].signed_Location_recorded===false,"fixed official metadata and redirect request ledger");
    const net=gets[0],archivePath=root+"/original/artifact-"+artifact.id+".zip";
    require(net.artifact_id===artifact.id&&net.method==="GET"&&net.attempt===1&&net.redirects===0&&net.retries===0
            &&net.authorization_sent===false&&net.cookies_sent===false&&net.bytes===artifact.bytes
            &&net.sha256===artifact.sha256&&net.output===archivePath
            &&net.host===calls[1].storage_host&&typeof net.host==="string"
            &&(/\.(?:blob\.core\.windows\.net|actions\.githubusercontent\.com)$/).test(net.host)
            &&hex(net.url_sha256)&&net.url_sha256===calls[1].location_sha256,"one bounded anonymous original ZIP GET");
    require(same(report.official_metadata,calls[0].original_metadata)
            &&report.official_metadata.path===root+"/api/artifact-"+artifact.id+".metadata.original.json"
            &&isUint(report.official_metadata.bytes)&&hex(report.official_metadata.sha256),"official metadata record binding");
    require(same(report.artifact_before,report.artifact_after)&&report.artifact_before.path===archivePath
            &&report.artifact_before.bytes===artifact.bytes&&report.artifact_before.sha256===artifact.sha256
            &&report.artifact_before.actual_bytes_independently_read===artifact.bytes,"two full ZIP observations stable");
    require(same(report.archive_inventory,pins.archive_inventory)&&report.archive_member_count===60
            &&report.archive_uncompressed_bytes===7374535&&report.all_members_fully_read_and_CRC_verified===true
            &&report.all_54_historical_pins_verified===true,"all sixty actual sealed members and fifty-four historical pins");
    const byName=new Map(pins.archive_inventory.map(x=>[x.normalized_path,x]));
    require(byName.size===60&&pins.archive_inventory.reduce((n,x)=>n+x.bytes,0)===7374535
            &&pins.archive_inventory.every(x=>x.full_member_CRC_read===true),"complete frozen inventory");
    for(const target of pins.historical_targets)
      require(target.archive_aliases.some(name=>{const row=byName.get(name);return row&&row.bytes===target.bytes&&row.sha256===target.sha256&&row.git_blob_sha1===target.git_blob_sha1;}),"historical pin absent from complete inventory");
    require(same(report.selected_source_indices,group.files.map(x=>x.index))&&report.selected_source_bytes===group.source_bytes
            &&report.all_selected_source_originals_fully_read===true&&Array.isArray(report.frame_files)
            &&report.frame_files.length===2,"actual exact selected source denominator");
    for(const [i,target] of group.files.entries()){
      const observed=report.frame_files[i],actual=rows.get(target.logical_path),member=byName.get(target.archive_member),record=observed.record;
      require(observed.source_index===target.index&&observed.logical_path===target.logical_path
              &&observed.archive_path===member.archive_path&&observed.origin==="sealed original source member "+member.archive_path
              &&actual.origin===observed.origin&&record.path===root+"/selected/"+String(target.index).padStart(3,"0")+".original"
              &&record.bytes===actual.bytes&&record.sha256===actual.sha256&&Array.isArray(record.identity)
              &&record.identity.length===9&&record.identity[5]===1&&record.identity[6]===actual.bytes
              &&(record.identity[2]&61440)===32768,"actual source copy identity and recovered source bytes");
    }
    const checks=["exact_operation_and_partition","all_21_inputs_rederived","guardian_request_digest",
      "before_after_input_identity","natural_900_3_cleanup","original_child_logs","worker_final_scope",
      "two_official_requests_one_anonymous_GET","sealed_artifact_two_reads","all_60_inventory_rows",
      "all_54_historical_pins","two_selected_whole_sources","SHA256_and_Git_blob","bounded_complete_late_END"];
    return {schema:"hia.core-source-partition-independent-audit.v1",status:"ORIGINAL_PARTITION_BYTES_VERIFIED",
      run_id:expected.run_id,job_id:expected.job_id,partition_id:expected.partition_id,partition_count:20,
      control_commit:expected.control_commit,workflow_commit:expected.workflow_commit,policy_sha256:expected.policy_sha256,
      plan_sha256:policy.control_files["partitions.json"].sha256,checks,
      raw_log:decoded.raw_log,manifest_sha256:decoded.manifest_sha256,terminal:decoded.terminal,
      source_files:group.files.map(x=>({index:x.index,path:x.logical_path,bytes:x.bytes,sha256:x.sha256,git_blob_sha1:x.git_blob_sha1})),
      original_records:decoded.files.map(({raw,...pin})=>pin),source_bytes:decoded.source_bytes,
      control_bytes:decoded.control_bytes,raw_bytes:decoded.raw_bytes,frame_count:decoded.frame_count,
      framed_stdout_bytes:decoded.framed_stdout_bytes,owner_events:life.events.map(x=>x.kind),
      input_identities:21,original_run_conclusion:"failure",original_failure_reclassified:false,
      result_body_observed:false,source_generated_again:false,qualification_executed:false,
      all_20_partitions_complete_claimed:false};
  }
  function aggregate(inputs,expected,raw) {
    const f=frozen(raw,expected),run=parse(inputs.run_raw),jobs=parse(inputs.jobs_raw);
    require(run.id===expected.run_id&&run.event==="create"&&run.run_attempt===1
            &&run.head_sha===expected.workflow_commit&&run.head_branch===expected.branch
            &&run.path===".github/workflows/hia-core-original-source-partitions-isolated.yml"
            &&run.status==="completed"&&run.conclusion==="success","actual whole matrix workflow terminal");
    require(jobs.total_count===20&&Array.isArray(jobs.jobs)&&jobs.jobs.length===20
            &&Array.isArray(inputs.partitions)&&inputs.partitions.length===20,"exact twenty provider jobs and twenty original logs");
    const byPart=new Map(),jobIds=new Set();
    const requiredSteps=["Check out only the exact reviewed custody controls and fixed workflow pins",
      "Verify frozen control bytes and create new private custody roots",
      "Read one fixed original source partition under its independent 900-second guardian",
      "Frame two fixed source originals and five controls after closed cleanup",
      "Preserve complete original artifact and partition custody"];
    for(const job of jobs.jobs){
      const match=/^recover_original_source_partition \((0|[1-9][0-9]*)\)$/.exec(job.name);
      require(match,"exact fixed matrix job name");
      const id=Number(match[1]);
      require(id<20&&!byPart.has(id)&&isUint(job.id)&&!jobIds.has(job.id)&&job.run_id===expected.run_id
              &&job.run_attempt===1&&job.head_sha===expected.workflow_commit&&job.head_branch===expected.branch
              &&job.status==="completed"&&job.conclusion==="success","exact distinct successful provider job");
      require(Array.isArray(job.steps)&&job.steps.every(x=>x.status==="completed"&&x.conclusion==="success")
              &&requiredSteps.every(name=>job.steps.filter(x=>x.name===name).length===1),"every original matrix job step succeeded");
      byPart.set(id,job);jobIds.add(job.id);
    }
    const seen=new Set(),sources=new Map(),audits=[];
    for(const part of inputs.partitions){
      require(isUint(part.partition_id)&&part.partition_id<20&&!seen.has(part.partition_id),"distinct input partition logs");
      const job=byPart.get(part.partition_id);
      require(job&&part.job_id===job.id&&typeof part.log_raw==="string","raw log tied to actual provider matrix job");
      const e={...expected,partition_id:part.partition_id,job_id:part.job_id};
      const decoded=decode(part.log_raw,e,raw),review=audit(decoded,e,raw);
      seen.add(part.partition_id);audits.push(review);
      for(const target of f.plan.partitions[part.partition_id].files){
        const actual=decoded.files.find(x=>x.path===target.logical_path);
        require(actual&&!sources.has(target.index)&&![...sources.values()].some(x=>x.path===actual.path),"cross-partition original uniqueness");
        sources.set(target.index,{index:target.index,partition_id:part.partition_id,job_id:part.job_id,...actual});
      }
    }
    require(seen.size===20&&sources.size===40&&Array.from({length:40},(_,i)=>i).every(i=>sources.has(i))
            &&[...sources.values()].reduce((n,x)=>n+x.bytes,0)===7089249,"all forty exact whole original sources recovered");
    const ordered=[...sources.values()].sort((a,b)=>a.index-b.index),sortedAudits=audits.sort((a,b)=>a.partition_id-b.partition_id);
    return {report:{schema:"hia.core-original-source-twenty-partition-closure.v1",
      status:"ALL_40_ORIGINAL_SOURCE_BYTES_RECOVERED_NOT_QUALIFICATION",run_id:expected.run_id,run_attempt:1,
      control_commit:expected.control_commit,workflow_commit:expected.workflow_commit,policy_sha256:expected.policy_sha256,
      partition_plan_sha256:f.policy.control_files["partitions.json"].sha256,provider_run:seal(inputs.run_raw),
      provider_jobs:seal(inputs.jobs_raw),partitions:20,distinct_provider_jobs:20,source_files:40,
      assembly_files:39,ABI_files:1,source_bytes:7089249,all_original_sources_SHA256_and_Git_verified:true,
      partition_audits:sortedAudits,sources:ordered.map(({raw,...pin})=>pin),
      original_run_conclusion:"failure",original_failure_reclassified:false,source_generated_again:false,
      project_code_executed:false,native_compiler_executed:false,qualification_executed:false,
      all_20_partitions_complete_claimed:true,per_partition_RESULT_bodies_observed:false},
      sources:ordered};
  }
  return {decode,audit,aggregate,parse,same,pythonWire,gitBlob,seal,unbase64,decodeUTF8:utf8,validateFrozen:frozen};
}
