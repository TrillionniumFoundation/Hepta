function decode970InnerArchiveSliceLog(log, expected, H, utf8) {
"use strict";
function require(v,m){if(!v)throw new Error(m);}
const A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function encode64(bytes){let out="";for(let i=0;i<bytes.length;i+=3){const a=bytes[i],b=i+1<bytes.length?bytes[i+1]:0,c=i+2<bytes.length?bytes[i+2]:0,v=(a<<16)|(b<<8)|c;out+=A[(v>>>18)&63]+A[(v>>>12)&63]+(i+1<bytes.length?A[(v>>>6)&63]:"=")+(i+2<bytes.length?A[v&63]:"=");}return out;}
function decode64(s){require(typeof s==="string"&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),"noncanonical base64 syntax");const pad=s.endsWith("==")?2:s.endsWith("=")?1:0,out=new Uint8Array(s.length/4*3-pad);let k=0;for(let i=0;i<s.length;i+=4){let v=0;for(let j=0;j<4;j++)v=(v<<6)|(s[i+j]==="="?0:A.indexOf(s[i+j]));for(const n of [16,8,0])if(k<out.length)out[k++]=(v>>>n)&255;}require(encode64(out)===s,"noncanonical base64 bits");return out;}
function decodeUTF8(b){let out="",batch=[];for(let i=0;i<b.length;){const c=b[i++];let cp,n,min;if(c<128){cp=c;n=0;min=0;}else if(c>=194&&c<=223){cp=c&31;n=1;min=128;}else if(c>=224&&c<=239){cp=c&15;n=2;min=2048;}else if(c>=240&&c<=244){cp=c&7;n=3;min=65536;}else throw new Error("invalid UTF8 lead");require(i+n<=b.length,"short UTF8");for(let j=0;j<n;j++){const d=b[i++];require((d&192)===128,"invalid UTF8 continuation");cp=(cp<<6)|(d&63);}require(cp>=min&&cp<=1114111&&!(cp>=55296&&cp<=57343),"noncanonical UTF8 scalar");batch.push(cp);if(batch.length===2048){out+=String.fromCodePoint(...batch);batch=[];}}return out+String.fromCodePoint(...batch);}

const integer=(n)=>Number.isSafeInteger(n)&&n>=0;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const names=["custody/inner-selected.zip.slice","reader/guard/guardian.json","reader/guard/child.stdout.log","reader/guard/child.stderr.log","reader/recovery-terminal.json","reader/setup.json"];
const history=names.slice(0,1),readers=names.slice(1);
const expectedSource=expected||{};
require(typeof log==="string"&&integer(expectedSource.run_id),"exact run identity required");
require(/^(?:0[0-9]|1[0-8])$/.test(expectedSource.partition_id)
 &&expectedSource.control_commit==="eb1e312c3d030e704aa30cd4932726fa18f5a83c"
 &&expectedSource.workflow_commit==="a4b93e1a370f1c8c9b7fbf3fba7ebbbfeaf2adeb"
 &&expectedSource.policy_sha256==="178653ca3919761b8a3967c82e301eb8a61c1ff026402d45b0d825ae6d3ddd2e"
 &&integer(expectedSource.job_id),"fixed reviewed cohort and job identity required");
const ordinal=Number(expectedSource.partition_id);
const partition={id:expectedSource.partition_id,ordinal,offset:ordinal*458752,bytes:Math.min(458752,8316154-ordinal*458752),logical_path:names[0]};
const innerSize=8316154,innerSHA="d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e";
function matchingPartition(x){return x&&Object.keys(x).length===5&&Object.keys(partition).every(k=>x[k]===partition[k]);}
function matchingInner(x){return x&&x.bytes===innerSize&&x.sha256===innerSHA&&x.source_relative_path==="selected/13911977275/selected-originals.zip"&&x.retained_file==="014.original";}

const prefix=/^(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z )?(HIA_ORIGINAL_FRAME_MANIFEST_V1|HIA_ORIGINAL_FRAME_V1|HIA_ORIGINAL_FRAME_END_V1|HIA_ORIGINAL_FRAME_FAILURE_V1) (.*)$/;
let manifest=null,manifestRaw=null,manifestSHA=null,index=null,indexRaw=null,end=null,frames=0,rawCount=0,stdoutBytes=0;
const blocks=new Map(),offsets=new Map(),sequence=[];
for(const line of log.split("\n")){
 const m=prefix.exec(line);if(!m)continue;
 stdoutBytes+=utf8(m[1]+" "+m[2]+"\n").length;
 require(stdoutBytes<=1048576,"original framing stdout exceeds1MiB");
 let doc;try{doc=JSON.parse(m[2]);}catch{throw new Error("framing JSON malformed");}
 if(m[1]==="HIA_ORIGINAL_FRAME_FAILURE_V1")throw new Error("producer emitted explicit framing failure; preserve log without claiming END");
 if(m[1]==="HIA_ORIGINAL_FRAME_MANIFEST_V1"){
  require(manifest===null&&end===null,"duplicate/late manifest");
  const b=decode64(doc.base64);require(integer(doc.bytes)&&b.length===doc.bytes&&b.length<=131072&&H.sha256(b)===doc.sha256,"manifest byte seal differs");
  manifestRaw=decodeUTF8(b);manifest=JSON.parse(manifestRaw);manifestSHA=doc.sha256;
  require(manifest.schema==="hia.original-log-frame-manifest.v1"&&manifest.frame_bytes===24576&&manifest.maximum_raw_bytes===524288&&manifest.maximum_stdout_bytes===1048576,"frame contract differs");
  require(matchingPartition(manifest.partition)&&matchingInner(manifest.inner_archive_pin),"manifest interval or whole ZIP pin differs");
  const c=manifest.context;require(matchingPartition(c?.partition)&&matchingInner(c?.inner_archive_pin)&&c.event_ref==="codex/hia-970-inner-archive-parts-run-r1-20261112-e26e"&&c.event_ref_type==="branch","actual partition create event differs");
  require(c&&c.repository==="TrillionniumFoundation/Hepta"&&c.event==="create"&&c.run_id===expectedSource.run_id&&c.run_attempt===1,"actual run context differs");
  require(c.actual_control_checkout===expectedSource.control_commit&&c.actual_workflow_commit===expectedSource.workflow_commit&&c.policy_sha256===expectedSource.policy_sha256,"source control context differs");
  require(manifest.original_small_artifact.id===13913382201&&manifest.original_small_artifact.bytes===22390611&&manifest.original_small_artifact.sha256==="58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d","fixed small artifact differs");
  require(manifest.original_custody_status==="CUSTODY_HOLD"&&manifest.original_final_sha256==="afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345"&&manifest.qualification_executed===false&&manifest.original_product_statuses_reclassified===false&&manifest.original354_bodies_read===false&&manifest.inner_selected_archive_opened===false,"historical scope differs");
  const ix=manifest.derived_diagnostic_index,ib=decode64(ix.base64);require(ib.length===ix.bytes&&ib.length<=65536&&H.sha256(ib)===ix.sha256,"INDEX byte seal differs");
  indexRaw=decodeUTF8(ib);index=JSON.parse(indexRaw);require(index.schema==="hia.970.inner-archive-slice-index.v1"&&index.scope==="DERIVED_METADATA_ONLY_NOT_ORIGINAL_FILE_BODY"&&index.inner_selected_archive_opened===false&&index.original354_bodies_read===false&&index.original_custody_status==="CUSTODY_HOLD","INDEX scope differs");
  require(matchingPartition(index.partition)&&matchingInner(index.inner_archive_pin),"INDEX interval or complete ZIP differs");
  require(index.original_final_sha256===manifest.original_final_sha256&&index.small_artifact.id===13913382201&&index.small_artifact.sha256===manifest.original_small_artifact.sha256,"INDEX original identity differs");
  if(index.current_source_acceptance===true){
   require(Array.isArray(index.outer_directory)&&index.outer_directory.length===17&&new Set(index.outer_directory.map(x=>x.name)).size===17&&Object.keys(index.outer_member_hashes).length===17,"accepted full outer inventory differs");
   require(Array.isArray(index.original_captured_rows)&&index.original_captured_rows.length===15,"accepted captured population differs");
   for(const d of index.outer_directory){const r=index.outer_member_hashes[d.name];require(r&&r.bytes===d.bytes&&r.full_member_CRC_read===true&&/^[0-9a-f]{64}$/.test(r.sha256),"outer member CRC/SHA inventory differs");}
  }
  const s=index.selection_plan;require(s&&s.schema==="hia.970-inner-archive-slice-selection.v1"&&same(s.historical_targets,history)&&same(s.reader_targets,readers)&&s.rows.length===6&&same(s.rows.map(x=>x.name),names),"fixed6 selection ledger differs");
  let historical=0,current=0;const selected=[];
  for(const row of s.rows){
   require(["SELECTED_COMPLETE_ORIGINAL","MISSING","OMITTED_RAW_BUDGET"].includes(row.status),"unknown selection status");
   if(row.status==="MISSING"){require(row.bytes===null&&row.sha256===null&&row.raw_bytes_selected===0,"missing row carries body");continue;}
   require(integer(row.bytes)&&/^[0-9a-f]{64}$/.test(row.sha256),"invalid original metadata");
   if(row.status==="SELECTED_COMPLETE_ORIGINAL"){require(row.raw_bytes_selected===row.bytes,"selected extent differs");selected.push(row.name);if(row.name.startsWith("custody/"))historical+=row.bytes;else current+=row.bytes;}
   else require(row.raw_bytes_selected===0,"omitted row carries prefix");
  }
  require(historical<=458752&&current<=65536&&same(selected,s.selected_names)&&historical+current===s.total_original_raw_bytes_selected&&s.requested_ranges_truncated===false&&s.original_archive_partitioned===true&&s.whole_original_archive_in_one_partition===false,"partition or original-byte denominator differs");
  require(Array.isArray(manifest.files)&&same(manifest.files.map(x=>x.path),selected)&&manifest.files.length<=6&&manifest.total_raw_bytes===historical+current,"actual manifest population differs");
  for(const f of manifest.files){const row=s.rows.find(r=>r.name===f.path);require(row&&f.bytes===row.bytes&&f.sha256===row.sha256&&integer(f.bytes),"manifest original differs from INDEX");blocks.set(f.path,[]);offsets.set(f.path,0);sequence.push(f.path);}
  require(manifest.frame_count===manifest.files.reduce((n,f)=>n+Math.ceil(f.bytes/24576),0),"expected frame count differs");
 }else if(m[1]==="HIA_ORIGINAL_FRAME_V1"){
  require(manifest!==null&&end===null&&doc.manifest_sha256===manifestSHA,"frame lacks active manifest");
  require(blocks.has(doc.path)&&integer(doc.offset)&&doc.offset===offsets.get(doc.path)&&integer(doc.length)&&doc.length>0&&doc.length<=24576,"frame path/offset/length differs");
  const f=manifest.files.find(x=>x.path===doc.path),b=decode64(doc.base64);require(b.length===doc.length&&H.sha256(b)===doc.sha256&&doc.offset+b.length<=f.bytes,"actual chunk seal differs");
  const first=sequence.find(n=>offsets.get(n)<manifest.files.find(x=>x.path===n).bytes);require(first===doc.path,"frame file order differs");
  require(b.length===Math.min(24576,f.bytes-doc.offset),"noncanonical chunk partition");
  blocks.get(doc.path).push(b);offsets.set(doc.path,doc.offset+b.length);frames++;rawCount+=b.length;
 }else{
  require(manifest!==null&&end===null&&doc.schema==="hia.original-log-frame-terminal.v1"&&doc.manifest_sha256===manifestSHA,"terminal identity differs");
  require(["INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION","FRAMING_HOLD"].includes(doc.status)&&doc.files===manifest.files.length&&doc.frames===frames&&doc.raw_bytes===rawCount&&doc.source_bytes_complete===true&&doc.original_custody_status==="CUSTODY_HOLD"&&doc.qualification_executed===false&&doc.original_product_statuses_reclassified===false,"terminal scope/count differs");
  require(/^[0-9a-f]{64}$/.test(doc.result_sha256)&&same(doc.missing_frame_targets,manifest.missing_frame_targets),"terminal RESULT or missing ledger differs");
  if(doc.status==="INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION")require(manifest.files.length===6&&manifest.missing_frame_targets.length===0&&manifest.source_originals_accepted===true&&manifest.all_historical_targets_framed===true,"COMPLETE without full6 originals");
  end=doc;
 }
}
require(manifest!==null&&end!==null&&frames===manifest.frame_count&&rawCount===manifest.total_raw_bytes,"complete terminal absent or denominator differs");
const files=[];
for(const f of manifest.files){
 require(offsets.get(f.path)===f.bytes,"file incomplete");const b=new Uint8Array(f.bytes);let off=0;for(const part of blocks.get(f.path)){b.set(part,off);off+=part.length;}
 require(H.sha256(b)===f.sha256,"whole original SHA differs");
 let raw=null;if(f.path!==names[0])try{raw=decodeUTF8(b);require(same(Array.from(utf8(raw)),Array.from(b)),"UTF8 roundtrip");}catch{raw=null;}
 if(f.path.endsWith(".json"))require(raw!==null,"JSON original is not UTF8");
 files.push({path:f.path,bytes:f.bytes,sha256:f.sha256,git_blob_sha1:H.sha1([...H.ascii("blob "+b.length+"\0"),...b]),raw,base64:encode64(b)});
}
const selected=files.find(x=>x.path==="custody/inner-selected.zip.slice");
if(selected){
 require(selected.bytes===partition.bytes,"actual slice extent differs");
 // Do not reinterpret or normalize arbitrary compressed bytes as text.
 selected.raw=null;selected.binary=true;
}
if(end.status==="INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION"){
 require(selected!==undefined,"complete without original ZIP interval");
 const claim=index.actual_archive_slice_binding;
 require(claim&&matchingPartition(claim.partition)&&matchingInner(claim.inner_archive_pin)
   &&claim.bytes===selected.bytes&&claim.sha256===selected.sha256
   &&claim.full_inner_sha256_verified===true&&claim.same_original_range_independently_read===true
   &&claim.inner_members_opened===false&&claim.original_bytes_recompressed===false,
   "complete without actual interval-to-whole-original binding");
}
return {schema:"hia.970-inner-archive-slice-independent-decode.v1",run_id:expectedSource.run_id,job_id:expectedSource.job_id,partition,whole_inner_bytes:innerSize,whole_inner_sha256:innerSHA,status:end.status,protocol_complete:true,original_result_reclassified:false,manifest_sha256:manifestSHA,manifest_raw:manifestRaw,index_raw:indexRaw,files,frame_count:frames,total_raw_bytes:rawCount,protocol_stdout_bytes:stdoutBytes,full_joblog_bytes:utf8(log).length,full_joblog_sha256:H.sha256(utf8(log)),terminal:end,warning:"A valid FRAMING_HOLD END is complete bounded evidence transport, never a product or historical-custody PASS."};
}

function exact970JSON(raw) {
"use strict";
let p=0,nodes=0;
function fail(){throw new Error("invalid or excessive lossless JSON");}
function ws(){while(p<raw.length&&/[ \t\r\n]/.test(raw[p]))p++;}
function str(){const start=p++;let escaped=false;while(p<raw.length){const c=raw[p++];if(c==='"'&&!escaped){const value=JSON.parse(raw.slice(start,p));return value;}if(c==='\\'&&!escaped)escaped=true;else escaped=false;if(c.charCodeAt(0)<32)fail();}fail();}
function value(depth){ws();if(depth>128||++nodes>100000)fail();const c=raw[p];if(c==='"')return["string",str()];if(c==="{"){p++;ws();const map=[],keys=new Set();if(raw[p]!=="}")while(true){ws();if(raw[p]!=='"')fail();const k=str();if(keys.has(k))fail();keys.add(k);ws();if(raw[p++]!==":")fail();map.push([k,value(depth+1)]);ws();if(raw[p]==="}")break;if(raw[p++]!==",")fail();}p++;map.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);return["object",map];}if(c==="["){p++;ws();const a=[];if(raw[p]!=="]")while(true){a.push(value(depth+1));ws();if(raw[p]==="]")break;if(raw[p++]!==",")fail();}p++;return["array",a];}
for(const word of ["true","false","null"])if(raw.slice(p,p+word.length)===word){p+=word.length;return[word];}
const m=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(raw.slice(p));if(!m||m.index!==0)fail();p+=m[0].length;return["number",m[0]];}
const result=value(0);ws();if(p!==raw.length)fail();return result;
}
function exact970Field(node,key){if(!node||node[0]!=="object")throw new Error("lossless object expected");const pair=node[1].find(x=>x[0]===key);if(!pair)throw new Error("lossless key missing "+key);return pair[1];}
function equal970JSONNodes(a,b){return JSON.stringify(a)===JSON.stringify(b);}

function wire970ExactNode(node, level) {
"use strict";
if(level===undefined)level=0;
const indent="  ".repeat(level),next="  ".repeat(level+1);
function quoted(s){return JSON.stringify(s).replace(/[\u007f-\uffff]/g,c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"));}
switch(node[0]){
case"string":return quoted(node[1]);
case"number":return node[1];
case"true":return"true";
case"false":return"false";
case"null":return"null";
case"array":return node[1].length?"[\n"+node[1].map(x=>next+wire970ExactNode(x,level+1)).join(",\n")+"\n"+indent+"]":"[]";
case"object":return node[1].length?"{\n"+node[1].map(([k,v])=>next+quoted(k)+": "+wire970ExactNode(v,level+1)).join(",\n")+"\n"+indent+"}":"{}";
default:throw new Error("invalid exact JSON node");
}
}

function audit970InnerArchiveSlice(decoded, expected, H, utf8, policyRaw) {
"use strict";
function require(v,m){if(!v)throw new Error(m);}
function plainSame(a,b){function sort(x){if(Array.isArray(x))return x.map(sort);if(x&&typeof x==="object")return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])]));return x;}return JSON.stringify(sort(a))===JSON.stringify(sort(b));}
function pywire(x){function sort(y){if(Array.isArray(y))return y.map(sort);if(y&&typeof y==="object")return Object.fromEntries(Object.keys(y).sort().map(k=>[k,sort(y[k])]));return y;}return JSON.stringify(sort(x),null,2)+"\n";}
function raw(name){const f=decoded.files.find(x=>x.path===name);require(f&&typeof f.raw==="string","missing text control "+name);return f.raw;}
require(decoded.status==="INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION"
 &&decoded.files.length===6&&decoded.original_result_reclassified===false,"partition is held or incomplete");
require(H.sha256(utf8(policyRaw))==="178653ca3919761b8a3967c82e301eb8a61c1ff026402d45b0d825ae6d3ddd2e","actual frozen policy SHA differs");
const policy=JSON.parse(policyRaw),manifest=JSON.parse(decoded.manifest_raw),index=JSON.parse(decoded.index_raw),context=manifest.context,partition=decoded.partition;
const gRaw=raw("reader/guard/guardian.json"),wRaw=raw("reader/recovery-terminal.json"),sRaw=raw("reader/setup.json");
const g=JSON.parse(gRaw),w=JSON.parse(wRaw),s=JSON.parse(sRaw),life=g.lifecycle;
const mt=exact970JSON(decoded.manifest_raw),it=exact970JSON(decoded.index_raw),gt=exact970JSON(gRaw),wt=exact970JSON(wRaw),st=exact970JSON(sRaw);
require(equal970JSONNodes(exact970Field(st,"context"),exact970Field(mt,"context")),"setup/context lossless identity differs");
require(context.schema==="hia.actions.970-inner-archive-slice-context.v1"
 &&context.actual_control_checkout===expected.control_commit&&context.actual_workflow_commit===expected.workflow_commit
 &&context.policy_sha256===expected.policy_sha256&&context.run_id===expected.run_id
 &&context.run_attempt===1&&context.repository==="TrillionniumFoundation/Hepta"
 &&context.event==="create"&&context.event_ref_type==="branch"
 &&context.event_ref==="codex/hia-970-inner-archive-parts-run-r1-20261112-e26e"
 &&plainSame(context.partition,partition)&&plainSame(context.inner_archive_pin,policy.inner_archive)
 &&context.qualification_executed===false&&context.token_or_signed_URL_in_context===false,
 "current context differs from original interval operation");
const root=context.root,publicRoot=context.public_root;
require(typeof root==="string"&&root.startsWith("/")&&root.endsWith("/hia-970-inner-archive-parts-r1-"+partition.id)
 &&!root.split("/").includes("..")&&!root.split("/").includes(".")
 &&publicRoot===root.slice(0,root.lastIndexOf("/")+1)+"hia-970-inner-archive-parts-public-r1-"+partition.id,"partition roots differ");
const source=context.control_sources,controllerSuffix="/"+policy.control_prefix+"/controller.py";
const controllerPaths=Object.keys(source||{}).filter(x=>x.endsWith(controllerSuffix));
require(controllerPaths.length===1,"unique actual controller source absent");
const checkout=controllerPaths[0].slice(0,-controllerSuffix.length),control=checkout+"/"+policy.control_prefix;
const expectedSource={};
for(const [name,pin]of Object.entries(policy.control_files))expectedSource[control+"/"+name]=pin.sha256;
expectedSource[control+"/policy.json"]=expected.policy_sha256;
for(const [name,pin]of Object.entries(policy.unchanged_original_workflows))expectedSource[checkout+"/"+name]=pin.sha256;
require(plainSame(source,expectedSource),"complete fixed controller source map differs");
require(context.python&&context.python.resolved.startsWith("/")&&/^3\.14\.4\b/.test(context.python.version)
 &&/^[0-9a-f]{64}$/.test(context.python.binary.sha256)
 &&context.python.binary.path===context.python.resolved,"actual interpreter identity differs");
const inputs={...expectedSource};
for(const [name,pin]of Object.entries(policy.control_files))inputs[root+"/control/"+name]=pin.sha256;
inputs[root+"/control/policy.json"]=expected.policy_sha256;
// Rebuild only the controller's exact canonical context from lossless typed
// tokens. Nanosecond integers keep their original decimal lexemes.
const contextPath=root+"/context.json";
const exactContextRaw=wire970ExactNode(exact970Field(st,"context"))+"\n";
require(typeof s.source_identities?.[contextPath]==="string"
 &&H.sha256(utf8(exactContextRaw))===s.source_identities[contextPath],
 "actual lossless canonical context source SHA differs");
inputs[contextPath]=s.source_identities[contextPath];
inputs[context.python.resolved]=context.python.binary.sha256;
const command=[context.python.resolved,"-I","-S","-B",root+"/control/worker.py","--root",root,"--policy-sha256",expected.policy_sha256,"--partition",partition.id];
require(s.schema==="hia.actions.970-inner-archive-slice-setup.v1"&&s.status==="PREPARED_NOT_EXECUTED"
 &&plainSame(s.command,command)&&plainSame(s.source_identities,inputs)
 &&s.controller_seconds===900&&s.cleanup_seconds===3&&s.token_received===false&&s.project_code_executed===false
 &&s.capacity_before.free_bytes>=8589934592&&s.capacity_before.free_inodes>=100000,
 "complete original setup/limits/input mapping differs");
const request={schema:"hia-external-guardian-request.v1",controller_seconds:900,command,cwd:root,source_identities:inputs};
require(H.sha256(utf8(pywire(request)))===s.guardian_config_sha256,"actual guardian request SHA differs from exact reconstructed ASCII request");
require(g.schema==="hepta.hia.external-qualification-guardian.v1"&&g.status==="EXTERNAL_OWNED_PROCESS_COMPLETED"
 &&g.cwd===root&&plainSame(g.command,command)&&g.external_controller_seconds===900
 &&g.cold_180_second_gate_modified===false
 &&g.lifecycle_implementation_sha256===policy.control_files["process_owner_impl.py"].sha256
 &&plainSame(g.source_identities_before,inputs)&&plainSame(g.source_identities_after,inputs)
 &&g.input_identity_preserved===true,"actual bound guardian/source identity differs");
require(life?.schema==="hepta.hia.external-qualification-guardian.v1.lifecycle"
 &&life.status==="OWNED_PROCESS_COMPLETED"&&life.returncode===0
 &&life.subreaper_enabled===true&&life.qualification_started===true
 &&life.qualification_seconds===900&&life.cleanup_seconds===3
 &&life.timed_out===false&&life.exit_observed_before_deadline===true
 &&life.event_overflow===false&&plainSame(life.interrupted_signals,[])&&(life.owner_error??null)===null,
 "current natural owner failed");
const cleanup=life.cleanup,allowed=new Set(["qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"]);
require(cleanup?.attempted===true&&cleanup.complete===true&&cleanup.observed_echild===true&&cleanup.leader_reaped===true
 &&cleanup.deadline_exceeded===false&&plainSame(cleanup.errors,[])&&plainSame(cleanup.remaining_direct_children,[])
 &&Array.isArray(life.events)&&life.events.length>0&&life.events.every(e=>allowed.has(e.kind))
 &&["qualification_started","qualification_exit_observed","owned_child_reaped"].every(k=>life.events.some(e=>e.kind===k)),
 "current owner cleanup/kill/event boundary differs");
const expectedLogs={};
for(const name of ["child.stdout.log","child.stderr.log"])expectedLogs[root+"/guard/"+name]=decoded.files.find(x=>x.path==="reader/guard/"+name).sha256;
require(plainSame(g.logs,expectedLogs),"actual child logs differ from original guardian");
require(w.schema==="hia.actions.970-inner-archive-slice-worker.v1"
 &&w.status==="INNER_ARCHIVE_SLICE_VERIFIED_PENDING_NATURAL_GUARDIAN"&&w.root===root
 &&w.policy_sha256===expected.policy_sha256&&plainSame(w.partition,partition)
 &&plainSame(w.small_artifact,policy.small_artifact)
 &&w.outer_originals_verified===true&&w.original_final_status==="CUSTODY_HOLD"
 &&w.original_final_sha256===policy.original_final_sha256&&w.original_captured_count===15
 &&w.inner_selected_archive_opened===false&&w.original354_bodies_read===false
 &&plainSame(w.missing_frame_targets,[])&&plainSame(w.expected_frame_targets,policy.diagnostic_targets.historical),
 "actual current worker scope or source binding differs");
for(const name of ["original_large_artifacts_downloaded","project_code_executed","qualification_executed","original_product_statuses_reclassified","token_or_signed_URL_recorded","unselected_original_product_members_executed","original_cold_or_compiler_headers_reclassified"])require(w[name]===false,"actual worker scope changed "+name);
const calls=w.API_attempts,gets=w.GET_attempts;
require(Array.isArray(calls)&&calls.length===2&&calls[0].role==="official_metadata"&&calls[1].role==="official_download_redirect"
 &&calls[0].status===200&&calls[1].status===302
 &&calls.every(x=>x.artifact_id===13913382201&&x.attempt===1&&x.retries===0&&x.host==="api.github.com"&&x.credential_sent_only_to_official_API===true)
 &&calls[1].authorization_forwarded===false&&calls[1].signed_Location_recorded===false
 &&Array.isArray(gets)&&gets.length===1&&gets[0].artifact_id===13913382201&&gets[0].attempt===1
 &&gets[0].retries===0&&gets[0].redirects===0&&gets[0].authorization_sent===false&&gets[0].cookies_sent===false
 &&gets[0].bytes===policy.small_artifact.bytes&&gets[0].sha256===policy.small_artifact.sha256
 &&w.official_metadata?.provider_head_sha_observed===policy.original_operation.workflow_commit,"actual one-GET credential/metadata boundary differs");
require(equal970JSONNodes(exact970Field(wt,"small_zip_before"),exact970Field(wt,"small_zip_after"))
 &&w.small_zip_before.bytes===policy.small_artifact.bytes&&w.small_zip_before.sha256===policy.small_artifact.sha256
 &&w.small_zip_before.actual_bytes_independently_read===policy.small_artifact.bytes,"outer full ZIP exact before/after differs");
const slice=decoded.files.find(x=>x.binary===true),claim=w.archive_slice,claimTyped=exact970Field(wt,"archive_slice");
require(slice&&slice.bytes===partition.bytes&&claim.bytes===slice.bytes&&claim.sha256===slice.sha256
 &&plainSame(claim.partition,partition)&&plainSame(claim.inner_archive_pin,policy.inner_archive)
 &&claim.full_inner_sha256_verified===true&&claim.same_original_range_independently_read===true
 &&claim.inner_members_opened===false&&claim.original_bytes_recompressed===false
 &&equal970JSONNodes(claimTyped,exact970Field(it,"actual_archive_slice_binding"))
 &&equal970JSONNodes(exact970Field(claimTyped,"inner_before"),exact970Field(claimTyped,"inner_after")),
 "actual opaque slice and complete-inner before/after lossless binding differs");
require(claim.inner_before.path===root+"/captured/014.original"
 &&claim.inner_before.bytes===8316154&&claim.inner_before.sha256===policy.inner_archive.sha256
 &&claim.inner_before.actual_bytes_independently_read===8316154,
 "actual whole inner ZIP pin differs");
require(Array.isArray(w.frame_files)&&w.frame_files.length===1&&w.frame_files[0].logical_path===slice.path
 &&w.frame_files[0].record.path===root+"/selected/inner-archive.slice.bin"
 &&w.frame_files[0].record.bytes===slice.bytes&&w.frame_files[0].record.sha256===slice.sha256
 &&w.frame_files[0].record.actual_bytes_independently_read===slice.bytes,
 "actual slice record differs from full framed bytes");
return {schema:"hia.970-inner-slice-independent-owner-audit.v1",status:"PARTITION_ORIGINAL_BYTES_AND_NATURAL_OWNER_VERIFIED_NOT_QUALIFICATION",
 run_id:decoded.run_id,job_id:decoded.job_id,partition,raw_files:6,slice_sha256:slice.sha256,
 whole_inner_bytes:8316154,whole_inner_sha256:policy.inner_archive.sha256,natural_900_3:true,
 exact_integer_lexemes_compared:true,full_request_reconstructed:true,credential_boundary_verified:true,
 original_custody_status:"CUSTODY_HOLD",historical_result_reclassified:false,qualification_executed:false};
}

function aggregate970InnerArchivePartitions(records, run, jobs, H, utf8, policyRaw) {
"use strict";
function require(v,m){if(!v)throw new Error(m);}
const fixed={control_commit:"eb1e312c3d030e704aa30cd4932726fa18f5a83c",workflow_commit:"a4b93e1a370f1c8c9b7fbf3fba7ebbbfeaf2adeb",policy_sha256:"178653ca3919761b8a3967c82e301eb8a61c1ff026402d45b0d825ae6d3ddd2e"};
const branch="codex/hia-970-inner-archive-parts-run-r1-20261112-e26e",wanted=Array.from({length:19},(_,i)=>String(i).padStart(2,"0"));
const report={schema:"hia.970-inner-archive-nineteen-partition-aggregate.v1",status:"COHORT_HOLD",run_id:run?.id,
 expected_partitions:wanted,actual_partitions:[],errors:[],parts:[],full_inner_zip_recovered:false,
 original_custody_status:"CUSTODY_HOLD",original_frame_status:"FRAMING_HOLD",
 historical_cancelled_run_unchanged:true,historical_result_reclassified:false,qualification_executed:false};
const decoded=[];
try {
 require(run?.id===43162816113&&run.run_attempt===1&&run.event==="create"
  &&run.head_sha===fixed.workflow_commit&&run.head_branch===branch
  &&run.path===".github/workflows/hia-970-inner-archive-partitions.yml",
  "official unique run identity differs");
 require(Array.isArray(jobs)&&jobs.length===19&&new Set(jobs.map(j=>j.id)).size===19,
  "official nineteen unique jobs incomplete");
 const official=new Map();
 for(const job of jobs){
  const m=/^Retain original inner ZIP slice (0[0-9]|1[0-8])$/.exec(job.name);
  require(m&&job.run_id===run.id&&!official.has(m[1]),"official job partition/run mismatch");
  official.set(m[1],job);
 }
 require(wanted.every(id=>official.has(id)),"official matrix missing partition");
 require(Array.isArray(records)&&records.length<=19&&new Set(records.map(r=>r.job_id)).size===records.length,
  "duplicate or excessive log records");
 const seen=new Set();
 for(const record of records){
  let id=null;
  try{
   require(record&&Number.isSafeInteger(record.job_id)&&typeof record.log==="string","raw joblog record required");
   const pair=[...official].find(([_,j])=>j.id===record.job_id);require(pair,"log from unknown official job");id=pair[0];
   require(!seen.has(id),"duplicate partition log");seen.add(id);
   const expected={...fixed,run_id:run.id,job_id:record.job_id,partition_id:id};
   const item=decode970InnerArchiveSliceLog(record.log,expected,H,utf8);
   const audit=audit970InnerArchiveSlice(item,expected,H,utf8,policyRaw);
   const job=pair[1];require(job.status==="completed"&&job.conclusion==="success","official job is not terminal success");
   decoded.push(item);report.parts.push({partition:item.partition,job_id:item.job_id,manifest_sha256:item.manifest_sha256,
    joblog_bytes:item.full_joblog_bytes,joblog_sha256:item.full_joblog_sha256,
    raw_files:item.files.length,frames:item.frame_count,raw_bytes:item.total_raw_bytes,
    slice_sha256:item.files[0].sha256,owner_audit:audit});
  }catch(error){report.errors.push({partition:id,job_id:record?.job_id??null,reason:String(error?.message??error)});}
 }
 report.actual_partitions=decoded.map(x=>x.partition.id).sort();
 report.missing_partitions=wanted.filter(id=>!report.actual_partitions.includes(id));
 require(run.status==="completed"&&run.conclusion==="success","official original run not terminal success");
 require(records.length===19&&decoded.length===19&&report.errors.length===0&&report.missing_partitions.length===0,
  "complete matching nineteen-log cohort not available");
 const zip=new Uint8Array(8316154);
 const alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 function from64(s){const pad=s.endsWith("==")?2:s.endsWith("=")?1:0,out=new Uint8Array(s.length/4*3-pad);let p=0;for(let i=0;i<s.length;i+=4){let v=0;for(let j=0;j<4;j++)v=(v<<6)|(s[i+j]==="="?0:alpha.indexOf(s[i+j]));for(const shift of [16,8,0])if(p<out.length)out[p++]=(v>>>shift)&255;}return out;}
 let offset=0;
 for(const item of decoded.sort((a,b)=>a.partition.ordinal-b.partition.ordinal)){
  require(item.partition.offset===offset,"actual original slice gap/overlap");
  const file=item.files.find(x=>x.path==="custody/inner-selected.zip.slice"),bytes=from64(file.base64);
  require(bytes.length===item.partition.bytes&&H.sha256(bytes)===file.sha256,"reassembly actual slice seal differs");
  zip.set(bytes,offset);offset+=bytes.length;
 }
 require(offset===8316154,"reassembled original ZIP extent differs");
 const sha=H.sha256(zip);require(sha==="d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e","reassembled original full ZIP external seal differs");
 report.status="ORIGINAL_INNER_ZIP_FULL_SHA_RECOVERED_NOT_QUALIFICATION";
 report.full_inner_zip_recovered=true;report.bytes=offset;report.sha256=sha;
 report.aggregate_raw_files=decoded.reduce((n,d)=>n+d.files.length,0);
 report.aggregate_frames=decoded.reduce((n,d)=>n+d.frame_count,0);
 report.aggregate_raw_bytes=decoded.reduce((n,d)=>n+d.total_raw_bytes,0);
 report.inner_members_decompressed=false;report.original354_bodies_verified=false;
 return{report,decoded,zip_bytes:zip};
}catch(error){report.errors.push({stage:"COHORT",reason:String(error?.message??error)});
 report.actual_partitions=decoded.map(x=>x.partition.id).sort();
 report.missing_partitions=wanted.filter(id=>!report.actual_partitions.includes(id));
 return{report,decoded,zip_bytes:null};
}
}
