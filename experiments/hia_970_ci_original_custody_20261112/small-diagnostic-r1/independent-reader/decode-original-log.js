function decode970SmallDiagnosticLog(log, expected, H, utf8) {
"use strict";
function require(v,m){if(!v)throw new Error(m);}
const A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function encode64(bytes){let out="";for(let i=0;i<bytes.length;i+=3){const a=bytes[i],b=i+1<bytes.length?bytes[i+1]:0,c=i+2<bytes.length?bytes[i+2]:0,v=(a<<16)|(b<<8)|c;out+=A[(v>>>18)&63]+A[(v>>>12)&63]+(i+1<bytes.length?A[(v>>>6)&63]:"=")+(i+2<bytes.length?A[v&63]:"=");}return out;}
function decode64(s){require(typeof s==="string"&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),"noncanonical base64 syntax");const pad=s.endsWith("==")?2:s.endsWith("=")?1:0,out=new Uint8Array(s.length/4*3-pad);let k=0;for(let i=0;i<s.length;i+=4){let v=0;for(let j=0;j<4;j++)v=(v<<6)|(s[i+j]==="="?0:A.indexOf(s[i+j]));for(const n of [16,8,0])if(k<out.length)out[k++]=(v>>>n)&255;}require(encode64(out)===s,"noncanonical base64 bits");return out;}
function decodeUTF8(b){let out="",batch=[];for(let i=0;i<b.length;){const c=b[i++];let cp,n,min;if(c<128){cp=c;n=0;min=0;}else if(c>=194&&c<=223){cp=c&31;n=1;min=128;}else if(c>=224&&c<=239){cp=c&15;n=2;min=2048;}else if(c>=240&&c<=244){cp=c&7;n=3;min=65536;}else throw new Error("invalid UTF8 lead");require(i+n<=b.length,"short UTF8");for(let j=0;j<n;j++){const d=b[i++];require((d&192)===128,"invalid UTF8 continuation");cp=(cp<<6)|(d&63);}require(cp>=min&&cp<=1114111&&!(cp>=55296&&cp<=57343),"noncanonical UTF8 scalar");batch.push(cp);if(batch.length===2048){out+=String.fromCodePoint(...batch);batch=[];}}return out+String.fromCodePoint(...batch);}

const integer=(n)=>Number.isSafeInteger(n)&&n>=0;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const names=["custody/guard/child.stderr.log","custody/guard/child.stdout.log","custody/recovery-terminal.json","custody/guard/guardian.json","custody/FINAL.json","custody/FRAME-RESULT.json","custody/supervisor.stderr.log","custody/supervisor.stdout.log","custody/recovery.json","custody/selected/13911977275/CUSTODY.json","custody/context.json","custody/setup.json","custody/guard/request.json","reader/guard/guardian.json","reader/guard/child.stdout.log","reader/guard/child.stderr.log","reader/recovery-terminal.json","reader/setup.json"];
const history=names.slice(0,13),readers=names.slice(13);
const expectedSource=expected||{};
require(typeof log==="string"&&integer(expectedSource.run_id),"exact run identity required");
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
  const c=manifest.context;require(c&&c.repository==="TrillionniumFoundation/Hepta"&&c.event==="create"&&c.run_id===expectedSource.run_id&&c.run_attempt===1,"actual run context differs");
  require(c.actual_control_checkout===expectedSource.control_commit&&c.actual_workflow_commit===expectedSource.workflow_commit&&c.policy_sha256===expectedSource.policy_sha256,"source control context differs");
  require(manifest.original_small_artifact.id===13913382201&&manifest.original_small_artifact.bytes===22390611&&manifest.original_small_artifact.sha256==="58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d","fixed small artifact differs");
  require(manifest.original_custody_status==="CUSTODY_HOLD"&&manifest.original_final_sha256==="afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345"&&manifest.qualification_executed===false&&manifest.original_product_statuses_reclassified===false&&manifest.original354_bodies_read===false&&manifest.inner_selected_archive_opened===false,"historical scope differs");
  const ix=manifest.derived_diagnostic_index,ib=decode64(ix.base64);require(ib.length===ix.bytes&&ib.length<=65536&&H.sha256(ib)===ix.sha256,"INDEX byte seal differs");
  indexRaw=decodeUTF8(ib);index=JSON.parse(indexRaw);require(index.schema==="hia.970.small-diagnostic-index.v1"&&index.scope==="DERIVED_METADATA_ONLY_NOT_ORIGINAL_FILE_BODY"&&index.inner_selected_archive_opened===false&&index.original354_bodies_read===false&&index.original_custody_status==="CUSTODY_HOLD","INDEX scope differs");
  require(index.original_final_sha256===manifest.original_final_sha256&&index.small_artifact.id===13913382201&&index.small_artifact.sha256===manifest.original_small_artifact.sha256,"INDEX original identity differs");
  if(index.current_source_acceptance===true){
   require(Array.isArray(index.outer_directory)&&index.outer_directory.length===17&&new Set(index.outer_directory.map(x=>x.name)).size===17&&Object.keys(index.outer_member_hashes).length===17,"accepted full outer inventory differs");
   require(Array.isArray(index.original_captured_rows)&&index.original_captured_rows.length===15,"accepted captured population differs");
   for(const d of index.outer_directory){const r=index.outer_member_hashes[d.name];require(r&&r.bytes===d.bytes&&r.full_member_CRC_read===true&&/^[0-9a-f]{64}$/.test(r.sha256),"outer member CRC/SHA inventory differs");}
  }
  const s=index.selection_plan;require(s&&s.schema==="hia.970-small-diagnostic-selection.v1"&&same(s.historical_targets,history)&&same(s.reader_targets,readers)&&s.rows.length===18&&same(s.rows.map(x=>x.name),names),"fixed18 selection ledger differs");
  let historical=0,current=0;const selected=[];
  for(const row of s.rows){
   require(["SELECTED_COMPLETE_ORIGINAL","MISSING","OMITTED_RAW_BUDGET"].includes(row.status),"unknown selection status");
   if(row.status==="MISSING"){require(row.bytes===null&&row.sha256===null&&row.raw_bytes_selected===0,"missing row carries body");continue;}
   require(integer(row.bytes)&&/^[0-9a-f]{64}$/.test(row.sha256),"invalid original metadata");
   if(row.status==="SELECTED_COMPLETE_ORIGINAL"){require(row.raw_bytes_selected===row.bytes,"selected extent differs");selected.push(row.name);if(row.name.startsWith("custody/"))historical+=row.bytes;else current+=row.bytes;}
   else require(row.raw_bytes_selected===0,"omitted row carries prefix");
  }
  require(historical<=458752&&current<=65536&&same(selected,s.selected_names)&&historical+current===s.total_original_raw_bytes_selected&&s.original_files_truncated===false,"partition or original-byte denominator differs");
  require(Array.isArray(manifest.files)&&same(manifest.files.map(x=>x.path),selected)&&manifest.files.length<=18&&manifest.total_raw_bytes===historical+current,"actual manifest population differs");
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
  require(["DIAGNOSTIC_ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION","FRAMING_HOLD"].includes(doc.status)&&doc.files===manifest.files.length&&doc.frames===frames&&doc.raw_bytes===rawCount&&doc.source_bytes_complete===true&&doc.original_custody_status==="CUSTODY_HOLD"&&doc.qualification_executed===false&&doc.original_product_statuses_reclassified===false,"terminal scope/count differs");
  require(/^[0-9a-f]{64}$/.test(doc.result_sha256)&&same(doc.missing_frame_targets,manifest.missing_frame_targets),"terminal RESULT or missing ledger differs");
  if(doc.status==="DIAGNOSTIC_ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION")require(manifest.files.length===18&&manifest.missing_frame_targets.length===0&&manifest.source_originals_accepted===true&&manifest.all_historical_targets_framed===true,"COMPLETE without full18 originals");
  end=doc;
 }
}
require(manifest!==null&&end!==null&&frames===manifest.frame_count&&rawCount===manifest.total_raw_bytes,"complete terminal absent or denominator differs");
const files=[];
for(const f of manifest.files){
 require(offsets.get(f.path)===f.bytes,"file incomplete");const b=new Uint8Array(f.bytes);let off=0;for(const part of blocks.get(f.path)){b.set(part,off);off+=part.length;}
 require(H.sha256(b)===f.sha256,"whole original SHA differs");
 let raw=null;try{raw=decodeUTF8(b);require(same(Array.from(utf8(raw)),Array.from(b)),"UTF8 roundtrip");}catch{raw=null;}
 if(f.path.endsWith(".json"))require(raw!==null,"JSON original is not UTF8");
 files.push({path:f.path,bytes:f.bytes,sha256:f.sha256,git_blob_sha1:H.sha1([...H.ascii("blob "+b.length+"\0"),...b]),raw,base64:encode64(b)});
}
const oldFinal=files.find(x=>x.path==="custody/FINAL.json");
if(oldFinal)require(oldFinal.sha256==="afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345","actual original FINAL seal differs");
return {schema:"hia.970-small-diagnostic-independent-decode.v1",status:end.status,protocol_complete:true,original_result_reclassified:false,manifest_sha256:manifestSHA,manifest_raw:manifestRaw,index_raw:indexRaw,files,frame_count:frames,total_raw_bytes:rawCount,protocol_stdout_bytes:stdoutBytes,full_joblog_bytes:utf8(log).length,full_joblog_sha256:H.sha256(utf8(log)),terminal:end,warning:"A valid FRAMING_HOLD END is complete bounded evidence transport, never a product or historical-custody PASS."};
}
