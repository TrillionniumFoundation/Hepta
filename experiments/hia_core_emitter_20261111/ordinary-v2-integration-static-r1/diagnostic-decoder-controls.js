const h=new Function(load("core.lowering.bytehash.helpers"))();
const z=new Function(load("core.lowering.custody.decoder.js"))();
const decode=new Function(load("core.lowering.emitter.actions-r3.diagnostic.decoder.js"))();
const api={utf8:h.utf8,sha256:h.digest256,base64Bytes:z.base64Bytes,bytesBase64:z.bytesBase64,utf8Text:z.utf8Text};
const names=[];for(const stage of ["prepare","run","finalize"])for(const channel of ["stdout","stderr"])names.push("stage/"+stage+"."+channel+".log");
names.push("setup.json","context.json","guard/request.json","FINAL.json","guard/guardian.json","evidence/report.json","guard/child.stdout.log","guard/child.stderr.log");
function fixture(closed=true){
 const records=[["DIAGNOSTIC_BEGIN",{schema:"hia.core-emitter-actions-diagnostic.v1",control_commit:"9473e0fca206dc27ed87122f4a5d45a905d8b35c",workflow_commit:"4d508b8e7b66d8f2801e76f6b6bb4794eb4bdac7",run_id:43131161021,run_attempt:1,policy_sha256:"0cf91131f947850badb125537249c94229f5cf0590653363702b378913a84dcf",maximum_original_raw_bytes:4194304,fixed_file_count:14,directory_scans:0,product_execution:false,original_exit_status_modified:false,frames_are_original_bytes:true}],["DIAGNOSTIC_BOUNDARY",{closed_current_operation_ECHILD:closed,error_type:closed?null:"RuntimeError",natural_success_inferred:false}]];
 let total=0,printed=0; const obs={};
 for(const [i,name] of names.entries()){
  const bytes=i%3===0?new Uint8Array([0,255,128,13,10,226,152,131]):new Uint8Array();
  const digest=h.digest256(bytes);const record={name,bytes:bytes.length,sha256:digest,frame_bytes:8192,frame_count:bytes.length?1:0};
  const gated=i>=10;
  if(closed||!gated||name==="guard/guardian.json"){obs[name]={status:"COMPLETE_ORIGINAL_READ",bytes:bytes.length,sha256:digest};total+=bytes.length;}
  if(!closed&&gated){records.push(["ORIGINAL_UNAVAILABLE",{name,status:"CLOSED_CURRENT_OPERATION_NOT_PROVEN",observed_sha256:obs[name]?.sha256??null,observed_bytes:obs[name]?.bytes??null,original_bytes_printed:0}]);continue;}
  records.push(["ORIGINAL_BEGIN",record]);
  if(bytes.length)records.push(["ORIGINAL_FRAME",{name,index:0,offset:0,bytes:bytes.length,sha256:digest,base64:z.bytesBase64(bytes)}]);
  records.push(["ORIGINAL_END",{name,bytes:bytes.length,sha256:digest,frame_count:record.frame_count}]);printed+=bytes.length;
 }
 records.push(["DIAGNOSTIC_END",{original_raw_byte_budget_reserved:total,verified_original_bytes_read:total,original_raw_bytes_printed:printed,maximum_raw_bytes:4194304,closed_current_operation_ECHILD:closed,fixed_file_observations:obs,original_exit_status_modified:false,qualification_claimed:false}]);
 return records;
}
function wire(rows){return rows.map(([kind,v])=>"2026-11-12T01:00:00.0000000Z HIA_CORE_EMITTER_"+kind+" "+JSON.stringify(v)).join("\n")+"\n";}
const results=[];for(const closed of [true,false]){const r=decode(wire(fixture(closed)),api);if(r.files.length+r.unavailable.length!==14)throw Error("positive count");results.push({case:closed?"14 original files including exact non-UTF8 bytes":"10 original files plus four explicitly gated originals",expected:"ACCEPT",actual:"ACCEPT"});}
const cases=[
 ["wrong current control commit",r=>r[0][1].control_commit="0".repeat(40)],
 ["missing final marker",r=>r.pop()],
 ["repeated marker",r=>r.push(r[r.length-1])],
 ["missing original frame",r=>r.splice(r.findIndex(x=>x[0]==="ORIGINAL_FRAME"),1)],
 ["nonconsecutive frame offset",r=>r.find(x=>x[0]==="ORIGINAL_FRAME")[1].offset=1],
 ["different original whole SHA",r=>r.find(x=>x[0]==="ORIGINAL_END")[1].sha256="0".repeat(64)],
 ["different frame payload",r=>r.find(x=>x[0]==="ORIGINAL_FRAME")[1].base64="AAAAAAAAAAA="],
 ["unexpected file name",r=>r.find(x=>x[0]==="ORIGINAL_BEGIN")[1].name="arbitrary/path"],
 ["closed flag false while gated bytes appear",r=>r[1][1].closed_current_operation_ECHILD=false],
 ["wrong total byte denominator",r=>r[r.length-1][1].original_raw_bytes_printed++],
 ["missing successful observation",r=>delete r[r.length-1][1].fixed_file_observations[names[0]]]
];
for(const [name,mutate]of cases){const r=fixture();mutate(r);let refused=false,reason;try{decode(wire(r),api);}catch(e){refused=true;reason=String(e);}if(!refused)throw Error("decoder false acceptance "+name);results.push({case:name,expected:"REFUSE",actual:"REFUSE",reason});}
const report={schema:"hia.core-emitter-diagnostic-decoder-controls.v1",scope:"SYNTHETIC_V8_DECODER_ONLY_NO_ACTIONS_OR_PRODUCT_EXECUTION",status:"PASS",controls:results.length,results,actual_run_logs_used:false,actual_original_reports_recovered:false,product_execution:false,qualification_claimed:false};
store("core.lowering.emitter.actions-r3.diagnostic.decoder.controls-report.json",JSON.stringify(report,null,2)+"\n");text(report);