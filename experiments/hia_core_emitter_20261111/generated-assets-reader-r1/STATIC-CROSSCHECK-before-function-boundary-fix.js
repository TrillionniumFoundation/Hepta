const h=new Function(load("core.lowering.bytehash.helpers"))();
const s=new Function(load("core.lowering.sha1.bytes.helper"))();
const p="core.lowering.emitter.assets-recovery.r1.";
const pins=JSON.parse(load(p+"asset-pins.json")),policy=JSON.parse(load(p+"policy.json"));
const checks=[];
function check(name, value){if(!value)throw Error("static source asset check: "+name);checks.push(name);}
function code(source,name){const start=source.indexOf("\ndef "+name+"(");if(start<0)throw Error("missing def "+name);const end=source.indexOf("\ndef ",start+2);return source.slice(start,end<0?source.length:end).trim();}
const source=load(p+"sources"),bw=load("core.peer.small-log-reader.r1.worker.py"),bc=load("core.peer.small-log-reader.r1.controller.py");
check("103 unique external member pins",pins.archive_members.length===103&&new Set(pins.archive_members.map(x=>x.archive_path)).size===103);
check("actual upload log independently says 103 files",load("core.lowering.emitter.actions-r3.actual.joblog.txt").includes("there will be 103 files uploaded"));
check("103 exact raw-byte denominator",pins.archive_members.reduce((a,x)=>a+x.bytes,0)===12024858);
const selected=pins.archive_members.filter(x=>x.logical_path!==null);
check("54 exact selected originals / 7251108 bytes",selected.length===54&&selected.reduce((a,x)=>a+x.bytes,0)===7251108);
check("bounded original payload leaves control-record room",7251108<(8<<20)&&policy.frame_limits.raw_bytes===(8<<20)&&policy.frame_limits.stdout_bytes===(12<<20));
const original=load("core.lowering.emitter.actions-r3.actual.original-pins");
for(const row of original){const raw=h.utf8(load("core.lowering.emitter.actions-r3.actual.raw."+row.name));check("raw original "+row.name,raw.length===row.bytes&&h.digest256(raw)===row.sha256&&s.blobSha(raw,h.utf8)===row.git_blob_sha1&&selected.some(x=>x.logical_path==="original/"+row.name&&x.sha256===row.sha256&&x.bytes===row.bytes));}
const report=load("core.lowering.emitter.actions-r3.actual.authoring.report");
check("39 exact current source-only unit pins",report.units.length===39&&pins.archive_members.filter(x=>x.role==="assembly").every(x=>report.units.some(u=>u.path.endsWith("/"+x.archive_path.slice(x.archive_path.indexOf("/evidence/")+1))&&u.size===x.bytes&&u.sha256===x.sha256&&u.git_blob_sha1===x.git_blob_sha1)));
check("39 unframed authoring originals pinned from actual report",pins.archive_members.filter(x=>x.role==="authoring").length===39&&report.units.every(u=>pins.archive_members.some(x=>x.archive_path===u.authoring.path.slice("/home/runner/work/_temp/".length)&&x.bytes===u.authoring.size&&x.sha256===u.authoring.sha256)));
check("four unframed source inventories retained as exact pins",["candidate_before","candidate_after","candidate_physical_before","candidate_physical_after"].every(k=>pins.archive_members.some(x=>x.archive_path===report[k].path.slice("/home/runner/work/_temp/".length)&&x.sha256===report[k].sha256&&x.bytes===report[k].size)));
const af=load("core.lowering.emitter.actions-r2.A.files");
check("six original control copies match frozen original A2 bytes",pins.archive_members.filter(x=>x.role==="source_control").length===6&&pins.archive_members.filter(x=>x.role==="source_control").every(x=>af.some(y=>y.path.endsWith("/"+x.archive_path.split("/").at(-1))&&h.digest256(h.utf8(y.content))===x.sha256)));
for(const name of ["require","wire","identity","read","create","new_client","deadline_check","api_request","bounded_response","official_location","storage_download"]){check("unchanged official transport helper "+name,code(bw,name)===code(source["worker.py"],name));}
for(const name of ["require","wire","identity","read","file_record","create","sync_dir","document","prepare","run","expected_setup_identities","check_setup","closed_guardian","natural_guardian"]){const old=code(bc,name).replaceAll("hia.actions.small-original-frames-","hia.actions.core-emitter-assets-");check("unchanged custody ownership helper "+name,old===code(source["controller.py"],name));}
check("unchanged framing except bounded file-count adaptation",code(bc,"output_frames").replace("require(len(files) <= 32","require(len(files) <= 64")===code(source["controller.py"],"output_frames"));
for(const [name,pin]of Object.entries(policy.control_files)){const raw=h.utf8(source[name]);check("new frozen control identity "+name,raw.length===pin.bytes&&h.digest256(raw)===pin.sha256&&s.blobSha(raw,h.utf8)===pin.git_blob_sha1);}
check("original source identity/source-only scope pinned",pins.original_run.candidate_commit===report.candidate_commit&&pins.original_run.candidate_tree===report.candidate_tree&&pins.original_run.status===report.status&&!report.native_compiler_executed&&!report.product_tests_executed&&!report.cold_qualified);
const result={schema:"hia.core-emitter-assets-reader-static-crosscheck.v1",status:"FINITE_V8_SOURCE_AND_PIN_CROSSCHECK_PASS",checks,count:checks.length,python_parsed:false,controller_executed:false,original_archive_read:false,asset_bytes_recovered:false,product_execution:false,qualification_execution:false};
store(p+"STATIC-CROSSCHECK.json",JSON.stringify(result,null,2)+"\n");
text({status:result.status,count:result.count});
