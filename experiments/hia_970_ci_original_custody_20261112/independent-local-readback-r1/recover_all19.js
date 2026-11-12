"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const root=__dirname,out=path.join(root,"all19-recovery-r1");
fs.mkdirSync(out,{mode:0o700});
const source=fs.readFileSync(path.join(root,"inputs/decoder.js"),"utf8");
if(crypto.createHash("sha256").update(source).digest("hex")!=="8892d3f07bac1454abd6163368af3abe6325c23d7ecac85348aa6e0527ebdb99")throw Error("frozen decoder changed");
const D=new Function(source+"\nreturn {decode970InnerArchiveSliceLog,audit970InnerArchiveSlice,aggregate970InnerArchivePartitions};")();
const H={sha1:a=>crypto.createHash("sha1").update(Buffer.from(a)).digest("hex"),sha256:a=>crypto.createHash("sha256").update(Buffer.from(a)).digest("hex"),ascii:s=>Array.from(Buffer.from(s,"ascii"))};
const utf8=s=>new Uint8Array(Buffer.from(s,"utf8")),wire=x=>JSON.stringify(x,null,2)+"\n";
const run=JSON.parse(fs.readFileSync(path.join(root,"run-and-jobs/run.original.json"),"utf8"));
const jobsSDK=JSON.parse(fs.readFileSync(path.join(root,"run-and-jobs/jobs.sdk.json"),"utf8"));
const jobs=jobsSDK.jobs;
const records=jobs.map(job=>{const part=/slice (\d\d)$/.exec(job.name)[1];return {job_id:job.id,log:fs.readFileSync(path.join(root,"recovered-logs/part-"+part+".log"),"utf8")};});
const policy=fs.readFileSync(path.join(root,"inputs/policy.json"),"utf8");
const result=D.aggregate970InnerArchivePartitions(records,run,jobs,H,utf8,policy);
function record(b){return{bytes:b.length,sha256:H.sha256(b),git_blob_sha:H.sha1(Buffer.concat([Buffer.from("blob "+b.length+"\0","ascii"),b]))};}
function save(name,data){const b=Buffer.isBuffer(data)?data:Buffer.from(data,"utf8"),p=path.join(out,name);fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});const fd=fs.openSync(p,"wx",0o400);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}if(!fs.readFileSync(p).equals(b))throw Error("readback differs");return {path:name,...record(b)};}
const files=[];
files.push(save("AGGREGATE.json",wire(result.report)));
if(result.report.status!=="ORIGINAL_INNER_ZIP_FULL_SHA_RECOVERED_NOT_QUALIFICATION")throw Error(JSON.stringify(result.report.errors));
if(!Buffer.from(result.zip_bytes).equals(fs.readFileSync(path.join(root,"container-readback-r1/selected-originals.zip"))))throw Error("log reassembly differs from exact original small artifact");
save("selected-originals.from-19-frames.zip",Buffer.from(result.zip_bytes));
for(const item of result.decoded){
 const pn="part-"+item.partition.id,rawFiles=[];
 for(const f of item.files){
   const rel=pn+"/originals/"+f.path+(f.binary?".base64":"");
   const saved=save(rel,f.binary?f.base64:f.raw);
   files.push(saved);
   rawFiles.push({original_path:f.path,original_bytes:f.bytes,original_sha256:f.sha256,original_git_blob_sha:f.git_blob_sha1,stored_path:rel,storage_encoding:f.binary?"canonical_base64_no_line_breaks":"utf-8",...saved});
 }
 files.push(save(pn+"/workflow-job-original.log",records.find(r=>r.job_id===item.job_id).log));
 files.push(save(pn+"/FRAME-MANIFEST.original.json",item.manifest_raw));
 files.push(save(pn+"/INDEX.derived-original.json",item.index_raw));
 const expected={run_id:run.id,job_id:item.job_id,partition_id:item.partition.id,control_commit:"eb1e312c3d030e704aa30cd4932726fa18f5a83c",workflow_commit:"a4b93e1a370f1c8c9b7fbf3fba7ebbbfeaf2adeb",policy_sha256:H.sha256(utf8(policy))};
 files.push(save(pn+"/INDEPENDENT-AUDIT.json",wire(D.audit970InnerArchiveSlice(item,expected,H,utf8,policy))));
 files.push(save(pn+"/RAW-FILES.json",wire({schema:"hia.original-log-recovery-files.v1",run_id:run.id,job_id:item.job_id,partition:item.partition,files:rawFiles})));
}
files.push(save("run.original.json",fs.readFileSync(path.join(root,"run-and-jobs/run.original.json"))));
files.push(save("jobs.sdk.json",fs.readFileSync(path.join(root,"run-and-jobs/jobs.sdk.json"))));
const inventory={schema:"hia.970-all19-original-recovery-local-inventory.v1",status:"ALL19_RECOVERED_AND_BYTE_EQUAL_TO_ORIGINAL_ZIP_NOT_NEW_QUALIFICATION",raw_files:114,frames:440,raw_bytes:9252841,zip:record(Buffer.from(result.zip_bytes)),decoder:{bytes:Buffer.byteLength(source),sha256:H.sha256(utf8(source))},files};
save("RECOVERY-INVENTORY.json",wire(inventory));
console.log(JSON.stringify({status:result.report.status,raw_files:114,frames:440,raw_bytes:9252841,files:files.length,file_bytes:files.reduce((n,r)=>n+r.bytes,0),zip:inventory.zip}));
