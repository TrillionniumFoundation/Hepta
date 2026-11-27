
const ROOT="/tmp/hia-op13-actual-transport-r3-dda7";
const REPO="TrillionniumFoundation/Hepta";
const sh=s=>"'"+String(s).replace(/'/g,"'\\''")+"'";
const eq=(a,b)=>a.bytes===b.bytes&&a.git_blob===b.git_blob&&a.sha256===b.sha256;
async function readWhole(row){
 const program="from pathlib import Path\nimport hashlib,json,stat\np=Path("+JSON.stringify(row.path)+")\ns=p.lstat();assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)=="+row.mode+"\nb=p.read_bytes();assert p.lstat()==s\nprint(json.dumps({'pin':{'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()},'text':b.decode('utf-8')}))\n";
 const r=await tools.exec_command({cmd:"python3 -c "+sh(program),workdir:"/tmp",shell:"/bin/bash",login:false,max_output_tokens:250000});
 if(r.exit_code!==0)throw new Error("local read failed "+row.logical+": "+r.output);
 const d=JSON.parse(r.output);if(!eq(d.pin,row.pin))throw new Error("local pin differs "+row.logical);return d;
}
async function writeFiles(files){
 const req={operation:"write_batch",files};
 const r=await tools.write_stdin({session_id:load("op13r3:batch-writer-session"),chars:JSON.stringify(req)+"\n",yield_time_ms:250,max_output_tokens:4000});
 store("op13r3:last-write",r);
 const lines=r.output.trim().split(/\r?\n/).filter(Boolean);
 let ack;
 for(const line of lines){const d=JSON.parse(line);if(d.status==="FAIL")throw new Error("disk writer failure "+line);if(d.status==="PASS_WRITTEN_READBACK")ack=d;}
 if(!ack||ack.files.length!==files.length)throw new Error("missing complete disk acknowledgement");
 for(let i=0;i<files.length;i++){if(ack.files[i].path!==files[i].path)throw new Error("disk path mismatch");if(files[i].pin&&!eq(ack.files[i].pin,files[i].pin))throw new Error("disk pin mismatch");}
 return ack;
}
async function publish(i){
 const row=load("op13r3:publication")[i];
 if(!row)throw new Error("index outside publication");
 const key="op13r3:leaf:"+i; let state=load(key)||{index:i,logical:row.logical};
 if(state.complete)return {index:i,logical:row.logical,status:"PREVIOUS_COMPLETE"};
 const d=await readWhole(row);
 if(!state.post){
  const r=await tools.mcp__codex_apps__github_create_blob({repository_full_name:REPO,encoding:"utf-8",content:d.text});
  state.post=r;store(key,state);
 }
 const sha=state.post.structuredContent?.sha;
 if(sha!==row.pin.git_blob)throw new Error("POST did not ACK exact Git at "+i+" "+JSON.stringify(state.post));
 if(!state.get){
  const r=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:REPO,blob_sha:row.pin.git_blob});
  state.get=r;store(key,state);
 }
 const actual=state.get.structuredContent?.content;
 if(actual!==d.text)throw new Error("full GET differs at "+i);
 const stem=String(i).padStart(3,"0");
 const receipt={schema:"hepta.op13.actual.complete-custody.blob-receipt.v1",index:i,logical:row.logical,pin:row.pin,post_ack_git:sha,full_get_equal:true,actual_get_path:ROOT+"/actual-get/"+row.logical};
 state.ack=await writeFiles([
  {path:ROOT+"/actual-get/"+row.logical,content:actual,pin:row.pin},
  {path:ROOT+"/tool-envelopes/"+stem+".POST.json",content:JSON.stringify(state.post)+"\n"},
  {path:ROOT+"/tool-envelopes/"+stem+".GET.json",content:JSON.stringify(state.get)+"\n"},
  {path:ROOT+"/receipts/"+stem+".json",content:JSON.stringify(receipt)+"\n"}
 ]);
 state.complete=true;store(key,state);
 const completed=load("op13r3:complete-indices")||[];if(!completed.includes(i)){completed.push(i);completed.sort((a,b)=>a-b);store("op13r3:complete-indices",completed);}
 return {index:i,logical:row.logical,bytes:row.pin.bytes,git:row.pin.git_blob,status:"POST_ACK_FULL_GET_DISK_READBACK"};
}
