
const PREFIX="v90processraw";
const ROOT=load(PREFIX+":root");
const P=(new Function(load(PREFIX+":publisher-code")))();
const rows=load(PREFIX+":metadata").chunks;
async function localPython(body){
 let r=await tools.exec_command({cmd:"python - <<'PY'\n"+body+"\nPY",shell:"/bin/bash",login:false,workdir:"/",max_output_tokens:12000,yield_time_ms:1000});
 let output=r.output;
 while(r.session_id!==undefined){r=await tools.write_stdin({session_id:r.session_id,chars:"",yield_time_ms:1000,max_output_tokens:12000});output+=r.output;}
 if(r.exit_code!==0)throw Error("scheduler local control failed: "+JSON.stringify(r));
 return JSON.parse(output);
}
async function progress(){
 return await localPython("from pathlib import Path\nimport json,hashlib,base64\np=Path("+JSON.stringify(ROOT)+")\nt=json.loads((p/'TRANSPORT.json').read_text())\nnext_index=0\nfor i,r in enumerate(t['chunks']):\n q=p/'GIT-CUSTODY'/ (r['file']+'.receipt.json')\n if not q.is_file():break\n x=json.loads(q.read_text())\n assert x['file']==r['file'] and x['full_get_verified'] is True\n for k,v in [('bytes',r['bytes']),('sha256',r['sha256']),('git_blob',r['git_blob']),('full_get_bytes',r['bytes']),('full_get_sha256',r['sha256']),('full_get_blob',r['git_blob'])]:assert x[k]==v,(i,k)\n assert (p/'GIT-CUSTODY'/'readback'/r['file']).is_file()\n next_index=i+1\nprint(json.dumps({'next':next_index,'total':len(t['chunks'])}))");
}
async function runBatch(){
 const before=await progress();const start=before.next;
 if(start===rows.length)return {status:"ALL_CHUNKS_FULL_GET_COMPLETE",...before};
 const selected=rows.slice(start,start+2);
 const selectedNames=selected.map(x=>x.file);
 await localPython("from pathlib import Path\nimport json\np=Path("+JSON.stringify(ROOT)+")\nfiles="+JSON.stringify(selectedNames)+"\nfor f in files:assert not (p/'GIT-CUSTODY'/(f+'.intent.json')).exists(),f\nprint(json.dumps({'new_intents_absent':files}))");
 const label="GIT-CUSTODY/SCHEDULE-2-"+String(start).padStart(3,"0");
 const begun={schema:"hepta.immutable-cas.batch.v1",scope:PREFIX,status:"STARTED",started_at:new Date().toISOString(),max_concurrency:2,highwater_from_disk:start,items:selected,policy:"Independent exclusive intent, POST ACK, full GET and all identities; wait both; no automatic POST retries; stop next batch on any unknown/error."};
 await P.writeJson(label+".started.json",begun);
 const settled=await Promise.allSettled(selected.map(r=>P.publish(r.file,r)));
 const terminals=settled.map((r,i)=>r.status==="fulfilled"?{file:selected[i].file,status:"FULL_GET_COMPLETE",receipt:r.value}:{file:selected[i].file,status:"ERROR_OR_UNKNOWN",error:String(r.reason),stack:r.reason?.stack||null});
 const verification=await localPython("from pathlib import Path\nimport json,hashlib,base64\np=Path("+JSON.stringify(ROOT)+")\nt=json.loads((p/'TRANSPORT.json').read_text())\nselected="+JSON.stringify(selectedNames)+"\nverified=[]\nfor r in t['chunks']:\n if r['file'] not in selected:continue\n q=p/'GIT-CUSTODY'/(r['file']+'.receipt.json')\n if not q.is_file():continue\n b=(p/'GIT-CUSTODY'/'readback'/r['file']).read_bytes()\n assert len(b)==r['bytes'] and hashlib.sha256(b).hexdigest()==r['sha256']\n assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\\0'+b).hexdigest()==r['git_blob']\n raw=base64.b64decode(b,validate=True)\n assert base64.b64encode(raw)==b and len(raw)==r['decoded_bytes'] and hashlib.sha256(raw).hexdigest()==r['decoded_sha256']\n assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\\0'+raw).hexdigest()==r['decoded_computed_git_blob']\n verified.append(r['file'])\nprint(json.dumps({'strict_readback_verified':verified}))");
 const after=await progress();store(PREFIX+":raw-next",after.next);
 const ok=settled.every(r=>r.status==="fulfilled")&&after.next===start+selected.length&&verification.strict_readback_verified.length===selected.length;
 const report={...begun,status:ok?"FULL_GET_COMPLETE":"STOPPED_ERROR_OR_UNKNOWN",finished_at:new Date().toISOString(),terminals,verification,continuous_highwater_from_disk:after.next};
 await P.writeJson(label+".terminal.json",report);
 if(!ok)throw Error("Batch stopped; no new batch permitted: "+JSON.stringify(report));
 return report;
}
return {progress,runBatch};
