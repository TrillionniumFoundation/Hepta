const h=new Function("tools",load("r5-publisher"))(tools);
const uniq=load("r5-unique");
const start=load("r5-cursor"),end=Math.min(start+12,uniq.length);const successes=load("r5-results");
for(let i=start;i<end;i++){
 const row=uniq[i];const raw=await h.read(row.local);
 if(raw.sha256!==row.sha256||raw.git_blob!==row.git_blob||raw.bytes!==row.bytes)throw new Error("frozen bytes changed");
 await h.journal({event:"BLOB_INTENT",ordinal:i,git_blob:row.git_blob,sha256:row.sha256,bytes:row.bytes,local:row.local,path:row.path});
 const prior=load("r5-base-blobs").includes(row.git_blob);
 if(!prior){
   const r=await tools.mcp__codex_apps__github_create_blob({repository_full_name:"TrillionniumFoundation/Hepta",content:raw.text,encoding:"utf-8"});
   await h.journal({event:"BLOB_RESPONSE",ordinal:i,git_blob:row.git_blob,result:r});
   const ack=JSON.parse(h.content(r));if(ack.sha!==row.git_blob)throw new Error("blob ACK differs");
 }else await h.journal({event:"BLOB_REUSED_FROM_BASE",ordinal:i,git_blob:row.git_blob});
 const got=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/"+row.git_blob});
 const actual=h.content(got);const equal=actual===raw.text;
 await h.journal({event:"BLOB_FULL_READBACK",ordinal:i,git_blob:row.git_blob,bytes:row.bytes,sha256:row.sha256,equal});
 if(!equal)throw new Error("full readback mismatch");
 successes.push({ordinal:i,git_blob:row.git_blob,bytes:row.bytes,sha256:row.sha256,full_readback:true,reused_from_base:prior});
 store("r5-cursor",i+1);store("r5-results",successes);
}
text({done:load("r5-cursor"),total:uniq.length});
