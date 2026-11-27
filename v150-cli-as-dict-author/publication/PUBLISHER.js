(async function publishOne(index,row,raw){
 const H=eval(load("op8.pub.hash_source"));
 const root="/workspace/hia-cli-as-dict-owner-publication-r1-dda7",repo="TrillionniumFoundation/Hepta";
 const id=String(index).padStart(3,"0");
 function parse(r){if(r?.isError)throw Error("tool isError");const s=r?.structuredContent;if(s&&typeof s.content==="string"){try{return JSON.parse(s.content)}catch{}}if(s&&typeof s==="object")return s;for(const c of r?.content||[])if(c.type==="text"){try{return JSON.parse(c.text)}catch{}}throw Error("missing tool JSON")}
 async function save(kind,value){const textValue=JSON.stringify(value,null,2)+"\n";const response=await tools.apply_patch("*** Begin Patch\n*** Add File: "+root+"/"+kind+"/"+id+".json\n+"+textValue.slice(0,-1).split("\n").join("\n+")+"\n*** End Patch");if(response?.isError)throw Error("receipt save failed "+kind);return response}
 if(H.blob(raw)!==row.git_blob||H.utf8(raw).length!==row.bytes||H.sha256(H.utf8(raw))!==row.sha256)throw Error("local input mismatch");
 await save("INTENTS",{index,path:row.path,repository:repo,sha:row.git_blob,bytes:row.bytes,sha256:row.sha256,encoding:"utf-8",operation:"create_blob"});
 const ack=await tools.mcp__codex_apps__github_create_blob({repository_full_name:repo,encoding:"utf-8",content:raw});
 store("op8.pub.pending."+id,{index,row,raw,ack});
 await save("ACK",ack);
 if(parse(ack).sha!==row.git_blob)throw Error("ACK identity differs");
 const fetched=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:repo,blob_sha:row.git_blob});
 store("op8.pub.pending."+id,{index,row,raw,ack,fetched});
 await save("GET",fetched);
 const actual=fetched?.structuredContent?.content;
 if(fetched?.isError||typeof actual!=="string"||actual!==raw||H.blob(actual)!==row.git_blob||H.sha256(H.utf8(actual))!==row.sha256)throw Error("complete GET bytes differ");
 const result={index,path:row.path,bytes:row.bytes,sha256:row.sha256,git_blob:row.git_blob,mode:row.mode||"100644",posix_mode:row.posix_mode||420,post_ack_sha:parse(ack).sha,full_get_exact:true,full_get_bytes:H.utf8(actual).length,full_get_sha256:H.sha256(H.utf8(actual)),full_get_git_blob:H.blob(actual),intent:root+"/INTENTS/"+id+".json",ack:root+"/ACK/"+id+".json",full_get:root+"/GET/"+id+".json"};
 await save("VERIFIED",result);
 store("op8.pub.verified."+id,result);
 return result;
})
