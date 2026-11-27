(async function publish(name,raw){
 const A=eval(load("v152.audit.helper.source"));
 if(typeof raw!=="string")throw Error("raw text required");
 if(!/^[A-Za-z0-9._/-]+$/.test(name)||name.includes(".."))throw Error("unsafe publication name");
 const pin={bytes:A.H.utf8(raw).length,git_blob:A.H.blob(raw),sha256:A.H.sha256(A.H.utf8(raw))},key="v152.remote.pub."+name;
 const prior=load(key+".intent"); if(prior&&(prior.git_blob!==pin.git_blob||prior.bytes!==pin.bytes||prior.sha256!==pin.sha256))throw Error("changed publication intent "+name);
 store(key+".raw",raw);store(key+".intent",{repository:A.repo,name,...pin,encoding:"utf-8",no_filesystem_claim:true});
 let ack=load(key+".ack");
 if(!ack){if(load(key+".post_started"))throw Error("uncertain prior POST; inspect object before another mutation "+name);store(key+".post_started",true);ack=await tools.mcp__codex_apps__github_create_blob({repository_full_name:A.repo,encoding:"utf-8",content:raw});store(key+".ack",ack);}
 if(A.result(ack).sha!==pin.git_blob)throw Error("POST acknowledgement mismatch "+name);
 const get=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:A.repo,blob_sha:pin.git_blob});store(key+".get",get);
 if(get?.isError||get?.structuredContent?.content!==raw)throw Error("full GET mismatch "+name);
 const verified={name,...pin,post_ack:true,full_get_exact:true};store(key+".verified",verified);return verified;
})
