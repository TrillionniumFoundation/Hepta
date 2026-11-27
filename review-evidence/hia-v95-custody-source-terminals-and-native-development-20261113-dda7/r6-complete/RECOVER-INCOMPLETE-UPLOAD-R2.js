
const P=(new Function(load("v88r6formal:publisher-code")))();
const H=(new Function(load("phase_hash_utility_code")))();
function b64(bytes){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",out=[];for(let i=0;i<bytes.length;i+=3){const x=bytes[i],y=bytes[i+1]||0,z=bytes[i+2]||0;out.push(a[x>>2],a[((x&3)<<4)|(y>>4)],i+1<bytes.length?a[((y&15)<<2)|(z>>6)]:"=",i+2<bytes.length?a[z&63]:"=");}return out.join("");}
async function retryAfter404(file, row, priorGet, label){
 if(!priorGet.isError||priorGet.structuredContent?.error_code!=="NOT_FOUND")throw Error("retry requires actual fixed-object 404");
 const source=await P.readText(file,row.bytes), m=P.meta(source);
 for(const k of ["bytes","sha256","git_blob"])if(m[k]!==row[k])throw Error("original identity mismatch "+k);
 await P.writeJson("GIT-CUSTODY/"+file+"."+label+".intent.json",{file,...m,operation:"one same-byte immutable POST after preserved UNKNOWN and actual fixed-object GET 404",prior_get_error:priorGet.structuredContent,timestamp:new Date().toISOString()});
 const post=await tools.mcp__codex_apps__github_create_blob({repository_full_name:"TrillionniumFoundation/Hepta",content:source,encoding:"utf-8"});
 store("v88r6formal:"+file+":"+label+":post",post);await P.writeJson("GIT-CUSTODY/"+file+"."+label+".post.json",post);
 if(post.isError||post.structuredContent?.sha!==m.git_blob)throw Error("retry POST did not ACK: "+JSON.stringify(post));
 const get=await tools.mcp__codex_apps__github_fetch_blob({repository_full_name:"TrillionniumFoundation/Hepta",blob_sha:m.git_blob});
 store("v88r6formal:"+file+":"+label+":get",get);
 if(get.isError||typeof get.structuredContent?.content!=="string"){await P.writeJson("GIT-CUSTODY/"+file+"."+label+".get-error.json",get);throw Error("retry full GET failed");}
 const back=get.structuredContent.content,bm=P.meta(back);
 for(const k of ["bytes","sha256","git_blob"])if(bm[k]!==row[k])throw Error("full GET identity mismatch "+k);
 if(back!==source)throw Error("full GET bytes mismatch");
 const raw=H.b64decode(back), d=load("v88r6formal:metadata").chunks.find(x=>x.file===file);
 if(!d||b64(raw)!==back||back.includes("\n")||back.includes("\r")||raw.length!==d.decoded_bytes||H.sha256Bytes(raw)!==d.decoded_sha256)throw Error("decoded chunk mismatch");
 await P.writeText("GIT-CUSTODY/readback/"+file,back);
 const receipt={file,...m,custody_mode:"UNKNOWN_THEN_ACTUAL_404_THEN_ONE_SAME_BYTES_POST_ACK_FULL_GET",post_ack:post.structuredContent,full_get_verified:true,full_get_bytes:bm.bytes,full_get_sha256:bm.sha256,full_get_blob:bm.git_blob,decoded:{bytes:raw.length,sha256:H.sha256Bytes(raw)},verified_at:new Date().toISOString(),original_unknown_retained:true,retry_label:label};
 await P.writeJson("GIT-CUSTODY/"+file+".receipt.json",receipt);store("v88r6formal:"+file+":receipt",receipt);const all=load("v88r6formal:receipts")||[];all.push(receipt);store("v88r6formal:receipts",all);return receipt;
}

async function resumeRead(file,row,get,label){
 const post=load("v88r6formal:"+file+":post");
 if(post?.isError||post?.structuredContent?.sha!==row.git_blob)throw Error("requires original exact POST ACK");
 if(get.isError||typeof get.structuredContent?.content!=="string")throw Error("requires actual complete fixed-object GET");
 const back=get.structuredContent.content,m=P.meta(back),source=await P.readText(file,row.bytes);
 for(const k of ["bytes","sha256","git_blob"])if(m[k]!==row[k])throw Error("GET mismatch "+k);
 if(back!==source)throw Error("exact source mismatch");
 const raw=H.b64decode(back),d=load("v88r6formal:metadata").chunks.find(x=>x.file===file);
 if(!d||b64(raw)!==back||back.includes("\n")||back.includes("\r")||raw.length!==d.decoded_bytes||H.sha256Bytes(raw)!==d.decoded_sha256)throw Error("decoded chunk mismatch");
 await P.writeJson("GIT-CUSTODY/"+file+"."+label+".json",{file,original_post:post,original_failed_get_metadata:load("v88r6formal:"+file+":fullget"),actual_get_content_identity:m,extra_post:false,reason:"Resume local persistence from exact successful read-only GET after previous read failure; no write replay."});
 await P.writeText("GIT-CUSTODY/readback/"+file,back);
 const receipt={file,...m,custody_mode:"POST_ACK_THEN_FAILED_READ_THEN_ACTUAL_FULL_GET_NO_EXTRA_POST",post_ack:post.structuredContent,full_get_verified:true,full_get_bytes:m.bytes,full_get_sha256:m.sha256,full_get_blob:m.git_blob,decoded:{bytes:raw.length,sha256:H.sha256Bytes(raw)},verified_at:new Date().toISOString(),resume_label:label};
 await P.writeJson("GIT-CUSTODY/"+file+".receipt.json",receipt);store("v88r6formal:"+file+":receipt",receipt);
 const all=load("v88r6formal:receipts")||[];all.push(receipt);store("v88r6formal:receipts",all);return receipt;
}

return {retryAfter404,resumeRead};
