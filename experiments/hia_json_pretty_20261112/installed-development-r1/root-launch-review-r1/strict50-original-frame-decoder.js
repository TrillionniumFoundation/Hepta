
const H=new Function(load("hia-v8-byte-helpers"))();
return function(log,wanted){
 const expectedNames=[...["prepare","run","finalize"].flatMap(s=>["stdout","stderr"].map(c=>"stage/"+s+"."+c+".log")),"setup.json","context.json","guard/request.json","FINAL.json","guard/guardian.json","evidence/report.json","guard/child.stdout.log","guard/child.stderr.log","evidence/native-cases.json","evidence/native-child.stdout.log","evidence/native-child.stderr.log"];
 expectedNames.push("evidence/installation/package-report.json","evidence/installation/installed-cases.json","evidence/installation/installed-request.json");
 for(const label of ["packaging-tools","sdist","wheel","install","installed-child"])for(const suffix of [".stdout.log",".stderr.log",".process-owner.json",".process-owner.json.request.json",".process-owner.json.stdout.log",".process-owner.json.stderr.log"])expectedNames.push("evidence/installation/"+label+suffix);
 if(expectedNames.length!==50||new Set(expectedNames).size!==50)throw Error("decoder population");
 const markers=[];for(const line of log.split("\n")){const clean=line.replace(/^\d{4}-\d\d-\d\dT\S+Z\s+/,""),m=clean.match(/^HIA_JSON_PRETTY_([A-Z_]+) (.*)$/);if(m)markers.push({kind:m[1],value:JSON.parse(m[2])});}
 const records=new Map(),begins=[],boundaries=[],ends=[];let frameCount=0,active=null;
 for(const m of markers){const v=m.value;
 if(m.kind==="DIAGNOSTIC_BEGIN")begins.push(v);
 else if(m.kind==="DIAGNOSTIC_BOUNDARY")boundaries.push(v);
 else if(m.kind==="DIAGNOSTIC_END")ends.push(v);
 else if(m.kind==="ORIGINAL_BEGIN"){
  if(active||records.has(v.name)||!expectedNames.includes(v.name)||!Number.isInteger(v.bytes)||v.bytes<0||v.bytes>4194304||v.frame_bytes!==8192||v.frame_count!==Math.ceil(v.bytes/8192))throw Error("badbegin");
  active={begin:v,parts:[],size:0,next:0};
 }else if(m.kind==="ORIGINAL_FRAME"){
  if(!active||v.name!==active.begin.name||v.index!==active.next||v.offset!==active.size)throw Error("badframeorder");
  const b64=v.base64;if(typeof b64!=="string"||!/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64))throw Error("base64");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if(b64.endsWith("==")&&(alphabet.indexOf(b64[b64.length-3])&15)!==0)throw Error("noncanonicalbase64");
  if(b64.endsWith("=")&&!b64.endsWith("==")&&(alphabet.indexOf(b64[b64.length-2])&3)!==0)throw Error("noncanonicalbase64");
  const part=H.unbase64(b64);
  if(part.length!==v.bytes||part.length!==Math.min(8192,active.begin.bytes-active.size)||H.sha256(part)!==v.sha256)throw Error("badframebytes");
  active.parts.push(part);active.size+=part.length;active.next++;frameCount++;
 }else if(m.kind==="ORIGINAL_END"){
  if(!active||v.name!==active.begin.name||v.bytes!==active.begin.bytes||v.sha256!==active.begin.sha256||v.frame_count!==active.begin.frame_count||active.size!==v.bytes||active.next!==v.frame_count)throw Error("badend");
  const all=new Uint8Array(active.size);let off=0;for(const p of active.parts){all.set(p,off);off+=p.length;}
  if(H.sha256(all)!==v.sha256)throw Error("wholehash");
  const text0=H.utf8decode(all);if(H.utf8encode(text0).length!==all.length||H.sha256(H.utf8encode(text0))!==v.sha256)throw Error("utf8");
  records.set(v.name,{name:v.name,text:text0,bytes:all.length,sha256:v.sha256,frames:v.frame_count});active=null;
 }else throw Error("unavailable_or_unknown_marker:"+m.kind+JSON.stringify(v));
 }
 if(active||begins.length!==1||boundaries.length!==1||ends.length!==1||records.size!==50||expectedNames.some(n=>!records.has(n)))throw Error("incomplete sequence");
 const begin=begins[0],boundary=boundaries[0],end=ends[0];
 for(const [k,v] of Object.entries(wanted))if(begin[k]!==v)throw Error("identity:"+k);
 const total=[...records.values()].reduce((s,r)=>s+r.bytes,0);
 if(begin.fixed_file_count!==50||begin.maximum_original_raw_bytes!==4194304||end.original_raw_byte_budget_reserved!==total||end.original_raw_bytes_printed!==total||end.verified_original_bytes_read!==total||Object.keys(end.fixed_file_observations).length!==50)throw Error("total");
 for(const [name,r]of records){const x=end.fixed_file_observations[name];if(x.status!=="COMPLETE_ORIGINAL_READ"||x.bytes!==r.bytes||x.sha256!==r.sha256)throw Error("endobservations");}
 return {begin,boundary,end,records:[...records.values()],complete_raw_bytes:total,frame_count:frameCount,all_fixed50_read:true,all_sha256_verified:true,no_test_reexecution:true};
}