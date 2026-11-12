
const root='/tmp/hia-full32-r4-gzip-custody-r1-20261112-e26e';
function q(s){return "'"+String(s).replaceAll("'","'\\''")+"'";}
async function py(op,args=[],max=30000){
 const cmd=['python3','-I','-S','-B',root+'/publication_io.py',op,...args].map(q).join(' ');
 const r=await tools.exec_command({cmd,shell:'bash',login:false,workdir:'/',max_output_tokens:max});
 if(r.exit_code!==0)throw new Error('Local journal IO failed: '+r.output);
 return JSON.parse(r.output);
}
function content(r){if(r.isError)throw new Error(JSON.stringify(r));let c=r.structuredContent?.content;if(typeof c==='string')return c;if(r.structuredContent?.sha)return JSON.stringify(r.structuredContent);if(r.structuredContent)return JSON.stringify(r.structuredContent);throw new Error('No exact body');}
async function read(path){let out='',meta;for(let start=0;;start+=48000){let v=await py('read',[path,String(start),'48000']);if(!meta)meta=v;else if(meta.sha256!==v.sha256||meta.chars!==v.chars)throw new Error('source changed');out+=v.text;if(out.length===meta.chars)return{...meta,text:out};if(out.length>meta.chars)throw new Error('bad chunks');}}
async function write(path,text){let first=true;for(let i=0;i<text.length||first;i+=40000){await py(first?'write':'append',[path,text.slice(i,i+40000)],1000);first=false;}}
async function journal(v){return await py('journal',[JSON.stringify(v)],1000);}
return{root,q,py,content,read,write,journal};
