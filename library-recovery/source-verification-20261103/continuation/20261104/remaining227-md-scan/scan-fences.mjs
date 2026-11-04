/* Newly authored parser; no archived program is evaluated or executed. */
const H = (() => {
return (function auditHashFactory() {
  const utf8 = (text) => {
    const out=[];
    for(let i=0;i<text.length;i++){
      let c=text.charCodeAt(i);
      if(c>=0xd800&&c<=0xdbff){const d=text.charCodeAt(++i);if(!(d>=0xdc00&&d<=0xdfff))throw new Error("unpaired UTF-16 high surrogate");c=0x10000+((c-0xd800)<<10)+(d-0xdc00);}
      else if(c>=0xdc00&&c<=0xdfff)throw new Error("unpaired UTF-16 low surrogate");
      if(c<0x80)out.push(c);else if(c<0x800)out.push(0xc0|(c>>>6),0x80|(c&63));else if(c<0x10000)out.push(0xe0|(c>>>12),0x80|((c>>>6)&63),0x80|(c&63));else out.push(0xf0|(c>>>18),0x80|((c>>>12)&63),0x80|((c>>>6)&63),0x80|(c&63));
    }
    return Uint8Array.from(out);
  };
  const padded = (input) => {
    const bytes=typeof input==="string"?utf8(input):input;
    const size=Math.ceil((bytes.length+9)/64)*64, out=new Uint8Array(size);
    out.set(bytes);out[bytes.length]=128;
    const view=new DataView(out.buffer);view.setUint32(size-8,Math.floor(bytes.length/536870912),false);view.setUint32(size-4,(bytes.length*8)>>>0,false);
    return out;
  };
  const hex = h=>h.map(x=>(x>>>0).toString(16).padStart(8,"0")).join("");
  const rotl=(a,n)=>(a<<n)|(a>>>(32-n));
  const rotr=(a,n)=>(a>>>n)|(a<<(32-n));
  const sha1=input=>{
    const p=padded(input),v=new DataView(p.buffer),w=new Int32Array(80);let h=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
    for(let off=0;off<p.length;off+=64){
      for(let i=0;i<16;i++)w[i]=v.getInt32(off+i*4,false);
      for(let i=16;i<80;i++)w[i]=rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
      let [a,b,c,d,e]=h;
      for(let i=0;i<80;i++){let f,k;if(i<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(i<40){f=b^c^d;k=0x6ed9eba1;}else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(rotl(a,5)+f+e+k+w[i])|0;e=d;d=c;c=rotl(b,30);b=a;a=t;}
      h=[h[0]+a,h[1]+b,h[2]+c,h[3]+d,h[4]+e].map(x=>x|0);
    }
    return hex(h);
  };
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const sha256=input=>{
    const p=padded(input),v=new DataView(p.buffer),w=new Int32Array(64);let h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for(let off=0;off<p.length;off+=64){
      for(let i=0;i<16;i++)w[i]=v.getInt32(off+i*4,false);
      for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2];w[i]=((rotr(a,7)^rotr(a,18)^(a>>>3))+w[i-16]+(rotr(b,17)^rotr(b,19)^(b>>>10))+w[i-7])|0;}
      let [a,b,c,d,e,f,g,q]=h;
      for(let i=0;i<64;i++){const t1=(q+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+K[i]+w[i])|0;const t2=((rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c)))|0;q=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
      h=[h[0]+a,h[1]+b,h[2]+c,h[3]+d,h[4]+e,h[5]+f,h[6]+g,h[7]+q].map(x=>x|0);
    }
    return hex(h);
  };
  const fp=text=>{const b=utf8(text),header=utf8("blob "+b.length+"\0"),joined=new Uint8Array(header.length+b.length);joined.set(header);joined.set(b,header.length);return {git_blob_sha:sha1(joined),sha256:sha256(b),bytes:b.length};};
  return {utf8,sha1,sha256,fp};
})();
})();
const scan = (() => {

return function scanFences(source,H){
  const lines=source.match(/[^\n]*(?:\n|$)/g).filter(x=>x.length), starts=[];
  let pos=0;for(const s of lines){starts.push(pos);pos+=s.length;}
  const out=[];
  for(let i=0;i<lines.length;i++){
    const m=/^ {0,3}(\x60{3,}|~{3,})([^\r\n]*)\r?\n?$/.exec(lines[i]);
    if(!m|| (m[1][0]==="\x60" && m[2].includes("\x60")))continue;
    let closed=false;
    for(let j=i+1;j<lines.length;j++){
      const c=/^ {0,3}(\x60{3,}|~{3,})[ \t]*\r?\n?$/.exec(lines[j]);
      if(!c||c[1][0]!==m[1][0]||c[1].length<m[1].length)continue;
      const start=starts[i]+lines[i].length,end=starts[j],body=source.slice(start,end);
      if(body.length)out.push({language:m[2].trim(),opening_fence_line:i+1,first_content_line:i+2,last_content_line:j,closing_fence_line:j+1,byte_start:H.utf8(source.slice(0,start)).length,byte_end:H.utf8(source.slice(0,end)).length,content:body,...H.fp(body)});
      i=j;closed=true;break;
    }
    if(!closed)break;
  }
  return out;
};
})();
export function scanFences(source) { return scan(source, H); }
export function fingerprint(source) { return H.fp(source); }
