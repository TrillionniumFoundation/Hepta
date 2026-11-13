
function bytes(s) {
  const out=[];
  for(const c of s) {
    let x=c.codePointAt(0);
    if(x<128) out.push(x);
    else if(x<2048) out.push(192|(x>>6),128|(x&63));
    else if(x<65536) out.push(224|(x>>12),128|((x>>6)&63),128|(x&63));
    else out.push(240|(x>>18),128|((x>>12)&63),128|((x>>6)&63),128|(x&63));
  }
  return new Uint8Array(out);
}
function padded(input) {
  const n=input.length, b=new Uint8Array(Math.ceil((n+9)/64)*64);
  b.set(input);b[n]=128;
  const view=new DataView(b.buffer),bit=BigInt(n)*8n;
  view.setUint32(b.length-8,Number(bit>>32n),false);
  view.setUint32(b.length-4,Number(bit&0xffffffffn),false);
  return b;
}
function hex(a) { return Array.from(a,x=>(x>>>0).toString(16).padStart(8,"0")).join("");}
function sha256(input) {
  if(typeof input==="string")input=bytes(input);
  const b=padded(input),v=new DataView(b.buffer);
  const k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const rr=(x,n)=>(x>>>n)|(x<<(32-n)),w=new Uint32Array(64);
  for(let p=0;p<b.length;p+=64) {
    for(let i=0;i<16;i++)w[i]=v.getUint32(p+4*i,false);
    for(let i=16;i<64;i++) {
      const x=w[i-15],y=w[i-2],s0=rr(x,7)^rr(x,18)^(x>>>3),s1=rr(y,17)^rr(y,19)^(y>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let [a,c,d,e,f,g,j,l]=h;
    for(let i=0;i<64;i++) {
      const t1=(l+(rr(f,6)^rr(f,11)^rr(f,25))+((f&g)^(~f&j))+k[i]+w[i])>>>0;
      const t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&c)^(a&d)^(c&d)))>>>0;
      l=j;j=g;g=f;f=(e+t1)>>>0;e=d;d=c;c=a;a=(t1+t2)>>>0;
    }
    [a,c,d,e,f,g,j,l].forEach((x,i)=>h[i]=(h[i]+x)>>>0);
  }
  return hex(h);
}
function sha1(input) {
  if(typeof input==="string")input=bytes(input);
  const b=padded(input),v=new DataView(b.buffer),w=new Uint32Array(80);
  const h=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
  const rol=(x,n)=>(x<<n)|(x>>>(32-n));
  for(let p=0;p<b.length;p+=64) {
    for(let i=0;i<16;i++)w[i]=v.getUint32(p+4*i,false);
    for(let i=16;i<80;i++)w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1)>>>0;
    let [a,c,d,e,f]=h;
    for(let i=0;i<80;i++){
      const fun=i<20?((c&d)|(~c&e)):i<40?(c^d^e):i<60?((c&d)|(c&e)|(d&e)):(c^d^e);
      const k=i<20?0x5a827999:i<40?0x6ed9eba1:i<60?0x8f1bbcdc:0xca62c1d6;
      const t=(rol(a,5)+fun+f+k+w[i])>>>0;f=e;e=d;d=rol(c,30)>>>0;c=a;a=t;
    }
    [a,c,d,e,f].forEach((x,i)=>h[i]=(h[i]+x)>>>0);
  }
  return hex(h);
}
function gitBlob(input) {
 const b=typeof input==="string"?bytes(input):input;
 const prefix=bytes("blob "+b.length+"\0"),all=new Uint8Array(prefix.length+b.length);
 all.set(prefix);all.set(b,prefix.length);return sha1(all);
}
return {bytes,sha256,sha1,gitBlob};
