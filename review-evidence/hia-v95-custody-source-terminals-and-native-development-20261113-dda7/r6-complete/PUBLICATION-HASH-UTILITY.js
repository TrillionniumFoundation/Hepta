function sha256Bytes(input){
 const H="6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19".split(" ").map(x=>parseInt(x,16));
 const K="428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2".split(" ").map(x=>parseInt(x,16));
 const len=input.length,b=new Uint8Array(Math.ceil((len+9)/64)*64);b.set(input);b[len]=128;let bitLength=BigInt(len)*8n;for(let i=0;i<8;i++){b[b.length-1-i]=Number(bitLength&255n);bitLength>>=8n;}
 const rr=(a,n)=>(a>>>n)|(a<<(32-n)),w=new Uint32Array(64);
 for(let off=0;off<b.length;off+=64){for(let i=0;i<16;i++)w[i]=(b[off+4*i]<<24)|(b[off+4*i+1]<<16)|(b[off+4*i+2]<<8)|b[off+4*i+3];for(let i=16;i<64;i++)w[i]=(w[i-16]+(rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>>3))+w[i-7]+(rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>>10)))>>>0;
 let[a,c,d,e,f,g,h,j]=H;for(let i=0;i<64;i++){const t1=(j+(rr(f,6)^rr(f,11)^rr(f,25))+((f&g)^(~f&h))+K[i]+w[i])>>>0,t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&c)^(a&d)^(c&d)))>>>0;j=h;h=g;g=f;f=(e+t1)>>>0;e=d;d=c;c=a;a=(t1+t2)>>>0;}for(const[i,v]of[a,c,d,e,f,g,h,j].entries())H[i]=(H[i]+v)>>>0;}
 return H.map(x=>x.toString(16).padStart(8,"0")).join("");
}
function utf8(s){const raw=unescape(encodeURIComponent(s));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function inflateZlib(bytes){
 if(bytes.length<6||((bytes[0]<<8)|bytes[1])%31|| (bytes[0]&15)!==8 || bytes[1]&32)throw Error("unsupported zlib header");
 let bit=16,out=new Uint8Array(65536),used=0;
 const bits=n=>{let v=0;for(let i=0;i<n;i++){if(bit>=8*(bytes.length-4))throw Error("truncated deflate");v|=((bytes[bit>>3]>>(bit&7))&1)<<i;bit++;}return v;};
 const emit=v=>{if(used===out.length){const grown=new Uint8Array(out.length*2);grown.set(out);out=grown;}out[used++]=v;};
 const huffman=lens=>{const counts=new Uint32Array(16),next=new Uint32Array(16),table=new Map();for(const n of lens)if(n)counts[n]++;let code=0;for(let n=1;n<=15;n++){code=(code+counts[n-1])<<1;next[n]=code;}for(let sym=0;sym<lens.length;sym++){const n=lens[sym];if(!n)continue;let v=next[n]++,rev=0;for(let i=0;i<n;i++){rev=(rev<<1)|(v&1);v>>>=1;}table.set((n<<16)|rev,sym);}return table;};
 const sym=t=>{let v=0;for(let n=1;n<=15;n++){v|=bits(1)<<(n-1);const s=t.get((n<<16)|v);if(s!==undefined)return s;}throw Error("invalid huffman symbol");};
 const lb=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258],le=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
 const db=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577],de=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
 let final=0;
 while(!final){final=bits(1);const type=bits(2);if(type===0){bit=(bit+7)&~7;const n=bits(16),inverse=bits(16);if((n^inverse)!==65535)throw Error("bad stored block");for(let i=0;i<n;i++)emit(bits(8));continue;}if(type===3)throw Error("reserved block");let lit,dist;
 if(type===1){lit=huffman(Array.from({length:288},(_,i)=>i<144?8:i<256?9:i<280?7:8));dist=huffman(new Array(32).fill(5));}
 else{const nl=bits(5)+257,nd=bits(5)+1,nc=bits(4)+4,order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],cl=new Array(19).fill(0);for(let i=0;i<nc;i++)cl[order[i]]=bits(3);const ct=huffman(cl),lens=[];while(lens.length<nl+nd){const s=sym(ct);if(s<=15)lens.push(s);else{let n,value;if(s===16){if(!lens.length)throw Error("missing repeat");n=bits(2)+3;value=lens[lens.length-1];}else if(s===17){n=bits(3)+3;value=0;}else if(s===18){n=bits(7)+11;value=0;}else throw Error("bad code length");if(lens.length+n>nl+nd)throw Error("code length overflow");for(let j=0;j<n;j++)lens.push(value);}}lit=huffman(lens.slice(0,nl));dist=huffman(lens.slice(nl));}
 for(;;){const s=sym(lit);if(s<256){emit(s);continue;}if(s===256)break;if(s<257||s>285)throw Error("invalid length");const length=lb[s-257]+bits(le[s-257]),d=sym(dist);if(d>29)throw Error("invalid distance");const distance=db[d]+bits(de[d]);if(distance>used)throw Error("distance outside history");for(let i=0;i<length;i++)emit(out[used-distance]);}}
 const result=out.slice(0,used);let a=1,b=0;for(const v of result){a=(a+v)%65521;b=(b+a)%65521;}const expected=((bytes.at(-4)<<24)|(bytes.at(-3)<<16)|(bytes.at(-2)<<8)|bytes.at(-1))>>>0;if((((b<<16)|a)>>>0)!==expected)throw Error("Adler32 mismatch");return result;
}
function decodeUtf8(bytes){
 const parts=[],codes=[];let i=0;
 const flush=()=>{if(codes.length){parts.push(String.fromCharCode(...codes));codes.length=0;}};
 while(i<bytes.length){const start=i,b=bytes[i++];let cp,n;
  if(b<128){cp=b;n=0;}else if(b>=194&&b<=223){cp=b&31;n=1;}else if(b>=224&&b<=239){cp=b&15;n=2;}else if(b>=240&&b<=244){cp=b&7;n=3;}else throw Error("invalid UTF8 lead "+start);
  if(i+n>bytes.length)throw Error("truncated UTF8 "+start);
  for(let j=0;j<n;j++){const c=bytes[i++];if((c&192)!==128)throw Error("invalid UTF8 continuation "+(i-1));cp=(cp<<6)|(c&63);}
  if(n===1&&cp<128||n===2&&cp<2048||n===3&&cp<65536||cp>1114111||cp>=55296&&cp<=57343)throw Error("noncanonical UTF8 "+start);
  if(cp<=65535)codes.push(cp);else{cp-=65536;codes.push(55296+(cp>>>10),56320+(cp&1023));}
  if(codes.length>=8192)flush();
 }
 flush();return parts.join("");
}
function sha1Bytes(input){
 const n=input.length,m=Math.ceil((n+9)/64)*64,data=new Uint8Array(m);data.set(input);data[n]=128;
 const dv=new DataView(data.buffer);dv.setUint32(m-8,Math.floor(n/536870912),false);dv.setUint32(m-4,(n*8)>>>0,false);
 let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
 const w=new Uint32Array(80);const rol=(x,k)=>((x<<k)|(x>>>(32-k)))>>>0;
 for(let p=0;p<m;p+=64){
  for(let i=0;i<16;i++)w[i]=dv.getUint32(p+4*i,false);
  for(let i=16;i<80;i++)w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
  let a=h0,b=h1,c=h2,d=h3,e=h4;
  for(let i=0;i<80;i++){let f,k;if(i<20){f=(b&c)|((~b)&d);k=0x5a827999;}else if(i<40){f=b^c^d;k=0x6ed9eba1;}else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(rol(a,5)+f+e+k+w[i])>>>0;e=d;d=c;c=rol(b,30);b=a;a=t;}
  h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;
 }
 return [h0,h1,h2,h3,h4].map(x=>x.toString(16).padStart(8,"0")).join("");
}
function b64decode(s){if(s.length%4||!/^[A-Za-z0-9+/]*={0,2}$/.test(s))throw new Error("noncanonical base64");const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";const out=new Uint8Array(s.length/4*3-(s.endsWith("==")?2:s.endsWith("=")?1:0));let p=0;for(let i=0;i<s.length;i+=4){const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==="="?0:alphabet.indexOf(s[i+2]),d=s[i+3]==="="?0:alphabet.indexOf(s[i+3]);const n=(a<<18)|(b<<12)|(c<<6)|d;if(p<out.length)out[p++]=n>>16;if(p<out.length)out[p++]=n>>8;if(p<out.length)out[p++]=n;}return out;}
return {utf8,sha256Bytes,sha1Bytes,inflateZlib,decodeUtf8,b64decode};