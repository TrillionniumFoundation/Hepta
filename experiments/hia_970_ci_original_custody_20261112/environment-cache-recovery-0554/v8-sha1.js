return function sha1Original(a){
if(!(a instanceof Uint8Array))throw Error("SHA1 byte input");
const h=new Uint32Array([0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]),w=new Uint32Array(80),L=(x,n)=>(x<<n)|(x>>>(32-n));
function block(v,o){for(let i=0;i<16;i++)w[i]=v.getUint32(o+4*i);for(let i=16;i<80;i++)w[i]=L(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);let x=h[0],b=h[1],c=h[2],d=h[3],e=h[4];for(let i=0;i<80;i++){const f=i<20?(b&c)|((~b)&d):i<40?b^c^d:i<60?(b&c)|(b&d)|(c&d):b^c^d,k=i<20?0x5a827999:i<40?0x6ed9eba1:i<60?0x8f1bbcdc:0xca62c1d6,t=(L(x,5)+f+e+k+w[i])>>>0;e=d;d=c;c=L(b,30);b=x;x=t;}h[0]=(h[0]+x)>>>0;h[1]=(h[1]+b)>>>0;h[2]=(h[2]+c)>>>0;h[3]=(h[3]+d)>>>0;h[4]=(h[4]+e)>>>0;}
const full=a.length-a.length%64,v=new DataView(a.buffer,a.byteOffset,a.byteLength);for(let o=0;o<full;o+=64)block(v,o);
const rest=a.length-full,p=new Uint8Array(rest+9<=64?64:128);p.set(a.subarray(full));p[rest]=128;const z=new DataView(p.buffer);z.setUint32(p.length-8,Math.floor(a.length/536870912));z.setUint32(p.length-4,(a.length*8)>>>0);for(let o=0;o<p.length;o+=64)block(z,o);
return Array.from(h,x=>x.toString(16).padStart(8,"0")).join("");
};