
function sha1(bytes) {
 if(typeof bytes==="string") bytes=new TextEncoder().encode(bytes);
 const n=bytes.length, z=new Uint8Array(((n+9+63)>>6)<<6);z.set(bytes);z[n]=128;
 const bits=n*8; for(let i=0;i<8;i++)z[z.length-1-i]=Math.floor(bits/2**(8*i))&255;
 let h=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
 const rol=(x,n)=>(x<<n)|(x>>>(32-n));const w=new Int32Array(80);
 for(let at=0;at<z.length;at+=64){
 for(let i=0;i<16;i++)w[i]=(z[at+4*i]<<24)|(z[at+4*i+1]<<16)|(z[at+4*i+2]<<8)|z[at+4*i+3];
 for(let i=16;i<80;i++)w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
 let[a,b,c,d,e]=h;
 for(let i=0;i<80;i++){let f,k;if(i<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(i<40){f=b^c^d;k=0x6ed9eba1;}else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}const t=(rol(a,5)+f+e+k+w[i])|0;e=d;d=c;c=rol(b,30);b=a;a=t;}
 h=h.map((x,i)=>(x+[a,b,c,d,e][i])|0);
 }
 return h.map(x=>(x>>>0).toString(16).padStart(8,"0")).join("");
}
function blobSha(bytes,utf8){const hdr=utf8("blob "+bytes.length+"\0");const all=new Uint8Array(hdr.length+bytes.length);all.set(hdr);all.set(bytes,hdr.length);return sha1(all);}
return {sha1,blobSha};