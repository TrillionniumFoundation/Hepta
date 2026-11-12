return function readVerifiedOriginalZip(){
const sha256=new Function(load("root-bounded-original-sha256-helper"))();
const parts=load("root-970-original-inner-ZIP-base64-slices"),zip=new Uint8Array(8316154);
if(!Array.isArray(parts)||parts.length!==19)throw Error("nineteen original intervals required");
const alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",table=new Int16Array(128);table.fill(-1);for(let i=0;i<64;i++)table[alpha.charCodeAt(i)]=i;
for(let i=0;i<19;i++){
 const x=parts[i],p=x.partition,expected=Math.min(458752,8316154-i*458752);
 if(p.ordinal!==i||p.id!==String(i).padStart(2,"0")||p.offset!==i*458752||p.bytes!==expected||x.bytes!==expected)throw Error("fixed original interval identity");
 const s=x.base64,pad=s.endsWith("==")?2:s.endsWith("=")?1:0;
 if(s.length%4||s.length/4*3-pad!==expected)throw Error("original encoded extent");
 const out=new Uint8Array(expected);let at=0;
 for(let j=0;j<s.length;j+=4){let value=0;for(let k=0;k<4;k++){const c=s.charCodeAt(j+k);let v;if(c===61){if(j+4!==s.length||k<2)throw Error("base64 padding");v=0;}else {v=c<128?table[c]:-1;if(v<0)throw Error("base64 alphabet");}value=(value<<6)|v;}for(const shift of [16,8,0])if(at<out.length)out[at++]=(value>>>shift)&255;}
 if(sha256(out)!==x.sha256)throw Error("original slice SHA");
 zip.set(out,p.offset);
}
if(sha256(zip)!=="d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e")throw Error("full original ZIP SHA");
const exports={};new Function("exports","module","define",load("root-pako-pinned-source-raw"))(exports,{exports},undefined);
const reader=new Function(load("root-fixed-original-zip-reader-helper"))()(exports,{sha256});
const directory=load("root-970-original-inner-ZIP-directory");
if(directory.member_count!==356||directory.sha256!=="d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e")throw Error("verified original directory");
return {zip,reader,directory,decodeUTF8:new Function(load("root-bounded-original-utf8-helper"))(),sha256};
};
