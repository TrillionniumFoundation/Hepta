return function(R){
const need=(x,m)=>{if(!x)throw Error(m);};
const table=new Uint32Array(256);
for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0);table[n]=c>>>0;}
function crc32(a){let c=0xffffffff;for(const b of a)c=(c>>>8)^table[(c^b)&255];return(c^0xffffffff)>>>0;}
function inspect(zip,maximumEntries=1040,maximumExpanded=234881024){
 const len=zip.length;need(len>=22,"ZIP too small");
 const u16=p=>{need(p>=0&&p+2<=len,"ZIP u16 boundary");return zip[p]|zip[p+1]<<8;};
 const u32=p=>{need(p>=0&&p+4<=len,"ZIP u32 boundary");return(zip[p]|zip[p+1]<<8|zip[p+2]<<16|zip[p+3]<<24)>>>0;};
 let eocd=-1;for(let p=len-22;p>=Math.max(0,len-22-65535);p--){if(u32(p)===0x06054b50&&p+22+u16(p+20)===len){need(eocd===-1,"ambiguous EOCD");eocd=p;}}
 need(eocd>=0&&u16(eocd+4)===0&&u16(eocd+6)===0,"single-disk EOCD required");
 const count=u16(eocd+10),size=u32(eocd+12),start=u32(eocd+16);
 need(count>0&&count<=maximumEntries&&count===u16(eocd+8)&&count!==65535&&size!==4294967295&&start!==4294967295,"bounded ZIP32 directory");
 need(start+size===eocd,"exact ZIP directory boundary");
 const entries=[],seen=new Set();let p=start,total=0;
 for(let i=0;i<count;i++){
  need(u32(p)===0x02014b50&&p+46<=eocd,"central header");
  const flags=u16(p+8),method=u16(p+10),crc=u32(p+16),compressed=u32(p+20),expanded=u32(p+24);
  const nl=u16(p+28),el=u16(p+30),cl=u16(p+32),disk=u16(p+34),local=u32(p+42),external=u32(p+38);
  need(nl>0&&p+46+nl+el+cl<=eocd&&disk===0&&!(flags&1)&&(flags&~0x0808)===0&&(method===0||method===8),"central member bounds/flags/method");
  const name=R.decode(zip.slice(p+46,p+46+nl));
  need(!name.startsWith("/")&&!name.endsWith("/")&&!name.includes("\\")&&!/[\x00-\x1f\x7f]/.test(name)&&name.split("/").every(x=>x&&x!=="."&&x!=="..")&&!seen.has(name),"canonical unique file name");
  const mode=external>>>16;need((mode&0xf000)===0||(mode&0xf000)===0x8000,"ordinary ZIP file");
  seen.add(name);total+=expanded;need(total<=maximumExpanded&&expanded<=maximumExpanded&&compressed!==4294967295&&expanded!==4294967295&&local!==4294967295,"expanded bound/ZIP32");
  need(u32(local)===0x04034b50&&u16(local+6)===flags&&u16(local+8)===method,"matching local header");
  const lnl=u16(local+26),lel=u16(local+28),data=local+30+lnl+lel;
  need(lnl===nl&&R.decode(zip.slice(local+30,local+30+lnl))===name&&data+compressed<=start,"local name/data boundary");
  let end=data+compressed,descriptor=0;
  if(flags&8){let q=end;if(u32(q)===0x08074b50){q+=4;descriptor+=4;}need(u32(q)===crc&&u32(q+4)===compressed&&u32(q+8)===expanded,"data descriptor identity");end=q+12;descriptor+=12;}
  else need(u32(local+14)===crc&&u32(local+18)===compressed&&u32(local+22)===expanded,"local size/CRC identity");
  need(end<=start,"member overlaps directory");entries.push({name,flags,method,crc32:crc,compressed_bytes:compressed,bytes:expanded,local_offset:local,data_offset:data,end_offset:end,descriptor_bytes:descriptor});p+=46+nl+el+cl;
 }
 need(p===eocd,"exact directory consumption");
 const physical=[...entries].sort((a,b)=>a.local_offset-b.local_offset);let next=0;
 for(const e of physical){need(e.local_offset===next,"gap/overlap in local members");next=e.end_offset;}
 need(next===start,"local stream boundary");
 for(const name of seen){const a=name.split("/");a.pop();while(a.length){need(!seen.has(a.join("/")),"file ancestor");a.pop();}}
 return{entries,entry_count:count,expanded_bytes:total,directory_offset:start,directory_bytes:size,eocd_offset:eocd,comment_bytes:u16(eocd+20)};
}
function extract(zip,e){
 let out;
 if(e.method===0){need(e.bytes===e.compressed_bytes,"stored member length");out=zip.slice(e.data_offset,e.end_offset-e.descriptor_bytes);}
 else{
  out=new Uint8Array(e.bytes);let bit=e.data_offset*8,op=0,blocks=0,final=0;const limit=(e.data_offset+e.compressed_bytes)*8;
  const read=n=>{need(bit+n<=limit,"stored deflate EOF");let v=0;for(let k=0;k<n;k++,bit++)v|=((zip[bit>>>3]>>>(bit&7))&1)<<k;return v;};
  while(!final){need(++blocks<=65536,"stored deflate block bound");final=read(1);need(read(2)===0,"artifact compression-level0 stored blocks required");bit=(bit+7)&~7;const n=read(16),nn=read(16);need((n^nn)===65535&&op+n<=out.length&&bit+n*8<=limit,"stored deflate length");out.set(zip.slice(bit>>>3,(bit>>>3)+n),op);op+=n;bit+=n*8;}
  need(op===e.bytes&&bit===limit,"exact stored deflate member");
 }
 need(out.length===e.bytes&&crc32(out)===e.crc32,"full member size/CRC");
 return out;
}
return{inspect,extract,crc32};
};