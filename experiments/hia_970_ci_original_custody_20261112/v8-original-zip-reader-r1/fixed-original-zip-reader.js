return function makeFixedOriginalZipReader(P,H) {
  "use strict";
  const fail=m=>{throw new Error("ORIGINAL_ZIP_REFUSAL: "+m);};
  const need=(v,m)=>{if(!v)fail(m);};
  const table=new Uint32Array(256);
  for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xedb88320^(c>>>1):c>>>1;table[n]=c>>>0;}
  function crc32(bytes){let c=0xffffffff;for(let i=0;i<bytes.length;i++)c=table[(c^bytes[i])&255]^(c>>>8);return (c^0xffffffff)>>>0;}
  function ascii(bytes){const chunks=[];for(let off=0;off<bytes.length;off+=32768){const sub=bytes.subarray(off,Math.min(bytes.length,off+32768));for(let i=0;i<sub.length;i++)need(sub[i]<128,"non-ASCII bounded archive name/JSON");chunks.push(String.fromCharCode(...sub));}return chunks.join("");}
  function inflateExact(bytes,expectedBytes) {
    need(bytes instanceof Uint8Array&&Number.isSafeInteger(expectedBytes)&&expectedBytes>=0&&expectedBytes<=134217728,"bounded compressed input and exact output extent");
    const result=new Uint8Array(expectedBytes),i=new P.Inflate({raw:true,chunkSize:65536});let at=0;
    i.onData=chunk=>{need(at+chunk.length<=expectedBytes,"inflated original exceeds independently pinned extent");result.set(chunk,at);at+=chunk.length;};
    const ok=i.push(bytes,true);
    need(ok===true&&i.err===0&&i.ended===true&&at===expectedBytes&&i.strm.total_in===bytes.length&&i.strm.avail_in===0,"complete exact raw DEFLATE stream and output required");
    return result;
  }
  function inspect(zip,pins) {
    need(zip instanceof Uint8Array&&pins&&zip.length===pins.bytes&&pins.bytes===8316154&&pins.sha256==="d72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e","exact original selected ZIP external extent/seal required");
    need(H.sha256(zip)===pins.sha256,"whole original selected ZIP SHA differs");
    const v=new DataView(zip.buffer,zip.byteOffset,zip.byteLength),end=zip.length,u16=at=>{need(at>=0&&at+2<=end,"u16 extent");return v.getUint16(at,true);},u32=at=>{need(at>=0&&at+4<=end,"u32 extent");return v.getUint32(at,true);};
    const u64=at=>{const n=u32(at)+u32(at+4)*4294967296;need(Number.isSafeInteger(n),"ZIP64 unsafe integer");return n;};
    function extraValues(at,size,wants){const stop=at+size;need(stop<=end,"extra extent");let found=false,values=[];while(at<stop){need(at+4<=stop,"truncated extra header");const id=u16(at),len=u16(at+2);at+=4;need(at+len<=stop,"truncated extra body");if(id===1){need(!found,"duplicate ZIP64 extra");found=true;let p=at;for(const w of wants){if(w){need(p+8<=at+len,"ZIP64 missing size");values.push(u64(p));p+=8;}else values.push(null);}}at+=len;}need(!wants.some(Boolean)||found,"required ZIP64 extra absent");return values;}
    let eocd=-1;for(let i=end-22;i>=Math.max(0,end-65557);i--){if(u32(i)===0x06054b50&&i+22+u16(i+20)===end){eocd=i;break;}}
    need(eocd>=0&&u16(eocd+4)===0&&u16(eocd+6)===0&&u16(eocd+8)===356&&u16(eocd+10)===356&&u16(eocd+20)===0,"exact single-disk356-entry uncommented original ZIP");
    const centralBytes=u32(eocd+12),centralAt=u32(eocd+16);
    need(centralAt+centralBytes===eocd&&centralAt>0,"complete central directory extent");
    need(Array.isArray(pins.members)&&pins.members.length===356&&new Set(pins.members.map(x=>x.name)).size===356,"356 independently pinned member names");
    const wanted=new Map(pins.members.map(x=>[x.name,x])),seen=new Set(),rows=[];let at=centralAt,total=0;
    for(let ordinal=0;ordinal<356;ordinal++){
      need(at+46<=eocd&&u32(at)===0x02014b50,"central entry signature");
      const made=u16(at+4),needed=u16(at+6),flags=u16(at+8),method=u16(at+10),crc=u32(at+16);
      let compressed=u32(at+20),uncompressed=u32(at+24),offset=u32(at+42);
      const nameBytes=u16(at+28),extraBytes=u16(at+30),commentBytes=u16(at+32),disk=u16(at+34),attrs=u32(at+38),next=at+46+nameBytes+extraBytes+commentBytes;
      need(next<=eocd&&nameBytes>0&&nameBytes<=64&&commentBytes===0&&disk===0&&(made>>>8)===3&&needed<=45&&flags===0&&method===8&&((attrs>>>16)&0xffff)===0o100400,"fixed regular owner-only original member metadata");
      const name=ascii(zip.subarray(at+46,at+46+nameBytes));
      need(/^(?:[0-9]{4}\.raw|DIRECTORY\.json|SELECTED\.json)$/.test(name)&&wanted.has(name)&&!seen.has(name),"unplanned or duplicate original member name");
      const zv=extraValues(at+46+nameBytes,extraBytes,[uncompressed===0xffffffff,compressed===0xffffffff,offset===0xffffffff]);
      if(uncompressed===0xffffffff)uncompressed=zv[0];if(compressed===0xffffffff)compressed=zv[1];if(offset===0xffffffff)offset=zv[2];
      const pin=wanted.get(name);
      need(Number.isSafeInteger(pin.bytes)&&pin.bytes>=0&&pin.bytes<=134217728&&/^[0-9a-f]{64}$/.test(pin.sha256)&&uncompressed===pin.bytes&&compressed>=0&&offset+30<=centralAt,"member exact pinned raw extent");
      if(pin.crc32!==undefined)need(pin.crc32===crc,"original independently pinned CRC differs");
      need(u32(offset)===0x04034b50&&u16(offset+4)===needed&&u16(offset+6)===flags&&u16(offset+8)===method&&u32(offset+14)===crc,"local/central original header binding");
      const ln=u16(offset+26),le=u16(offset+28);need(ln===nameBytes&&offset+30+ln+le<=centralAt,"local name/extra extents");
      need(ascii(zip.subarray(offset+30,offset+30+ln))===name,"local/central member name differs");
      let lc=u32(offset+18),lu=u32(offset+22);const lv=extraValues(offset+30+ln,le,[lu===0xffffffff,lc===0xffffffff]);
      if(lu===0xffffffff)lu=lv[0];if(lc===0xffffffff)lc=lv[1];
      need(lu===uncompressed&&lc===compressed,"local/central ZIP64 sizes differ");
      const dataAt=offset+30+ln+le,dataEnd=dataAt+compressed;need(dataEnd<=centralAt,"compressed original data overlaps directory");
      rows.push({ordinal,name,bytes:uncompressed,sha256:pin.sha256,crc32:crc,compressed_bytes:compressed,local_offset:offset,data_offset:dataAt,data_end:dataEnd});
      seen.add(name);total+=uncompressed;at=next;
    }
    need(at===eocd&&seen.size===356&&total===126634528,"complete original member population and raw byte denominator");
    const spans=[...rows].sort((a,b)=>a.local_offset-b.local_offset);let boundary=0;
    for(const x of spans){need(x.local_offset===boundary,"original local entries have gap/overlap");boundary=x.data_end;}
    need(boundary===centralAt,"complete contiguous local ZIP extent");
    return {schema:"hia.root.fixed-selected-zip-directory.v1",status:"EXACT_ORIGINAL_ZIP_DIRECTORY_VERIFIED",bytes:zip.length,sha256:pins.sha256,members:rows,total_uncompressed_bytes:total,member_count:356,all_member_bodies_inflated:false};
  }
  function extract(zip,row) {
    need(zip instanceof Uint8Array&&row&&row.data_offset>=0&&row.data_end<=zip.length&&row.data_end-row.data_offset===row.compressed_bytes,"selected member compressed extent");
    const raw=inflateExact(zip.subarray(row.data_offset,row.data_end),row.bytes);
    need(crc32(raw)===row.crc32&&H.sha256(raw)===row.sha256,"complete decompressed original CRC/SHA differs");
    return raw;
  }
  return {inspect,extract,inflateExact,crc32,ascii};
};
