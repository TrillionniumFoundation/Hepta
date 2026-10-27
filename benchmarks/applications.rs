//! Independently authored fallible-Vec Rust application baseline.
#![allow(dead_code)]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppResult {
    pub status: u32, pub reserved: u32, pub bytes: u64,
    pub records: u64, pub checksum: u64,
}
impl AppResult {
    fn empty(status: u32) -> Self { Self {status,reserved:0,bytes:0,records:0,checksum:0} }
}
fn zeroed(length: usize) -> Result<Vec<u8>, u32> {
    let mut bytes=Vec::new();bytes.try_reserve_exact(length).map_err(|_|10u32)?;
    bytes.resize(length,0);Ok(bytes)
}
fn step(state: &mut u64) -> u64 {
    *state=state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);*state
}
fn feed(hash: u64, byte: u8) -> u64 { (hash ^ u64::from(byte)).wrapping_mul(1099511628211) }

fn packet(units: usize,request:u64) -> Result<AppResult,u32> {
    let mut wire=zeroed(units*64)?;
    let mut histogram=zeroed(256)?;
    let mut state=request ^ 11400714819323198485;
    for frame in wire.chunks_exact_mut(64) {
        frame[0]=60;frame[1]=0;frame[2]=(step(&mut state)&7) as u8;
        let mut sum=0u8;
        for byte in &mut frame[4..] {
            *byte=(step(&mut state)>>32) as u8;sum=sum.wrapping_add(*byte);
        }
        frame[3]=sum;
    }
    let middle=(units/2)*64;
    match request%8 {1=>wire[middle]=61,2=>wire[middle+4]^=1,3=>wire[middle+2]=8,_=>{}}
    let mut result=AppResult {status:0,reserved:0,bytes:0,records:0,checksum:14695981039346656037};
    while (result.bytes as usize)<wire.len() {
        let at=result.bytes as usize;
        let remaining=&wire[at..];
        if remaining.len()<4 {result.status=2;return Ok(result);}
        let length=u16::from_le_bytes([remaining[0],remaining[1]]) as usize;
        if length!=60 || length>remaining.len()-4 {result.status=2;return Ok(result);}
        let kind=remaining[2] as usize;
        if kind>=8 {result.status=4;return Ok(result);}
        let mut sum=0u8;
        for &byte in &remaining[4..4+length] {
            sum=sum.wrapping_add(byte);result.checksum=feed(result.checksum,byte);
        }
        if sum!=remaining[3] {result.status=3;return Ok(result);}
        histogram[kind]=histogram[kind].wrapping_add(1);
        result.bytes+=(4+length) as u64;result.records+=1;
    }
    for byte in histogram {result.checksum=feed(result.checksum,byte);}
    Ok(result)
}
#[no_mangle]
pub extern "C" fn packet_app(units:usize,request:u64)->AppResult {
    if units==0 || units>4096 {return AppResult::empty(1);}
    packet(units,request).unwrap_or_else(AppResult::empty)
}

fn transform(units:usize,request:u64)->Result<AppResult,u32> {
    let length=units*256;
    let mut input=zeroed(length+4)?;input[..4].copy_from_slice(b"HPTA");
    let mut state=request ^ 15111065706836454659;
    for byte in &mut input[4..] {*byte=(step(&mut state)>>32) as u8;}
    if request%8==1 {input[0]=0;}
    if &input[..4]!=b"HPTA" {return Ok(AppResult::empty(2));}
    let mut scratch=zeroed(256)?;
    let mut output=zeroed(length)?;
    let mut previous=request as u8;
    for (chunk_number,chunk) in input[4..].chunks(256).enumerate() {
        for (i,&byte) in chunk.iter().enumerate() {
            previous=byte.rotate_left(3)^previous;scratch[i]=previous;
        }
        let offset=chunk_number*256;
        for (i,&byte) in scratch[..chunk.len()].iter().rev().enumerate() {
            output[offset+i]=byte^((offset+i) as u8);
        }
    }
    let checksum=output.iter().fold(14695981039346656037,|hash,&byte|feed(hash,byte));
    Ok(AppResult {status:0,reserved:0,bytes:length as u64,records:units as u64,checksum})
}
#[no_mangle]
pub extern "C" fn transform_app(units:usize,request:u64)->AppResult {
    if units==0 || units>4096 {return AppResult::empty(1);}
    transform(units,request).unwrap_or_else(AppResult::empty)
}
