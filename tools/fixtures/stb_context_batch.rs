use std::arch::asm;
#[no_mangle]
pub unsafe extern "C" fn batch(input:*const i32,output:*mut i32,n:usize,divisor:i32,rounds:u32)->u64 {
    let input=std::slice::from_raw_parts(input,n);
    let output=std::slice::from_raw_parts_mut(output,n);
    let mut checksum=0u64;
    for round in 0..rounds {
        asm!("", options(nostack,preserves_flags));
        for (a,b) in input.iter().zip(output.iter_mut()) {*b=*a/divisor;}
        checksum=checksum.wrapping_add(output[round as usize % n] as u32 as u64);
    }
    checksum
}
