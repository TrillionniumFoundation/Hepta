#[repr(C)]
pub struct ParseResult { pub value: u64, pub consumed: usize, pub status: u32 }
#[no_mangle]
pub unsafe extern "C" fn evaluate(input: *const u8, n: usize) -> ParseResult
/* AGENT_BODY_BEGIN */
{ ParseResult { value: 0, consumed: 0, status: 1 } }
/* AGENT_BODY_END */
