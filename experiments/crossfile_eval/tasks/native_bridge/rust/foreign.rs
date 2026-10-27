#[repr(C)]
pub struct ForeignResult { pub value: i64, pub status: i32 }
extern "C" {
    fn c_adjust(a: i64, b: i64) -> i64;
    fn cpp_scale(value: i64, factor: i64) -> ForeignResult;
}
pub fn adjusted(a: i64, b: i64) -> i64 { a + b }
pub fn scaled(value: i64, factor: i64) -> ForeignResult { ForeignResult { value: value * factor, status: 0 } }
