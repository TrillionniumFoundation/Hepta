use crate::candidate::foreign;
pub fn run(a: i64, b: i64) -> i64 {
    let result = foreign::scaled(foreign::adjusted(a, b), b);
    if result.status == 0 { result.value } else { -100 - result.status as i64 }
}
