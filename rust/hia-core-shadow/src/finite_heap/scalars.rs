//! Conservative scalar facts for heap extents, not an execution interpreter.
//! Unknown stays unknown; no observed allocation failure supplies a fact.
use serde_json::Value;
use super::{unknown, R};
use crate::int_bits;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Fact { Unknown, Int(i128, i128), Bool(bool), Unit }

impl Fact {
    pub(super) fn constant(value: &Value) -> Self {
        if let Some(n) = value.as_i64() { Self::Int(n as i128, n as i128) }
        else if let Some(n) = value.as_u64() { Self::Int(n as i128, n as i128) }
        else if let Some(b) = value.as_bool() { Self::Bool(b) }
        else if value.is_null() { Self::Unit } else { Self::Unknown }
    }
    pub(super) fn span(self) -> Option<(i128, i128)> {
        if let Self::Int(lo, hi) = self { Some((lo, hi)) } else { None }
    }
    pub(super) fn exact(self) -> Option<i128> {
        self.span().and_then(|(lo, hi)| (lo == hi).then_some(lo))
    }
    pub(super) fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Int(a,b), Self::Int(c,d)) => Self::Int(a.min(c), b.max(d)),
            (a,b) if a == b => a,
            _ => Self::Unknown,
        }
    }
}

fn domain(ty: &str) -> Option<(i128, i128)> {
    int_bits(ty).map(|(signed, width)| if signed {
        (-(1_i128 << (width - 1)), (1_i128 << (width - 1)) - 1)
    } else { (0, (1_i128 << width) - 1) })
}
pub(super) fn intrinsic(ty: &str) -> Fact {
    if int_bits(ty).is_some_and(|(_, width)| width <= 32) {
        let (lo, hi) = domain(ty).unwrap(); Fact::Int(lo, hi)
    } else { Fact::Unknown }
}
fn wrap(n: i128, ty: &str) -> Option<i128> {
    let (signed, bits) = int_bits(ty)?;
    let word = n & ((1_i128 << bits) - 1);
    Some(if signed && word >= (1_i128 << (bits - 1)) { word - (1_i128 << bits) } else { word })
}
fn exact_wrapped(n: i128, ty: &str) -> Fact {
    wrap(n, ty).map(|x| Fact::Int(x,x)).unwrap_or(Fact::Unknown)
}

fn arithmetic(op: &str, a: Fact, b: Fact, ty: &str) -> R<Fact> {
    let (Some((al,ah)), Some((bl,bh)), Some((low,high))) = (a.span(), b.span(), domain(ty))
        else { return Ok(Fact::Unknown); };
    let operation = op.split('.').nth(1).unwrap_or("");
    // The largest u64 product exceeds signed i128. Checked arithmetic refuses
    // that exact overflow; modular multiplication keeps only the target bits.
    if al == ah && bl == bh && op.ends_with(".wrap") {
        let value = match operation {
            "add" => al.wrapping_add(bl), "sub" => al.wrapping_sub(bl),
            "mul" => al.wrapping_mul(bl), _ => return Ok(Fact::Unknown),
        };
        return Ok(exact_wrapped(value, ty));
    }
    let endpoints = match operation {
        "add" => al.checked_add(bl).zip(ah.checked_add(bh)),
        "sub" => al.checked_sub(bh).zip(ah.checked_sub(bl)),
        "mul" => {
            let corners = [al.checked_mul(bl), al.checked_mul(bh), ah.checked_mul(bl), ah.checked_mul(bh)];
            if corners.iter().all(Option::is_some) {
                let values = corners.map(Option::unwrap);
                Some((*values.iter().min().unwrap(), *values.iter().max().unwrap()))
            } else { None }
        },
        _ => None,
    };
    if let Some((lo,hi)) = endpoints {
        if low <= lo && lo <= hi && hi <= high { return Ok(Fact::Int(lo,hi)); }
    }
    if al == ah && bl == bh && op.ends_with(".checked") {
        return unknown("checked constant arithmetic may trap");
    }
    Ok(Fact::Unknown)
}

fn cast(a: Fact, ty: &str, mode: &str) -> R<Fact> {
    let Some((low,high)) = domain(ty) else { return Ok(Fact::Unknown); };
    if !matches!(mode, "checked" | "wrap") { return unknown("unreviewed cast mode"); }
    let Some((lo,hi)) = a.span() else { return Ok(intrinsic(ty)); };
    if mode == "checked" {
        let (lo,hi) = (lo.max(low), hi.min(high));
        return Ok(if lo <= hi { Fact::Int(lo,hi) } else { Fact::Unknown });
    }
    if low <= lo && hi <= high { return Ok(a); }
    if lo == hi { return Ok(exact_wrapped(lo,ty)); }
    Ok(intrinsic(ty))
}

fn shift(op: &str, a: Fact, b: Fact, ty: &str) -> R<Fact> {
    let (Some((lo,hi)), Some((cl,ch)), Some((_,bits))) = (a.span(), b.span(), int_bits(ty))
        else { return Ok(Fact::Unknown); };
    if cl < 0 || ch >= i128::from(bits) {
        return if lo == hi && cl == ch { unknown("checked constant shift count traps") }
               else { Ok(Fact::Unknown) };
    }
    let mut corners = [0;4];
    for (index,(n,count)) in [(lo,cl),(lo,ch),(hi,cl),(hi,ch)].into_iter().enumerate() {
        // All machine values are at most 64 bits and counts at most 63;
        // these mathematical endpoints fit i128 even before target wrapping.
        corners[index] = if op == "int.shl.checked" { n << count as u32 } else { n >> count as u32 };
    }
    let low = *corners.iter().min().unwrap(); let high = *corners.iter().max().unwrap();
    let (min,max) = domain(ty).unwrap();
    if min <= low && high <= max { return Ok(Fact::Int(low,high)); }
    if lo == hi && cl == ch { return Ok(exact_wrapped(low,ty)); }
    Ok(Fact::Unknown)
}

fn divrem(op: &str, a: Fact, b: Fact, ty: &str) -> R<Fact> {
    let (Some((bl,bh)),Some((low,high))) = (b.span(), domain(ty)) else { return Ok(Fact::Unknown); };
    if bl == 0 && bh == 0 { return unknown("checked constant division or remainder traps"); }
    if let (Some(x),Some(y)) = (a.exact(), b.exact()) {
        if y == 0 || ty.starts_with('i') && x == low && y == -1 {
            return unknown("checked constant division or remainder traps");
        }
        let value = if op == "int.div.checked" { x / y } else { x % y };
        return Ok(Fact::Int(value,value));
    }
    if bl <= 0 || bh > high { return Ok(Fact::Unknown); }
    let (al,ah) = a.span().unwrap_or((low,high));
    if al < low || ah > high { return Ok(Fact::Unknown); }
    if !ty.starts_with('i') {
        return Ok(if op == "int.rem.checked" { Fact::Int(0,bh-1) }
                  else { Fact::Int(al/bh,ah/bl) });
    }
    Ok(if op == "int.div.checked" { Fact::Int(-al.min(0).abs()/bl,ah.max(0)/bl) }
       else { Fact::Int(if al < 0 { -(bh-1) } else { 0 },if ah > 0 { bh-1 } else { 0 }) })
}

pub(super) fn transfer(op: &str, args: &[Fact], ty: &str, attrs: &Value) -> R<Fact> {
    let a = args.first().copied().unwrap_or(Fact::Unknown);
    let b = args.get(1).copied().unwrap_or(Fact::Unknown);
    if matches!(op, "int.add.checked" | "int.sub.checked" | "int.mul.checked" |
                    "int.add.wrap" | "int.sub.wrap" | "int.mul.wrap") {
        return arithmetic(op,a,b,ty);
    }
    match op {
        "const" => Ok(Fact::constant(&attrs["value"])),
        "int.cast" => cast(a,ty,attrs["mode"].as_str().unwrap_or("")),
        "int.shl.checked" | "int.shr.checked" => shift(op,a,b,ty),
        "int.div.checked" | "int.rem.checked" => divrem(op,a,b,ty),
        "int.neg.checked" => {
            if let (Some((lo,hi)),Some((low,high))) = (a.span(),domain(ty)) {
                if low <= -hi && -lo <= high { return Ok(Fact::Int(-hi,-lo)); }
                if lo == hi { return unknown("checked constant negation may trap"); }
            }
            Ok(Fact::Unknown)
        },
        "select" => Ok(match a {
            Fact::Bool(true) => b,
            Fact::Bool(false) => args.get(2).copied().unwrap_or(Fact::Unknown),
            _ => b.join(args.get(2).copied().unwrap_or(Fact::Unknown)),
        }),
        "bool.not" => Ok(if let Fact::Bool(x) = a { Fact::Bool(!x) } else { Fact::Unknown }),
        "bool.and" | "bool.or" => Ok(if let (Fact::Bool(x),Fact::Bool(y)) = (a,b) {
            Fact::Bool(if op == "bool.and" { x && y } else { x || y })
        } else { Fact::Unknown }),
        "compare.eq" | "compare.ne" | "compare.lt" | "compare.le" | "compare.gt" | "compare.ge" => {
            if let (Fact::Bool(x),Fact::Bool(y)) = (a,b) {
                return Ok(match op { "compare.eq" => Fact::Bool(x==y), "compare.ne" => Fact::Bool(x!=y), _ => Fact::Unknown });
            }
            Ok(if let (Some(x),Some(y)) = (a.exact(),b.exact()) {
                Fact::Bool(match op { "compare.eq" => x==y,"compare.ne" => x!=y,"compare.lt" => x<y,
                    "compare.le" => x<=y,"compare.gt" => x>y,_ => x>=y })
            } else { Fact::Unknown })
        },
        "bit.not" => Ok(if let (Some((lo,hi)),Some((low,high))) = (a.span(),domain(ty)) {
            if lo < low || hi > high { Fact::Unknown }
            else if ty.starts_with('i') { Fact::Int(-hi-1,-lo-1) }
            else { Fact::Int(high-hi,high-lo) }
        } else { Fact::Unknown }),
        "bit.and" | "bit.or" | "bit.xor" => {
            if let (Some(x),Some(y)) = (a.exact(),b.exact()) {
                return Ok(exact_wrapped(match op { "bit.and"=>x&y,"bit.or"=>x|y,_=>x^y },ty));
            }
            let Some((_,maximum))=domain(ty) else { return Ok(Fact::Unknown); };
            if op == "bit.and" {
                let bound = [a,b].into_iter().filter_map(|value| value.span())
                    .filter(|(lo,hi)| 0<=*lo && lo<=hi && *hi<=maximum).map(|(_,hi)|hi).min();
                return Ok(bound.map(|n|Fact::Int(0,n)).unwrap_or(Fact::Unknown));
            }
            if let (Some((al,ah)),Some((bl,bh)))=(a.span(),b.span()) {
                if al>=0 && bl>=0 && ah<=maximum && bh<=maximum {
                    let bits=128-ah.max(bh).leading_zeros();
                    let ceiling=(1_i128<<bits)-1;
                    if ceiling<=maximum { return Ok(Fact::Int(0,ceiling)); }
                }
            }
            Ok(Fact::Unknown)
        },
        // Memory loads and every other operation cannot mint a size fact here.
        _ => Ok(Fact::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn covers(fact: Fact, value: i128) {
        if let Fact::Int(lo,hi) = fact {
            assert!(lo <= value && value <= hi, "{fact:?} excludes {value}");
        } else {
            assert_eq!(fact,Fact::Unknown);
        }
    }

    #[test]
    fn interval_operations_cover_every_value_in_signed_and_unsigned_byte_partitions() {
        let signed = [(-128,-65),(-64,-1),(-1,0),(0,15),(16,127)];
        let unsigned = [(0,0),(0,255),(17,31),(64,200),(254,255)];
        let mut observed_bounds = 0;
        for (ty,ranges) in [("i8",signed.as_slice()),("u8",unsigned.as_slice())] {
            for &(al,ah) in ranges { for &(bl,bh) in ranges {
                for op in ["int.add.checked","int.sub.checked","int.mul.checked",
                           "int.add.wrap","int.sub.wrap","int.mul.wrap",
                           "int.div.checked","int.rem.checked","bit.and","bit.or","bit.xor"] {
                    let result = transfer(op,&[Fact::Int(al,ah),Fact::Int(bl,bh)],ty,&json!({}));
                    // A refused input cannot authorize a payload bound.
                    let Ok(fact) = result else { continue; };
                    if fact != Fact::Unknown { observed_bounds += 1; }
                    for x in al..=ah { for y in bl..=bh {
                        let mathematical = match op {
                            "int.add.checked"|"int.add.wrap"=>Some(x+y),
                            "int.sub.checked"|"int.sub.wrap"=>Some(x-y),
                            "int.mul.checked"|"int.mul.wrap"=>Some(x*y),
                            "int.div.checked" if y!=0 && !(ty=="i8"&&x==-128&&y==-1)=>Some(x/y),
                            "int.rem.checked" if y!=0 && !(ty=="i8"&&x==-128&&y==-1)=>Some(x%y),
                            "bit.and"=>Some(x&y),"bit.or"=>Some(x|y),"bit.xor"=>Some(x^y),
                            _=>None,
                        };
                        let Some(value)=mathematical else {continue;};
                        let value = if op.ends_with(".wrap") {
                            if ty=="i8" {value as i8 as i128} else {value as u8 as i128}
                        } else {
                            let in_range=if ty=="i8" {i8::try_from(value).is_ok()} else {u8::try_from(value).is_ok()};
                            if !in_range {continue;} value
                        };
                        covers(fact,value);
                    }}
                }
            }}
        }
        assert!(observed_bounds>100,"test must exercise actual non-top bounds");
    }

    #[test]
    fn casts_shifts_and_negation_cover_all_representable_values_in_partition_intervals() {
        let ranges = [(-128,-65),(-64,-1),(-1,0),(0,15),(16,127),(128,255)];
        for (lo,hi) in ranges {
            for ty in ["i8","u8"] {
                for mode in ["checked","wrap"] {
                    let fact=transfer("int.cast",&[Fact::Int(lo,hi)],ty,&json!({"mode":mode})).unwrap();
                    for value in lo..=hi {
                        if mode=="checked" && (if ty=="i8" {i8::try_from(value).is_err()} else {u8::try_from(value).is_err()}) {continue;}
                        covers(fact,if ty=="i8" {value as i8 as i128} else {value as u8 as i128});
                    }
                }
                if (ty=="i8"&&hi>127)||(ty=="u8"&&lo<0) {continue;}
                for op in ["int.shl.checked","int.shr.checked"] {
                    for (cl,ch) in [(0,0),(1,7),(3,5)] {
                        let fact=transfer(op,&[Fact::Int(lo,hi),Fact::Int(cl,ch)],ty,&json!({})).unwrap();
                        for value in lo..=hi { for count in cl..=ch {
                            let result=if ty=="i8" {
                                (if op=="int.shl.checked" {(value as i8).wrapping_shl(count as u32)} else {(value as i8).wrapping_shr(count as u32)}) as i128
                            } else {
                                (if op=="int.shl.checked" {(value as u8).wrapping_shl(count as u32)} else {(value as u8).wrapping_shr(count as u32)}) as i128
                            };
                            covers(fact,result);
                        }}
                    }
                }
                let complement=transfer("bit.not",&[Fact::Int(lo,hi)],ty,&json!({})).unwrap();
                for value in lo..=hi {
                    covers(complement,if ty=="i8" {(!(value as i8)) as i128} else {(!(value as u8)) as i128});
                }
                if ty=="i8" {
                    let negated=transfer("int.neg.checked",&[Fact::Int(lo,hi)],ty,&json!({})).unwrap();
                    for value in lo.max(-127)..=hi {covers(negated,-value);}
                }
            }
        }
    }

    #[test]
    fn exact_u64_overflow_and_signed_minimum_traps_never_supply_false_size_facts() {
        let maximum=u64::MAX as i128;
        let exact=Fact::Int(maximum,maximum);
        assert_eq!(transfer("int.mul.wrap",&[exact,exact],"usize",&json!({})).unwrap(),Fact::Int(1,1));
        assert!(transfer("int.mul.checked",&[exact,exact],"usize",&json!({})).is_err());
        assert_eq!(transfer("int.shl.checked",&[exact,Fact::Int(63,63)],"u64",&json!({})).unwrap(),
                   Fact::Int(1_i128<<63,1_i128<<63));
        let minimum=Fact::Int(i64::MIN as i128,i64::MIN as i128);
        for op in ["int.div.checked","int.rem.checked"] {
            assert!(transfer(op,&[minimum,Fact::Int(-1,-1)],"isize",&json!({})).is_err());
        }
        assert!(transfer("int.neg.checked",&[minimum],"i64",&json!({})).is_err());
        assert_eq!(transfer("buffer.load",&[],"u8",&json!({})).unwrap(),Fact::Unknown);
        assert_eq!(transfer("int.cast",&[Fact::Unknown],"usize",&json!({"mode":"checked"})).unwrap(),Fact::Unknown);
    }
}
