
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicBool,AtomicU64,Ordering};
struct Counted;
static ACTIVE:AtomicBool=AtomicBool::new(false);
static ALLOCS:AtomicU64=AtomicU64::new(0);static FREES:AtomicU64=AtomicU64::new(0);
static LIVE:AtomicU64=AtomicU64::new(0);static PEAK:AtomicU64=AtomicU64::new(0);
fn account(n:usize){if ACTIVE.load(Ordering::SeqCst){ALLOCS.fetch_add(1,Ordering::SeqCst);let now=LIVE.fetch_add(n as u64,Ordering::SeqCst)+n as u64;PEAK.fetch_max(now,Ordering::SeqCst);}}
unsafe impl GlobalAlloc for Counted {
unsafe fn alloc(&self,l:Layout)->*mut u8{let p=System.alloc(l);if !p.is_null(){account(l.size());}p}
unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8{let p=System.alloc_zeroed(l);if !p.is_null(){account(l.size());}p}
unsafe fn dealloc(&self,p:*mut u8,l:Layout){if ACTIVE.load(Ordering::SeqCst){FREES.fetch_add(1,Ordering::SeqCst);LIVE.fetch_sub(l.size() as u64,Ordering::SeqCst);}System.dealloc(p,l);}
}
#[global_allocator] static A:Counted=Counted;
fn reset(){ALLOCS.store(0,Ordering::SeqCst);FREES.store(0,Ordering::SeqCst);LIVE.store(0,Ordering::SeqCst);PEAK.store(0,Ordering::SeqCst);ACTIVE.store(true,Ordering::SeqCst);}
fn capture()->[u64;4]{ACTIVE.store(false,Ordering::SeqCst);[ALLOCS.load(Ordering::SeqCst),FREES.load(Ordering::SeqCst),LIVE.load(Ordering::SeqCst),PEAK.load(Ordering::SeqCst)]}

mod api_original {#![forbid(unsafe_code)] include!("api.rs");}
mod client {#![forbid(unsafe_code)] include!("client.rs");}
mod audit;mod utility;mod probe;
mod api {
use std::sync::atomic::{AtomicU64,Ordering};
static CALLS:AtomicU64=AtomicU64::new(0);static ARG0:AtomicU64=AtomicU64::new(0);static ARG1:AtomicU64=AtomicU64::new(0);static BAD:AtomicU64=AtomicU64::new(0);
pub fn reset(a:u64,b:u64){CALLS.store(0,Ordering::SeqCst);BAD.store(0,Ordering::SeqCst);ARG0.store(a,Ordering::SeqCst);ARG1.store(b,Ordering::SeqCst);}
pub fn result()->(u64,u64){(CALLS.load(Ordering::SeqCst),BAD.load(Ordering::SeqCst))}
pub fn saturating_sum(a:u32,b:u32)->u32{
CALLS.fetch_add(1,Ordering::SeqCst);let (a0,a1)=(a as u64,b as u64);if a0!=ARG0.load(Ordering::SeqCst)||a1!=ARG1.load(Ordering::SeqCst){BAD.store(1,Ordering::SeqCst);}
let value=super::api_original::saturating_sum(a,b);value
}
}
use std::io::{self,BufRead};
fn main(){for line in io::stdin().lock().lines(){let line=line.unwrap();let v:Vec<u32>=line.split_whitespace().map(|x|x.parse().unwrap()).collect();
api::reset(v[0] as u64,v[1] as u64);reset();let e=client::entrypoint(v[0],v[1],v[2]);let er=capture();let ec=api::result();
api::reset(v[0] as u64,v[1] as u64);reset();let p=probe::provider_probe(v[0],v[1],v[2]);let pr=capture();let pc=api::result();
println!("{} {} {} {} {} {} {} {} {} {} {} {} {} {}",e,p,er[0],er[1],er[2],er[3],ec.1,pr[0],pr[1],pr[2],pr[3],pc.1,ec.0,pc.0);
}}
