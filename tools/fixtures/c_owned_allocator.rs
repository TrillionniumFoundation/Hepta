struct Observed;
static TRACK:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static REFUSE:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static ALLOC:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static FREE:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static LIVE:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
static REFUSALS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Observed {
  unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
    if TRACK.load(std::sync::atomic::Ordering::SeqCst)&&REFUSE.load(std::sync::atomic::Ordering::SeqCst) {
      REFUSALS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
      return core::ptr::null_mut();
    }
    let p=std::alloc::GlobalAlloc::alloc(&std::alloc::System,layout);
    if TRACK.load(std::sync::atomic::Ordering::SeqCst)&&!p.is_null() {
      ALLOC.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
      LIVE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
    }
    p
  }
  unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
    if TRACK.load(std::sync::atomic::Ordering::SeqCst) {
      FREE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
      LIVE.fetch_sub(1,std::sync::atomic::Ordering::SeqCst);
    }
    std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,layout);
  }
}
#[global_allocator]static A:Observed=Observed;
fn main() {
  TRACK.store(true,std::sync::atomic::Ordering::SeqCst);
  assert_eq!(h_probe(7,true),30);
  assert_eq!(h_probe(13,false),19);
  REFUSE.store(true,std::sync::atomic::Ordering::SeqCst);
  assert_eq!(h_probe(65519,true),1001);
  REFUSE.store(false,std::sync::atomic::Ordering::SeqCst);
  assert_eq!(h_probe(17,true),40);
  assert_eq!(h_probe(usize::MAX,true),1001);
  assert_eq!(h_probe(0,true),23);
  TRACK.store(false,std::sync::atomic::Ordering::SeqCst);
  let observed=(ALLOC.load(std::sync::atomic::Ordering::SeqCst),FREE.load(std::sync::atomic::Ordering::SeqCst),LIVE.load(std::sync::atomic::Ordering::SeqCst),REFUSALS.load(std::sync::atomic::Ordering::SeqCst));
  assert_eq!(observed,(3,3,0,1));
  println!("{} {} {} {}",observed.0,observed.1,observed.2,observed.3);
}
