// Independent safe Rust implementation of the same byte ring and CRC algorithm.
struct Ring { bytes: Vec<u8>, tail: usize, head: usize }
impl Ring {
    fn empty(&self) -> bool { self.head == self.tail }
    fn items(&self) -> usize { self.head.wrapping_sub(self.tail) & (self.bytes.len()-1) }
    fn full(&self) -> bool { self.items() == self.bytes.len()-1 }
    fn queue(&mut self, value: u8) {
        let mask=self.bytes.len()-1;
        if self.full() { self.tail=(self.tail+1)&mask; }
        self.bytes[self.head]=value; self.head=(self.head+1)&mask;
    }
    fn queue_arr(&mut self, input: &[u8]) { for &v in input { self.queue(v); } }
    fn dequeue(&mut self, output: &mut u8) -> bool {
        if self.empty() { return false; }
        *output=self.bytes[self.tail]; self.tail=(self.tail+1)&(self.bytes.len()-1); true
    }
    fn dequeue_arr(&mut self, output: &mut [u8]) -> usize {
        let mut n=0; while n<output.len() && self.dequeue(&mut output[n]) { n+=1; } n
    }
    fn peek(&self, index: usize) -> Option<u8> {
        if index>=self.items() { None } else { Some(self.bytes[(self.tail+index)&(self.bytes.len()-1)]) }
    }
}
fn bytes(n: usize) -> Option<Vec<u8>> {
    let mut result=Vec::new(); result.try_reserve_exact(n).ok()?; result.resize(n,0); Some(result)
}
fn compare(a: &[u8], b: &[u8]) -> i32 {
    for (&x,&y) in a.iter().zip(b) { if x!=y { return i32::from(x)-i32::from(y); } } 0
}
#[no_mangle]
pub extern "C" fn legacy_checksum_chunk(count: usize, packed: u64, state: u32, polynomial: u32) -> u64 {
    if count==0 { return u64::from(state); }
    if count>8 { return 1<<32; }
    let Some(storage)=bytes(16) else { return 2<<32; };
    let Some(mut input)=bytes(8) else { return 2<<32; };
    let Some(mut output)=bytes(8) else { return 2<<32; };
    for (i,slot) in input[..count].iter_mut().enumerate() { *slot=(packed>>(i*8)) as u8; }
    let mut ring=Ring { bytes: storage, tail: 0, head: 0 };
    assert!(ring.empty()); ring.queue_arr(&input[..count]);
    assert_eq!(ring.items(),count); assert!(!ring.full());
    assert_eq!(ring.peek(0),Some(input[0]));
    assert_eq!(ring.dequeue_arr(&mut output[..count]),count);
    assert_eq!(compare(&input[..count],&output[..count]),0);
    assert_eq!(compare(&input[..count],&output[..count]),0);
    let mut value=state;
    for &byte in &output[..count] {
        value^=u32::from(byte);
        for _ in 0..8 { value=(value>>1) ^ if value&1 != 0 { polynomial } else { 0 }; }
    }
    ring.queue(input[0]); assert!(ring.dequeue(&mut output[0]));
    assert_eq!(output[0],input[0]); assert!(ring.empty()); u64::from(value)
}
