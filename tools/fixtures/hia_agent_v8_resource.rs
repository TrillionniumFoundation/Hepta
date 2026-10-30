// Selected audited Vec API for the prospective textual-v8 versus Rust tasks.
// Real std::Vec storage, bounded before allocation. This is API-event evidence,
// not all-process allocator accounting or a proof about machine instructions.
// IndexMut observes mutable access; the subsequent actual read verifies content.
#[allow(dead_code)]
mod audited {
    use std::cell::RefCell;
    use std::ops::{Index, IndexMut};
    #[derive(Default)]
    struct State {
        epoch:u64, active:bool, mode:u8, phase:u8, length:usize, index:usize,
        first:u8, last:u8, odd:bool, allocations:usize, releases:usize, live:usize,
        helper_calls:usize, wrote:bool, read_after_write:bool, caller_read_first:bool, caller_mut_after_first:bool, caller_read_final:bool, events:std::vec::Vec<String>,
        reads:std::vec::Vec<(u8,usize,u8)>, writes:std::vec::Vec<(u8,usize)>,
    }
    impl State {
        fn event(&mut self, value:String) {
            assert!(self.events.len()<4096,"E_V8_RESOURCE_EVENT_LIMIT");
            self.events.push(value);
        }
        fn owner(&self, epoch:u64) {
            assert!(self.active && self.epoch==epoch && self.live==1,"E_V8_RESOURCE_OWNER");
        }
    }
    std::thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
    pub struct Vec<T> { inner:std::vec::Vec<T>, epoch:u64 }
    pub fn begin(mode:u8,x:u32,y:u32) {
        STATE.with(|cell| {
            let mut s=cell.borrow_mut();
            assert!(!s.active && s.live==0,"E_V8_UNFINISHED_CALL");
            let epoch=s.epoch.checked_add(1).unwrap();
            let (length,index,first,last,odd)=match mode {
                1=>{let n=(3+x%11) as usize;(n,((x^y) as usize)%n,(x>>3).wrapping_add(y) as u8,(x>>3).wrapping_add(y) as u8,false)},
                2=>{let n=(5+x%7) as usize;let b=x.wrapping_add(y.wrapping_mul(3)) as u8;(n,((y>>2) as usize)%n,b,b^165,false)},
                3=>{let n=(8+x%9) as usize;(n,n-1,(x^y) as u8,(x^y) as u8,y&1!=0)},
                _=>panic!("E_V8_BAD_AUDIT_MODE")
            };
            *s=State{epoch,active:true,mode,phase:if mode==3 {1}else{0},
                     length,index,first,last,odd,..State::default()};
        });
    }
    pub fn make_vec(value:u8,length:usize)->Vec<u8> {
        let epoch=STATE.with(|cell| {
            let mut s=cell.borrow_mut();
            assert!(s.active && s.live==0 && s.allocations==0,"E_V8_ALLOCATION_COUNT");
            assert!(s.length==length && (1..=16).contains(&length) && value==0,"E_V8_ALLOCATION_CONTRACT");
            assert!(s.mode==3 || s.phase==0,"E_V8_HELPER_CANNOT_REPLACE_OWNER");
            s.allocations+=1;s.live+=1;
            s.event(format!("{{\"event\":\"allocate\",\"length\":{}}}",length));
            s.epoch
        });
        Vec{inner:std::vec![value;length],epoch}
    }
    impl<T> Vec<T> {
        pub fn len(&self)->usize {
            STATE.with(|cell|cell.borrow().owner(self.epoch));self.inner.len()
        }
        pub fn is_empty(&self)->bool {self.len()==0}
    }
    impl Index<usize> for Vec<u8> {
        type Output=u8;
        fn index(&self,index:usize)->&u8 {
            let value=self.inner[index];
            STATE.with(|cell| {
                let mut s=cell.borrow_mut();s.owner(self.epoch);let phase=s.phase;
                s.reads.push((phase,index,value));
                if phase==1 && index==s.index && value==s.first && s.wrote {s.read_after_write=true;}
                if phase==2 && index==s.index && value==s.first && s.wrote {s.caller_read_first=true;}
                if phase==2 && index==s.index && value==s.last && s.caller_mut_after_first {s.caller_read_final=true;}
                s.event(format!("{{\"event\":\"read\",\"phase\":{},\"index\":{},\"value\":{}}}",phase,index,value));
            });
            &self.inner[index]
        }
    }
    impl IndexMut<usize> for Vec<u8> {
        fn index_mut(&mut self,index:usize)->&mut u8 {
            assert!(index<self.inner.len(),"E_V8_INDEX_BOUND");
            STATE.with(|cell| {
                let mut s=cell.borrow_mut();s.owner(self.epoch);let phase=s.phase;
                s.writes.push((phase,index));
                if phase==1 && index==s.index {s.wrote=true;}
                if phase==2 && index==s.index && s.caller_read_first {s.caller_mut_after_first=true;}
                s.event(format!("{{\"event\":\"mutable_access\",\"phase\":{},\"index\":{}}}",phase,index));
            });
            &mut self.inner[index]
        }
    }
    pub fn drop(value:Vec<u8>) {std::mem::drop(value)}
    impl<T> Drop for Vec<T> {
        fn drop(&mut self) {
            STATE.with(|cell| {
                let mut s=cell.borrow_mut();s.owner(self.epoch);
                assert!(s.mode==3 || s.phase==2,"E_V8_RELEASE_BEFORE_RETURNED_BORROW_USE");
                s.live-=1;s.releases+=1;s.event("{\"event\":\"release\"}".into());
            });
        }
    }
    pub fn helper_begin() {
        STATE.with(|cell| {
            let mut s=cell.borrow_mut();assert!(s.phase==0 && s.live==1 && s.helper_calls==0);
            s.phase=1;s.helper_calls+=1;s.event("{\"event\":\"helper_begin\"}".into());
        });
    }
    pub fn helper_end() {
        STATE.with(|cell| {
            let mut s=cell.borrow_mut();assert!(s.phase==1 && s.live==1 && s.helper_calls==1);
            s.phase=2;s.event("{\"event\":\"helper_end\"}".into());
        });
    }
    pub fn finish(result:u32)->String {
        STATE.with(|cell| {
            let mut s=cell.borrow_mut();
            assert!(s.active && s.allocations==1 && s.releases==1 && s.live==0,"E_V8_RELEASE_CONTRACT");
            if s.odd {
                assert!(s.reads.is_empty() && s.writes.is_empty() && result==0,"E_V8_FAILURE_PATH_ACCESSED_BUFFER");
            } else {
                assert!(s.writes.contains(&(1,s.index)),"E_V8_NO_CANDIDATE_MUTABLE_ACCESS");
                if s.mode==1 || s.mode==3 {
                    assert!(s.read_after_write,"E_V8_NO_CANDIDATE_READBACK");
                }
                if s.mode==2 {
                    assert!(s.caller_read_first && s.caller_mut_after_first && s.caller_read_final,"E_V8_RETURNED_VIEW_USE");
                }
                assert!(result==256*s.length as u32+s.last as u32,"E_V8_RESOURCE_VALUE");
            }
            if s.mode!=3 {assert!(s.helper_calls==1 && s.phase==2,"E_V8_HELPER_SCOPE");}
            let out=format!("{{\"schema\":\"hepta.agent.v8.rust-vec-api-audit.v1\",\"epoch\":{},\"mode\":{},\"length\":{},\"index\":{},\"first_byte\":{},\"final_byte\":{},\"failure_path\":{},\"allocations\":{},\"releases\":{},\"live\":{},\"events\":[{}]}}",
                s.epoch,s.mode,s.length,s.index,s.first,s.last,s.odd,s.allocations,s.releases,s.live,s.events.join(","));
            s.active=false;out
        })
    }
}
