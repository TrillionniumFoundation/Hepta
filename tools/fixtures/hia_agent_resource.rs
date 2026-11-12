// Trusted, safe-Rust instrumentation for the finite buffer_lane Agent task.
// This observes the selected Vec API, not native allocation/store instructions.
// IndexMut observes mutable access; the following indexed read checks the
// actual stored byte. It does not distinguish an assignment of zero to an
// already-zero byte from merely taking its mutable reference.
//
// Embed this module, then compile candidate text in a child module containing:
//   use super::audited::{Vec, drop};
//   macro_rules! vec {
//       ($value:expr; $length:expr) => {
//           super::audited::make_vec($value, $length)
//       };
//   }
// The trusted driver calls audited::begin(x,y), candidate::invoke(x,y), and
// audited::finish(result). finish validates the complete invocation and returns
// one JSON ledger string for retained evidence. No candidate code is inserted
// in this module. Candidate source must retain the registered no-use/no-path
// profile so it cannot call this module's bookkeeping API directly.

mod audited {
    use std::cell::RefCell;
    use std::ops::{Index, IndexMut};

    const MAX_EVENTS: usize = 4096;

    #[derive(Default)]
    struct State {
        epoch: u64,
        active: bool,
        length: usize,
        index: usize,
        byte: u8,
        allocations: usize,
        releases: usize,
        explicit_releases: usize,
        live: usize,
        mutable_indices: usize,
        indexed_reads: usize,
        matched_mutable_index: bool,
        matched_reads: usize,
        events: std::vec::Vec<String>,
    }

    impl State {
        fn event(&mut self, text: String) {
            assert!(self.events.len() < MAX_EVENTS, "E_AGENT_BUFFER_EVENT_BUDGET");
            self.events.push(text);
        }

        fn owner(&self, epoch: u64) {
            assert!(self.active && self.epoch == epoch && self.live == 1,
                    "E_AGENT_BUFFER_OWNER_SCOPE");
        }
    }

    std::thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    pub struct Vec<T> {
        inner: std::vec::Vec<T>,
        epoch: u64,
        explicitly_released: bool,
    }

    pub fn begin(x: u32, y: u32) {
        STATE.with(|cell| {
            let mut previous = cell.borrow_mut();
            assert!(!previous.active && previous.live == 0, "E_AGENT_BUFFER_UNFINISHED_INVOCATION");
            let epoch = previous.epoch.checked_add(1).expect("E_AGENT_BUFFER_EPOCH_EXHAUSTED");
            let length = (x % 17 + 1) as usize;
            *previous = State {
                epoch,
                active: true,
                length,
                index: (y % (length as u32)) as usize,
                byte: x.wrapping_add(y) as u8,
                ..State::default()
            };
        });
    }

    pub fn make_vec(value: u8, length: usize) -> Vec<u8> {
        let epoch = STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            // Check BEFORE allocating: a wrong candidate cannot request an
            // unbounded buffer through this audited API.
            assert!(state.active && state.allocations == 0 && state.live == 0,
                    "E_AGENT_BUFFER_ALLOCATION_COUNT");
            assert!(length == state.length && (1..=17).contains(&length),
                    "E_AGENT_BUFFER_ALLOCATION_LENGTH");
            assert!(value == 0, "E_AGENT_BUFFER_NOT_ZEROED");
            state.allocations += 1;
            state.live += 1;
            state.event(format!("{{\"event\":\"allocate\",\"length\":{}}}", length));
            state.epoch
        });
        Vec { inner: std::vec![value; length], epoch, explicitly_released: false }
    }

    impl<T> Vec<T> {
        pub fn len(&self) -> usize {
            STATE.with(|cell| cell.borrow().owner(self.epoch));
            self.inner.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl Index<usize> for Vec<u8> {
        type Output = u8;

        fn index(&self, index: usize) -> &u8 {
            let observed = self.inner[index];
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                state.owner(self.epoch);
                state.indexed_reads += 1;
                if state.matched_mutable_index && index == state.index && observed == state.byte {
                    state.matched_reads += 1;
                }
                state.event(format!("{{\"event\":\"indexed_read\",\"index\":{},\"value\":{}}}",
                                    index, observed));
            });
            &self.inner[index]
        }
    }

    impl IndexMut<usize> for Vec<u8> {
        fn index_mut(&mut self, index: usize) -> &mut u8 {
            assert!(index < self.inner.len(), "E_AGENT_BUFFER_INDEX_BOUNDS");
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                state.owner(self.epoch);
                state.mutable_indices += 1;
                if index == state.index {
                    state.matched_mutable_index = true;
                }
                state.event(format!("{{\"event\":\"mutable_index\",\"index\":{}}}", index));
            });
            &mut self.inner[index]
        }
    }

    // Explicit release is separately observed from the language's automatic
    // Drop. A shadowed no-op drop or an implicit scope exit cannot satisfy it.
    pub fn drop(mut value: Vec<u8>) {
        value.explicitly_released = true;
        std::mem::drop(value);
    }

    impl<T> Drop for Vec<T> {
        fn drop(&mut self) {
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                state.owner(self.epoch);
                state.live -= 1;
                state.releases += 1;
                if self.explicitly_released {
                    state.explicit_releases += 1;
                }
                state.event(format!("{{\"event\":\"release\",\"explicit\":{}}}",
                                    self.explicitly_released));
            });
            // The real std::vec::Vec field is destroyed immediately after
            // this method returns, before the trusted driver calls finish.
        }
    }

    pub fn finish(result: u32) -> String {
        STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            assert!(state.active, "E_AGENT_BUFFER_NO_INVOCATION");
            assert!(state.allocations == 1 && state.releases == 1
                    && state.explicit_releases == 1 && state.live == 0,
                    "E_AGENT_BUFFER_UNBALANCED_OR_IMPLICIT_RELEASE");
            assert!(state.matched_mutable_index && state.matched_reads > 0,
                    "E_AGENT_BUFFER_NO_MATCHING_WRITE_READ_SEQUENCE");
            assert!(result == 256 * (state.length as u32) + (state.byte as u32),
                    "E_AGENT_BUFFER_RESULT");
            let ledger = format!(
                "{{\"schema\":\"hepta.agent.rust-vec-api-audit.v1\",\"epoch\":{},\"length\":{},\"index\":{},\"expected_byte\":{},\"allocations\":{},\"releases\":{},\"explicit_releases\":{},\"live\":{},\"mutable_indices\":{},\"indexed_reads\":{},\"matched_reads\":{},\"events\":[{}]}}",
                state.epoch, state.length, state.index, state.byte,
                state.allocations, state.releases, state.explicit_releases, state.live,
                state.mutable_indices, state.indexed_reads, state.matched_reads, state.events.join(","));
            state.active = false;
            ledger
        })
    }
}
