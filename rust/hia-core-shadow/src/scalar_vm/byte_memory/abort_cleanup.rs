//! Explicit, invocation-scoped byte-owner discharge after a language stop.
//!
//! This is not Rust Drop, stack unwinding, a user destructor, or a promise about
//! host panic/OOM/process death. The separately admitted profile reserves this
//! journal before executing any language instruction. Existing profiles never
//! call this module. Its whole invocation has scalar entry/results and no
//! external resource, chain, foreign, or callback capability.
use serde_json::{json, Value};
use super::{ByteMemory, Root};
use super::super::{RuntimeValue, MAX_ABORT_CLEANUP_ACTIONS};
use crate::{failure, R};

enum Event {
    Loan { id: u64, root: u64, parent: u64, parent_is_loan: bool,
           mutable: bool, formal: bool },
    Owner { id: u64, bytes: u64 },
}

pub(in crate::scalar_vm) struct AbortReservation {
    bound: u64,
    events: Vec<Event>,
}

impl AbortReservation {
    pub(in crate::scalar_vm) fn reserve(bound: u64) -> R<Self> {
        if bound > MAX_ABORT_CLEANUP_ACTIONS {
            return failure("E_HIA_CLEANUP_POLICY", "cleanup reservation exceeds the fixed action limit");
        }
        let mut events = Vec::new();
        // No journal capacity growth is permitted during the release phase.
        events.try_reserve_exact(bound as usize).map_err(|_| crate::VerifyError {
            code: "E_HIA_CLEANUP_RESERVATION", detail: "cannot reserve cleanup journal before execution".into(),
        })?;
        Ok(Self { bound, events })
    }
}

impl ByteMemory {
    fn audit_abort_inventory(&self, bound: u64, inspected: &mut u64) -> Result<(), &'static str> {
        if !self.chains.is_empty() || !self.chain_nodes.is_empty()
            || self.chains_created != 0 || self.chains_consumed != 0
            || self.chain_nodes_created != 0 || self.chain_nodes_dropped != 0 {
            return Err("unsupported_chain_inventory");
        }
        let actions = (self.owners.len() as u64).checked_add(self.loans.len() as u64)
            .ok_or("cleanup_count_overflow")?;
        if actions > bound { return Err("cleanup_reservation_insufficient"); }
        if self.allocations > self.attempts
            || self.owners_created.checked_sub(self.owners_dropped) != Some(self.owners.len() as u64) {
            return Err("cleanup_ledger_disagrees_with_inventory");
        }
        let mut bytes = 0_u64;
        let mut allocated_owners = 0_u64;
        for (id, payload) in &self.owners {
            *inspected += 1;
            if *id == 0 || *id > self.owners_created { return Err("invalid_owner_identity"); }
            bytes = bytes.checked_add(payload.len() as u64).ok_or("cleanup_payload_overflow")?;
            allocated_owners += u64::from(!payload.is_empty());
        }
        if bytes != self.live_bytes || bytes > self.peak_bytes || self.peak_bytes > self.max_heap {
            return Err("cleanup_payload_disagrees_with_inventory");
        }
        let mut local_loans = 0_u64;
        for (id, loan) in &self.loans {
            *inspected += 1;
            local_loans += u64::from(!loan.external);
            let Root::Owner(root) = loan.root else { return Err("unsupported_loan_root"); };
            if *id == 0 || *id > self.next_loan || root != loan.storage
                || !self.owners.contains_key(&root) {
                return Err("invalid_loan_root");
            }
            match &loan.parent {
                RuntimeValue::Owner(owner) if *owner == root && !loan.external => {},
                RuntimeValue::Loan(parent) if *parent < *id => {
                    let previous = self.loans.get(parent).ok_or("missing_loan_parent")?;
                    if previous.root != loan.root || previous.storage != loan.storage
                        || loan.mutable && !previous.mutable {
                        return Err("inconsistent_loan_parent");
                    }
                },
                _ => return Err("invalid_or_cyclic_loan_parent"),
            }
        }
        if self.allocations.checked_sub(self.frees) != Some(allocated_owners)
            || self.loans_started.checked_sub(self.loans_ended) != Some(local_loans) {
            return Err("cleanup_ledger_disagrees_with_inventory");
        }
        // Count actual audited-record visits, including a rejected prefix.
        // Report construction and tree-map lookups are not execution ticks or
        // a CPU/RSS theorem. Older parent IDs establish the release order.
        Ok(())
    }

    pub(in crate::scalar_vm) fn abort_cleanup(&mut self, mut reserve: AbortReservation,
                                               stopped: bool) -> Value {
        let before = self.report(true);
        let actual_records = self.owners.len() as u64 + self.loans.len() as u64;
        let formal_before = self.loans.values().filter(|loan| loan.external).count() as u64;
        let mut error = None;
        let mut inspected = 0;
        if !stopped {
            if !self.is_clean() { error = Some("normal_return_was_not_clean"); }
        } else {
            match self.audit_abort_inventory(reserve.bound, &mut inspected) {
                Err(reason) => error = Some(reason),
                Ok(()) => {
                    // All surviving children have larger IDs. Removing in
                    // descending order discharges local and call-formal views
                    // before their parent, including aliased readonly formals.
                    while let Some((id, loan)) = self.loans.pop_last() {
                        if reserve.events.len() as u64 >= reserve.bound {
                            // Preserve this record if an internal bug violates
                            // the already audited reservation. Never call it clean.
                            self.loans.insert(id, loan);
                            error = Some("cleanup_action_limit"); break;
                        }
                        let Root::Owner(root) = loan.root else {
                            self.loans.insert(id, loan);
                            error = Some("cleanup_root_changed"); break;
                        };
                        let (parent, parent_is_loan) = match loan.parent {
                            RuntimeValue::Owner(id) => (id, false),
                            RuntimeValue::Loan(id) => (id, true),
                            _ => { self.loans.insert(id, loan); error = Some("cleanup_parent_changed"); break; },
                        };
                        if !loan.external { self.loans_ended += 1; }
                        reserve.events.push(Event::Loan { id, root, parent, parent_is_loan,
                            mutable: loan.mutable, formal: loan.external });
                    }
                    if error.is_none() {
                        while let Some((&id, bytes)) = self.owners.last_key_value() {
                            let size = bytes.len() as u64;
                            if reserve.events.len() as u64 >= reserve.bound {
                                error = Some("cleanup_action_limit"); break;
                            }
                            // Reuse the existing owner release and counters;
                            // all byte views have already been explicitly ended.
                            if self.drop_owner(id).is_err() {
                                error = Some("cleanup_owner_release_failed"); break;
                            }
                            reserve.events.push(Event::Owner { id, bytes: size });
                        }
                    }
                    if error.is_none() && !self.is_clean() {
                        error = Some("cleanup_final_ledger_not_clean");
                    }
                },
            }
        }
        let status = if error.is_some() { "failed" } else if stopped { "completed" } else { "not_needed" };
        let events: Vec<Value> = reserve.events.iter().map(|event| match event {
            Event::Loan { id, root, parent, parent_is_loan, mutable, formal } => json!({
                "op":"end_loan", "loan":id, "root_owner":root,
                "parent_kind":if *parent_is_loan { "loan" } else { "owner" },
                "parent":parent, "mutable":mutable, "call_formal":formal,
            }),
            Event::Owner { id, bytes } => json!({"op":"drop_owner","owner":id,"bytes":bytes}),
        }).collect();
        json!({
            "schema":"hepta.hia.scoped-abort-cleanup.v1", "status":status,
            "scope":"entire_private_scalar_invocation", "error":error,
            "reserved_actions":reserve.bound, "inventory_records":actual_records,
            "inventory_records_checked":inspected,
            "call_formal_loans_before":formal_before,
            "call_formal_loans_after":self.loans.values().filter(|loan|loan.external).count(),
            "actions":events.len(), "events":events,
            "before":before, "after":self.report(true),
            "claims":{
                "explicit_machine_resource_discharge":error.is_none(),
                "cleanup_uses_reserved_actions_not_execution_ticks":true,
                "journal_reserved_before_language_execution":true,
                "user_destructors_or_callbacks_executed":false,
                "host_panic_oom_or_termination_cleanup_guaranteed":false,
                "process_rss_or_cpu_bound_proved":false,
                "general_unwind_or_native_cleanup_proved":false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocate(memory: &mut ByteMemory, size: u64) -> RuntimeValue {
        memory.operation("buffer.new",&[RuntimeValue::Scalar(json!(size))]).unwrap().remove(0)
    }

    #[test]
    fn alias_formals_children_and_empty_owners_discharge_in_actual_parent_order() {
        let mut memory = ByteMemory::new(16, None);
        let owner = allocate(&mut memory,3);
        allocate(&mut memory,0); // a real logical owner, not an allocation
        let parent = memory.operation("borrow.mut", &[owner]).unwrap().remove(0);
        let params = json!([{"name":"a","type":"readbuf"},{"name":"b","type":"readbuf"}]);
        let (formals, _) = memory.enter_call(&params,vec![parent.clone(),parent]).unwrap();
        memory.operation("borrow.read", &[formals[0].clone()]).unwrap();
        let before = memory.report(true);
        let result = memory.abort_cleanup(AbortReservation::reserve(6).unwrap(),true);
        assert_eq!(result["before"],before);
        assert_eq!(result["status"],"completed");
        assert_eq!(result["call_formal_loans_before"],2);
        assert_eq!(result["actions"],6);
        assert_eq!(result["events"].as_array().unwrap().iter().take(4)
            .map(|e|e["loan"].as_u64().unwrap()).collect::<Vec<_>>(),vec![4,3,2,1]);
        assert_eq!(result["events"][4],json!({"op":"drop_owner","owner":2,"bytes":0}));
        assert_eq!(result["after"]["loans_ended"],2); // formals are not borrow events
        assert_eq!(result["after"]["frees"],1);
        assert_eq!(result["after"]["owners_dropped"],2);
        assert!(memory.is_clean());
    }

    #[test]
    fn insufficient_reservation_is_not_cleanup_and_preserves_the_entire_prefix() {
        let mut memory = ByteMemory::new(8,None);
        allocate(&mut memory,3);
        let before = memory.report(true);
        let result = memory.abort_cleanup(AbortReservation::reserve(0).unwrap(),true);
        assert_eq!(result["status"],"failed");
        assert_eq!(result["error"],"cleanup_reservation_insufficient");
        assert_eq!(result["before"],before);
        assert_eq!(result["after"],before);
        assert_eq!(result["actions"],0);
        assert_eq!(result["claims"]["explicit_machine_resource_discharge"],false);
        assert!(!memory.is_clean());
        assert!(AbortReservation::reserve(MAX_ABORT_CLEANUP_ACTIONS+1).is_err());
    }

    #[test]
    fn malformed_root_parent_and_formal_counter_never_become_a_cleanup_success() {
        for mutation in 0..3 {
            let mut memory = ByteMemory::new(8,None);
            let owner = allocate(&mut memory,3);
            let loan = memory.operation("borrow.mut",&[owner]).unwrap().remove(0);
            let RuntimeValue::Loan(id) = loan else { panic!("expected actual loan") };
            match mutation {
                0 => memory.loans.get_mut(&id).unwrap().parent = RuntimeValue::Loan(id),
                1 => memory.loans.get_mut(&id).unwrap().root = Root::Owner(999),
                _ => memory.loans.get_mut(&id).unwrap().external = true,
            }
            let before = memory.report(true);
            let result = memory.abort_cleanup(AbortReservation::reserve(8).unwrap(),true);
            assert_eq!(result["status"],"failed");
            assert_eq!(result["before"],before);
            assert_eq!(result["after"],before);
            assert_eq!(result["actions"],0);
            assert!(result["inventory_records_checked"].as_u64().unwrap()>0);
            assert_eq!(result["call_formal_loans_after"],result["call_formal_loans_before"]);
            assert_eq!(result["claims"]["explicit_machine_resource_discharge"],false);
        }
    }

    #[test]
    fn returned_formal_materialization_is_counted_as_one_local_borrow() {
        let mut memory = ByteMemory::new(8,None);
        let owner = allocate(&mut memory,2);
        let parent = memory.operation("borrow.mut",&[owner]).unwrap().remove(0);
        let (formal, scope) = memory.enter_call(&json!([{"name":"p","type":"mutbuf"}]),vec![parent]).unwrap();
        memory.return_loan(&formal[0],&formal[0],true).unwrap();
        memory.leave_call(&scope).unwrap();
        let result = memory.abort_cleanup(AbortReservation::reserve(3).unwrap(),true);
        assert_eq!(result["status"],"completed");
        assert_eq!(result["call_formal_loans_before"],0);
        assert_eq!(result["before"]["loans_started"],2);
        assert_eq!(result["after"]["loans_ended"],2);
        assert!(memory.is_clean());
    }

    #[test]
    fn normal_return_is_not_repaired_and_chain_inventory_stays_outside_profile() {
        let mut dirty = ByteMemory::new(8,None);
        allocate(&mut dirty,1);
        let result = dirty.abort_cleanup(AbortReservation::reserve(8).unwrap(),false);
        assert_eq!(result["status"],"failed");
        assert_eq!(result["error"],"normal_return_was_not_clean");
        assert_eq!(result["before"],result["after"]);
        let mut chain = ByteMemory::new(8,None);
        chain.operation("chain.empty",&[]).unwrap();
        let result = chain.abort_cleanup(AbortReservation::reserve(8).unwrap(),true);
        assert_eq!(result["status"],"failed");
        assert_eq!(result["error"],"unsupported_chain_inventory");
        assert_eq!(result["before"],result["after"]);
    }
}
