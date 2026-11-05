//! Bounded advisory model for an explicitly announced queue of cache work.
//! Time fields are forecasts. They never certify elapsed wall time or code.
use serde::{Deserialize, Serialize};

pub const MAX_NS: u64 = 1_000_000_000_000;
pub const MAX_ARTIFACTS: usize = 8;
pub const MAX_HORIZON: usize = 12;
pub const SCHEMA: &str = "hepta.hia.ndu.dynamic-cache.model.v1";

pub fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64, String> {
    values.into_iter().try_fold(0_u64, |a, b| {
        a.checked_add(b).filter(|v| *v <= MAX_NS).ok_or("bounded sum overflow".into())
    })
}

pub fn hash_ok(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: String,
    pub resident_bytes: u64,
    pub prepare_ns: u64,
    pub retire_ns: u64,
    pub epochs: Vec<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub gate_ns: u64,
    pub solve_ns: u64,
    pub transport_validation_ns: u64,
    pub startup_ns: u64,
    pub close_ns: u64,
}

impl Decision {
    pub fn call(&self, ready: bool) -> Result<u64, String> {
        sum([self.solve_ns, self.transport_validation_ns, if ready { 0 } else { self.startup_ns }])
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub generation: u32,
    pub objective_digest: String,
    pub observation_digest: String,
    pub workload_sha256: String,
    pub artifacts: Vec<Artifact>,
    pub targets: Vec<usize>,
    pub direct_ns: Vec<u64>,
    pub packed_ns: Vec<u64>,
    pub ready_mask: u16,
    pub ready_epochs: Vec<u32>,
    pub memory_quota_bytes: u64,
    pub budget_ns: u64,
    pub sunk_cost_ns: u64,
    pub completion_value_ns: u64,
    pub decision: Decision,
    pub session_ready: bool,
}

impl Model {
    pub fn validate(&self) -> Result<(), String> {
        let n = self.artifacts.len();
        let h = self.targets.len();
        if self.schema != SCHEMA || self.generation == 0 || !(1..=MAX_ARTIFACTS).contains(&n)
            || !(1..=MAX_HORIZON).contains(&h) {
            return Err("model schema or finite bound".into());
        }
        if [&self.objective_digest, &self.observation_digest, &self.workload_sha256]
            .into_iter().any(|v| !hash_ok(v)) {
            return Err("source or observation identity".into());
        }
        if self.direct_ns.len() != h || self.packed_ns.len() != h || self.ready_epochs.len() != n
            || self.targets.iter().any(|x| *x >= n) || self.ready_mask >= 1 << n {
            return Err("array shape or resident mask".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for (i, a) in self.artifacts.iter().enumerate() {
            if a.id.is_empty() || a.id.len() > 32
                || !a.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !names.insert(&a.id) || a.epochs.len() != h || a.epochs.contains(&0)
                || a.epochs.windows(2).any(|w| w[0] > w[1])
                || a.resident_bytes == 0 || a.resident_bytes > 128 * 1024 * 1024
                || a.prepare_ns > MAX_NS || a.retire_ns > MAX_NS
                || self.ready_epochs[i] > a.epochs[0]
                || ((self.ready_mask & (1 << i) != 0) != (self.ready_epochs[i] != 0)) {
                return Err("artifact identity, cost, epoch or residency".into());
            }
        }
        let d = &self.decision;
        if [self.budget_ns, self.sunk_cost_ns, self.completion_value_ns, d.gate_ns,
            d.solve_ns, d.transport_validation_ns, d.startup_ns, d.close_ns]
            .into_iter().chain(self.direct_ns.iter().copied()).chain(self.packed_ns.iter().copied())
            .any(|x| x > MAX_NS)
            || self.memory_quota_bytes > 128 * 1024 * 1024
            || self.bytes(self.ready_mask)? > self.memory_quota_bytes {
            return Err("cost, quota or initial residency bound".into());
        }
        let envelope = sum([
            *self.direct_ns.iter().chain(&self.packed_ns).max().ok_or("empty horizon")?,
            sum(self.artifacts.iter().flat_map(|a| [a.prepare_ns, a.retire_ns]))?,
            sum([d.gate_ns, d.solve_ns, d.transport_validation_ns, d.startup_ns, d.close_ns])?,
        ])?;
        envelope.checked_mul(h as u64 + 1).filter(|v| *v <= MAX_NS)
            .ok_or("whole horizon cost envelope")?;
        Ok(())
    }

    pub fn bytes(&self, mask: u16) -> Result<u64, String> {
        sum(self.artifacts.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, a)| a.resident_bytes))
    }

    pub fn live(&self, batch: usize, ready: u16) -> u16 {
        self.artifacts.iter().enumerate().fold(ready, |mask, (i, a)| {
            let previous = if batch == 0 { self.ready_epochs[i] } else { a.epochs[batch - 1] };
            if previous != a.epochs[batch] { mask & !(1 << i) } else { mask }
        })
    }

    pub fn masks(&self) -> Result<Vec<u16>, String> {
        let mut masks = Vec::new();
        for m in 0..(1 << self.artifacts.len()) {
            if self.bytes(m)? <= self.memory_quota_bytes { masks.push(m); }
        }
        masks.sort_by_key(|m| (m.count_ones(), *m));
        Ok(masks)
    }
}
