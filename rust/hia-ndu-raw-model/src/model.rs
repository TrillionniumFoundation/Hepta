//! Exact, bounded decoding of the existing full-cost-v2 model.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_NS: u64 = 1_000_000_000_000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub source_sha256: String,
    pub verification_sha256: String,
    pub latency_ns: Vec<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub id: String,
    pub source_sha256: String,
    pub verification_sha256: String,
    pub support_sha256: String,
    pub status: String,
    pub valid: Vec<bool>,
    pub prepare_ns: u64,
    pub proof_ns: u64,
    pub retire_ns: u64,
    pub holding_ns: u64,
    pub resident_bytes: u64,
    pub latency_ns: Vec<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub gate_ns: u64,
    pub search_ns: u64,
    pub native_ns: u64,
    pub transport_ns: u64,
    pub validation_ns: u64,
    pub startup_ns: u64,
    pub close_ns: u64,
}

impl Decision {
    pub fn values(&self) -> [u64; 7] {
        [
            self.gate_ns,
            self.search_ns,
            self.native_ns,
            self.transport_ns,
            self.validation_ns,
            self.startup_ns,
            self.close_ns,
        ]
    }

    pub fn current_call(&self, session_ready: bool) -> Result<u64, String> {
        sum([
            self.search_ns,
            self.native_ns,
            self.transport_ns,
            self.validation_ns,
            if session_ready { 0 } else { self.startup_ns },
        ])
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub objective_digest: String,
    pub generation: u64,
    pub baseline: Baseline,
    pub variants: Vec<Variant>,
    pub ready: Vec<String>,
    pub memory_budget_bytes: u64,
    pub budget_ns: u64,
    pub sunk_cost_ns: u64,
    pub completion_value_ns: u64,
    pub decision: Decision,
    pub session_ready: bool,
    pub observation_sha256: String,
}

pub fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64, String> {
    values.into_iter().try_fold(0_u64, |a, b| {
        a.checked_add(b).ok_or_else(|| "cost overflow".into())
    })
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

impl Model {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "hepta.hia.ndu.full-cost.v2"
            || !(1..=u32::MAX as u64).contains(&self.generation)
            || !hash(&self.objective_digest)
            || !hash(&self.observation_sha256)
            || !hash(&self.baseline.source_sha256)
            || !hash(&self.baseline.verification_sha256)
            || !(1..=4).contains(&self.baseline.latency_ns.len())
            || !(1..=2).contains(&self.variants.len())
            || self.ready.len() > 2
        {
            return Err("invalid full-cost-v2 identity, horizon or variant bound".into());
        }
        let mut numbers = vec![
            self.memory_budget_bytes,
            self.budget_ns,
            self.sunk_cost_ns,
            self.completion_value_ns,
        ];
        numbers.extend(self.decision.values());
        numbers.extend(&self.baseline.latency_ns);
        let mut names = BTreeSet::new();
        for v in &self.variants {
            if v.id.is_empty()
                || v.id.len() > 32
                || v.id == "baseline"
                || !v
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
                || !names.insert(v.id.clone())
                || !hash(&v.source_sha256)
                || !hash(&v.verification_sha256)
                || !hash(&v.support_sha256)
                || !["verified", "unknown", "rejected", "timeout"].contains(&v.status.as_str())
                || v.valid.len() != self.baseline.latency_ns.len()
                || v.latency_ns.len() != v.valid.len()
            {
                return Err("invalid artifact identity, status or horizon".into());
            }
            numbers.extend([
                v.prepare_ns,
                v.proof_ns,
                v.retire_ns,
                v.holding_ns,
                v.resident_bytes,
            ]);
            numbers.extend(&v.latency_ns);
        }
        if numbers.into_iter().any(|n| n > MAX_NS) {
            return Err("integer exceeds full-cost-v2 bound".into());
        }
        let ready: BTreeSet<_> = self.ready.iter().collect();
        if ready.len() != self.ready.len() || self.ready.iter().any(|n| !names.contains(n)) {
            return Err("invalid initial residency".into());
        }
        if sum(self
            .variants
            .iter()
            .filter(|v| ready.contains(&v.id))
            .map(|v| v.resident_bytes))?
            > self.memory_budget_bytes
        {
            return Err("initial residency exceeds memory quota".into());
        }
        let maximum = self
            .baseline
            .latency_ns
            .iter()
            .chain(self.variants.iter().flat_map(|v| &v.latency_ns))
            .copied()
            .max()
            .ok_or("empty horizon")?;
        let costs = self
            .variants
            .iter()
            .flat_map(|v| [v.prepare_ns, v.proof_ns, v.retire_ns, v.holding_ns]);
        let bound = sum([maximum, sum(self.decision.values())?, sum(costs)?])?
            .checked_mul(self.baseline.latency_ns.len() as u64)
            .ok_or("path bound overflow")?;
        if bound > MAX_NS {
            return Err("whole-path cost bound".into());
        }
        Ok(())
    }
}
