//! Native exact DP, a finite beam, and a future-aware static-set control.
//! All use the same transition arithmetic and source-bound supplied model.
use crate::model::{Model, sum};
use serde::Serialize;

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct Action {
    pub batch: usize,
    pub mode: &'static str,
    pub ready_before: u16,
    pub ready_after: u16,
    pub invalidated: u16,
    pub acquired: u16,
    pub retired: u16,
    pub dispatch: &'static str,
    pub execution_ns: u64,
    pub prepare_ns: u64,
    pub retire_ns: u64,
    pub future_decision_ns: u64,
    pub gate_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Serialize)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub current_committed_ns: u64,
    pub close_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    pub states: u64,
    pub transitions: u64,
    pub beam_pruned: u64,
    pub materialized_actions: u64,
}

pub struct Planner<'a> {
    m: &'a Model,
    masks: Vec<u16>,
    prep: Vec<u64>,
    retire: Vec<u64>,
    live: Vec<Vec<u16>>,
    execution: Vec<Vec<u64>>,
    memo: Vec<Vec<Option<(u64, u16)>>>,
    pub stats: Stats,
}

impl<'a> Planner<'a> {
    pub fn new(m: &'a Model) -> Result<Self, String> {
        let count = 1 << m.artifacts.len();
        let mut prep = vec![0; count];
        let mut retire = vec![0; count];
        for mask in 1_usize..count {
            let i = mask.trailing_zeros() as usize;
            let previous = mask & (mask - 1);
            prep[mask] = sum([prep[previous], m.artifacts[i].prepare_ns])?;
            retire[mask] = sum([retire[previous], m.artifacts[i].retire_ns])?;
        }
        let live = (0..m.targets.len()).map(|b| (0..count).map(|mask| m.live(b, mask as u16)).collect()).collect();
        let execution = (0..m.targets.len()).map(|b| (0..count).map(|mask| {
            if mask & (1 << m.targets[b]) != 0 { m.direct_ns[b].min(m.packed_ns[b]) } else { m.direct_ns[b] }
        }).collect()).collect();
        Ok(Self { m, masks: m.masks()?, prep, retire, live, execution,
            memo: vec![vec![None; count]; m.targets.len()], stats: Stats::default() })
    }

    fn numeric(&self, batch: usize, ready: u16, target: u16) -> Result<u64, String> {
        let live = self.live[batch][ready as usize];
        let acquired = target & !live;
        let retired = ready & (!target | !live);
        let execution = self.execution[batch][target as usize];
        let future = if batch > 0 && target != live { self.m.decision.call(true)? } else { 0 };
        sum([execution, self.prep[acquired as usize], self.retire[retired as usize],
             self.m.decision.gate_ns, future])
    }

    fn action(&mut self, batch: usize, ready: u16, target: u16) -> Result<Action, String> {
        let live = self.live[batch][ready as usize];
        let acquired = target & !live;
        let retired = ready & (!target | !live);
        let packed = target & (1 << self.m.targets[batch]) != 0
            && self.m.packed_ns[batch] < self.m.direct_ns[batch];
        self.stats.materialized_actions += 1;
        Ok(Action { batch, mode: if target == live { "skip" } else { "invoke" },
            ready_before: ready, ready_after: target, invalidated: ready & !live,
            acquired, retired, dispatch: if packed { "packed" } else { "direct" },
            execution_ns: if packed { self.m.packed_ns[batch] } else { self.m.direct_ns[batch] },
            prepare_ns: self.prep[acquired as usize], retire_ns: self.retire[retired as usize],
            future_decision_ns: if batch > 0 && target != live { self.m.decision.call(true)? } else { 0 },
            gate_ns: self.m.decision.gate_ns, total_ns: self.numeric(batch, ready, target)? })
    }

    fn order(&self, batch: usize, ready: u16) -> Vec<u16> {
        let live = self.live[batch][ready as usize];
        let mut ordered = vec![live];
        ordered.extend(self.masks.iter().filter(|v| **v != live));
        ordered
    }

    fn tail(&mut self, batch: usize, ready: u16) -> Result<u64, String> {
        if batch == self.m.targets.len() { return Ok(self.m.decision.close_ns); }
        if let Some((cost, _)) = self.memo[batch][ready as usize] { return Ok(cost); }
        self.stats.states += 1;
        let mut best = (u64::MAX, 0);
        // Iterate the immutable mask bank without allocating a per-state list.
        let live = self.live[batch][ready as usize];
        for index in 0..=self.masks.len() {
            let target = if index == 0 { live } else { self.masks[index - 1] };
            if index > 0 && target == live { continue; }
            self.stats.transitions += 1;
            let cost = sum([self.numeric(batch, ready, target)?, self.tail(batch + 1, target)?])?;
            if cost < best.0 { best = (cost, target); }
        }
        self.memo[batch][ready as usize] = Some(best);
        Ok(best.0)
    }

    fn plan(&mut self, path: &[u16]) -> Result<Plan, String> {
        let mut actions = Vec::new();
        let mut ready = self.m.ready_mask;
        for (batch, target) in path.iter().enumerate() {
            actions.push(self.action(batch, ready, *target)?);
            ready = *target;
        }
        let current = self.m.decision.call(self.m.session_ready)?;
        let close = self.m.decision.close_ns;
        let total = sum(actions.iter().map(|a| a.total_ns).chain([current, close]))?;
        Ok(Plan { actions, current_committed_ns: current, close_ns: close, total_ns: total })
    }

    pub fn exact(&mut self) -> Result<Vec<Plan>, String> {
        self.tail(0, self.m.ready_mask)?;
        let mut ready = self.m.ready_mask;
        let mut path = Vec::new();
        for batch in 0..self.m.targets.len() {
            let target = self.memo[batch][ready as usize].ok_or("missing exact continuation")?.1;
            path.push(target);
            ready = target;
        }
        let plan = self.plan(&path)?;
        Ok(if plan.total_ns <= self.m.budget_ns { vec![plan] } else { Vec::new() })
    }

    pub fn light(&mut self) -> Result<Vec<Plan>, String> {
        // Exhaust all legal first resident sets, then retain each until an
        // announced invalidation. This is future-aware, but never performs DP.
        let mut best: Option<(u64, Vec<u16>)> = None;
        for first in self.order(0, self.m.ready_mask) {
            let mut path = vec![first];
            let mut ready = first;
            let mut total = self.numeric(0, self.m.ready_mask, first)?;
            for batch in 1..self.m.targets.len() {
                let target = self.m.live(batch, ready);
                total = sum([total, self.numeric(batch, ready, target)?])?;
                path.push(target);
                ready = target;
            }
            self.stats.transitions += path.len() as u64;
            if best.as_ref().is_none_or(|p| total < p.0) { best = Some((total, path)); }
        }
        let plan = self.plan(&best.ok_or("no legal resident set")?.1)?;
        Ok(if plan.total_ns <= self.m.budget_ns { vec![plan] } else { Vec::new() })
    }

    pub fn beam(&mut self, width: usize) -> Result<Vec<Plan>, String> {
        // This compaction is approximate: keep the cheapest path per resident
        // state, then at most width states. Exact DP remains an independent arm.
        let mut paths = vec![(0_u64, self.m.ready_mask, Vec::<u16>::new())];
        for batch in 0..self.m.targets.len() {
            let mut best: Vec<Option<(u64, Vec<u16>)>> = vec![None; 1 << self.m.artifacts.len()];
            for (cost, ready, prefix) in &paths {
                self.stats.states += 1;
                for target in self.order(batch, *ready) {
                    self.stats.transitions += 1;
                    let next = sum([*cost, self.numeric(batch, *ready, target)?])?;
                    let slot = &mut best[target as usize];
                    if slot.as_ref().is_none_or(|p| next < p.0) {
                        let mut path = prefix.clone();
                        path.push(target);
                        *slot = Some((next, path));
                    }
                }
            }
            paths = best.into_iter().enumerate().filter_map(|(mask, row)| {
                row.map(|(cost, path)| (cost, mask as u16, path))
            }).collect();
            // A free-preparation execution lower bound is identical for all
            // states here; ordering by prefix cost is exactly that beam bound.
            paths.sort_by_key(|p| (p.0, p.1));
            self.stats.beam_pruned += paths.len().saturating_sub(width) as u64;
            paths.truncate(width);
        }
        let mut result = Vec::new();
        for (_, _, path) in paths {
            let plan = self.plan(&path)?;
            if plan.total_ns <= self.m.budget_ns { result.push(plan); }
        }
        Ok(result)
    }
}
