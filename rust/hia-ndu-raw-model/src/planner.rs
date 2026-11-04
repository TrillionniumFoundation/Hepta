//! The existing bounded recurrence, including complete first-action witnesses.
//! No Python, model call, external process or candidate bank is consumed here.
use crate::model::{Model, Variant, sum};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
pub struct Action {
    pub mode: &'static str,
    pub batch: usize,
    pub ready_before: Vec<String>,
    pub ready_after: Vec<String>,
    pub acquired: Vec<String>,
    pub retired: Vec<String>,
    pub invalidated: Vec<String>,
    pub dispatch: String,
    pub costs: BTreeMap<&'static str, u64>,
    pub total_ns: u64,
    pub session_after: bool,
}

#[derive(Clone, Serialize)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub close_ns: u64,
    pub total_ns: u64,
    pub current_committed_ns: u64,
}

#[derive(Clone)]
struct Tail {
    total: u64,
    actions: Vec<Action>,
    close: u64,
}

pub struct Planner<'a> {
    model: &'a Model,
    variants: Vec<&'a Variant>,
    sets: Vec<u8>,
    cache: BTreeMap<(usize, u8, bool), Tail>,
    pub states: usize,
    pub actions: usize,
}

impl<'a> Planner<'a> {
    pub fn new(model: &'a Model) -> Result<Self, String> {
        model.validate()?;
        let mut variants: Vec<_> = model.variants.iter().collect();
        variants.sort_by(|a, b| a.id.cmp(&b.id));
        let mut sets = Vec::new();
        // Same combination order: empty, sorted singletons, sorted pairs.
        for count in 0..=variants.len() {
            for mask in 0..(1_u8 << variants.len()) {
                if mask.count_ones() as usize == count
                    && sum(variants
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, v)| v.resident_bytes))?
                        <= model.memory_budget_bytes
                {
                    sets.push(mask);
                }
            }
        }
        Ok(Self {
            model,
            variants,
            sets,
            cache: BTreeMap::new(),
            states: 0,
            actions: 0,
        })
    }

    fn names(&self, mask: u8) -> Vec<String> {
        self.variants
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, v)| v.id.clone())
            .collect()
    }

    fn live(&self, mask: u8, batch: usize) -> u8 {
        self.variants.iter().enumerate().fold(0, |out, (i, v)| {
            out | if mask & (1 << i) != 0 && v.status == "verified" && v.valid[batch] {
                1 << i
            } else {
                0
            }
        })
    }

    fn choices(&self) -> Vec<Option<u8>> {
        std::iter::once(None)
            .chain(self.sets.iter().copied().map(Some))
            .collect()
    }

    fn action(
        &self,
        batch: usize,
        ready: u8,
        session: bool,
        target: Option<u8>,
    ) -> Result<Option<Action>, String> {
        let live = self.live(ready, batch);
        let destination = target.unwrap_or(live);
        if self.live(destination, batch) != destination {
            return Ok(None);
        }
        let removed = ready & !destination;
        let acquired = destination & !live;
        let cost = |mask, f: fn(&Variant) -> u64| {
            sum(self
                .variants
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, v)| f(v)))
        };
        let d = &self.model.decision;
        let invoke = target.is_some();
        let mut costs = BTreeMap::from([
            ("gate_ns", d.gate_ns),
            ("search_ns", if invoke { d.search_ns } else { 0 }),
            ("native_ns", if invoke { d.native_ns } else { 0 }),
            ("transport_ns", if invoke { d.transport_ns } else { 0 }),
            ("validation_ns", if invoke { d.validation_ns } else { 0 }),
            (
                "startup_ns",
                if invoke && !session { d.startup_ns } else { 0 },
            ),
            ("retire_ns", cost(removed, |v| v.retire_ns)?),
            ("prepare_ns", cost(acquired, |v| v.prepare_ns)?),
            ("proof_ns", cost(acquired, |v| v.proof_ns)?),
            ("holding_ns", cost(destination, |v| v.holding_ns)?),
        ]);
        let mut choices = vec![(
            self.model.baseline.latency_ns[batch],
            "baseline".to_string(),
        )];
        choices.extend(
            self.variants
                .iter()
                .enumerate()
                .filter(|(i, _)| destination & (1 << i) != 0)
                .map(|(_, v)| (v.latency_ns[batch], v.id.clone())),
        );
        let (execution, dispatch) = choices.into_iter().min().ok_or("no dispatch")?;
        costs.insert("execution_ns", execution);
        let total_ns = sum(costs.values().copied())?;
        Ok(Some(Action {
            mode: if invoke { "invoke" } else { "skip" },
            batch,
            ready_before: self.names(ready),
            ready_after: self.names(destination),
            acquired: self.names(acquired),
            retired: self.names(removed),
            invalidated: self.names(ready & !live),
            dispatch,
            costs,
            total_ns,
            session_after: session || invoke,
        }))
    }

    fn mask(&self, names: &[String]) -> u8 {
        self.variants.iter().enumerate().fold(0, |out, (i, v)| {
            out | if names.contains(&v.id) { 1 << i } else { 0 }
        })
    }

    fn solve(&mut self, batch: usize, ready: u8, session: bool) -> Result<Tail, String> {
        let key = (batch, ready, session);
        if let Some(value) = self.cache.get(&key) {
            return Ok(value.clone());
        }
        self.states += 1;
        let value = if batch == self.model.baseline.latency_ns.len() {
            let close = if session {
                self.model.decision.close_ns
            } else {
                0
            };
            Tail {
                total: close,
                actions: Vec::new(),
                close,
            }
        } else {
            let mut best: Option<Tail> = None;
            for target in self.choices() {
                self.actions += 1;
                let Some(action) = self.action(batch, ready, session, target)? else {
                    continue;
                };
                let tail = self.solve(
                    batch + 1,
                    self.mask(&action.ready_after),
                    action.session_after,
                )?;
                let total = sum([action.total_ns, tail.total])?;
                if best.as_ref().is_none_or(|p| total < p.total) {
                    let mut actions = vec![action];
                    actions.extend(tail.actions);
                    best = Some(Tail {
                        total,
                        actions,
                        close: tail.close,
                    });
                }
            }
            best.ok_or("no legal skip continuation")?
        };
        self.cache.insert(key, value.clone());
        Ok(value)
    }

    pub fn frontier(&mut self) -> Result<Vec<Plan>, String> {
        let ready = self.mask(&self.model.ready);
        let call = self.model.decision.current_call(self.model.session_ready)?;
        let mut plans = Vec::new();
        for target in self.choices() {
            let skip = target.is_none();
            // A native request has already incurred this call, including when
            // its first artifact action is skip. Session close is still owed.
            let Some(action) = self.action(0, ready, skip || self.model.session_ready, target)?
            else {
                continue;
            };
            let extra = if skip { call } else { 0 };
            if sum([action.total_ns, extra])? > self.model.budget_ns {
                continue;
            }
            let tail = self.solve(1, self.mask(&action.ready_after), action.session_after)?;
            let total = sum([action.total_ns, tail.total, extra])?;
            if total <= self.model.budget_ns {
                let mut actions = vec![action];
                actions.extend(tail.actions);
                plans.push(Plan {
                    actions,
                    close_ns: tail.close,
                    total_ns: total,
                    current_committed_ns: extra,
                });
            }
        }
        Ok(plans)
    }
}
