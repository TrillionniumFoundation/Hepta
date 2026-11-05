//! Real allocation, transposition, cache eviction and matrix-vector work.
//! This is a native Rust experiment, NOT an HIA compiler qualification.
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

const MAX_BYTES: usize = 128 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Init { count: usize, n: usize, seed: u32, quota_bytes: usize },
    Prepare { id: usize, epoch: u32 },
    Retire { id: usize },
    Mutate { id: usize, epoch: u32, seed: u32 },
    Run { id: usize, vector_seed: u32, repeats: usize, dispatch: String },
    State,
    Close,
}

struct Matrix {
    seed: u32,
    epoch: u32,
    data: Vec<u32>,
    packed: Option<Vec<u32>>,
}

#[derive(Default)]
pub struct Workload {
    n: usize,
    quota: usize,
    matrices: Vec<Matrix>,
    closed: bool,
    allocations: u64,
    retirements: u64,
    reuses: u64,
    invalidations: u64,
    executions: u64,
}

fn allocate(size: usize) -> Result<Vec<u32>, String> {
    let mut result = Vec::new();
    result.try_reserve_exact(size).map_err(|e| e.to_string())?;
    result.resize(size, 0);
    Ok(result)
}

fn matrix(n: usize, seed: u32) -> Result<Vec<u32>, String> {
    let mut data = allocate(n.checked_mul(n).ok_or("matrix size overflow")?)?;
    for i in 0..n {
        for j in 0..n {
            data[i * n + j] = seed.wrapping_add((i as u32 + 1).wrapping_mul(17))
                .wrapping_add((j as u32 + 1).wrapping_mul(31));
        }
    }
    Ok(data)
}

#[inline(never)]
fn direct(data: &[u32], vector: &[u32], out: &mut [u32], n: usize) {
    for j in 0..n {
        let mut total = 0_u32;
        for i in 0..n { total = total.wrapping_add(data[i * n + j].wrapping_mul(vector[i])); }
        out[j] = total;
    }
}

#[inline(never)]
fn packed(data: &[u32], vector: &[u32], out: &mut [u32], n: usize) {
    for (j, row) in data.chunks_exact(n).enumerate() {
        out[j] = row.iter().zip(vector).fold(0_u32, |a, (v, x)| a.wrapping_add(v.wrapping_mul(*x)));
    }
}

fn checksum(out: &[u32]) -> u64 {
    out.iter().fold(0xcbf29ce484222325, |a, b| (a ^ (*b as u64)).wrapping_mul(0x100000001b3))
}

impl Workload {
    fn resident(&self) -> usize {
        self.matrices.iter().filter_map(|m| m.packed.as_ref()).map(|p| p.capacity() * 4).sum()
    }

    fn snapshot(&self) -> Value {
        json!({"n":self.n,"quota_bytes":self.quota,"resident_bytes":self.resident(),
            "baseline_bytes":self.matrices.iter().map(|m|m.data.capacity()*4).sum::<usize>(),
            "ready":self.matrices.iter().enumerate().filter(|(_,m)|m.packed.is_some()).map(|(i,_)|i).collect::<Vec<_>>(),
            "epochs":self.matrices.iter().map(|m|m.epoch).collect::<Vec<_>>(),
            "allocations":self.allocations,"retirements":self.retirements,"reuses":self.reuses,
            "invalidations":self.invalidations,"executions":self.executions,"closed":self.closed})
    }

    pub fn execute(&mut self, command: Command) -> Result<Value, String> {
        let started = Instant::now();
        if self.closed { return Err("workload is closed".into()); }
        if !matches!(command, Command::Init { .. }) && self.matrices.is_empty() {
            return Err("workload not initialized".into());
        }
        let body = match command {
            Command::Init { count, n, seed, quota_bytes } => {
                if !self.matrices.is_empty() || !(1..=8).contains(&count) || !(1..=1536).contains(&n)
                    || n * n * count * 4 > MAX_BYTES || quota_bytes > MAX_BYTES {
                    return Err("initialization or memory bound".into());
                }
                let mut values = Vec::new();
                for id in 0..count {
                    let current_seed = seed.wrapping_add(id as u32 * 101);
                    values.push(Matrix { seed:current_seed, epoch:1, data:matrix(n,current_seed)?, packed:None });
                }
                self.n = n;
                self.quota = quota_bytes;
                self.matrices = values;
                json!({"initialized":true})
            }
            Command::Prepare { id, epoch } => {
                let m = self.matrices.get(id).ok_or("unknown matrix")?;
                if epoch != m.epoch { return Err("stale preparation epoch".into()); }
                if m.packed.is_some() {
                    self.reuses += 1;
                    json!({"prepared":id,"reused":true})
                } else {
                    if self.resident().checked_add(self.n*self.n*4).ok_or("resident overflow")? > self.quota {
                        return Err("resident quota rejected preparation".into());
                    }
                    let mut buffer = allocate(self.n*self.n)?;
                    if self.resident() + buffer.capacity()*4 > self.quota {
                        return Err("allocator capacity exceeds resident quota".into());
                    }
                    for i in 0..self.n {
                        for j in 0..self.n { buffer[j*self.n+i] = m.data[i*self.n+j]; }
                    }
                    self.matrices[id].packed = Some(buffer);
                    self.allocations += 1;
                    json!({"prepared":id,"reused":false})
                }
            }
            Command::Retire { id } => {
                let m = self.matrices.get_mut(id).ok_or("unknown matrix")?;
                let existed = m.packed.take().is_some();
                self.retirements += u64::from(existed);
                json!({"retired":id,"existed":existed})
            }
            Command::Mutate { id, epoch, seed } => {
                let m = self.matrices.get_mut(id).ok_or("unknown matrix")?;
                if epoch <= m.epoch { return Err("nonmonotonic data epoch".into()); }
                // Build the new source first. A failed allocation retains the
                // previous valid source/cache; no partially updated epoch.
                let replacement = matrix(self.n, seed)?;
                let invalidated = m.packed.take().is_some();
                self.retirements += u64::from(invalidated);
                self.invalidations += u64::from(invalidated);
                m.data = replacement;
                m.epoch = epoch;
                m.seed = seed;
                json!({"mutated":id,"epoch":epoch,"invalidated_cache":invalidated})
            }
            Command::Run { id, vector_seed, repeats, dispatch } => {
                let m = self.matrices.get(id).ok_or("unknown matrix")?;
                if !(1..=64).contains(&repeats) || !matches!(dispatch.as_str(),"direct"|"packed") {
                    return Err("execution bound or kernel identity".into());
                }
                let data = if dispatch == "packed" { m.packed.as_ref().ok_or("cache is not resident")? } else { &m.data };
                let vector:Vec<u32> = (0..self.n).map(|i| vector_seed.wrapping_add(i as u32*13)%65521).collect();
                let mut out = allocate(self.n)?;
                let kernel = Instant::now();
                for _ in 0..repeats {
                    if dispatch == "packed" { packed(std::hint::black_box(data),std::hint::black_box(&vector),&mut out,self.n); }
                    else { direct(std::hint::black_box(data),std::hint::black_box(&vector),&mut out,self.n); }
                    std::hint::black_box(&out);
                }
                let kernel_ns = kernel.elapsed().as_nanos();
                // An independent O(n) algebraic oracle checks every output of
                // this generated matrix family; its cost remains in run wall.
                let check = Instant::now();
                let sum_v = vector.iter().fold(0_u32,|a,b|a.wrapping_add(*b));
                let sum_iv = vector.iter().enumerate().fold(0_u32,|a,(i,b)|a.wrapping_add((i as u32+1).wrapping_mul(*b)));
                let base = m.seed.wrapping_mul(sum_v).wrapping_add(17_u32.wrapping_mul(sum_iv));
                for (j, value) in out.iter().enumerate() {
                    let expected = base.wrapping_add(31_u32.wrapping_mul(j as u32+1).wrapping_mul(sum_v));
                    if *value != expected { return Err("full output oracle mismatch".into()); }
                }
                let digest = checksum(&out);
                let check_ns = check.elapsed().as_nanos();
                self.executions += 1;
                json!({"matrix":id,"epoch":m.epoch,"dispatch":dispatch,"repeats":repeats,
                    "checksum":digest,"kernel_ns":kernel_ns,"oracle_ns":check_ns,
                    "all_outputs_checked":self.n,"oracle_scope":"generated affine matrix family modulo 2^32"})
            }
            Command::State => json!({"state_requested":true}),
            Command::Close => {
                for m in &mut self.matrices {
                    self.retirements += u64::from(m.packed.take().is_some());
                    m.data.clear();
                    m.data.shrink_to_fit();
                }
                self.closed = true;
                json!({"closed":true})
            }
        };
        Ok(json!({"schema":"hepta.hia.ndu.dynamic-cache.workload.response.v1",
            "result":body,"state":self.snapshot(),"service_ns":started.elapsed().as_nanos(),
            "native_rust_experiment":true,"hia_compiler_qualification":false}))
    }
}
