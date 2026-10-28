# Registered NDU cost study

`PROTOCOL_20261028.json` is a new experiment, not a replacement for the older
negative graph, round3, or exact-request reuse results. Commit the protocol and
implementation before measurement; execute from a clean, fixed source commit.
The qualifier refuses uncommitted code, an unpinned native source or compiler,
and a build receipt that does not bind that same source commit.

## Two separate questions

The controller layer compares real one-shot, persistent full-rehash, persistent
sealed-image and exact-request cache transports with equally reusable fixed/DP
controls. Repeated requests and changed generations are separate traces. These
finite cost models do not establish an application speedup.

The application layer performs actual proof-gated native builds and checksum-
checked executions with six batches, stable reuse, changing input sizes, and two
modules competing for a shared compile-attempt permit. Baseline controls see the
same calibration and completed observations. Fixed commits a complete budget-DP
plan after initial probes; DP recomputes over the same complete stationary suffix
allocation set as NDU. Every arm may reuse an admitted artifact. Before every
execution, a fresh independent proof and SHA-matched sealed loaded-image check
remain required. Native NDU advice is always `DENY_ALL`, never a proof.

The permit owner consumes credit before any attempted candidate build; failure
does not refund it. This enforces one precisely scoped resource bound. It is not
a memory-safety theorem, aggregate RSS/CPU bound, or concurrent execution quota.
The workload declares future input sizes, not future observed execution times.
The finite stationary allocation space does not establish a universal optimum.

## Sealed-image optimization

The session performs an initial complete binary readback and SHA-256 admission.
Every evaluation rechecks the immutable manifest, descriptor device/inode/size,
all four Linux write/grow/shrink/seal seals, and actual `/proc/<pid>/exe` identity.
The default sealed profile skips redundant full image hashing only under those
conditions. The `rehash` comparison profile retains repeated real full hashes.
Ordinary mutable-path `NduBridge` checks remain unchanged. The kernel, loader,
native dependencies and host remain trusted; this is not hostile-host attestation.
Malformed replies, unknown fields, authority changes, identity drift and timeouts
close the session permanently. Exact advisory caching remains opt-in and off by
default; a cache hit never authorizes publication or replaces a fresh proof.

## Reproduce after freezing the source

Use a pinned Rust 1.90.0 installation for the c4 stream source and a new empty
Cargo target. The separate finite profile retains its original 4b source and
Rust 1.95.0 requirement. Do not substitute either identity for the other.

```sh
python tools/measure_hia_ndu_build.py \
  --ndu-source /path/to/c4-source \
  --expected-source c4a1bbed3a39beba43a6abf1a18b6f75c5725c21 \
  --output /tmp/ndu-complete-build \
  --target-dir /tmp/ndu-empty-target \
  --cargo /path/to/rust-1.90.0/bin/cargo \
  --rustc /path/to/rust-1.90.0/bin/rustc \
  --cargo-home /path/to/dependency-cache
python tools/qualify_hia_ndu_net_value.py \
  --identity /tmp/ndu-complete-build/build/identity.json \
  --build-envelope /tmp/ndu-complete-build/BUILD_ENVELOPE.json \
  --clang /path/to/clang \
  --output /tmp/ndu-net-value
```

Both tools write exclusively outside the source checkout. Raw native stdin,
stdout and stderr are retained; failed episodes retain their incurred cost.
The outer build receipt adds process startup and final manifest writing to the
existing detailed native build cost. Cold totals include this complete build
once for every standalone native arm. Warm totals exclude only this build;
calibration, proofs, compilation, admission, artifact checks, execution, evidence
serialization, cleanup and shutdown remain charged. Toolchain installation and
preexisting dependency-cache acquisition are disclosed exclusions. No fully cold
machine or statistical superiority claim is made. All three application groups
must admit every output and resource budget, and total native cold cost must beat
both controls for the registered economic gate to pass. A negative result is a
valid retained result and does not enable caching by default.
