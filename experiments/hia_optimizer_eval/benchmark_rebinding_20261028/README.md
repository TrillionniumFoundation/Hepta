# Preserved benchmark: current Core/LLVM correspondence after the loader fix

**The archive is intact, and current Python lowering/composition/LLVM emission
reproduces the two historical HIA Core and LLVM documents exactly. The complete
source snapshot changed. No performance result, proof receipt or deployment
permission is renewed by this audit.**

The benchmark remains the registered seven-arm, two-kernel, seven-group
experiment: 98 observations, quality gate passed, joint noninferiority gate
failed. All old build, proposal, verification, PGO, correctness and execution
costs remain the original observations.

## What was checked

`verify_rebinding.py` produced `AUDIT.json` without changing the original run.
It performed one streaming archive-member pass, retaining only small source,
JSON, Core/LLVM and the two HIA ELF byte arrays. It ran at reduced scheduling
priority. There were no solver imports or queries, subprocesses, native
compilations, candidate-library loads or workload calls. Its audit hook rejects an
attempt to import Z3, spawn a process or call `ctypes.dlopen`.

The audit established:

- All **260 members**, totaling **8,805,467 uncompressed bytes**, match the
  preserved manifest's SHA-256 and length. The 1,345,272-byte archive remains
  `0aa44299aabf4154f8cedc371309b4b4f2e33972986f795b4395af24a2e30e5a`.
- Every one of the **123 archived source bindings** agrees with its archived
  source bytes. **121 existing entries are unchanged**. Only
  `hepta/hia_adaptive.py` and `hepta/hia_stateful.py` changed;
  `hepta/native_mapping_identity.py` was added. The exact delta is in
  `SOURCE_DELTA.patch`. This is a new global source identity, not a relabeling
  of the old snapshot.
- The source fixture lowers to the same baseline Core. The fixed deterministic
  guard proposal and its composed Core are structurally identical. This is
  byte reconstruction using internal structural helpers, not independent
  semantic proof or a deployment path around the production checker.
- Current LLVM emission exactly reproduces **both complete LLVM byte strings**
  and their hashes. The native verifier/emitter identity, ordinary checker
  identity and guarded checker identity are unchanged. All **25 project source
  modules actually imported by this audit** match the historical bindings.
- Both HIA native build receipts match their archived Core, LLVM, compiler and
  artifact bytes. The two ELF inventories were re-parsed without loading them.
  The guarded native binding digest and the standalone/aggregate receipt agree.
- The two retained historical verification records each contain **30 saved
  obligations**. All 60 record occurrences have valid SMT-text hashes and the
  retained `unsat` result. The proof-record digests and Core/proposal/checker
  bindings match. No obligation was solved again.
- The five recorded tool executable identities—Clang, Clang++, Rust, LLD and
  llvm-profdata—still match. Executable aliases resolve to their recorded files.
  Z3's recorded library bytes and Python binding bytes also match, without
  importing or loading the solver. Version strings remain historical
  observations; no new `--version` process or solver query ran.
- All **seven backend artifacts**, the driver artifact and **six PGO profile
  files** match their records. The 98 individual sample JSON files equal the
  aggregate records, registered ordering, referenced library hashes and retained
  driver stdout. Checksums, **1,260 finite correctness observations**, and the
  **four training observations** match the unchanged finite oracle.
- Recomputing only the statistics over the old observations reproduces the
  recorded evaluation exactly. The published `benchmark-results.json` still
  points to the same raw report and retains its costs, builds and summaries.

The raw report remains
`9fc52240333beaac6881f48f3df400e793f5dc0066125a03d8a5368caf2103e7`.

## Exact output and implementation identities

| Item | SHA-256 |
| --- | --- |
| Baseline Core | `1de9c862ca95838fa22ce0aecc2d873735cdb67f16e1a318926bd7ad1ce492ab` |
| Baseline LLVM | `85179d6016ee5e1fe3c9b4768bfbd4f624f20dbbd7907fac7b5519ec3a8eef05` |
| Baseline native artifact | `cdef5a44d93f7d89a8256a4548490cb14ed8aa70b7bf2a22beecbdb7c406107d` |
| Guarded Core | `a3c6dfd1c9ed497ac4ef886193e7f5d4200a8203bdb813a51f7f1f154122088b` |
| Guarded LLVM | `1a449a6aaa9562a0f0723187500ee8f6f292ea2a64c2cf7aee7218f12890c44d` |
| Guarded native artifact | `e4d1aadd4f859188d16f802daee4e65425aed27923e73ce6f93e59ed9e96932c` |
| Native verifier/emitter | `0519011099263210f3f0e9c0ad11c0dc4586fdaf079c6df16746ba49cc4a3ef9` |
| Ordinary checker | `78694a5f57a303f576dd9b5430498affc9d65e7fa93d639721a940cf66554f12` |
| Guarded checker | `6c6df88ddca7e8ed64eff8adb26f0bc434cac63f180bdedb2091dd2db1a66acf` |

The unchanged current LLVM is evidence about these exact code-generation
outputs. The archive establishes the exact historical machine-code bytes that
were measured. This audit does not claim that a fresh compile has occurred or
that its complete linked file would necessarily be byte-identical.

## Why the persistent-loader fix does not rewrite these timings

The preserved benchmark C driver performs one ordinary-path `dlopen` per fresh
driver process, uses that handle, and closes it. Its source, binary and each
sample's fresh-process command are retained. It does not use the persistent
adaptive/stateful `/proc/self/fd/N` cache path repaired later. The historical
finite-correctness processes similarly load one backend library per fresh
Python process.

The recorded HIA original build cost remains **0.347401471 seconds**. The
guarded proposal/verification/emission/build phase remains **12.918605495
seconds**; the separate first verification interval remains **3.900177956
seconds**. These are historical costs and are not replaced with the small cost
of hashing or Python reconstruction. All other original costs remain in
`AUDIT.json` and the preserved raw report. The negative noninferiority outcome
is unchanged.

This correspondence does not transfer the benchmark timings to the newly
repaired adaptive or owned-state runtime. That runtime has its own separate
qualification and complete-cost observations.

## Explicitly unestablished boundaries

The following remain **unknown or not attempted**, rather than being filled in
from assumptions:

- The complete implicit toolchain dependency closure. The old plan records
  five executable files, not every shared library, compiler-rt/sysroot or
  system-linker dependency. Matching the recorded executables does not establish
  that wider historical closure.
- Fresh native compilation or bit-for-bit native rebuild reproducibility.
- Current loaded-mapping admission for these preserved binaries. This audit
  never loads a native library; ELF parsing and hashing cannot establish an
  actual process mapping.
- A fresh solver result or proof receipt. Saved SMT/result records are checked
  for integrity and unchanged checker/solver bytes, not independently re-solved.
- Performance of the current persistent runtime or a new workload population.

New deployment still requires the current independent verification/build path,
a new artifact-bound receipt and the applicable current artifact/mapping
admission checks. Historical JSON and `AUDIT.json` carry no deployment authority.

## Reproduce this read-only audit

Retain the original benchmark archive/manifest, repository sources and the exact
recorded tool and Z3 files. From the repository root, run:

```bash
/usr/bin/python3 experiments/hia_optimizer_eval/benchmark_rebinding_20261028/verify_rebinding.py
```

The script prints a new audit to stdout and writes only `SOURCE_DELTA.patch` in
this separate audit directory. It does not modify the original archive, source
snapshots, frozen evaluator files or timing records. It returns an explicit
`unknown_audit_not_closed` record and fails if an expected correspondence cannot
be established. `INDEX.json` identifies the exact delivered audit files.
