# Common-code sinking ablation: changed bytes, unchanged empty-path burden

This evidence belongs to implementation source
`4107d333c4f373420772ad1539727f35641d9692`, tree
`498de7ac645d3b5408a7cd76c3622802ea7efab9`, not the later archive commit.

[Draft PR #586](https://github.com/TrillionniumFoundation/Hepta/pull/586)
[Actual Clang20 run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41611184304)

## Exact original evidence

- `common-sink-4107d33.zip`: GitHub artifact 13218184673, ZIP SHA-256
  `a3ead9c1a22fa2ed8668a20bfe53f95ebd12179c14bf8c0159f0d5d783718f8e`.
  Frozen registration SHA-256:
  `f378a0931d8b6fe400be5bef7b8d72472bc11c7e9f8993668cc6b051b5ed118d`.
- `shrink-wrap-4107d33.zip`: GitHub artifact 13218059957, ZIP SHA-256
  `b7aaef8a67d1c51b14b8f8ad2340b806a0b114fb6143dca9f0b65d40a3519dd4`.
  Frozen registration SHA-256:
  `049ec67e552ab8ce34a94a6fac28ab4fb8cbbc6c0661d79eae950f3cbc6d85df`.

Both ZIP digests match GitHub's reported digest. All 35 common-sink and
39 shrink-wrap artifact inventory hashes were independently recomputed and
matched. Both registrations identify the exact clean source; before/after
source and tool identities match. Actual compiler is Ubuntu Clang 20.1.8,
not a simulated compiler. Each profile ran ten focused tests successfully.

## Results

Each profile performed eight actual compiler invocations. Common-sink retained
24 total commands and took 4.038009577 seconds; shrink-wrap retained 30 commands
and took 3.717929723 seconds. These durations exclude CI setup/testing and are
not a performance comparison between kernels.

The shrink-wrap profile again has identical default/off/on entire objects
and `.text` bytes for both workloads. The common-sink profile has:

- **Affine:** entire objects and `.text` identical.
- **Linear:** objects and `.text` differ. Symbol `calculate` shrinks from
  0x32a (810) to 0x327 (807) bytes, through nonempty/fallback register/layout
  differences. This three-byte change is not a latency improvement claim.
- Every instrumented trace object exactly matches its own uninstrumented arm.

Linear default object SHA-256:
`26daeb37aaa980300f6e6a9bf198a3375db47b065204406c7beab0c1fc33e05e`.
Linear common-sink-off object SHA-256:
`4e45c9ea14d17ab1f9cefb6ba7e4fabc55380f065f5cdf8ff5a7aa349180117f`.

## Why this does not advance to timing

Inspecting the real linear assembly, the entry still saves rbp, r14 and rbx,
copies parameters into callee-saved registers, evaluates the large-length guard,
and only then tests n=0. Its zero branch still clears r14 and jumps to a shared
return/restore path. The MIR also retains the early entry register copies.
Thus the targeted empty-path register-save burden did not improve. No target
code was executed, no timed samples were collected, and no correctness or
performance qualification of the altered machine code is asserted.

Per the prospective decision rule, this is a negative result for this fixed-cost
hypothesis. It does not justify a timing campaign merely because some bytes
changed. A future generic control-flow/SSA proposal needs an independent
semantic argument and compile-level evidence of the intended change first.

## Recheck

For either ZIP, load `reduction-layout/RESULT.json`; hash every path listed in
`artifact_sha256` relative to `reduction-layout/`. Compare each workload's
`default.o`, candidate `.o`, and each `.trace.o` directly. Read the matching
`.asm`, `.symbols`, and `.shrink-wrap.mir.txt` files rather than inferring
latency from object size. The complete raw compiler outputs are also retained
in RESULT command receipts.

All three applicable workflows on implementation HEAD 4107d33 passed: the
matrix diagnostic, actual-host ABI, and upstream C++ host qualification. This
is not qualification of the later evidence commit, Rust parity, or a P0–P7 pass.
`authority=DENY_ALL`, `production_activation_allowed=false`,
`performance_qualified=false`, `timing_performed=false` remain unchanged.
