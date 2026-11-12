# Fixed strong-baseline benchmark: actual follow-up result

The single registered run completed all **98 observations** and **1,260 finite correctness cases**. Source, compiler and artifact identities remained unchanged. Quality passed; the full strong-baseline noninferiority gate **did not pass**. No observation was discarded and no second measurement run was performed.

The checked HIA reduction was genuinely improved under an independently verified runtime guard. Both original-HIA comparisons pass the unchanged thresholds. Relative to the five strong language baselines, only packet_xor versus C with PGO passes all three noninferiority conditions in this run.

## Every registered comparison

Ratios are guarded HIA divided by the named baseline; smaller means lower time or memory. The upper bound is the registered one-sided 95% paired log-ratio t bound over seven groups. p95 is an empirical batch quantile, not a service latency guarantee.

| Kernel | Baseline | Paired time ratio | Upper 95% | Batch p95 ratio | Peak RSS ratio | All gates |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| full_lifecycle | hia_original | 0.6020 | 0.7123 | 0.6962 | 1.0000 | pass |
| full_lifecycle | rust_o3_lto | 1.2040 | 1.4486 | 1.4381 | 0.7872 | fail |
| full_lifecycle | c_o3_lto | 0.9840 | 1.2089 | 0.9361 | 1.0000 | fail |
| full_lifecycle | cpp_o3_lto | 1.0692 | 1.2458 | 1.2656 | 0.4167 | fail |
| full_lifecycle | c_pgo_lto | 1.1167 | 1.3771 | 1.4617 | 1.0000 | fail |
| full_lifecycle | cpp_pgo_lto | 1.0207 | 1.2086 | 1.1180 | 0.4167 | fail |
| packet_xor | hia_original | 0.7088 | 0.9333 | 0.5342 | 1.0000 | pass |
| packet_xor | rust_o3_lto | 0.9795 | 1.0907 | 1.0307 | 0.7945 | fail |
| packet_xor | c_o3_lto | 0.9930 | 1.1131 | 1.0042 | 1.0000 | fail |
| packet_xor | cpp_o3_lto | 1.0755 | 1.2215 | 1.2465 | 0.4370 | fail |
| packet_xor | c_pgo_lto | 0.9468 | 1.0028 | 0.9606 | 1.0000 | pass |
| packet_xor | cpp_pgo_lto | 0.9077 | 1.0932 | 0.8479 | 0.4370 | fail |

All peak-RSS ratios pass. In full_lifecycle, every strong baseline comparison fails the paired upper-bound criterion; Rust, C++ O3 and both PGO arms also fail the p95 gate. In packet_xor, the Rust, C O3 and C++ PGO mean point estimates are close to or below one, but their upper bounds exceed 1.05; C++ O3 also fails the p95 criterion. These near-one observations do not establish noninferiority.

## Actual preparation costs

| Preparation | Wall seconds |
| --- | ---: |
| c_o3_lto | 0.187974 |
| c_pgo_lto | 0.715352 |
| cpp_o3_lto | 0.473607 |
| cpp_pgo_lto | 1.453395 |
| hia_original | 0.347401 |
| hia_verified | 12.918605 |
| rust_o3_lto | 4.826329 |

The deterministic proposal cost 0.012381 s. The separately recorded first guarded proof cost 3.900178 s. The guarded arm total includes proposal, repeated independent verification, emission and native build. It is the cost of this actual qualification path; it should not be confused with a claim that every direct compiler invocation must repeat every qualification-stage proof.

The candidate preparation exceeds the original native build by 12.571204 s. Dividing that measured excess by paired mean savings for the same heldout input mixture gives:

| Kernel | Saved microseconds/call | Incremental preparation break-even calls |
| --- | ---: | ---: |
| full_lifecycle | 2.7237 | 4,615,419 |
| packet_xor | 3.8185 | 3,292,152 |

These are descriptive amortization point estimates against original HIA. The complete candidate-preparation counts are 4,742,965 and 3,383,130 calls respectively. They are not admission guarantees or a demonstrated payoff against Rust/C/C++; the observed full_lifecycle Rust comparison is slower, and the overall strong-baseline gate failed.

## What the exact generated code shows

The retained disassembly is derived from the exact measured artifacts, not a recompile or ablation. Original HIA performs a byte load, an addition and a carry-to-abort branch on each checksum iteration. The guarded fast path removes that branch and LLVM expands the reduction eight ways. The slow fallback retains the checked loop. The packet fast path also loses the original destination-minus-source alias-distance branch; that check remains only in the slow fallback. This differs from the earlier noalias-only experiment.

The remaining full_lifecycle fill loop still uses u32 SIMD addition followed by masks and packuswb, storing 16 bytes per iteration. The measured Rust artifact stores 32 bytes per iteration with two movdqu stores. The guarded artifact also contains both complete paths; the bytecode and machine-code size are consequently larger. These are observable structural differences, not a measured causal allocation of the remaining time gap. No new ablation or profile was run.

A concrete next certificate candidate is modular narrowing: trunc8(add.wrap32(i,seed)) equals add.wrap8(trunc8(i),trunc8(seed)); corresponding multiplication-by-13 and XOR-90 identities apply to the packet fill. A verifier must bind the entire use-def window, establish that no other observer sees the removed wider intermediates, and preserve loop indices, bounds, allocation calls and refusal paths. This could allow byte induction and packed byte arithmetic. It remains a proposed next experiment; it is not part of the frozen result.

## Evidence and scope

The lossless archive benchmark-final-01.tar.xz contains the exact source snapshot, all commands and streams, PGO profiles, native artifacts, every sample, proof/proposal/native receipts and all seven disassemblies. All **260 member hashes** were verified before only archived ELF duplicates were removed. Archive SHA-256:

`0aa44299aabf4154f8cedc371309b4b4f2e33972986f795b4395af24a2e30e5a`

This is one shared Linux x86-64 host, two synthetic buffer kernels, one frozen Clang 20.1.2 / Rust 1.95.0 toolchain setup and a finite input inventory. The earlier Rust 1.90.0 run used different holdout inputs and is retained separately. Neither universal language superiority nor global optimality is established.
