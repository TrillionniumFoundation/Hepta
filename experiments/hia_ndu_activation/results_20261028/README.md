# NDU heterogeneous activation: retained result

Measured implementation/protocol commit:
`b8d83ef67eb350d7497934828b06698d909d61e5`, based on the previously delivered
`2f49151ab9d8812eeb02ac2056f224f140099d76`. Later result-packaging commits do
not replace that identity. Native NDU still uses pinned source
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` and Rust 1.90.0.

## Result

The prior **zero-candidate activation** gap was closed in this finite study:
NDU actually compiled 9 selected candidates and delivered 54 correct candidate
observations. All 27 application episodes and 324 native executions completed
correctly within their declared budgets. Calibration retained all 54
observations. Every application execution performed a fresh independent proof
and checked the image actually loaded from sealed bytes.

The recorded Core, code, protocol, Clang/Python bytes, native NDU manifest and
driver stayed unchanged. Two genuinely different canonical Core programs ran:
single-buffer byte sum and double-buffer packet transform/XOR/reduction. The
17 relevant tests passed on the measured source, with zero skips (44.828 s).
These tests overlap existing coverage and are not 17 independent benchmarks.

**The complete cold economic advantage is still false.** In seconds:

| Standalone profile | Strong fixed | Complete DP | NDU warm | NDU cold |
| --- | ---: | ---: | ---: | ---: |
| Stable reuse | 129.146958 | 129.221015 | 130.291868 | 162.425066 |
| Changing load | 128.833233 | 123.527522 | 124.013672 | 156.146870 |
| Shared budget | 151.588022 | 143.228191 | 150.497580 | 182.630778 |
| Combined workload, setup once | 223.202420 | 209.610935 | 217.959028 | 250.092226 |

Each standalone profile charges common setup once; these profile rows must not
be summed. The combined interpretation charges it once for the combined
workload. The fresh, actual empty-target native build cost 32.133198039 s and
produced SHA-256
`96950b1d620460f52d44040e20aeeefeb39daf58cd4cd3da05eee9c587a146a6`.
This is a new observed build, not reuse or relabeling of the prior 47.61 s cost.
Warm totals omit only this native build.

The cost scope is the registered research driver. It excludes toolchain
installation, acquisition of dependency source caches, outer Python
startup/imports/argparse, post-run audit/encoding/archival and human engineering
outside that driver. It is not every possible deployment or economic cost.

## What the activation evidence does and does not show

All **72** native NDU selections matched the deterministic complete-DP plan key
on the **exact model** submitted to NDU: modeled selection regret was zero.
Executing arms saw the same initial bank and observation interface, but each
received its own completed timings. The audit avoids pretending their
counterfactual timings were identical.

Both DP and NDU built 9 candidates; fixed built 6. All actual builds selected
`guard-small`. NDU's 54 candidate outputs comprised 20 byte-sum and 34
packet-XOR observations. Only **7** of these inputs satisfied the declared
small guard. Other inputs exercised the preserved original fallback; a faster
whole artifact there cannot be credited to execution of the guarded fast body.
No hardware branch counter was measured.

The two semantic modules shared one enforced attempt credit, but **zero**
decisions contained two simultaneously predicted-profitable modules competing
for that credit. Consequently `ndu_shared_budget_competition_executed=false`.
Running two modules is not by itself evidence of meaningful budget competition.

These observations close neither NDU superiority over complete DP nor global
instruction optimality. The complete DP already covers the same finite
stationary suffix allocations. NDU's capability to rank those allocations does
not produce a better modeled allocation in this experiment. Native transport,
build and verification costs must still be paid.

## Why a further reuse change is justified

The forecast now includes the same fresh proof performed during actual
delivery. This exposed substantial recurrent solver cost: for byte sum,
`guard-wide` calibration delivery medians were roughly 4.40–5.36 s, whereas
the baseline medians were 0.091–1.048 s at the registered sizes. These are
combined proof-plus-execution costs, not machine-code kernel timings.

The next implementation can evaluate legal reuse of an internally verified,
immutable artifact with exact Core, policy, implementation and tool bindings,
bounded entry/byte/lease budgets and conservative release debt. That requires
adversarial lifetime and stale-identity checks. Importing producer receipts or
simply deleting fresh admission is not an accepted substitute. Fixed, DP and
NDU must receive identical reuse eligibility in any new experiment. This
prospective next step changes no result in this directory.

## Evidence inspection

`SUMMARY.json` is the direct machine-readable summary. `REGISTRATION.json`
contains the exact source hashes and protocol. `NATIVE_BUILD_IDENTITY.json` and
`NATIVE_BUILD_ENVELOPE.json` retain the real pinned native build and outer cost.
The test log and entire formal runner stdout are included.

`INDEX.json` binds three lossless JSON-fragment datasets: complete result,
complete calibration bank and the complete raw-file inventory. Every JSON
value is retained. The fragments stay below 48 KB for ordinary Git review.

```sh
python experiments/hia_ndu_activation/results_20261028/inspect_evidence.py
```

This only verifies/reconstructs evidence; it does not execute experiments.
Reconstruction of all three datasets passed. The original result contains
3,970,620 bytes, SHA-256
`076205256d83b6ba7d4dd46ada0482148d4d26a6243df67fd6d9e9c3dccfd391`.
There are 649 retained raw study/build files totaling 11,370,499 bytes,
including actual native images and request/response streams. Native binaries,
the original build directory and the source Git bundle are delivered in the
separate raw attachment, not disguised as textual Git evidence. Cargo targets,
installed toolchains and dependency caches are excluded from that attachment.

The measured host was a nonexclusive Linux executor. Model inference and
known team benchmark work were paused for this interval, which does not make
the machine exclusive or verify it as the user's dot workstation. All old
negative results remain unchanged. Authority is `DENY_ALL`; no safety or
production-deployment credential is issued.
