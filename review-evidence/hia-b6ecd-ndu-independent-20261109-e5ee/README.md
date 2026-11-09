# Final v16 source: independent NDU observation replay

**Recorded bytes and accounting replay: PASS. Stable incremental or economic
benefit: not established. Overall six-track acceptance: HOLD.**

This review uses only the original CI artifacts for source
`6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree
`4c51962e030e9ea39c6498224c99eb40fbdd2f35`.

| Original workflow | Artifact | ZIP bytes | Official SHA256 |
| --- | --- | ---: | --- |
| [Scalar integration and transport campaigns](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807348) | 13651783665 | 8,087,254 | `829735b11f5a4be9eb30e0eaee180dc7cca6b1fc3f93797e2d343b3c8d2dfad0` |
| [Frozen scalar-controller controls](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807356) | 13652586985 | 1,695,614 | `d46fb19432aea914534506a81f44b2d86786adbc0bb26fdd5c61911f6f7fefb6` |

Both original ZIP digests and sizes match their official metadata. Original
before/after source records are clean and bind the exact source and tree.
The union of 44 registered source paths matches exact Git bytes. Every one of
the scalar artifact's 475 members and controller artifact's 577 members was
read, CRC-checked and hashed. Complete member contents remain available in
[scalar-originals](scalar-originals/README.md) and
[controller-originals](controller-originals/README.md), with independent byte
integrity readers. These containers are not the original ZIP byte streams.

## Scalar integration and two transport campaigns

The original integration report records 180 distinct successful tests, with no
failure, error, skip or expected failure. The three original Rust framing
controls also passed, with their original stdout/stderr hashes checked. The
retained native image matches its build receipt and post-suite digest; this
reviewer did not execute it.

Each registered campaign has 72 completed cells, no failed or unstarted cells,
and no automatic retries. Each contains 1,020 original native responses and
510 Ordinary calls. The standard-library prepared and persistent replayers both
returned exit 0; their output files are byte-identical to the original CI
replay reports. The persistent reader checked frame/session identity, original
responses, closure and cost accounting without executing a native process.

Ordinary is faster in **all 24 pairs of each campaign**. Prepared transport is
faster than one-shot transport in all 24 pairs. Persistent transport is faster
than prepared transport in all 18 pairs at horizons 4, 16 and 64, but in only
one of six pairs at horizon 1. The median at horizon 1 is slower.

The persistent campaign's descriptive medians are:

| Horizon | Ordinary, ms | Prepared, ms | Persistent, ms |
| ---: | ---: | ---: | ---: |
| 1 | 0.171533 | 8.495233 | 8.928076 |
| 4 | 0.671987 | 16.302890 | 13.777557 |
| 16 | 2.606314 | 45.502950 | 31.907931 |
| 64 | 10.051395 | 164.252748 | 104.974643 |

The prepared replayer is not embedded in the original ZIP. Its exact B Git
bytes were obtained separately and match the original CI verifier digest. The
persistent replayer is embedded and also matches exact Git bytes. Both scripts
and their actual local execution receipts are retained here.

## Same-input scalar-controller controls

The original controller campaign completes all 128 scheduled calls and 64
pairs. Both arms choose the same specified winner from each identical frozen
pool. All 64 native calls have retained original request/response/identity and
cleanup observations. The independent standard-library `verify` entrypoint
checks all 307 content-addressed objects and all 128 cells; it returned exit 0
with output byte-identical to the original `VERIFICATION.json`.

NDU is faster in **0 of 64 pairs**. Complete-call median wall time is
**9.2602645 ms for NDU** and **0.044612 ms for Ordinary**. The median paired
Ordinary-minus-NDU difference is **-9.2165545 ms**. Every pair, original native
observation and measured interval remains in the retained campaign. Preparation,
capture/export/audit overhead and the original native build are identified
separately; nested costs are not summed twice.

## Limits

These are authored scalar-table workloads on a shared host. Supplied quality
flags and forecast costs are not observed user-task success, and the experiment
does not demonstrate learned proposal dynamics. Original timings and process
receipts are trusted observations, not independently authenticated host clocks
or hardware attestation. The replayers verify original bytes, finite decisions,
source bindings and arithmetic; they do not repeat the native experiments.

No new native, solver or provider call was made by these replayers. The original
controller campaign records no model calls, formal MCP calls or real user tasks. Those
campaign-local zeros do not provide the complete history or price of authoring,
search, model/provider use, infrastructure, energy or deployment. Money and
global full cost remain unknown. The source's original Agent task, machine
proof scope, public default and online installation are separate subjects.

These results preserve the negative Ordinary controls. Faster transport within
NDU does not establish incremental value over the matched Ordinary baseline.
