# Actual legacy C record/view migration: first full application trial

This is a completed, negative performance result. It does not replace the
earlier two-kernel or filecheck experiments, and the later IR PGO protocol must
be evaluated separately.

## Source and implementation scope

The run executed clean local commit
`ccd423bc9ee22888fec5d23f993978f2c0f51b57`, tree
`26695834a49be88dae42a41a2954954f721c7066`. Public commit
`e629d92d82752244edf11c3ae5a0c477a64e9252` has the identical tree;
its different commit identity does not relabel the measured execution.

The actual migrated Core is
`1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51`.
Eleven upstream bodies in three translation units come from the complete
pinned Ring-Buffer component and the generic musl `memcmp`/`bcmp` sources.
One authored CRC body is the fourth translation unit. The authored owned
integration client is counted separately. All consumed Clang AST stdout,
source snapshots, explicit pointer contracts, generated Hepta, Core and LLVM
are retained. No original C implementation is linked into the HIA target.

The scalar C entry is exercised through the common real file-checksum host.
Original foreign-pointer/record ABI, full musl, a large legacy application,
general C++ translation and whole-language source equivalence are outside this
claim. Zero manual edits to translated bodies do not measure human labor:
the pointer contracts and integration glue were authored.

## Completed checks

- 7 actual native unit tests passed, zero skips, on the measured source.
- 96 cases across 8 native arms: 768 differential calls, all correct.
- 24 cases at four allocation-refusal settings: 96 VM/C/HIA rows, all cleanup
  and allocation counts agree; maximum observed logical buffer payload is
  32 bytes. This is not process RSS or a universal memory upper bound.
- An API maintenance change adds a fifth translation unit containing a
  versioned CRC helper. All 12 direct C/HIA cases agree. Original upstream
  source bytes remain unchanged; manual migrated-body edits are zero.
- Successful and rejected candidate-switch paths both retain the expected
  application checksum. All eight application arms use the same native
  fork/exec supervisor and retain child `wait4` RSS and its pre-exec floor.

Independent all-input cursor arithmetic checks on this actual Core and the
449-obligation scalar lowering matrix are retained in
`../../hia_next_safety/results_20261028`. Those finite proof profiles do not
prove the complete native program or whole language.

## Registered performance result

There are 112 measured applications, no excluded samples. The candidate was
registered as `hia_native_lto` before measurement. All C/C++/Rust baselines
include LTO and target-native optimization; the respective PGO arms use real
training profiles. The fastest strong reference was `rust_native_pgo` for
both algorithms.

| Algorithm | HIA LTO median process ms | Rust PGO median process ms | Time ratio | HIA batch P99 ns | Rust batch P99 ns |
|---|---:|---:|---:|---:|---:|
| IEEE | 14.755458 | 12.088423 | 1.220627 | 428709 | 312219 |
| Castagnoli | 13.664657 | 12.744003 | 1.072242 | 546417 | 290725 |

`performance_advantage_gate` is **false**. P95/P99 summarize batches of up to
4096 input bytes, not a service request SLA. Process time includes supervisor
launch and waiting; the report separately retains reading, loading, checking,
monitoring, switching and recovery observations. The host was shared, so these
are descriptive observations without significance or universal-superiority
claims. The user's dot workstation was not observable.

Preparation is charged and retained: capture/lowering 9.755765 s; default HIA
build 0.470982 s; HIA native LTO build 0.184524 s; Rust LTO build 4.377687 s;
Rust PGO build/training 7.073578 s; maintenance 23.745080 s; the original
`whole_qualification_wall_ns` field records 62.485700 s inside `run()`.
Review found that this old field omits constructor source hashing, upstream
verification and project copying; their duration was not measured and is not
retrospectively invented. The IR PGO follow-up explicitly adds an initialization
timer. These shared-host wall times are not engineering person-hours and also
exclude outer Python startup/imports, toolchain acquisition and human work.

## Inspecting the complete records

`SUMMARY.json` gives the direct machine-readable result. `INDEX.json` binds
lossless fragment datasets for the entire qualification, full process ledger
and raw-file inventory. Every JSON value is retained. The native differential
ledger and source-bound unit-test log are included directly.

```sh
python experiments/hia_legacy_queue/results_20261028/inspect_evidence.py
```

All three datasets reconstructed successfully. The separately retained raw
directory has 243 files totaling 10,555,749 bytes, including actual native
images and consumed compiler output. The raw attachment also preserves the
original local Git history needed to resolve measured commit identities.
