# Loaded-mapping fix: preserved NDU evidence and current byte correspondence

The original finite-graph experiment remains unchanged. This directory records
an additional identity audit after fixing the actual Linux loader cache issue:
a closed numeric memfd can be reused while `dlopen` still retains an older
mapping for the same `/proc/self/fd/N` pathname. Hashing the new fd alone did not
identify the function returned by the loader.

The fix checks every resolved entry's actual executable mapping against the
still-open, fully sealed fd before calling it. Adaptive scalar loading checks
its entry; the owned-state driver checks all 14 exports. Failure releases the
loader reference and descriptor owned by that admission attempt.

## Evidence retained

`../run_20261028.tar.xz` is still exactly
`0b9d0824e59b8f07db67078996c8eebee02bcacb19b96c701f4a8fc89f736a1b`.
Its original `SOURCE_IDENTITY.json`, all native artifacts, proof obligations,
candidate requests, NDU responses, timing records and failed probes were not
rewritten. The original aggregate `RESULT.json` is still
`16ec2b60ca2e43095bf780cd429fca6eef69046bbabe7daed6c5c9097952938b`.

`AUDIT.json` was produced by the accompanying `verify_rebinding.py`. The audit:

- Re-read all **218 archive members**, checking their individual SHA-256,
  size and mode against the preserved manifest.
- Compared every archived source to its recorded digest and the current tree:
  **119 of 121 existing source entries are identical**. Only
  `hia_adaptive.py` and `hia_stateful.py` changed; `native_mapping_identity.py`
  is new. `SOURCE_DELTA.patch` shows that the two differences concern loading,
  its identity, diagnostics and cleanup.
- Regenerated the baseline canonical Core from the unchanged source. It also
  regenerated both finite guard proposals and structurally composed their
  canonical Core. Current LLVM emission has the **same three LLVM hashes** as
  the historical build receipts.
- Checked **27 native receipts**, including all actual episode builds, and
  their exact archived machine-code files, verification digest and complete
  compiler/Core/proof/artifact binding.
- Rehashed **1,342 saved successful SMT obligation records**, plus the
  **17 saved obligations** for the refused unguarded body. The refused body
  still has no native artifact; its saved last obligation is `sat`.
- Checked the archive identities and recorded checksums of all **99 successful
  execution samples**: 27 calibration samples and 72 episode samples.
- Verified that current Clang executable bytes, Z3 library/binding bytes,
  both proof checkers, the native backend, the NDU executable and all **93**
  recorded native source files still match their historical identities.
- Sealed each of the three preserved candidate shared objects into a new
  memfd, loaded it, and applied the current mapping gate to both exports.
  Those three admission checks passed. They made **zero workload calls**.

This audit did not invoke an SMT search, compile a candidate, rerun a NDU
decision, or measure a workload. It issued no new optimization proof receipt.
The deterministic guard reconstruction in the audit uses internal structural
helpers only to compare bytes; production deployment continues to require the
complete `verify_guarded_optimization` / build path.

## Exact compiler and runtime distinction

The following implementation identities remain identical:

| Component | SHA-256 |
| --- | --- |
| Ordinary optimization checker | `78694a5f57a303f576dd9b5430498affc9d65e7fa93d639721a940cf66554f12` |
| Guarded optimization checker | `6c6df88ddca7e8ed64eff8adb26f0bc434cac63f180bdedb2091dd2db1a66acf` |
| Core verifier / LLVM backend build identity | `0519011099263210f3f0e9c0ad11c0dc4586fdaf079c6df16746ba49cc4a3ef9` |
| Native NDU executable | `3f9533298792d443cedc0b224dc5577a2ef49cf68be74fb2cc611705935e1883` |

The native NDU source commit remains
`4b6391e116949af0c7e59776baead67271856bdb`.

The complete source inventory and the adaptive/stateful runtime identities
**changed**, as they should. `AUDIT.json` records their exact old and current
hashes; it does not relabel an old snapshot as current. No historical receipt,
serialized mapping record, NDU choice or this audit grants deployment authority.
A new deployment must independently verify/build, obtain a new receipt, and
pass current sealed-file mapping admission. A successful load-only audit is
not admission to the adaptive scalar profile or to arbitrary live-state migration.

The old NDU performance conclusion remains a historical result for the exact
preserved compiler, candidate bytes and fresh-process C driver. The driver
performs one `dlopen` per new process and closes its reference; it does not
exercise the persistent numeric-fd loader cache that this fix addresses.
No claim about the performance of the newly fixed adaptive/stateful runtime is
transferred from that experiment. NDU still established **no net advantage**:
its recorded median episode cost is 1.018801444 seconds, versus 0.967017653 for
complete lightweight DP and 1.027231604 for the strongest fixed plan. Fully
allocated NDU cost remains 20.026992679 seconds per episode under the declared
setup accounting. No timing or NDU choice was replaced by an audit result.

## Mapping-gate regression and reviewed boundary

`NATIVE_MAPPING_REGRESSION.log` and `.json` are exact copies of the actual
focused run: **18 tests passed, zero skips, 11.268 seconds**. The new isolated
negative control retains a previous library with the same export name but
different machine code, closes its fd, and forces numeric reuse. Production
admission rejects the actual cached old mapping before any call through it.
Normal admission subsequently executes the new implementation. Further
controls cover unavailable `/proc/self/maps`, driver reuse and cleanup;
existing adaptive/owned-state tests cover normal execution and lifetime gates.

Review found no additional counterexample within the qualified Linux profile.
The check deliberately requires a unique private, readable, nonwritable
executable mapping, matching device/inode, an in-file entry offset, and all four
file seals before and after reading the mapping inventory. A missing,
oversized, malformed or mismatched inventory refuses admission. Display names
and mutable publication paths are not identity. Callers retain the fd and their
own loader reference through all calls; the helper does not transfer ownership.

Its assertion is actual entry-to-file-object correspondence. It does not prove
the dynamic linker's relocations, libc implementations, or a memory image
modified by a malicious Python host, debugger, or kernel. These remain inside
the existing trusted-host/loader assumptions. `dlopen` itself can process ELF
initializers before symbol inspection; the production callers therefore still
accept only internally built, independently checked artifacts, not arbitrary
producer-supplied ELF files. The gate does not widen that admission contract.

## Reproduce the audit

Use the qualified Linux Python with `fcntl` seals and the pinned Z3 binding;
retain the original archive, native bridge binary/identity and source checkout.
Run from the repository root:

```bash
PYTHONPATH=/tmp/hepta-next-z3-20261028:. \
LD_LIBRARY_PATH=/tmp/hepta-next-llvm-20261028/usr/lib/x86_64-linux-gnu \
/usr/bin/python3 experiments/hia_ndu_graph/loaded_mapping_rebinding_20261028/verify_rebinding.py
```

The command prints a new audit to stdout. It does not modify the original
archive or this recorded report. Current mapping inode values can change on
reproduction; file contents and the source/compiler/Core/LLVM identities must
match. `INDEX.json` lists the exact files and hashes delivered in this directory.
