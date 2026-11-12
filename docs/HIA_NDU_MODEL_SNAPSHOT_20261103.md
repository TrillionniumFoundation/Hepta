# NDU finite-model preparation: bounded snapshots

The public Python preparation path is faster while keeping the existing finite
cost model, complete decision witnesses and native request bytes unchanged.
This does **not** establish a native NDU advantage, application speedup or full
lifecycle net benefit. Native invocation counts in this experiment are zero.

## Change and bounds

`validate_model` previously serialized an in-process model with the general
bounded JSON encoder, scanned that generated text with the general HIA JSON
preflight, decoded it, and then validated the finite model. Profiling identified
this round trip as the dominant preparation cost. The actual model has at most
two optional artifacts, four batches and a fixed inventory of fields.

The replacement snapshots only these schema-defined records and arrays before
running the same cost, identity, validity, budget and resource checks. Record
copies inspect at most `field_count + 1` item pairs; array copies slice at most
`maximum + 1` entries. The copy operation itself remains bounded even if a
caller grows a container after its initial length check. Exact builtin types
exclude conversion hooks. Unknown fields, duplicate residency, unsupported
types, invalid hashes, negative or excessive costs, invalid horizons and memory
quota violations still fail closed. Malformed status containers now produce
the cost-model rejection instead of an incidental unhashable-type exception.

Every mutable record and array is detached. Sharing an input list does not
create shared mutable lists in the admitted snapshot. Tuples retain their
previous JSON-array compatibility. Record keys retain the old sorted order,
including when callers serialize the snapshot without `sort_keys=True`.
Textual JSON decoding elsewhere in the system is unchanged. There is no cache
that could reuse a stale caller object, proof or native artifact.

## Frozen comparison

`benchmarks/hia_ndu_cost/MODEL_SNAPSHOT_PROTOCOL.json` registers 256 declared
models with seed 41101683, horizons 1–4, one or two artifacts, one warmup sweep
and eleven alternating paired sweeps. Its complete bytes are pinned in the
qualification tool so zero cases or other altered registrations cannot pass.
The exact previous implementation is stored beside it, bound to source commit
`18291446e048f760f5519823e865727ef51db11a` and SHA-256
`49f90825eea7a97309025555fd6af2c93f25561a14d45b40eb2304fd7313272c`.

Before timing, every case must satisfy all of the following:

- The validated snapshots agree with the frozen implementation.
- Complete exact witnesses, ties and search counters agree.
- Complete native request and plan bytes agree.
- All first-action minimum costs agree with an independent exhaustive schedule
  enumerator, both before invocation and after the current call is committed.
- Caller input remains unchanged.

The final run passed all 256 cases. All 66 timing samples are retained. Each
timing sample is a complete sweep of 256 public calls, including validation.

| Public operation | Baseline median per sweep | Snapshot median per sweep | Reduction |
| --- | ---: | ---: | ---: |
| `validate_model` | 144.061 ms | 13.021 ms | 90.962% |
| `exact_control` | 168.619 ms | 31.285 ms | 81.446% |
| `build_request` | 221.468 ms | 84.206 ms | 61.978% |

These measurements come from one shared Linux cloud environment and describe
Python model preparation only. The final report also retains p95 and total
observed time; no sample was removed. Startup, native evaluation, application
execution, tool acquisition, human engineering and energy are not measured.
All native authority remains `DENY_ALL` and `safety_certificate` remains false.

## Evidence and reproduction

The complete final registration, corpus, checks, samples and result are in
[experiments/hia_ndu_model_snapshot_20261103/final/](https://github.com/TrillionniumFoundation/Hepta/tree/06b1e9b284f612c47a2205e79c8685d8b366d9de/experiments/hia_ndu_model_snapshot_20261103/final). Two earlier implementation
observations are retained under `initial/` and `bounded-copy/`; their changed
source files are preserved against their recorded hashes. The final run is
selected because it contains both bounded copying and sorted-key compatibility,
not because it has the best result. The older budget-erasure experiment and its
protocol remain unchanged.

```bash
python3 -m unittest tests.test_hia_ndu_model_snapshot tests.test_hia_ndu_cost \
  tests.test_hia_ndu_current_profile -v
python3 tools/qualify_hia_ndu_model_snapshot.py --output /absolute/new-directory
```

The final 38 related tests pass. Coverage includes independent frontier
enumeration, exact budget boundaries, status/invalidation handling, caller
isolation, tuple and key-order compatibility, mutated leaves, oversized/cyclic
data, conversion hooks and altered registrations. Controlled growth tests
inject changes between the initial size check and the copy: record/array copies
remain bounded at 14/5 entries and reject the expanded input. Unknown or
substituted fields are checked at every record level. The three final review
tests were added after timing; their predecessor bytes remain in the final
evidence alongside both test logs. The measured implementation is unchanged.
