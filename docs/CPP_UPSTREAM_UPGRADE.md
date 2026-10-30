# Executed C++ library upgrade: nlohmann/json 3.11.3 to 3.12.0

This qualification rebuilds and executes one unchanged Hepta caller against
two real, unmodified upstream C++ library releases. The exact single-header
release bytes and MIT licenses are checked against `tests/fixtures/cpp_upgrade/lock.json`.
The SHA-256 identities are the ones published in the upstream
[3.11.3 release](https://github.com/nlohmann/json/releases/tag/v3.11.3) and
[3.12.0 release](https://github.com/nlohmann/json/releases/tag/v3.12.0).
No network access is needed for replay after checkout.

## What is generated and what is authored

The same small authored C++ `Document` adapter parses a JSON object with an
integer array, replaces one element, sums it and destroys the JSON value.
Its domain is at most 64 integers with magnitude at most one million. It
instantiates and uses the actual upstream `nlohmann::json` implementation.
The adapter, explicit bridge contract and Hepta caller are counted separately
from the generated C++ wrapper, C declarations and Hepta FFI declarations.
This is library integration, not a JSON-library implementation rewrite.

The generator checks the actual native constructor and method types. The
selected scoped call contains the entire C++ object lifetime and returns a
copied scalar through the C ABI. The retained C++ implementation, pointer
validity and foreign behavior remain explicit unsafe obligations.

Both versions execute the same 98 independently expected cases: valid arrays,
range errors, replacement limits, malformed JSON and wrong JSON types. Each
case compares direct C++ with a C caller -> Hepta -> generated C++ bridge and
with a Python integer/JSON oracle. The generated public C and Hepta bytes and
observed C export symbols must match across versions. The implementation
source is compared after normalizing only the selected-header directory.

## Observed upgrade cost

The first v2 run measured the following on this Linux x86-64 host using GCC
13.3 and Rust 1.90. These are wall-clock observations, not performance targets.

| Operation | 3.11.3 | 3.12.0 |
| --- | ---: | ---: |
| Generate and native-check bridge | 3.596 s | 3.746 s |
| Check and compile Hepta caller | 0.144 s | 0.120 s |
| Compile and link C++ integration | 7.142 s | 7.841 s |
| Execute normal/error case batch | 0.00294 s | 0.00398 s |
| Complete per-version qualification | 11.155 s | 12.007 s |

The transition required **zero changes** to the adapter, contract and Hepta
caller. That does not mean integration was free: the report includes the
initial authored adapter/contract/caller line counts, actual generation and
build times, and the per-version dependency snapshots. Human review hours and
agent token costs remain `null`; they have not been measured. One compatible
upgrade does not establish a general upgrade-cost advantage or promise
compatibility with an arbitrary later release.

Headers including the standard-library closure are hashed before and after
execution. Dynamic runtime library paths and hashes are observed with `ldd`.
This is an observed content closure, not a hermetic lock on every compiler
component, loader, operating-system action or runtime input.

## Actual foreign destructor termination is retained

The first v1 qualification failed under real allocation-refusal injection.
That failure is retained as `evidence/CPP_UPGRADE_V1_FAILED_20261025.json`.
It is not overwritten or converted into a recovered call.

Protocol v2 runs every observed allocation point in a separate process, so a
terminating point cannot erase the remaining denominator. On **each** exact
release, the calibration observes 17 ordinary C++ allocation attempts:

- Sites 1 through 14 return the exception status, preserve the output
  sentinel, restore the ordinary allocation baseline and recover on the next
  call.
- Sites 15 through 17 terminate with `SIGABRT` after `std::bad_alloc`.
  They carry `recovery_qualified=false`; the report's
  `all_allocation_failure_paths_recovered` remains false.

Actual GDB execution for site 15 on 3.12.0 shows
`json_value::destroy -> ~basic_json() noexcept -> scoped bridge` in the
termination path. The upstream destructor uses an internal vector while
destroying JSON containers. A failed allocation in that noexcept path cannot
be made recoverable by the surrounding C++ catch block. The full captured
stack and binary identity are in
`evidence/CPP_JSON_DESTRUCTOR_TERMINATION_20261025.json`.

A passing *upgrade observation* report therefore establishes the stated
source/API/ABI/behavior comparison and complete failure observation, **not**
complete foreign recovery or whole-library memory safety. The report validator
rejects crediting any of those terminating sites as a successful recovery.
The original protocol-v2 run is preserved in
`evidence/CPP_UPGRADE_V2_FIRST_RUN_20261025.json`; later compiler changes need
a fresh qualification.

A separate [finite caller-checkpoint profile](CPP_JSON_CHECKPOINT.md) now
retains the parent integer-array state across an isolated failing invocation
and tests reconstruction by a new explicit request. It retains these six
foreign terminations as failures and does not make the C++ library a safe
rewrite or qualify arbitrary foreign-state recovery.

## Retained evidence in qualification schema v2 / protocol v3

The current producer writes `hepta.cpp-upgrade-qualification.v2`. Earlier
schema-v1 reports remain historical observations and cannot satisfy this new
gate merely by changing their version or compiler identity.

Each version has a row before native work starts. Completed source checks,
builds and process observations are attached incrementally. A middle-stage
failure keeps that row and its preceding stages; the other version is still
attempted. The allocation rows are created for the complete calibrated
denominator before fault injection. Each isolated fault records its own
outcome, including unexpected failures, before the version can finish.

The harness now has a separate `--calibrate` invocation of the same executable.
Its retained output supplies the allocation-site denominator. Normal execution
and calibration must agree, and the subsequent fault commands must be exactly
that binary with arguments `1` through the calibrated count. Rewriting a
summary count does not erase the independent calibration observation or its
raw output file.

Every external process executed by this qualification records its exact stage
arguments, executable hash, exit status, elapsed time and original stdout and
stderr bytes. The byte streams are retained as files, encoded in the receipt,
and hashed; timeouts retain partial bytes even when they are not valid UTF-8.
The validator checks all representations against one another, so a zero exit
from an unrelated command cannot satisfy a compile or execution stage.

The version directory retains the selected header, exact generated C++/C/Hepta
sources, copied authored Hepta caller, generated Rust source and consumer C
header, original generation/check/build receipts, native objects, static
library and executable. Validation reads and hashes those actual files. It
uses the existing frontend with native checking disabled to reconstruct the
current expected Rust text; the retained native check and static-library build
must both identify that source, the same current project, and the pinned Rust
toolchain. The validator itself does not execute the compiler or binary.

Full `-MD` dependency files are retained for the actual bridge and harness
compilations, including standard-library headers. Their complete parsed path
sets and current content hashes must match the recorded closures. The separate
before/after header probe outputs are also retained and parsed. `ldd` runtime
paths and hashes must match its entire retained output, and `nm` output must
contain exactly the generated C export symbols. A list containing only two
selected headers, or an invented runtime library path, is insufficient.

The successful report, version rows, process rows, artifact rows, calibration,
fault rows and upgrade-cost claims have closed schemas. Canonical comparison
distinguishes booleans, integers and floats. Cost observations include the
isolated allocation attempts and dependency observations; they continue to
exclude unmeasured human review and agent tokens. The report cannot claim that
zero changed adapter lines imply zero development effort.

These are **consistency checks on local retained evidence**, not authentication
of a third party claiming to have run a program. An actor able to replace the
whole file set and invent every observation cannot be authenticated by
self-computed hashes. The real qualification process, its recorded toolchain,
and its execution environment remain part of the evidence assumptions.

## Reproduce

```sh
RUSTC=/path/to/pinned/rustc python -m tools.qualify_cpp_upgrade \
  --workdir /tmp/new-json-upgrade-work \
  --output /tmp/new-json-upgrade-report.json

RUSTC=/path/to/pinned/rustc python -m unittest tests.test_cpp_upgrade -v
```

Work and report destinations must be new. The gate also actually compiles an
incompatible method contract, which must be rejected, and a generated
implementation with an incorrect result, which must fail native execution.
The regression suite checks stale source identities, missing versions or
allocation sites, altered native cases, forged recovery, missing dependencies,
invented generated identities, missing artifacts and inflated cost/safety
claims. The updated focused suite ran nine tests with zero failures or skips,
including 35 inconsistent-receipt mutations and explicit middle-stage,
nonzero-exit and timeout-retention cases. The native cases compiled and executed
both exact upstream versions; refused candidates were retained as refusals.

Validation requires the retained work directory as well as the JSON report.
Keep that directory until its source/ABI/behavior qualification is reviewed;
deleting its artifacts deliberately makes later consistency validation fail.
