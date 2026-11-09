# Bounded native u16 self-hosting qualification

Implementation `ba1573ed9a873400a79f7abf0ad81db3e9b38b24` extends the
`ffa64c93dd4c51190fda8c0f647481a31ffbcf07` compiler with unsigned 16-bit
scalar semantics. Candidate `4138e0126fce634cb60498083ff7baec395c9f89`
also updates the native discovery test to expect the v14 support profile.
The declared limits and fixed borrowed-buffer entry ABI are unchanged.

## Observed results

| Qualification | Result | Scope |
|---|---:|---|
| Source, contract and independent Core-VM unit tests | 33/33 | Includes a separate temporary cold replay |
| Native discovery through the actual IPC client | 1/1 | Reads the v14 support contract |
| Retained source-only cold replay | 11/11 | 120.637 seconds within the existing 180-second computation and 3-second cleanup limits |
| Nested original/modified compiler qualification | 1215/1215 | Complete existing qualification families plus u16 select witnesses |
| Native language qualification | 1026/1026 | 89.743 seconds; B3 and M3 each compile 78 positive programs, 262 refusals and 170 runtime-trap programs |
| Independent scalar observations | 1050 | Mathematical integer/boolean results compared with the general Core VM before B0 |

The counts describe overlapping qualification layers and are not added as
independent tests. The original and modified compilers have these exact image
identities:

| Images | SHA-256 |
|---|---|
| B1 = B2 = B3 | `dceb53202787e6ce52eeb44f039aaecc8823ed80d2ee62fbb03a995d4d5a1bce` |
| M1 | `2c23eaaded0bdcced0b08ae9021bea81993e78915f469af8fa1f15e1fb1551c2` |
| M2 = M3 | `240fbe1ab7431acfd9eb66190f0e58ae23aafee9d420189845d4b87dad3546ef` |

Each image is 729,964 bytes. The generated HIA compiler contains 87 functions,
5,959 instructions and 1,515 blocks, inside the unchanged 128-function,
8,192-instruction and 1,536-block limits. Both cold and language runs retain
the same 252-file source manifest, which was also rehashed against the candidate.

## What changed

The compiler accepts `u16` constants, all existing unsigned arithmetic and
bitwise operations, comparisons, wrap casts, selection, helper parameters,
block arguments and single scalar returns. Narrow arithmetic normalizes to
16 bits; checked addition/multiplication detect high-bit loss, and checked
shifts reject amounts of 16 or more. The scalar code follows the resource
codes, so every resource/owner classification remains a closed range or set.
Repeated scalar call/edge arguments and swapped tail-call arguments are tested;
attempts to use a u16 value as an owner or loan are transactionally refused.

## Evidence and replay

`summary.json` binds the implementation, source manifest, original report ZIP,
and individual original report/log bytes. `original-reports.zip` contains the
unaltered cold report, the complete nested qualification report, the complete
language report, the unit/discovery logs and a member SHA-256 manifest. The
per-invocation input/output files and native images are also retained in the
execution workspace; the ZIP contains the reports and logs, not those files.
These are local process observations, not host attestation.

From the exact candidate, use fresh output paths:

```sh
python -B tools/generate_hia_selfhost_contract.py --check
python -B tools/replay_hia_selfhost_cold.py --output /tmp/u16-cold.json
python -B tests/test_hia_selfhost_language_coverage.py --output /tmp/u16-language.json
python -B -m unittest tests.test_hia_agent_native_tools.ArtifactContractTests.test_discovery_is_readable_and_source_bound -v
```

## Remaining obligations

This closes the missing unsigned 16-bit scalar support within the bounded
profile. It does not establish complete Core self-hosting or a compiler
refinement proof. Signed scalar types, returned owners/loans, general
multiple-result calls/returns, general modules/identifiers/effects/linking,
and general ABI/resource/FFI/ISA/loader correctness remain open. Fifty covered
opcode names do not establish all-input coverage. This record does not select
a public release, deploy a worker, or turn the six aggregate gates into PASS.
