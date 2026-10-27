# Typed C caller repair: preserved counterexamples and corrected controls

Two separately compiled C observation harnesses lacked the declarations for
their `uint64_t` entry points. GCC accepted the calls with an implicit-function
warning and treated the return as `int`. Actual retained executions demonstrate
that the old callers lost the upper 32 bits and sign-extended the lower 32 bits.
The repaired callers preserve both high-value test vectors, and the production
strict flags reject the undeclared calls at compilation.

This appendix preserves **two distinct frozen repair attempts**. Neither the
historical source candidate nor the first repair attempt was rerun to generate
the second attempt. The archive reviewer only reads bytes, Git objects and
integer data. These are caller ABI controls and targeted test records, not a
complete candidate qualification or new performance samples.

## Source identities and actual observations

Both probes use legacy source from
`44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314`. The fixes form two consecutive
commits; their fixed source identities remain separate:

| Caller | Fixed source commit | Fixed Git tree |
| --- | --- | --- |
| Composed owners | `5b1eb7096062a9b8619aadbeafa06d7bc9c568cb` | `cb264223a73844591127ce688fa4f2679f6e0048` |
| Single owner | `a1ade3cc2bf4a3b3eabd87f82ba6c8c515215e49` | `a66ecada21e9cf0dea2f9eded90b7f3ca722062a` |

Each probe independently retains its source snapshot before and after, legacy
and fixed harnesses, synthetic callee source/object, generated case header,
all process arguments and output bytes, and both linked executable files.
The six recorded source-file identities in each snapshot match the immutable
Git objects, and each before/after pair is identical with clean tracked status.

| Actual control | Composed caller | Single-owner caller |
| --- | --- | --- |
| Expected first return | `0x2656789aabcdef0f` | `0x2656789aabcdef05` |
| Legacy actual first return | `0xffffffffabcdef0f` | `0xffffffffabcdef05` |
| Legacy link result | Exit 0, implicit declaration warning | Exit 0, implicit declaration warning |
| Legacy execution | Exit 2, value mismatch on case 0 | Exit 2, value mismatch on case 0 |
| Fixed execution | Exit 0, both cases correct | Exit 0, both cases correct |
| Fixed observation digest | `5183b7b35f069fae` | `bcd7b49e5dbe4aca` |
| Strict flags with old harness | Compile exit 1, no output executable | Compile exit 1, no output executable |

The second expected return is `0x2eef8807deadbee1` for the composed caller and
`0x2eef8887deadbeeb` for the single-owner caller. The independent reviewer
recomputes both expressions and their FNV observation digests using Python
integers. The old result is verified to equal sign extension of the expected
result's low 32 bits. The legacy executable stops on the first mismatch; the
fixed executable exercises both cases.

The two callee fixtures use the high `size_t`, `uint8_t` and `uint32_t`
arguments as arithmetic data. They allocate no resource. This keeps these
caller controls distinct from the unchanged migrated resource workloads:
437/613/833 composed cases and 475 single-owner cases. Existing resource
oracles and performance protocols were not relaxed by these repairs.

## Code review findings

The composed C declaration is exactly
`uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t)`.
The single-owner declaration is exactly
`uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t)`.
The parameter and return types match their generated exports and independent
callees on the qualified 64-bit host.

The standalone LLVM route compiles the C caller as a separate translation
unit. The earlier three-route C validation concatenates generated C before
its harness, so that route already has the typed function definition in
scope. The new declarations are compatible with those definitions. The
original C++ wrappers already declare their C-linkage entry points, and the
Rust harnesses use their own typed declarations. The defect and evidence
therefore concern the separate C callers of the direct LLVM routes.

Both production link commands now reject implicit function declarations,
implicit integer types and non-prototype declarations. The producer and
receipt validator share `_link_command`, so the same strict argument list is
required when reviewing a recorded link. The harness and qualifier are also
part of the input identity. New negative receipt cases remove the strict
implicit-declaration flag and require rejection. The actual negative ABI
tests remove the prototype from a temporary harness and invoke the same
production flags; they cannot obtain a passing result by merely asserting
that the flag exists in source text.

The independent read-only review found no blocking defect in either repair.
It verified all 14 process records, 28 raw stdout/stderr files, and 6 retained
ELF files across the two probes. It did not invoke the compiler, a qualifier,
an emulator, or a native executable. `review.json` contains the independently
derived source, stream, return-value and test-denominator results.

## Targeted test logs

These are four separately retained test runs. They overlap and must not be
summed into a unique-test count.

| Associated repair state | Actual test run | Tests | Skips / failures / errors | Terminal seconds |
| --- | --- | ---: | --- | ---: |
| Composed fix | Caller controls | 2 | 0 / 0 / 0 | 0.185 |
| Composed fix | Composed migration/LLVM suite | 25 | 0 / 0 / 0 | 42.806 |
| Both fixes | Both callers' controls | 4 | 0 / 0 / 0 | 0.314 |
| Both fixes | Selected caller/owned/composed suite | 21 | 0 / 0 / 0 | 25.201 |

All four original logs have terminal `OK` summaries. They do not embed a Git
commit identifier; their association with the repair worktree is supplied
by the operator's execution record. The frozen probe reports provide the
explicit before/after source identities. The standalone verifier preserves
that distinction rather than treating an unlabelled unit log as an
independently signed source-bound qualification.

## Historical warning scan

The original audit script and its output are retained in `originals/`.
The audit examines exactly **46 top-level JSON files** from frozen source
`3a424e427b378400802c9e3c2fef558c0a352756`, recursively visiting their `stderr`
fields. It records **10 matching stderr records**: 9 in
`cpp_composed_llvm.json` and 1 in `cpp_owned_llvm.json`. Every report's byte
count and SHA-256, each matching JSON pointer and line, and each full stderr
text hash remain in the original audit result.

The archive reviewer independently reread those same 46 original reports,
checked all their identities, and reproduced all 10 findings. This actual
read-only replay is recorded in `warning-original-replay.json`. The scan
does not cover hidden compiler logs, stderr absent from these JSON files,
or other historical runs. A zero additional match in this defined scope
does not establish that all C callers in the repository are correct.

The 46 original JSON files already belong to
`evidence/resource_composition_20261026/source_candidate/`; they are not
duplicated here. A byte-identical copy of that archive's member manifest
binds each report identity to its existing retained member. Default local
verification checks this reference and the audit inventory. The optional
`--warning-report-root` mode rereads all 46 original files and independently
recomputes the warning scan. These two verification modes are reported
separately.

## Archive and reproducibility

`caller-originals.tar.xz.b64` retains **70 members / 441,628 bytes**, including
the complete two probe directories, both original probe scripts, six original
run/driver logs, both commit diffs, and source bytes for changed receipt tests
that the probe snapshots did not already contain. It includes all **6 ELF
files / 69,592 bytes**. The archive was compressed once with single-thread
XZ preset 6 into 49,388 bytes, encoded as one 65,853-byte base64 file. File
permission bits are retained; USTAR owner and timestamp metadata are
normalized. The verifier reads members in memory and never extracts or
executes them.

`source-proof.json` retains the raw Git commit and necessary tree objects
for the baseline and both repairs. Twenty source-byte bindings include the
snapshot inputs, both exact baseline qualifiers/harnesses, fixed harness
copies, and additional changed test files. The verifier follows those
directory objects to each blob ID and checks the retained bytes against
both Git SHA-1 and SHA-256. This is a proof for the relevant retained source
files, not an archive of the complete repository or every compiler binary.

From this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py
```

To also replay the warning scan from the existing frozen source-candidate
originals, including originals decoded from that separate evidence archive:

```sh
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py \
  --warning-report-root /absolute/path/to/artifacts/composition-candidate-20261026-run1
```

Only the Python standard library is required. The expected sidecar inventory
and hashes are in `MANIFEST.json`; the expected archive inventory and hashes
are in `archive.manifest.json`. `verification.json` records the final offline
verification. `verification-with-warning-originals.json` additionally records
the actual 46-report warning replay. Integrity is ultimately anchored by the
Git commit containing this appendix; a self-contained manifest is not an
independent execution signature.

Passing these controls closes the demonstrated caller-width defect within
their scope. Historical qualification reports remain unchanged and do not
qualify the repaired callers. A complete new candidate still needs its own
qualification. No full-project blocker closure, general C/C++ source
equivalence, physical-platform coverage, or universal performance result is
asserted by this appendix.
