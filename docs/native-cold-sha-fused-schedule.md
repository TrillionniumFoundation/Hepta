# Native SHA schedule and round fusion

This is a qualified SHA component checkpoint. It does not declare the whole
180 second cold replay, final installation, or native-only activation complete.

The nonalias HIA implementation now generates schedule words 16 through 63
in groups of four, stores every word at the original workspace offset, and
performs the corresponding rounds immediately. The computed word feeds its
round directly. The first sixteen message words and the first four rounds
retain the existing handling of arbitrary full-u64 chaining values.

Only local round state and reads of disjoint round-constant storage move
across schedule stores. Final chaining writes remain after all rounds.
The checked-in foreign-view dispatcher, original alias fallback, and native
image packer are unchanged. No new native seed, helper, accepted extent,
hash omission, execution cache, or proof authority is introduced.

## Actual artifacts

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Composite | 116455 | 214aea20ce10da438d1a96e98b0a25ed1151776e1fd577047c336d57cd54ae19 |
| Nonalias flat | 51778 | 20fe349b39b97d977648a638ebff73ee1f109b6d719499e47d13ddd50abf66c0 |
| Original fallback | 64588 | 30f72e80f11d72b7a991304b4218a59232d7607dd6a399c7cc13bcb3ba8a0bd3 |
| Dispatcher | 89 | f8854771debc2f88f8d51d1cdf3b55b2766fc5094531547169b2dd267b969f0b |
| HIA source | 54403 | 3c46f59b647de5998f71e995c0496b110bf9138a50f6ade926f445a1345d4ce0 |

The adjacent JSON records the actual source pins, qualification evidence
hashes, and the interleaved benchmark. Native source construction uses the
existing assembly, projector, filter and endian toolchain, with the actual
checked-in source as input; the candidate is not used to build itself.

## Completed component checks

- 27043 SHA transition checks compare all 1184 state bytes, including original
  VM cases, FIPS vectors, padding splits, random partitions, arbitrary full-u64
  state, 8 MiB input, concurrent states, and digest/copy/reuse.
- 2000 offset-alias checks compare the entire owning memory allocation.
- 51 native packer checks include exact extents, short views, atomic refusal,
  mutated headers, and actual composite bytes.
- 5894 mechanical foreign-view routing checks preserve the alias fallback.

Eight alternating old/new and new/old 8 MiB measurements compare against the
previous qualified ca44949d component, not the much older reference image.
Median process CPU time was 141335661.5 ns before and 133805129 ns after,
a 1.056279849 ratio (about 5.3 percent less CPU time). This is a microbenchmark;
actual cold driver, archive, and master acceptance remain separate gates.

A fully expanded schedule passed semantics but was slower (0.874 ratio).
An intermediate chunk-of-16 variant was also slower. Their development
evidence remains outside this source checkpoint. They were not adopted.

## Reproduction and limits

Use tools.qualify_hia_cold_sha256_stream against the original pinned oracle,
tools.qualify_hia_cold_sha_offset_alias with the two actual images, and
tools.qualify_hia_cold_sha_alias_packer with the fixed fallback and actual
nonalias flat. Evidence locators in the JSON identify the exact invocation
outputs and hashes. Python here is a development author and external test
observer; SHA computation in the tested candidate is HIA-native.

This checkpoint changes only the HIA SHA implementation. It does not change
the 180 second execution deadline, the three second cleanup allowance, cold
phase inventory, capacities, concurrency, archive hashes, or custody rules.

## Actual archive consumer

The same V8 archive policy (234402 bytes, dfcf80c0677bc093e07053828a6415bd2f3d41d71ce269ffb07809b01b5d2df0)
and packer were rebuilt and compared byte for byte with the prior qualified
consumer. Only SHA changes in the new 351684 byte image, whose SHA-256 is
5950a07041ac24b5e2c381011c472627827d2121b9afc9e97fa763113a3edd54.

All 19 original archive controls and 19 AZ02 controls pass, including actual
concurrent external writes to the archive, an input and the journal. Six
alternating actual original-chain archives match all 28828792 bytes and
SHA-256 7698544aa6b8897d67ddd4df309246f4aad45f57dfd4f9722fb07aab02a75bc7.
The median component wall time is 3.25695389 seconds before and 2.984196146
seconds after (1.091400742 ratio). This is an archive consumer result; the
whole cold replay remains a separate unsatisfied gate at this checkpoint.
