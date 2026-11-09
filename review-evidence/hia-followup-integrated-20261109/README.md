# Integrated v14, supplied-image and cost replay follow-up

Base: #816 merge `20eace37747fde9aa0fc9c14cdb0159db30f5161`.
This selectively includes the fifteen new scalar-control study/integrity files
from #812/#814, bounded boolean equality/inequality, independent Safe Core
wrapping multiplication, bounded repository snapshot reads, and complete
prepared/persistent timing-containment repairs.

The combined test run used local code commit
`2848ec59c344b340b341afb01d5515a501496cda`, tree
`4d1cc76365e0ae37228fc2e59d0d77bbe10202e4`: **177/177 tests passed** in
15.341 seconds, with no failure, error, skip or expected failure. The count
includes the three real native stream tests and overlaps component counts.

The separate **105/105** native boolean-equality checks passed in
20.382286048 seconds. Their complete 252-file source manifest still matches
the final source, including the generated v14 contract. They retain actual
baseline rejection, B0/B1/B2/B3, M1/M2/M3, dynamic and negative inputs,
ELF/flat comparisons and short-output observations. This is finite evidence.

## Native provenance and the earlier incomplete local check

The stream tests used original artifact `13645004336` from successful run
`42550772601`, source `39ae467a5806a9c969133e6e8801f83c96f246aa`.
The 8,087,531-byte ZIP matches its official SHA256
`17d95cb5dc80380c05ff3d0c4e8bd7c3722f4a44b86810b08642d01d381d9d52`;
all 475 members passed CRC. Existing `_bridge_identity` checked its executable
and receipt against this source's adapter, builder, dependency lock and
upstream pins. This reuses the original build; no new build was performed.

An earlier local 48-test invocation lacked those native paths: 45 succeeded,
three native tests were skipped, and the explicit no-skip assertion exited 1.
That invocation remains unqualified. Supplying independently recovered original
bytes enabled a separate three-test pass and the final 177-test pass; it does
not relabel the earlier result.

## Original evidence and scope

`raw-qualification.zip` is 3,092,965 bytes, SHA256
`eb3fd0aa4a29c8579c9d0cd90d1b0ac37e5c575c5a5a246338ab81ae6af6c80e`.
All 685 ZIP members passed CRC; the 683 regular-file members were compared
byte-for-byte with original local files. It contains all 105-check child
artifacts/logs and complete native-stream and 177-test logs. The qualification
report SHA256 is
`002d3f58fb4feb31f49e0abcb382c717ed0c1ceb1bd256df8ba8bfc718106632`.

Earlier failures remain in their original component directories: the initial
boolean fixture error, unsupported multiply tests, snapshot accounting control,
sparse fixture errors, and cost arithmetic/containment counterexamples. The
added exact-source CI step replays the original scalar 64-pair measurements
without new evaluator or provider calls.

General Core, whole-compiler correctness, general resources/FFI and a complete
ISA/loader theorem remain unproved. The original stranger-Agent extension still
lacks its old-domain/new-domain proof contract, formal adoption and provider
bill. Internally consistent cost measurements do not establish complete
lifecycle/monetary costs or stable NDU economic benefit. Six-track acceptance
remains **HOLD**; published-source CI is an independent gate.
