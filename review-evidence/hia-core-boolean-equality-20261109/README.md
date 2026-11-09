# Boolean equality admission, bounded selfhost profile v14

Base: `20eace37747fde9aa0fc9c14cdb0159db30f5161`, tree
`d6ae9ae842c61682917fff8e2538ff9fba3c0056`.

The native compiler previously rejected matching `bool` operands for
`compare.eq` and `compare.ne`, although those signatures are accepted by the
independent general Core checker. The v14 compiler admits these two forms and
keeps unsigned-only ordered comparisons. The source contract, language inventory,
Agent discovery expectation and documentation all name the new profile; the
historical v13 qualification documents remain historical records.

`source-tests-final.log`: 34 tests passed in 24.626 seconds, zero failures/errors/
skips. This covers the selfhost source, complete declared source inventory,
general Core reference oracles and actual discovery of the new contract.

`qualify.py` is a small replay entry point. Its successful second run passed
105/105 checks in 24.691559573 seconds. B0 is explicitly built with the Python
seed path; B1/B2/B3 and M1/M2/M3 are compiled by the preceding HIA image.

| Generation | SHA256 |
| --- | --- |
| B1 = B2 = B3 | `2b1bd02faf752e881765d88223b8511376d792a583b1548a8939a824d1228204` |
| M1 | `a5c50bc496d29a8090f2f035a46e21278d2aa3049e2fa6dca4649bdcbcfe5922` |
| M2 = M3 | `54dbaca15d9ace78e676291a20019286df0ee9f3a957da19bc0b3b4634be1de7` |

The unchanged baseline compiler actually rejects both valid bool comparisons.
The new B3 and M3 each compile both operations and run 32 input cases, with
both boolean operands decoded from input bytes selected from 0, 1, 2 and 255.
The qualification also retains 26 malformed-comparison refusals, four short
output-capacity refusals, and four matching flat/ELF text comparisons. Native
result values, unchanged source/output bytes, child logs and invocation receipts
are retained. The successful report binds all 252 selfhost source entries.

The first run is retained as failed: its replay script supplied the unsupported
format name `shared-library` instead of the existing `seed-shared`. The child
refused before B1 execution. The corrected script and fresh second directory
retain that failure independently; no runtime implementation changed to accept
the invalid format. A separate remote generation/source-test request on x230
timed out twice during identity recovery; no remote completion is claimed here.

`raw-evidence.zip` contains both complete local attempts and their generated
source, machine images, input/output bytes, reports and logs. All 701 original
members were rehashed against `FILES.json`; ZIP CRC verification passed.

- ZIP bytes: 3,393,683; members including `FILES.json`: 702.
- ZIP SHA256: `ed11869940765d6741b8976b8ecd3ad3c3a5eac1eb16104d7c058294136ffe21`.
- Compiler source SHA256: `fd5bbef58afa78dbfd7a61c5f1a35e149aae8663beee63b907c8678a8b3505b1`.

Run from this source checkout with a new output path:

```sh
python -B review-evidence/hia-core-boolean-equality-20261109/qualify.py --output /tmp/new-boolean-equality-evidence
```

This is finite source-bound evidence. General Core types, module/identifier/
effect combinations, arbitrary result shapes, full compiler/ABI/allocator/ISA/
loader correctness and the six-track aggregate acceptance remain open. The
public release lock and online configuration are not changed by this patch.
