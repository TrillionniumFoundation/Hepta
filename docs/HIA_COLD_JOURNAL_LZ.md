# Bounded lossless HIAQAZ02 cold journal codec

This separate native profile adds an optional LZ mode to the existing lossless
cold-journal chunk format. It retains every original raw journal byte. The
original HIAQAZ01 source and executable are unchanged.

## Wire and memory contract

Every chunk keeps its 32-byte header: magic, raw extent, payload extent and
mode, each eight bytes. Raw extent is 1..65,504 and complete encoded extent
is 33..65,536 bytes. HIAQAZ01 accepts only modes 0 (raw) and 1 (original RLE).
HIAQAZ02 accepts those same modes and the new mode 2.

Mode 2 consists of literal tokens (byte tag 0, little-endian u16 length,
literal bytes) and match tokens (byte tag 1, little-endian u16 length,
little-endian u16 backwards distance). Literal lengths are nonzero. Matches
have length at least 8, distance at least 1 and no greater than current output,
and must fit the declared remaining output. Match copies advance forwards;
overlap is intentional. Distances below 8 copy byte by byte. Larger distances
use ordered eight-byte groups plus a byte tail. The decoder independently
checks all extents, tags, final output length and exact input consumption.

The encoder first produces the original RLE/raw candidate. If its payload is
below 64 bytes it keeps that result immediately. Otherwise an 8,192-slot u16
last-position-plus-one dictionary at workspace offset 3,276,800 identifies
previous equal eight-byte strings. The 16 KiB dictionary is cleared for each
chunk. The encoder uses a separate temporary candidate at 880,000 and only
selects LZ when it is strictly shorter than the already available original
encoding. Selected payload remains at 800,032; decoded output remains at
940,000. The standalone six-argument test entry requires 3,293,184 workspace
bytes. The production driver's existing 4 MiB workspace limit is not increased.

The decoder never reads the encoder dictionary or the original raw chunk.
Decoder-only callers therefore do not need encoder scratch. The new generator
exports CODEC, ENTRY and HELPERS for explicit driver/archive composition; it
does not modify their existing implementations or change their deadlines.

## Qualification

Both previous and new actual native flat images were independently constructed
from HIA source through the fixed original HIA assembly frontend, HIA projector
and original HIA seed backend. The target self-host compiler was not used.
The new source has 11 functions, 170 blocks and 992 operations; flat size is
61,328 bytes, SHA-256
717e624e71b35ab864e3fee853475f27c3a2769442ca5fec4fc3395e2e6f1d33.

All 3,251 recorded checks pass. They include all original 45 codec gates,
original entry/capacity refusals, chunk boundaries, 1,000 random and structured
chunks, 28 overlapping/distant-match cases, 81 raw/dictionary poison checks,
14 malformed LZ cases and 2,000 mutated grammar comparisons. A separate
specification decoder, without any encoder state, checks the exact accepted
bytes or refusal for every grammar mutation. A mutation that forms another
valid stream is compared as that stream; it is not falsely reported as a
required rejection. Unchanged input, output tail and workspace canaries are
checked on every actual native call.

The complete existing original-names journal was also processed, not only
selected samples: 59,855 chunks and 692,299,755 complete raw evidence bytes.
Each old chunk was decoded by the original actual native implementation and
the independent specification decoder. Each new chunk was encoded and decoded
by the new actual native implementation and compared to those same raw bytes.
After fsync, the complete new physical file was read and decoded again; its
physical SHA and full uncompressed SHA matched the values accumulated while
writing.

| Actual names journal | Bytes |
| --- | ---: |
| Complete original raw evidence | 692,299,755 |
| Previous physical file | 168,106,539 |
| New physical file | 88,818,778 |

Physical bytes decrease by 47.17%, without discarding or changing any evidence.
The external full-journal comparison and write/readback pass took 31.16 seconds.
That includes several observer and native decode passes; it is not a claim
about the end-to-end cold deadline or the cost of one production driver pass.

The final integration must still retain each native encode/decode byte check,
the running physical SHA, the fsync followed by actual file SHA, the archive's
node-stream validation and all existing SHA passes. The original 180 + 3
second whole-cold contract remains an independent acceptance gate.

## Reproduce

    python3 -m tools.qualify_hia_cold_qualification_codec_lz --old OLD.flat --new NEW.flat --output NEW_DIRECTORY --journal EXISTING_HIAQAZ01_JOURNAL

The adjacent qualification index contains all construction source/Core/wire/tool
pins, actual native image pins, detailed check groups and retained evidence.
