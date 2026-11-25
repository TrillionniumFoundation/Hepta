# Native rank canonical serialization and unselected Core comparison

Two actual HIA roles passed 1290 cases: 420 JSON trees, 612 binary64 cases, 161 selected subtrees, three large transport cases, 17 atomic private refusals and 77 Core comparisons. The Core cases used 38 actual fresh native normalizations and the unchanged original remainder comparison. Large transport cases contain 100000 integer digits, a nine-MiB floating token and a string exceeding 64 MiB. Finite IEEE conversion/printing is the qualified CPython-compatible algorithm.

The canonical flat is 216748 bytes, SHA-256 2b9b658fd0c5211d020b60238472119f136075b3e89f638f84ed0ad7835f4fa0. The unchanged-Core flat is 108658 bytes, SHA-256 381902ad4e92287af2491e17ac92b7baca1ac036adeaa8af01d0ef694fb9869a.

## Canonical private ABI

The six-word entry consumes HIANJQ01/128. Words at 8/16/24/32 are action, selected node, source length and owned arena length; all other words are zero. Tail order is raw JSON then its fresh 72-byte-node arena. Work size is max(131072 + node count, arena bytes + 16384). Input, output and work are disjoint and owner-held.

Action 0 measures; action 1 emits after an internal measure. Return zero gives HIANKJ01/64 with full u64 output length at 8, root at 16, source length at 24 and arena length at 32. Emitted bytes start at 64. Short output refuses atomically with 0xfffffffe; nonfinite conversion is 0xfffffff0. Numeric lengths and output sizing do not pass through a u32 result. Object keys sort by decoded UTF-8 order and integers retain exact decimal value. The selected subtree cannot traverse its root's sibling. Caller business limits, typed integer limits and freezing rules remain separate.

## Unselected Core private ABI

HIANUC01/128 has name length at 8, before JSON/arena lengths at 16/24, after JSON/arena lengths at 32/40; remaining words are zero. Tail is function-name bytes, before canonical Core JSON, before owned arena, after canonical Core JSON, after owned arena. Work covers 131072 plus the larger node count. Return zero produces HIANUR01/64: equality at 8, reason at 16 (0 same, 1 module metadata, 2 other-function content, 3 remaining count).

Only freshly normalized canonical Core belongs here. Metadata outside the functions array and the ordered sequence after excluding the selected name are compared exactly. The selected function may be absent in the after program: the original remainder check permits that, while the subsequent fresh proof determines behavioral admission.

The reusable qualifier accepts explicit canonical, unchanged, decoder, normalizer, baseline and output paths. It uses original Python only as an external oracle. Source, flat and evidence digests are recorded in the accompanying JSON. These components do not establish full-rank or production closure.
