# Native compact-immediate qualification

The change selects the existing zero-extending MOV r32, imm32 encoding only
for u64 values below 2**32. The native encoder, register checks, REX handling,
flag behavior, bounds, edge transfers and call staging are otherwise unchanged.
An independent AST review found that `immediate` is the only changed function
in each generated cold profile relative to 6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807.

Both profiles were actually constructed using the four original pinned native
roots. Each passes 475 valid wire cases, 13 invalid wires and five actual SIGILL
controls including the exact bytes written before a bounds trap. B1 emits B2,
and B2 emits byte-identical B3. `qualification.json`, complete compressed case
observations and `construction.json` retain these finite results.

The bounded emitter observer alternates baseline and candidate order across
ten trials per tool. It compiles the same projected wire on both emitters.
These are component timings, excluding projection and process launch.

| Actual tool image | Baseline bytes | Candidate bytes |
| --- | ---: | ---: |
| cold_qualification_driver | 269660 | 252348 |
| cold_sha256_nonalias | 42958 | 40284 |
| cold_source_bootstrap_entry | 330326 | 309205 |

The raw timings and every image SHA are in `emitter-observation.json`. The first
observation harness requested a 4 MiB output/workspace, outside the seed's
original 1 MiB domain, and the native seed correctly returned 4294967293. That
failed harness, stderr, construction records and report are retained. The
published observer uses the original 1 MiB domain; no product bound was changed.

Reproduction from this source checkout, with the four pinned native roots in
`$BOOTSTRAP` and new output directories:

```sh
python -B -m tools.qualify_hia_seed_cold_backend --bootstrap "$BOOTSTRAP" --output "$QUALIFICATION"
python -B tools/qualify_hia_cold_seed_emitter.py --bootstrap "$BOOTSTRAP" --qualification "$QUALIFICATION" --baseline-commit 6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807 --output "$OBSERVATION"
```

Native source preparation passed after 53 successful native preseed calls.
Both construction-plan serializations agree byte for byte, and the actual
native contract producer regenerated the source identity. The source authority
still has 1284 entries, and the original 60 phases, 479882 nodes, fourteen
checks, 180-second cold limit and three-second cleanup limit remain unchanged.
The preparation checkout began at 6f7 with the reviewed component changes and
the three already-merged PR967 helper files overlaid. Publication builds on
2991919767a3924630418e645e0d7afccc63fd7a; this evidence does not mislabel that
development preparation as a clean run of the later publication commit.

`index.json` pins every retained evidence file. Full cold, release, installation,
installed rebuild, whole-stack rewrite and old-stack retirement remain open.
