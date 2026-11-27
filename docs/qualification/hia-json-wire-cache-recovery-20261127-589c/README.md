# Historical JSON wire cache recovery

This restores the missing HIAWIR04 immutable-summary cache, HIAWIR05 adjacent
key/value CHILD transport, and allocator-child dumpability setup from
`6ddb7d4bda799befdaf9c92f5e9586c71042cda9` onto the canonical source
`06d21f6032d7b3a946b1d6581a13c5cfd5fa4375`.

The current v9 word-load generator, ordered partial writes, current SHA-256
stream implementation, native-v2 contract, native transport/capture, and
release qualification logic remain in place. The qualifier changes only its
two JSON output calls to compact separators. The retained serialization control
checks complete source/AST preservation apart from those parameters and exact
parsed-field equality using an existing report solely as a data fixture.

## Actual verification

The original 19 cache tests, four source/Core VM tests, and two allocator-child
boundary tests all passed: 25 run, zero failures, zero errors, zero skips.
The native cache image and binary64 formatter were actually compiled from these
sources by historical native B1 `acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`
through the original 1107-byte native observer. This is explicit development
component verification. The original C dumpability witness is an external test
fixture; it is not a HIA compiler or product implementation.

`controls.json` records the actual before/after source pins and original test
outcome. `controls.stderr` retains every test name and result. The two build
directories retain original requests, process-state records and complete zlib
stdout/stderr. `original-native-stream-readback.json` verifies their actual
decoded HIAOBR02 frames, unchanged source echoes and full output, including the
exact produced-image bytes. Those images are recoverable from the retained raw
stdout; no reconstructed process response replaces the original evidence.

`source-readback.json` is the post-test readback of all physically present
tracked files, with every unchanged path verified against the base Git blob.
It is not an invented before-execution whole-source capture. The source pin
inventory and preservation decisions bind the selective historical recovery.

## Remaining qualification

The generated `json_wire.hepta` is a member of the frozen native source authority
and has changed. The old F/D qualification cannot cover this candidate. A new
matching source freeze and full native cold/installed qualification are required.
The unchanged 13 `WireNativeTests` and seven `ChainSourceTests` were not rerun in
this targeted receipt; they are explicitly listed as unexecuted in the method
inventory. Complete installed release qualification and whole-stack native
closure remain false. No production activation or legacy retirement occurred.
