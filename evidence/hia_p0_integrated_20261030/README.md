# Frozen Hepta P0 evidence, 2026-10-30

The measured implementation is commit `50c4067399989e7194028576c38c0e783b78cf06`.
The earlier interrupted run01 used `ba267bf824a0f978f86b2003c8e4f0e9f70935ce`.
All original outcomes remain intact: run01/run02 were interrupted, run03 ended
with one board-class setup error and 4178 executed methods, and run04 completed
4183 Python tests with no failures/errors/skips. The Rust resource crate ran
109 tests separately. The canonical safety matrix ran 364 selected methods and
covered 39 capabilities. These denominators must not be added together.

## Explicit matrix capture limitation

The canonical `integrated-safety-50c40673/qualification.json`, its complete
unittest log, and its 364 per-method records are preserved and passed. The outer
terminal **combined diagnostic stream is partial**: the tool reported 143944
original tokens and truncated the response at the requested 8000-token budget.
`OUTER_CAPTURE_PARTIAL.json` preserves the actual retained chunks and limitation.
It is not a complete stdout/stderr capture. No missing diagnostic text has been
reconstructed, and no run04 output has been borrowed to fill it. The completed
matrix was not repeated merely to replace this diagnostic stream.

## Contents and boundaries

The P0 package preserves all four qualification output trees; canonical matrix
records and external after-snapshot; launch scripts/logs; retained development
failures and fixes; official Boost/GDB and QEMU acquisition/setup records,
package archives, actual board report, raw commands, and before/after snapshots;
tool-pin and independent run03/run04 reviews; four actual NDU bridge binaries,
receipts, and receipt-bound source bytes. P3 contributes its frozen launch
records and small actual result reports. Its large native payload is packaged
separately by its producer. The older archive-plan file is retained as a
historical draft, not as this package's current member inventory.

`apt-lists-20261030.tar.xz` separately preserves all six original APT list files
(91690550 bytes), including rolling repository index bytes that may not be
available again. Its manifest records the observed empty cache directories.

These are integrity and consistency records. They are not signatures from an
independent authority, execution of the archived programs, a complete source or
dynamic-loader/sysroot/environment closure, universal language-soundness proof,
absolute resource-safety proof, or evidence of global optimality/performance
superiority. Selected source files and bridge inputs are retained; the full
Hepta repository remains identified by its measured Git commits.

## Offline verification without extraction or execution

Use a trusted external copy of `verify_evidence.py` and the two SHA256 pins from
`CHECKSUMS.json`. The verifier uses only the Python standard library, reads the
compressed archive and manifest, and prints JSON to stdout. It does not create
files, extract members to disk, import archived modules, execute native binaries,
run Git/compiler/test commands, or access the network.

```sh
python3 -I verify_evidence.py \
  --archive p0-evidence-20261030.tar.xz \
  --manifest p0-evidence-20261030.manifest.json \
  --archive-sha256 VALUE_FROM_CHECKSUMS \
  --manifest-sha256 VALUE_FROM_CHECKSUMS
```

Repeat with the `apt-lists-20261030` archive/manifest and their own pins. The
external pins are required before decompression. Every archived regular member
has a bounded path/size and SHA256 in its sidecar manifest. Duplicate, absolute,
traversing, linked, or special members are refused. P0 verification additionally
checks core source/denominator/outcome consistency, source and external snapshot
equality, retained failed runs, matrix partial-capture disclosure, and the four
bridge binary/source identities. Manifest files are sidecars, so every file
inside each archive can have a non-self-referential member digest.

The archives were read directly from stable source files; no large raw staging
copies or hardlinks were needed. Original evidence directories were not deleted.
