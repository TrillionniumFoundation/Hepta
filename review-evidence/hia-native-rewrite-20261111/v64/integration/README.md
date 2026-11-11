# v64 original development evidence

The 117-test native group and both complete 17-test installed-resource attempts
are original development observations. They do not constitute a matching-source
cold qualification or a full retained regression pass.

`FINAL_HANDOFF.json` and `stage3.json` pin the exact tested source. The later
publication adds the project audit, README and inventory; it receives its own
fresh source contract and external qualification. Original test failures remain.

The three largest raw archives are stored in lossless ordered parts.
`raw-archive-parts.json` gives every part and complete archive SHA-256 and byte
length. Concatenate only its declared parts, in their listed order, to recover
the original archive. The adjacent original `*-raw-custody.json` files enumerate
every internal member, length, mode and SHA-256. Complete archive paths inside
old receipts identify their original capture location, not a new execution.

The original Python 3.12.14 installed-resource attempt failed one test because
its fcntl module lacks F_ADD_SEALS. An existing Python 3.13.5 passed a real memfd
seal probe and then all unchanged 17 tests. Neither production nor test
assertions were changed for that environment. Original summaries and raw files
for both attempts remain independently identifiable.

The native group retains 218 files / 57,754,383 raw bytes. The first installed
attempt retains 733 files / 43,279,152 raw bytes; the second retains 736 files /
43,415,259 raw bytes. Root independently streamed and checked every member's
bytes, SHA-256 and mode; see `../independent/raw-readback/report.json` (relative
to the v64 directory, `independent/raw-readback/report.json`). No native replay
was invented as part of that readback.
