# Historical evidence paths on case-insensitive filesystems

Two archived directories contained both `BASE.json` (program) and `base.json`
(native receipt). These names collide on common Windows/macOS filesystems.
The program snapshots now use `BASE_PROGRAM.json`. Their original bytes and
both receipt bytes are unchanged; the JSON migration ledger binds all four
sizes and SHA-256 values. Active generators use the distinct program name too.

The original 611-file evidence index also includes its original `VERIFY.py`.
Both remain immutable historical evidence. On the current source, run:

```sh
python -B tools/verify_hia_retained_evidence.py
```

The current entry point pins the exact original index and migration ledger,
resolves only the two declared moves, and checks every original size/hash,
including the original verifier bytes. It retains all 611 logical file identities
and 26,120,286 bytes. Missing unmodified rows, changed bytes, ambiguous paths,
symlinks, traversal and modified contract bytes are rejected. Metadata is read
under an explicit bound; archived programs are never executed. No old experiment
is rerun or rescored, and this check grants no safety or performance certificate.

The original verifier describes the original layout and is not rewritten to
interpret later layouts. The closure workflow now calls the pinned migration
entry point. Native-host jobs independently require clean, stable tracked Git
state, and C++ qualification rejects casefold collisions before compilation.
