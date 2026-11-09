# Preserve the original failed publication gate and repair its source contract

PR #830 head `7bf6949be0ec99278df991ee8a71b3dc083f33a9` was actually checked out
by [run 42591794376](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42591794376),
attempt 1, job `129074920943`. Step 5, **Freeze this exact candidate against the
reviewed runtime source**, exited 2 with `Selfhost-Core source/seed/loader closure
differs from actual committed files`. Subsequent qualification steps were skipped.
The final upload step also failed because the rejected freeze had produced no
files at its upload location. Neither outcome is relabelled as success.

The changed Agent service and proof-contract sources were not followed by
regeneration of `docs/HIA_SELFHOST_CORE_SUPPORT.json`. Its two declared hashes
were stale. The existing generator now refreshes precisely those two entries.
The same 252 source files remain; compiler assembly, support profile, capacities,
ABI, assumptions and every other contract field are unchanged. The release
checker and workflow are unchanged and no condition is relaxed.

The original complete job log is retained as gzip with its raw byte count and
SHA256 in `repair.json`, alongside original run/job/step metadata. The existing
`generate_hia_selfhost_contract.py --check` succeeds after regeneration, and all
six `SelfhostContractTests` pass without skips. Original command outputs are
retained. The corrected support document changes the measured worker inventory;
old local/native receipts retain their original identities. The repaired
publication must run its own exact-head CI before acceptance.
