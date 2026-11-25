# Source capture hashes the complete admitted file domain

The source audit protocol already allows a regular single-link file through 64 MiB. Its previous implementation called the SHA stream update once with the entire captured file. The SHA role correctly retained its separate 8 MiB input limit, so the real 11,192,933-byte capacity qualification pool was refused with exit 18. The ordinary release pipeline stopped in its second source audit batch. The preceding seven-stage construction, matching 60-phase cold replay and public post-cold source bootstrap remain separate successful evidence; they did not exercise this ordinary audit path.

The HIA source-capture owner now issues updates of at most 1 MiB over the already captured bytes. The stream command needs one preceding byte. Before each call HIA saves that byte, writes the update command, then restores the byte before selecting another piece or reporting a hash failure. No source data is omitted, repeated or reordered. The final digest must still equal the request's complete source pin.

The syscall adapter only maps the selected view. It validates the captured extent, offset and remaining length by subtraction before forming a pointer. It does not implement SHA or decide source policy. The initial and final hash calls, workspace sizes, file limits, source count, path restrictions, pre/post identity and timestamps, and publication behavior remain unchanged.

## Qualification

All 12 original source-capture test methods passed, including 407 calls through the original native capture harness, all declared recipe and packer-kit inputs, the complete matching 1,127-file source inventory, late failures and the sealed native compiler consumer. The new binary was supplied to those unchanged test methods; their source inputs and cold report were the already frozen production candidate, not a fabricated success report for the changed source.

The added 22 real process cases cover empty files, hash block boundaries, 1 MiB and 8 MiB transitions, the exact failing pool size, 64 MiB minus one and the exact 64 MiB boundary in both metadata forms. They also preserve refusal of 64 MiB plus one, size overflow, incorrect pins and declared sizes, and the original 1 MiB limit for non-audit captures. Seven actual HIA policy plus SHA runs independently checked every selected payload view, each prefix restoration, the final complete digest and restoration on a hash failure.

`HIA_SOURCE_CAPTURE_STREAMING.json` records the exact binaries, source pins and retained reports. These are component gates. The changed source still requires a newly captured inventory, matching complete cold replay and public post-cold/ordinary construction before it can replace the prior frozen candidate.
