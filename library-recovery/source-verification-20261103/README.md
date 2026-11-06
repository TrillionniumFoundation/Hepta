# Source verification recovery checkpoint — 2026-11-03

This isolated archival Draft preserves the reconstructed **2,952-object incremental verification ledger**, together with frozen candidate fingerprints, baseline fingerprints and the exact retained GitHub refs. It does not add recovered application source or modify production paths.

The recorded union is **4,969 verified candidates of 6,116**: 2,017 in the earlier baseline plus 2,952 disjoint incremental objects. **1,147 candidates remain unverified.** The frozen candidate groups remain 5,456 original candidates, 34 newly found bundle candidates and 626 newly found R70 candidates. These include source containers and research text; byte coverage is not scientific acceptance. No deletion is authorized by this checkpoint.

## Recovery provenance

An execution-runtime reset removed the transient workspace. The previously observed complete ledger had SHA-256 `dc738d4762d7fd5ffb221005bd2079ae2145dd0d47b4da9c3681670cbf61c63e`; its original JSON serialization was not recovered and is not falsely identified with this new file.

The new ledger was reconstructed from a durable 1,086-object checkpoint, 1,286 RR-SNN original structured API readbacks recovered from session state and rehashed, and fresh readbacks of the same 580 immutable source paths from the most recent publication batch. The latter batch's original temporary raw readback files were lost; its 587 paths including seven auxiliary files were fetched again. A further 93 original RR-SNN auxiliary readbacks were recovered. Auxiliary licenses and metadata do not enlarge the source-candidate denominator.

The complete reconstructed JSON has SHA-256 `49f2ad294a7edfb9741d1b5354057437464982cad7047960cd9c62689ac67770` and is losslessly represented by `LEDGER_HEADER.json` plus the ordered `increment-*.json` files. Original structured source evidence and the new raw readbacks are retained separately; this small Git archive stores their identities and provenance, not large duplicated source or log payloads.

## Verification

Run `python3 verify_ledger.py` in this directory. It checks every checkpoint file hash, reconstructs the complete ledger in memory, checks its exact SHA-256, verifies 2,952 unique increment identities, validates source byte fingerprints against the frozen 6,116 candidates, and checks disjointness from the 2,017-object baseline. It performs no network calls and does not execute recovered source. Consequently it validates this checkpoint's metadata consistency; it does not itself repeat the physical remote source readbacks.

The ledger contains repository, immutable commit, path, ref, Git blob identity, SHA-256 and byte length for every incremental verified object. Those exact paths support independent remote-byte rechecking. `ARCHIVE_REFS.json` records the fresh ref checks after the reset.

## Preserved limits

DRAFT / ARCHIVAL_ONLY / SHADOW_ONLY / DENY_ALL / HOLD_NO_GO remain in force. Neither HIA P0–P7 nor HCSN P0–P6 is closed by source synchronization. Complete CI, scientific evidence, unresolved source containers, repository attribution and the remaining byte-verification gaps retain their own gates. The original files remain retained. `clearance_allowed` and `all_library_source_synced` remain false.
