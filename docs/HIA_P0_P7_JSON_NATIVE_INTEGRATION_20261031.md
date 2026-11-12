# HIA P0–P7 exact-identity JSON + native integration

Research-only branch based on #465 at `5b100d33c7e57e3b4dffd18c32b01db1bbcd1110`; this carries the exact
six reviewed Git blobs from #462 (`38c75c5e889bb02e6e6159b2e28e94a2f0a285ab`).
The three source readers were verified identical to #462's parent
`c646d58bb3339baca7c520e2a0b05534866f4c14` before applying those
blobs. No heuristic merge and no change to NDU scoring, LLVM lowering,
Rust owner semantics, C/C++ migration or runtime activation.

The stricter evidence wire admission preserves these maximums:
full-cost and native-registration: 262,144 wire bytes, 65,536 nodes,
64 depth; native paired replay: 8 MiB bytes, 262,144 nodes, 64 depth.
The same immutable input is checked before JSON value-tree allocation.
All refusals and the original `DENY_ALL` advisory authority remain.

## Real exact-HEAD qualification

- `hia-crosslane-json-native.yml` runs strict same-SHA Core/P0/P1/P5
  regression including the new node/depth adversarial suite, with zero skips.
- The real Linux C/ELF observer and native paired-replay test suite runs on
  the same code/tree and retains source-bound results.
- The inherited #465 LLVM/native/migration and existing host-matrix
  workflows remain independent and must be assessed at the source SHA
  executing them; no earlier green workflow is silently transferred.

## Remaining P0–P7 gates

All remain **OPEN**: P0 whole backend refinement; P1 general pointer/
lifetime/exception guarantees; P2 multi-host full native ABI & hardware;
P3 real-world third-party C/C++ maintenance and human cost; P4 global
verified optimization under strong baselines; P5 independently replicated
full-net NDU benefit against fixed/DP (previous real results negative);
P6 unseen Agent coding productivity; P7 final-use/fence/journal/crash/
rollback and physical host deployment. No simulated/synthetic positive may
close one of these.

**Authority: DENY_ALL. Production activation: false. Keep Draft; no main
merge until separate full evidence and independent review.**

## Strict test gate hardened on this integrated source

The exact test gate from Hepta #466 at `db4608200ce600ebbecf0eb9c31e9c99e5c094b7` is imported
with only one additive mandatory test module:
`tests.test_hia_evidence_json_structure`. It rejects expected failures,
unplanned/duplicate/disappearing cases, skips, changed source identity and
untracked workspace changes; its independent negative self-tests run as a
`gate` suite on this same source. No other scope or safety authority is changed.
