# Seven-track Library source divergence audit — 2026-11-03

## Scope / authority

Historical source: ChatGPT Library `Hepta_seven_track_20261101.zip`, `source/changed-files/` (tested `a9be5fb5ac2231e731e750237f64818a6d0d623f`, delivered `2fedab7db59f56189f2b95eab4fa987a2abb5d2a`).
Compared against PR #552 head `f0b97c38caf8c7103fcbc27c9f148f8146e170d8` on `work/hia-seven-track-core-convergence-next`. The 4 missing historical files were recovered separately on `recovery/library-seven-track-20261103`; their original blob identities were verified. 21/35 archived source paths were already identical; 10 had divergent contents.

The table below records original/source blob SHA prefixes, current PR-head Git Blob SHA prefixes and content-line multiset comparisons. Line counts include a final trailing blank line when present; *old retained* is not an ordered diff or semantic equivalence proof. The source ZIP was inspected locally and all current versions were read directly from the GitHub connector. Do not use older copies to overwrite current implementation.

| Path | Historical blob | PR #552 blob | Old retained | New / old line changes | Review disposition |
| --- | --- | --- | ---: | ---: | --- |
| `.github/workflows/hepta-verified-optimization.yml` | `a7b2014e4839` | `3b7dd0db5ebc` | 353/354 | +12/−1 | Keep current detached external regression checkout and Rust PGO registration |
| `benchmarks/hia_agent_maintenance_v2/README.md` | `e51835bc6d57` | `2957bbdeed61` | 68/68 | +36/−0 | Keep current zero-generation preflight documentation |
| `docs/HIA_NDU_REVERSIBLE_RESIDENCY.md` | `89c56cfaf700` | `276a420d1067` | 121/121 | +20/−0 | Keep current native artifact-identity / cost documentation |
| `docs/HIA_SEQUENTIAL_CORE_PROOF_CHAIN.md` | `415355916a28` | `cc3f4ad0b024` | 78/79 | +5/−1 | Keep current capability-flow dependency in proof source lock |
| `hepta/hia_scalar_totality.py` | `3a10454727a9` | `b0d6ac56e25c` | 316/318 | +3/−2 | Keep capability-flow in both verification source inventories |
| `tools/qualify_hia_agent_maintenance.py` | `5306afc19102` | `653e173af9f3` | 787/787 | +15/−0 | Keep new preflight subcommand and request prohibition |
| `tools/qualify_hia_native_ndu.py` | `94c25e09cd73` | `16dfc1d7dc83` | 840/853 | +63/−13 | Keep current runtime identity, cost ledger and v3 qualification changes |
| `tools/qualify_hia_release_parity.py` | `54f36accd23a` | `4e751e462cdf` | 266/274 | +46/−8 | Keep separately registered Rust PGO v2 profile and identity checks |
| `tools/qualify_hia_sequential_core.py` | `d7407fccd2b` | `ee7bd96f1d04` | 194/195 | +2/−1 | Keep capability-flow source identity |
| `tools/qualify_hia_verified_increment.py` | `f55d9dbacd2c` | `26333690b790` | 293/300 | +78/−6 | Keep expanded test roster and clean-checkout admission controls |

## Decision

1. **10/10 original conflicting path contents remain preserved only as historical source**, not as pending direct replacements. The selected current PR head contains additional guards, identities, new tool registration and documentation; replacing them with older bytes would discard later work.
2. These path-level dispositions close the **archive-vs-current replacement decision**, not untested semantic correctness. No tests ran during this audit, no CI success or general soundness was inferred from filenames or line counts.
3. **4/4 absent archival paths** were restored in this *separate* branch and remote blob hashes checked against the original bytes. Historical `FREEZE.json`, `RELEASE_LOCK.json` and `RESULTS.json` do not constitute a current release approval.
4. PR #552 remains the source of subsequent implementation changes, not the obsolete archive. Keep recovery separate until the destination for host-specific historical evidence is reviewed.
5. Unpushed commits on the original dot machine cannot be enumerated by the GitHub connector; the present container has no dot checkout. Other Library artifacts still require repository mapping, secrets/size review and content-hash deduplication.

## Acceptance limits

The archived seven-track study retained negative results (release-performance thresholds, NDU full-lifecycle advantage and Agent cohort execution). The newer PR itself also reports open P0–P7 production gates. Neither archival recovery nor this line comparison closes those experiments.
