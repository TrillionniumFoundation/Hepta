# Complete installed-resource inventory and source continuity

The installed hosted reference wheel has a different role from the ordinary native production package. Its original resource gate is retained as an independent API and custody observation. The ordinary package keeps its separately checked complete 289-member domain. This change does not replace either gate with the other.

## The original failure and reviewed resource extension

The original `AgentInstalledResourceTests.test_wheel_resources_are_exact_and_worker_identity_matches_source` constructed an independent 261-member resource set. The actual reference wheel contained those 261 members plus 29 declared resources. There were no missing original members. The original failure remains evidence; the earlier temporary wheel was not retained, and a same-source reference-wheel reconstruction corroborated its exact 29-member difference.

The added members are derived from source producers, without reading a wheel to manufacture an expectation:

| Domain | Count | Explicit producer |
| --- | ---: | --- |
| Complete nominal program source resources | 10 | `hepta/hia_nominal_program_native.py: PACKAGE_RESOURCES`, consumed by `setup.py: nominal_program_resources` |
| Native scalar NDU source and build custody | 16 | `hepta/hia_ndu_native.py: SOURCES`, copied only after matching cold-source SHA checks by `tools/build_hia_default_release.py: _native_ndu_members` |
| Native assembly companions | 3 | `ASSEMBLY_RENDER_RESOURCE`, `ASSEMBLY_SYNTAX_RESOURCE`, and `ASSEMBLY_DIAGNOSTIC_RESOURCE`, explicitly inserted by the reference-wheel builder |

`tests/hia_installed_resource_history.py` contains the independently reviewed explicit 10/16/3 declarations. It compares them to their producer declarations and checks all 26 source files against the complete source contract. The exact original 261 names are frozen in `tests/fixtures/hia_installed_resource_successors.json`, independently reconstructed from the original assertion and the declared matching-cold owner set. Every current invocation must produce the same 261-member predecessor before adding the disjoint 29-member extension. Both 261 and 290 remain explicit assertions.

The original installed gate still checks every earlier source byte, installed resource byte, per-owner image digest, package-root exclusion and Worker identity. It now applies the same source/installed byte comparisons to all 26 additional source resources. All three mandatory assembly images are compared to the installed copies and their exact original pin positions 15, 16 and 17. Removing an old member or adding an unreviewed member remains a failure.

## Exact historical test bytes

The native-distribution source gate retains its original four-file reference fixture without changing any expected bytes. For this resource test, that fixture describes a 75,021-byte file with SHA256 `51b7d24fc511258a05cb086eea2ff1729d409a0fda21317cc6efdb24057b0015`; its existing reviewed reference-profile splice restores the complete 74,950-byte predecessor with SHA256 `5e0db72475d8aa67bdc94d3e7866f0765d9e712711eaf3df0796416b80181d8f`.

Subsequent source-distribution support additions produced an 84,895-byte file with SHA256 `c74f6ad8c7dda2af33574976cf7a783a9310717d07f392cacd6fbcde9268dcb3`. Review of its entire difference found three insertion groups in `SDIST_SUPPORT_FILES`, preserving all prior methods and assertions. That successor had not been connected to the earlier reference fixture, so the original source gate correctly refused it.

The separate resource history now records two exact, finite relations: the reviewed support-list additions, and this inventory qualification extension. For each recognized complete successor it verifies its full size/SHA, every reverse splice, the full predecessor size/SHA, every forward splice and exact whole-file forward replay. The shared reference history calls `reference_source(name, data)` first, then applies its unchanged older fixture. Unknown names or unreviewed bytes are returned unchanged for the existing downstream refusal; no wildcard, normalization or fallback acceptance is introduced.

The fixture and helper are part of the complete source registry and sdist. Qualification must include the original native-distribution source gate and the real installed resource gate, in addition to the small source-history controls. A temporary source overlay used to qualify the shared hook is labeled as such; it does not replace execution after the final combined source is committed.
