# Native evidence for the six-track increment

All observations in this directory come from the exact implementation commit
`03c8205271dc5e8f9c5cad806e46056bffe2bc02`, GitHub Actions run
[41059492139](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41059492139).
This later evidence commit is not the source or a rerun of those artifacts.

The original ZIPs were downloaded through the authorized GitHub connector and
their SHA-256 values checked against the workflow upload logs. `ARCHIVES.json`
records the ZIP identities. Each cohort manifest records every original file's
size and SHA-256. The deterministic `*-original-text.tar.gz` archives preserve
every UTF-8, NUL-free file byte for byte, including failed observations, requests,
receipts and source copies. Native binaries and object files remain in the
original Actions artifacts and are inventoried, not included in these text
archives. The seven most useful native reports are also copied without changes
under `x86/` and `arm/`.

| Qualification | x86_64 | AArch64 |
| --- | ---: | ---: |
| Shared semantic tests | 14/14 | 14/14 |
| Native ABI and allocator cases within the semantic test | 30 | 30 |
| Guarded binding tests | 13/13, including 2 native | Not run by this job |
| Historical INIReader revisions | 2 | 2 |
| Real INIReader qualification commands | 48 | 48 |
| Linux interface cases | 21/21 | 21/21 |
| Completed callback jobs | 244 | 244 |

Tests and cases are different denominators; the 30 native cases are not 30
additional unit test methods. The INIReader runtime is 10.625443552 s on x86_64
and 14.359492500 s on AArch64. These are automated qualification times, not
human migration, review or upgrade costs.

The portfolio experiment completed all ten registered episodes, but its
competition gate and measured net-gain gate were both false. No arm executed a
nonbaseline candidate. Do not interpret a green workflow as evidence of NDU
economic advantage. Complete per-episode and original Rust NDU records are in
the portfolio archive. Agent preflight in these CI hosts recorded missing CLI
executables and zero model requests; separate local formal attempts have their
own source identities and evidence.

The reports retain their explicit limits: no whole-language soundness theorem,
no compiler/backend refinement theorem, no general C++ translator, no complete
lifetime or human-cost estimate, no arbitrary shared-memory concurrency proof,
and no physical-device/MMIO/DMA/hardware-interrupt qualification.
