# Original GitHub Actions native cold failure at 1818a0a8

The actual `verified-kernels` job `140496611513` in workflow run
`45996352205` failed while running native cold construction from exact Git
commit `1818a0a851c8c5fdb84c822d6f0afbe9e8cc8132`. This directory preserves
the original failed reports, owner receipt, execution trace, resource samples,
preparation and construction records. It does not qualify the whole cold or
the complete native release.

The original Actions artifact is `15198110992`,
`verified-native-cold-evidence`. Its ZIP is 99,655,338 bytes, SHA-256
`abf8e9f6a55796d6597fce2de77918e1fab679756bc9ce7080e49b7e4790ceb1`.
It was downloaded through the GitHub connector, then the complete byte stream
and all 1,410 member contents were independently hashed. The ZIP's complete
member inventory and SHA-256 pins are in `artifact-members.json`. This is an
inventory of actual retained files, not a claim that every partial archive
was admitted.

## Observed result

| Step | Original result | Native elapsed time | Cleanup | External elapsed time |
| --- | --- | ---: | ---: | ---: |
| Seven-stage construction | PASS, 4,442 nodes and 45 installed tools | 138.858020415 s | 9.243077 ms | 201.585390964 s |
| Native source export | PASS, all 1,282 files / 247,268,856 bytes exact | Two original export modes retained | — | Original mode records retained |
| Full cold | **FAIL at the original deadline**, leader 124 | 180.003375155 s | 24.222088 ms | 205.298854167 s |

The owner receipt retains the original 180-second qualification limit and
3-second cleanup limit. It records the timeout, complete bounded cleanup and
no remaining identities. Only one cold command ran; the post-bootstrap,
release, installation and installed rebuild commands were never started. The
original failed chain report's `native_descendants_only: false` is preserved;
this diagnostic does not substitute a successful descendant-admission claim.

Twenty-one nonempty phase archives remained, all in the reference families.
The complete list, exact lengths and SHA-256 hashes are recorded in
`readback.json`. Nonempty files are not promoted to sealed or qualified
archives. The original 60-phase / 479,882-node requirement remains unmet.

The initial resource sample reported load average 1.06; the retained cgroup
CPU limit samples report `max 100000`. The trace lacks the per-child user and
system CPU fields present in the separate ROG observation, so this artifact
does not support the same child-CPU attribution. No CPU model is inferred from
the elapsed time or resource counters.

## Source distinction and custody

This run used the original 532,193-byte driver, SHA-256
`7ba244d01989b94b9368cdde3fdb5712dfdcc4c0f3f44d8e86a98fbe11e09e48`.
The separate `de0c0325` ROG run used a later driver with the pre-encoding cache.
These runs used different source heads and machines. Their progress and elapsed
times are not presented as a controlled performance comparison.

`original-ci-evidence.tar.gz` contains 73 unchanged original evidence members,
including its own member manifest. It is 854,828 bytes, SHA-256
`1bc64ec6bc1d113ef4ecb9c640583f4aa573a951523b286e237fdfb592573fc4`.
`read_original_artifact.py` reproduces this extraction and readback from the
exact full ZIP. The extraction rejects another artifact identity, source head,
duplicate member path, altered deadline, incomplete cleanup or invented
success. It neither executes the product nor modifies any original report.

The initial Mac download attempt ended with a recorded 300-second transport
timeout. The later connector download was independently complete; no partial
transport was treated as a successful readback. The complete ZIP remains an
external Actions artifact; its large binary workload contents are not copied
into Git merely to repeat the smaller original diagnostics stored here.
