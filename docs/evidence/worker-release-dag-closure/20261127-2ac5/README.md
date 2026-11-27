# Worker installation follows the complete Store release DAG

The real installed public-jobs gate used exact Hepta source
04feaffc29bd77ae4ab3695eb08602726a01ba1c and the independently installed,
verified 301-member Store package
201fd124d0c6fc80cb9ad97816e4f69cbc1ea669462b3f86d168566f57817f7e
(194,753,597 bytes). The native Worker installer naturally returned 74 after
640.335481059 seconds; its native owner returned 65. It did not time out and
no public START was issued.

The failed owner rebuilt a 289-member package,
4353de273aeea3a9d76a70df629812578f567e0c84f9d1d5d7b108ebc7cf3d03
(169,092,914 bytes). Every common member's bytes and mode were identical.
The twelve missing members belong to Future and GenerationLease. The existing
phase-7002 package-size guard correctly refused that incomplete package.

The existing author already declares eight release DAGs. Its committed Worker
owner and DAG HIA sources were stale: the native DAG stopped the Store sequence
at index 5 and started Worker stages at index 5. The current author produces
indices 8 and 24 and the matching complete path table. The original generator
--check failed with worker_install_owner differs.

This change regenerates only worker_install_owner.hepta and
worker_install_dag.hepta; the packer is byte-identical. No source-author
semantics, size or digest guard, permission check, timeout or production
admission rule changes. Two full-source generation regression tests, registered
as host qualification inputs, catch an unsynchronized owner or DAG.

## Actual component results

- Original native images: 5 of 26 current release/Worker stage-boundary probes
  pass; index 5 prematurely resumes phase 6000. This is a retained negative
  control, not a passing result.
- Regenerated native images: all 26 probes pass, including all eight source
  paths, sixteen Worker paths, the Store end and the Worker end. The actual
  native capture wire's selected path and SHA match the physical source.
- Both original and regenerated images retain the package length, regular-file
  type, digest and syscall-failure refusals. Sixteen native probes pass, including
  the expected old/new Worker start indices.
- The unchanged qualify_hia_worker_install_sources.py passes all three member
  constructions, 39 real native calls and 21 original source-refusal cases.
  Retained embedded images equal independent source compilation, and reordered
  named sources yield the same executable.
- The original generate_hia_worker_install_owner --check now passes in
  3.312798998 seconds. Both generation regression tests pass in a 2.950989962
  second process (2.791 seconds reported by unittest).

The component compiler is the actual native hia-source-build, SHA256
494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af.
The HIAKIT01 composer was reconstructed from the exact three source roles using
its real sources and pack operations, then consumed by the unchanged member
qualification. The new Worker-owner ELF is 1,274,182 bytes, SHA256
b1ab61c1bd971949a485e12cca88dea89d36c86360d7225afa99f79a22510daa.

These are development component results. They do not qualify a new full cold
build, a new 301-member release, installation, or public START/STATUS. Those gates
must execute on the subsequent unified source and its actual package.

## Raw evidence

raw-evidence.tar.gz retains the original installation command, complete exec
trace and empty stdout/stderr, the full failed report, all package member
comparisons, original generator refusal, compiled original and regenerated
images, direct native probe source/results, all sixteen compressed complete
input/terminal-state/control-plan records, original member qualification
products and call results, and the generator/test stdout and stderr. The member
manifest and archive hash were independently read back after compression.

The large original and failed Store packages remain unchanged in the owned
04fe release and failed public19-v3 staging directories, respectively. Their
paths, full hashes, member byte hashes, modes and stable file stamps are
recorded in the comparison. No failed installation is relabeled as success.
