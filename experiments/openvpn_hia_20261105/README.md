# OpenVPN / HIA native integration pilot — 2026-11-05

This delivery contains a real, opt-in external byte-buffer ABI, a verified HIA
packet-ID codec compiled to a native object, and an actual link into the official
OpenVPN application. Finite correctness tests and bounded encrypted UDP sessions
passed. **The measured codec is slower than official C. Real TUN forwarding,
real DCO execution, production hotspot identification and end-to-end performance
qualification remain open.**

## Acceptance against the requested five stages

| Stage | Work actually completed | Acceptance status |
| --- | --- | --- |
| 1. Freeze the official baseline | OpenVPN archive and all 545 regular release files verified; Hepta base and kernel version recorded; Clang, OpenSSL, kernel configuration, application binaries and link inputs hashed; original application gprof runs retained | Partial. Self-test profiling does not identify real-tunnel hotspots. DCO runtime evidence is unavailable |
| 2. Minimal external buffer interface | Explicit immutable export manifest, bounded synchronous borrowed ranges, independent origin checking, numeric admission and alias rejection, packed status ABI, caller-owned lifetime | Passed for the documented finite Linux x86-64 profile; arbitrary C-pointer liveness and backend refinement are not proved |
| 3. One real kernel | Four packet-ID codec exports implemented in HIA; original C differential tests include full bytes, metadata, state and partial failures; decoded streams also compared through the unchanged official C replay window | Passed for the recorded finite cases. The replay algorithm itself remains C |
| 4. Official application integration | The same 99 official application objects link the exact HIA/adapter objects; crypto self-tests, real UDP/TLS peers, negative certificate cases, replay/tag rejection, reconnect and rekey observed | Partial. Actual `--dev null` application sessions passed; no real TUN/IP tunnel ran |
| 5. Fair performance comparison | Matched-compiler original C, direct HIA, adapter+HIA and same-byte-ABI C control; both corrected timed runs retained in full | Partial. Microkernel regression is established here; DCO-off tunnel and official DCO comparisons remain unrun |

## Exact baseline

| Component | Identity |
| --- | --- |
| Official OpenVPN | v2.7.8, commit `dc1f569087135894ac2703aeabd7a960ee9452d4` |
| Official archive SHA-256 | `c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36` |
| Hepta/HIA starting point | `3102c2bb6cd819c27aef36cc927c23b39b279204`, the frozen draft PR #682 head, plus this delivery's recorded changes |
| Compiler | Clang 20.1.8, executable and extracted official package hashes in [toolchain-lock.json](toolchain-lock.json) |
| Microkernel options | Linux x86-64, `-O3 -fPIC`, no LTO, CPU affinity 0 |
| Official application options | Clang 20.1.8, `-O3 -g -fno-omit-frame-pointer`; exact configure/link inputs retained |
| OpenSSL | 3.0.13, actual linked library hashes retained |
| Host | Linux 6.18.57; AMD EPYC 9V74; shared host, no locked frequency |
| Final HIA object SHA-256 | `67e17b4113f8aeca171efb9b1a45909373daddeaae448060c20ec080e0725983` |
| Final adapter object SHA-256 | `64c78f6e9e8d04d9887a040460e157aae53a75aac738c996f650e80555e3ea6f` |

The application/replay receipts name the final2 native objects. Corrected runs
2, 3 and 4 have identical packet and adapter object bytes. Run4 additionally
rechecked correctness with a strict UBSan exit gate and did not collect another
performance sample. The final ABI source hashes match the unit-test receipts.
This is a research branch based on the frozen HIA draft, not a claim that the
new ABI has shipped in Hepta's main release.

## What passed

| Executed check | Observed result | Evidence |
| --- | --- | --- |
| ABI and existing LLVM/composite regression suite | 31 methods, no failures/errors/skips | [ABI validation](abi/validation.json) |
| Independent source-export and command-log regression suite | 13 methods, no failures/errors/skips | [Regression receipt](review/regression.json) |
| Packet codec differential | 228,336 inputs; 456,672 complete comparisons; zero differences | [Final correctness receipt](packet-results/corrected-run4/summary.json) |
| Upstream partial-failure behavior | 68,211 calls with observable partial changes preserved | [Codec contract and results](PACKET_KERNEL.md) |
| Real guard pages | 15,504 boundary cases; zero differences/faults | [Guard-page output](packet-results/corrected-run4/guard-pages.stdout) |
| Admission and receiver behavior | 83 raw ABI, 80 adapter rejection and 11 receiver observations passed; HIA frees 0, caller frees 2 | [Admission output](packet-results/corrected-run4/admission.stdout) |
| C-side ASan + UBSan | Differential/admission suites passed; both stderr files empty | [Final correctness receipt](packet-results/corrected-run4/summary.json) |
| Official C replay-window integration | 70,663 inputs; 275,509 complete-state comparisons; zero differences, including 53 rejected calls that mutate backtrack statistics | [Fresh replay receipt](replay/final/validation.json) |
| Official application crypto self-tests | C/HIA × AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305: 6/6; each length 1–1768 | [Reviewed application result](baseline-application/integration-run-final2/baseline-reviewed-v2.json) |
| Actual loopback UDP/TLS scenarios | C/C, C/HIA, HIA/C × positive, wrong name, untrusted CA: 9/9; positive peers each complete 4 rekeys and recover after reconnect | [Application review](review/application-review.md) |
| Actual encrypted UDP replay and bad tag | Both mixed orientations pass; each receiving endpoint rejects one exact duplicate and one corrupted tag, then continues and rekeys | [Adversarial UDP receipt](baseline-application/udp-adversarial-final2/udp-probe.json) |

Positive mixed sessions execute **all four** HIA entrypoints. HIA client counts
are 28/32/12/12 for read/write/read_epoch/write_epoch; HIA server counts are
32/28/12/15. ABI errors are zero. These are calls from real OpenVPN encrypted
ping traffic over UDP, with `--dev null`, not TUN IP payload. Trace wrappers are
diagnostic only and are excluded from performance comparisons.

The public ABI cannot authenticate a dangling pointer or a caller's claimed
allocation size. Live, properly initialized caller storage and concurrency
discipline remain preconditions. HIA ordinary input errors use explicit returns;
Core traps still abort and do not roll back writes. ASan/UBSan instrument the C
oracle, adapter and drivers, not the generated HIA object; real guard pages test
the HIA access boundaries separately. See the [ABI contract](../../docs/hia_foreign_buffer_abi.md).

## Performance: all corrected samples, including regressions

Values are medians of batch-average nanoseconds per call, pooled across **all
36 samples per mode/arm** from corrected runs 2 and 3. Each sample executes
1,000,000 calls after warmup. All six triplet orders are used repeatedly, the
C byte-ABI control is balanced before/after, and no sample is discarded.

| Mode | Official C | Direct HIA, including boundary checks | Adapter + HIA | C byte-ABI control | Adapter / official C |
| --- | ---: | ---: | ---: | ---: | ---: |
| Long write | 4.381 ns | 15.018 ns | 22.607 ns | 12.773 ns | 5.16× |
| Long read | 2.917 ns | 10.951 ns | 18.020 ns | 15.304 ns | 6.18× |
| Epoch write | 2.885 ns | 10.620 ns | 17.566 ns | 11.974 ns | 6.09× |
| Epoch read | 2.141 ns | 10.139 ns | 14.811 ns | 12.854 ns | 6.92× |

The implementation does **not** show a speedup over original C. These are tiny
successful codec paths with reused buffers on a shared host. They are not
request-tail latency or a VPN throughput estimate. The C byte-ABI control calls
separately compiled original C while the HIA wrapper/core have different inlining
visibility, so it is not an isolated language-speed comparison. Nor can unlike
harness times be subtracted to obtain an exact additive adapter cost.

The [all-sample summary](review/performance-all-samples.json) binds both raw logs;
[PACKET_KERNEL.md](PACKET_KERNEL.md) shows each run separately and explains the
workload, correctness domain and remaining measurement limits. The original
application self-test profile is documented in [BASELINE.md](BASELINE.md): it
does not establish packet-ID coding as a deployed hotspot.

## Preserved failures and review corrections

- The early two-arm prototype and its regressions remain under
  `packet-results/historical-prototype-two-arm/`, explicitly outside the final
  qualification because its full source snapshot was not retained.
- An intermediate adapter edit failed compilation. Exact failed source and
  diagnostics remain under `packet-results/compile-failure/` and
  `replay/fresh-attempt1/`. The failing object was not used for final claims.
- Corrected run2 completed differential/performance work, then LeakSanitizer
  could not inspect the managed host's process state. That failure remains.
  Subsequent C-side sanitizer runs disabled only leak scanning; final4 also
  uses `UBSAN_OPTIONS=halt_on_error=1`. No later run replaces run2's timings.
- The initial application observer miscounted reconnect key installation as a
  rekey. Original logs and reports remain intact; the final review reinterprets
  the same logs with explicit new-session boundaries and a stronger four-entry
  HIA trace gate. It does not claim a newly executed network experiment.
- The first default-MTU GCM profile produced no time samples. The later large-MTU
  self-test profile and its inability to expose production hotspots remain explicit.

## The remaining target-host work

Actual observations on this host are `CapEff=0`, `CapBnd=0`, absent `/dev/net/tun`,
`# CONFIG_OVPN is not set` and `DCO version: N/A`. The [kernel configuration](review/kernel-config.txt)
and [preflight receipts](tunnel-preflight-dco/trial.json) preserve the evidence.
These prevent real TUN/DCO qualification here. Compiling DCO support is not
runtime evidence.

[TUN_DCO_ACCEPTANCE.md](TUN_DCO_ACCEPTANCE.md) supplies source-checked target-host
commands and acceptance observations. Its network commands remain **unexecuted**.
It requires real payload forwarding, actual `tun`/`ovpn` interface identity,
kernel peer-counter deltas, authenticated replay/reconnect/rekey checks, and
separate C-off / HIA-off / official-C-DCO measurements. The principal comparison
keeps a common protocol profile; Linux DCO in this frozen release does not support
epoch data, so epoch-capable userspace sessions are checked separately. This
avoids confounding a wire-format change with implementation cost. DCO is an
official deployment reference, not a claim that the userspace HIA codec executes
inside the kernel.

For reproduction, start with [BASELINE.md](BASELINE.md) and
[PACKET_KERNEL.md](PACKET_KERNEL.md), then [replay/REVIEW.md](replay/REVIEW.md).
Use fresh external output directories. The repository contains source, hashes,
nonsecret logs and receipts; the runner's temporary PKI and compiled binaries
are not publication artifacts.
