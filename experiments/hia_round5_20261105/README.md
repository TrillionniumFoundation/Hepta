# HIA round 5 — frozen-source delivery and evidence

**The registered unified execution completed; the seven research goals are not all closed.**

- [完整中文交付报告](DELIVERY_REPORT_ZH.md)
- [七项完成标准与机器可读状态](CLOSURE_MATRIX.json)
- [独立结果摘要（中文）](SUMMARY.zh.md) / [English summary](SUMMARY.en.md) / [exact cells and costs](SUMMARY.json)
- [Authoritative terminal receipts](TERMINAL_STATUS.json)
- [Archive identities, restore results and scope](EVIDENCE_INDEX.json)
- [Source draft PR #737](https://github.com/TrillionniumFoundation/Hepta/pull/737)

## Identity

| Role | SHA |
| --- | --- |
| Measured source commit | `0a06ef4f0894681af92b0caefba0704c1278d2cc` |
| App-published source commit | `67da0ab0a51203f6f640c4459bc15bef442885b8` |
| Exactly matching full Git tree | `a5239982f9fd8f08ab3a6e791147fc989e8d9df6` |

The published commit is not relabeled as the measured commit. Original commit-object bytes are retained in [COMMITS.json](COMMITS.json) and `raw-commits/`. This evidence branch is separate from the frozen source branch; evidence additions did not change the measured implementation.

## Final outcome

| Item | Observation |
| --- | --- |
| Unified qualification | 36/36 commands, 34/34 execution/evidence flags |
| CORE | 613 planned = started = finished; no failure/error/skip; all S3 IDs retained |
| Fresh proof | 595.116502644 s under the original 600 s budget, exit 0 |
| Independent replay | 43.595967989 s, exit 0; not a second Lean-kernel run |
| Composition | 2005.257633654 s, exit 0 |
| Complete frozen sequence | 2670.960663875 s; already includes its child phases |
| Strong AOT | median 372/372, p95 371/372, p99/joint 340/372; cold 38/48 |
| Memory/resource-cost | memory 5680/5680; resource/cost 6842/6852 |
| NDU | 0/3 net-winning scenarios; fresh bridge cost included |
| GSL 5.0.1 supplement | actual HIA LLVM linked; 2496 positive rows / 7488 scalar calls match |
| Two-host Linux supplement | same artifacts, six expected stage outcomes, zero X230 compilations |
| Agent productivity | not demonstrated; audited historical 29 requests, 0/16 correct cells; no new requests |
| Wider authority | DENY_ALL; no safety certificate; twelve broader refinement obligations remain unproved |

The 34 flags do not turn the retained AOT or NDU failures into successes. S3-to-current AOT transitions include 51 fail→pass and 26 pass→fail cells. All ten cold failures are n=0. The shared host was nonexclusive, and activity-inventory limitations are retained in [SHARED_HOST_ACTIVITY.json](SHARED_HOST_ACTIVITY.json).

## Evidence packages

| Package | Contents and boundary |
| --- | --- |
| [raw-static-evidence.tar.xz](raw-static-evidence.tar.xz) | Specialist controls, source checks, original failed attempts and preflight evidence |
| [proof.tar.xz](proof.tar.xz) | Complete fresh proof and independent-replay records, source/tools/registration and outer logs |
| [composition.tar.xz](composition.tar.xz) | Completed 36-command composition, public artifacts, raw AOT/NDU observations, global result and full inclusion/exclusion manifests |
| [gsl-hia-connection.tar.xz](gsl-hia-connection.tar.xz) | Actual 5.0.1 HIA LLVM migration supplement; all positive and negative evidence |
| [p2-two-host.tar.xz](p2-two-host.tar.xz) | Same package and shared libraries on desktop and X230; runner, receipts, raw output and restore manifest |
| [windows-gha-evidence-review.tar.xz](windows-gha-evidence-review.tar.xz) | Four completed exact-head Windows CI artifacts audited; original small streams, API identities and CRLF analysis; original full CI ZIPs excluded |
| [macos-gha-evidence-review.tar.xz](macos-gha-evidence-review.tar.xz) | Two completed exact-head macOS AArch64 CI artifacts audited; actual backend and retained observations; original full CI ZIPs excluded |
| [independent-analysis.tar.xz](independent-analysis.tar.xz) | Independent final parser, complete audit, all failed cells/transitions/costs, historical test scope and CI snapshot |

The index lists archive SHA256, Git blob SHA1, file counts, restore checks and exclusions. Private NDU source/build products, dependency caches, toolchains and model weights are not published; corresponding public identity/build/cost receipts are retained. Windows/macOS Rust-backend CI is not HIA LLVM native platform qualification. General model theorems, fixed-program verification and finite observations remain distinct.

The source PR stays Draft. The recorded CI snapshot has 6 completed successful jobs and 100 queued jobs; it does not establish all CI passed. No main merge or production activation is claimed.
