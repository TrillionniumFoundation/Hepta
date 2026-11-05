# Exact Library HIA/OpenVPN feasibility source custody

**Status: Research / HOLD. This is not a full HIA execution, OpenVPN tunnel, TUN/DCO benchmark, or product qualification.**

This isolated draft pins the five original **byte-identical** source and input-identity files from Library archive `hia_openvpn_feasibility_probe_20261105.zip`. The archive's seven manifest-covered members were checked against its original hashes and ZIP CRC. Baseline Hepta code was pinned at `125d11c5454835a7df1dc51915fc49901fbede5b`. The independent generated-C probe is a limited Hepta-to-C11 feasibility test.

| Filename | SHA-256 of original bytes | Git Blob SHA-1 |
| --- | --- | --- |
| `probe.hepta` | `77895f2e33f2dbe04054b3136abf383096043c331e4cf934e8c679c6fc4fc9bf` | `4cf103f0da8c94212c0bd76440abed3e4a321376` |
| `harness.c` | `899d1aaddd1006a4617a04b66ec495ab09067d7d88b2acb9340fae3900d708f8` | `7a46f5e6daea5ea36447e614abd22f8cd097f2e1` |
| `probe_generated.c` | `3052fc0383c67303c053ec4c7d5ea71d6276cbcfd61118f592dc09241acb15dd` | `885c5fd9dad5d82880cb470dc80e2f8b746db836` |
| `run_probe.py` | `6a83b2243aa5522b25c640ef77401be064e90fd4066324f838357c577cabf97b` | `12894783beb9559fd4235f6c49b4c922394381af` |
| `source-git-objects.json` | `d83ff77ae5ba304d4da323272dde5a334020c62967228fcf609be1b1dc21c961` | `6a9ee32991f0ae451a73ed99e09aed708bc605af` |

## Reproduction of the narrow C contract

On a Linux host with a C11 compiler and UBSan support, from the directory containing these files:

```bash
cc -std=c11 -O3 -fsanitize=undefined -fno-sanitize-recover=all -Wall -Wextra harness.c probe_generated.c -o ./probe-executable
./probe-executable
python -m py_compile run_probe.py
```

The C executable should report **513 finite byte-boundary and bidirectional C-call observations passed**. In the original checkout, this standalone command and Python compilation completed successfully. `run_probe.py` additionally depends on the exact pinned Hepta compiler modules listed by `source-git-objects.json` and writes generated artifacts to its working directory; execute that driver only inside an isolated copied checkout with a configured Python import path and appropriate toolchain. `probe_generated.c` is a pinned *artifact source*, not proof that the current compiler independently regenerates it.

## Unclosed acceptance gates

No authorized native HIA execution, ABI lifecycle or aliasing envelope, production OpenVPN/TUN/DCO session, rekey/reconnect, authentication negatives, kernel peer statistics, or fair performance comparison is established by this probe. The independent OpenVPN program lives in Draft PR #695; its real target test failed and needs rerun with the Netlink repair from Draft PR #712. Preserve both contexts; do not merge this archival branch, deploy, clear Library, or treat these observations as throughput evidence.

This Draft intentionally excludes raw `probe-result.json`, logs, binary outputs, model files, credentials, personal email addresses, and large evidence bundles.
