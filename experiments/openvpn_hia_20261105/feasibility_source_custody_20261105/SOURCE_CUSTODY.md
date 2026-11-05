# Library HIA finite probe — source custody (HOLD)

Source-only custody from `hia_openvpn_feasibility_probe_20261105.zip` (7,437 bytes, SHA-256 `74e61b9a2988c49e9eb0df23a7fbfb2e2739b19e7f9af2adfa56d24f6ca999d0`). Original member bytes are retained via the exact Git blob objects below; the original ZIP, observations and compiler artifacts remain in Library.

| Source | Bytes | Original SHA-256 | Git blob |
|---|---:|---|---|
| harness.c | 601 | 899d1aaddd1006a4617a04b66ec495ab09067d7d88b2acb9340fae3900d708f8 | 7a46f5e6daea5ea36447e614abd22f8cd097f2e1 |
| probe.hepta | 413 | 77895f2e33f2dbe04054b3136abf383096043c331e4cf934e8c679c6fc4fc9bf | 4cf103f0da8c94212c0bd76440abed3e4a321376 |
| probe_generated.c | 3478 | 3052fc0383c67303c053ec4c7d5ea71d6276cbcfd61118f592dc09241acb15dd | 885c5fd9dad5d82880cb470dc80e2f8b746db836 |
| run_probe.py | 2452 | 6a83b2243aa5522b25c640ef77401be064e90fd4066324f838357c577cabf97b | 12894783beb9559fd4235f6c49b4c922394381af |

Pinned compiler source in the original run: Hepta `125d11c5454835a7df1dc51915fc49901fbede5b`. The original driver imports Hepta Python modules, writes reports beside itself and contains Linux-specific tooling paths. Do not mistake the presence of the script for a fresh HIA compiler qualification.

A new, independent *generated-C-only* Linux replay was performed with:

```sh
cc -std=c11 -O3 -Wall -Wextra -Wpedantic -fsanitize=undefined -fno-sanitize-recover=all harness.c probe_generated.c -lm -o hia_probe
./hia_probe
python -m py_compile run_probe.py
```

Observed: exit 0 and `513 finite byte-boundary and bidirectional-C-call observations passed`; Python syntax passed. This reproduces a finite C ABI fixture **only**. No actual OpenVPN tunnelling, real TUN/DCO, rekey, renegotiation, packet processing, performance or independent deployment gate was exercised. **Draft/HOLD; no production qualification.** No original log, binary, credential or unrelated Library file is included. Library-wide cleanup remains forbidden until the separate full-inventory gate passes.
