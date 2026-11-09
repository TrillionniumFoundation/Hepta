# Same-source NDU repeat: complete original member preservation

This packet retains the original member streams from [post-integration run 42572528877](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42572528877), artifact `13654707994`, for exact source `6ecd8023615a6e0b2dc269379fb059c656b38b6f`.

The original ZIP was 19,758,336 bytes and matched the official SHA256 `8b791d08e2f3543b1ec5f9c0447233da6f75a3b68fd5bc7c59d909d0aed572c2` before preservation. All **1,796 original members** (227,409,926 bytes) are mapped in original order with names, CRCs, sizes, SHA256 and ZIP attributes. Equal contents share 1,135 objects totaling 188,125,020 bytes. The eight parts reconstruct an 8,101,048-byte tar.xz, SHA256 `7ee180d21b026e2958ccfd9d1523757bc9d5725eecebe524e2e98a2ffcd47818`.

The standalone `python -I -B verify.py` invocation actually returned exit 0. It reads every retained object and checks all original member mappings without extracting or executing them. Its script, stdout/stderr and execution receipt are included. Original duplicate contents were also compared byte for byte during construction.

This archive is a different representation from the original ZIP. The standalone reader cannot recompute GitHub's ZIP digest from it, and does not rerun proofs, authenticate timings or establish performance gains. The [independent repeat comparison](../hia-b6ecd-ndu-repeat-independent-20261109-e5ee/README.md) retains both repeated narrowed-kernel successes and the new policy-training p99 failure, without changing the first artifact's evidence.

