# B full native NDU: original member preservation

Source: `6ecd8023615a6e0b2dc269379fb059c656b38b6f`. Original [run 42565815059](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815059), artifact `13653895483`.

The downloaded original ZIP was 19,759,307 bytes and matched GitHub's recorded SHA256 `d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff` before preservation.

This directory preserves **all 1,796 original member byte streams and their original ordered names, CRCs and ZIP attributes**. Their total content is 227,392,009 bytes. Equal-content members share 1,135 unique objects (188,107,103 bytes). The eight archive parts reconstruct an 8,038,616-byte content-addressed tar.xz with SHA256 `de4d7363cbc5c8db6410756a90a3c18135f2b78c683ef3294ed070ee76378005`.

Run the standalone reader from any working directory:

```sh
python -I -B verify.py
```

The recorded invocation actually returned exit 0. It checked archive parts, the complete member index, every unique object's size/SHA/CRC, original member order, every mapping and aggregate counts. It reads objects without extracting or executing them. Duplicate contents were also compared byte for byte against original ZIP members during construction.

This is a different archive representation; it is **not the original ZIP byte stream**. The standalone reader cannot recompute GitHub's original ZIP digest from it. Preservation neither reruns any proof/native workflow nor authenticates timing, cost or the correctness of reported claims. See the separate independent review for the original experiment's scope and outcomes.

