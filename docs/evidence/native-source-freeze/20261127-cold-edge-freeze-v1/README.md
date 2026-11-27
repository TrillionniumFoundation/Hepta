# Native freeze for separate cold seed profiles

The merged source base is `bbb29187723d21e0439706471f2c1acf9c4bda5f`, including the original Slot and bounded-memory caller evidence. Actual native entry preparation performed 53 calls, and the native HIA contract producer froze all 1,284 files / 247,562,703 bytes. Python authoring files and machine images are excluded from the native authority.

The authority adds exactly two HIA profiles. The pre- and post-cold construction plans were regenerated twice with byte-identical output. All original 60 qualification plans and 479,882 nodes retain their exact catalog identities, 180-second deadline, 3-second cleanup and 2/1/2/4 scheduler bounds.

The changed construction graph has 4528 nodes in seven stages. These are construction operations, separate from the unchanged qualification phase count. The actual new root driver and SHA images are pinned by the retained preseed report; no previous cold success is inherited.

`native-preparation.tar.gz` retains every preparation input, stdout/stderr and exact before/after source pin, plus the actual 53-call preparation report. Its SHA-256 is `48964bb80ff2a3c0eaec4c20dfc5c14474aaf7d7325639a3f7e268ff2883a929` (468460 bytes). The archive has 22 members, including its full hash manifest.

This is successful source preparation, not a completed cold, matching release, install, installed rebuild or whole-stack qualification. The next exact committed source must still pass the original full chain.
