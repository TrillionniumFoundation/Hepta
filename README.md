# Isolated native heap optimization development gate

This branch contains a harness and immutable inputs, not a product checkout.
It checks out exact product `5f7f95367e8e395863801487e969d286b9091110`
(`4f4e58e06a6e03adcd6548bd8ea4ef591c20359f`), verifies all 3,120 tracked
file bytes, Git objects and executable modes, and applies exactly six reviewed
paths. The 81b6 retained compiler is used only for development compilation.

Python 3.14.4 runs the original source and adapter groups, complete private
native/VM group, the targeted general-map overwrite control, and all five
public native methods. These are 38 outer tests, including the original 134
reference plus 134 native tests. Original compiler child timeout 20 seconds,
original public child timeout 150 seconds, and analysis limits 1024/64/32768
remain unchanged. The 1,800-second outer suite supervisor is separate from
these product and test limits.

No cold report, current-source release qualification, full-product pass,
default switch, deletion, or live deployment is claimed by this job. Complete
raw files remain in the artifact, including failures. Log capsules are a
lossless text subset with an explicit inventory, not a replacement for the
complete binary evidence.
