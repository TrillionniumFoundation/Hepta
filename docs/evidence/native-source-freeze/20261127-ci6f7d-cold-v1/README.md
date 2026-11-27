# Original CI failure for the qualified ROG candidate

GitHub Actions run 46008392381, job 140537280980 executed exact source 6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807. Its seven native construction stages passed (4,528 construction nodes, 45 installed tools), and its 1,284-entry native source export passed. The actual full cold qualification did not complete under the unchanged 180 second gate.

The original native owner receipt records 180,003,171,057 ns before timeout and 35,153,824 ns of bounded cleanup. Its signed leader result is -9 and its timeout field is 1. The complete ordinary failure report remains unchanged, including its false native_descendants_only field. There are 25 nonempty phase archives and one empty archive in the captured output; these file counts are not a claim that any incomplete set passed the complete qualification gate.

Artifact 15204175387 was downloaded in full: 204,180,596 bytes, SHA256 e542fe544d5756e536f654c8b2f288fea6bd84f65b4cc35e3645b11c1c72fb13. All 1,425 members (877,308,321 uncompressed bytes) were independently read and SHA256 pinned in artifact-members.json. The smaller original-ci-evidence.tar.gz retains 73 original reports, receipts, streams and traces with individual member hashes, rechecked after archive construction. read_original_artifact.py reproduces this readback from the exact full ZIP.

The same source later passed the complete 60-phase original gate on ROG at 178.065100738 seconds; that separate observation is preserved under ../20261127-6f7d-cold-v1/. It does not turn this CI run green, alter its resource or timing records, reuse its partial output as qualification, or authorize legacy removal. The original budgets and scheduler remain unchanged.
