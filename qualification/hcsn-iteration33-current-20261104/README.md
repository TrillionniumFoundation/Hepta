# HCSN iteration 33: current source qualification

This isolated research branch preserves the complete research/hcsn tree from e179de289b44210920e80ed5f376e5abbe864fee (Draft #512). It does not move that draft, modify its original report, or change any scientific gate.

## Concrete provenance gap

The original iteration-33 raw report has SHA256 840399acfe262e43450d2f5f0ac2d89a65bc0e87a24156ffc9da7b2443726d99. Its recorded test fingerprint is 75d512f5c62b4ded677e55252df8f3e925e8271468486a780499d761ea11bb97, while the committed test hashes to 5cb79deae3a090b2d2fe47993838a69dd35099fb4048dfd296015bf000ca3f75. The model and evidence-generator fingerprints match. The reason for the historical mismatch is not established here.

## Commands and acceptance

The runner executes the original four test modules, derives their 38 unique names from exact source, and requires every case once with no failure, error, skip, missing or extra case. This scope is the four original modules, not every HCSN test.

It then runs the original evidence command with 45,000 samples for each of three seeds and two transition matrices (270,000 synthetic trajectories). The fresh report must identify the current three source hashes and retain all seven OPEN gates, scientific_admission=false and production_activation=false. Any changed nonmetadata top-level fields versus the old report are recorded without claiming historical byte identity.

The original independent gate is run on an empty untrusted directory and must exit 2, with all P0–P6 OPEN, no verified independent attestation, no full closure and no production activation.

All research and qualification files are compared with exact Git blobs before and after execution; changes outside the four qualification paths are refused. Complete returned logs, the case inventory, both source snapshots, fresh raw evidence, refusal result and receipt are retained. Nine reader controls are synthetic and separate from research execution.

## Toolchain and boundaries

Python 3.13.5 and NumPy 2.3.5 match the old raw report. SciPy 1.16.3 is a new explicit compatible pin; the historical SciPy version was not recorded. The official v1.16.3 pyproject requires Python >=3.11 and NumPy >=1.25.2,<2.6. The actual pip installation report is retained. BLAS/OMP settings match the original reproduction command.

The new hosted job has a 15-minute limit and each original command a 600-second execution limit; timeout or incomplete output fails. Returned streams above 8 MiB are refused for retention; this is not a subprocess memory or incremental-output limit. The source input budget is 4 MiB.

No local execution environment was available when authored. Commit publication or static review does not establish a passed hosted run. Only the exact-source successful receipt qualifies these finite research commands. All P0–P6 requirements, production admission, external attestation, model-scale/equal-compute/hardware and held-out scientific requirements remain open.

Official dependency source: https://github.com/scipy/scipy/blob/v1.16.3/pyproject.toml
