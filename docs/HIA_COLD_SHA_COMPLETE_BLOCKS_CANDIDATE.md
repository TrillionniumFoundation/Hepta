# Complete-block SHA candidate

This experimental native HIA path retains the original alias dispatcher and fallback. Only pairwise-disjoint updates with at least two complete blocks use the new helper. It keeps the 16-word schedule and chaining values in scalar variables for all complete blocks except the last. The last block uses the original compression, restoring the complete original 1,184-byte state before return. Partial blocks, initialization/finalization, arbitrary full-u64 state and round constants, output, traps, and alias fallback remain under the original controls.

The author accepts only the exact original expanded source SHA and verifies that removing its new helper and call recovers the original complete AST. The helper uses a fixed group of eight rounds.

The original 27,043 SHA transitions, 2,000 offset-alias controls and 51 native packer controls passed on the actual target. Native source preparation was repeated without drift for 1,292 sources and the original 60 phases / 479,882 nodes.

Performance remains an experiment. A local Intel microbenchmark improved, while the actual retained 47,954,509-byte ROG archive regressed by about 11% CPU with all four complete output archives still byte-identical. This source is not approved as a performance improvement. Both the ROG and CI complete cold gates must still pass with the original 180-second qualification and 3-second cleanup. No budget, scheduler, original assertion, negative control, or phase was changed.

Complete semantic-control observations and preparation records are retained under docs/evidence/cold-sha-complete-blocks-20261127-2807. Existing full-stack, release, install, and rebuild qualification is not inherited.
