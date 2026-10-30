# Rust scoped cleanup: separate execution identities

The current qualification is [final-953](final-953/README.md). [history-3533](history-3533/README.md) preserves the earlier whole-source execution and all development inputs, failed controls and old/new executed CLI bytes. Both are self-contained inert archives with independent manifests and readers. Their test/observation denominators and source identities must not be combined.
