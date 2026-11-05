# Unique owner slot exchange fixture

This authored component uses the actual captured C++ standard-library
`std::unique_ptr<unsigned char[]>`, with repeated member swap and release/reset.
It is an integration fixture, not a newly migrated upstream library.

The complete component is translated through the explicit v3 profile described
in `docs/HIA_CPP_UNIQUE_SWAP_V3.md`. The native qualification preserves the
allocator and independent C caller evidence used by the earlier reset/reuse
profiles. The original C++ implementation is never linked into the Hepta target.
