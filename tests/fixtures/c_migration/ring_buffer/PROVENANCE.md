# Frozen upstream stateful ring buffer

Repository: https://github.com/AndersKaloer/Ring-Buffer

Commit: `8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba`

`ringbuffer.c`, `ringbuffer.h`, `LICENSE` and `UPSTREAM_README.md` contain the
unmodified bytes of the paths recorded in `UPSTREAM.json`. The last file is
upstream `README.md` under a local disambiguating filename. MIT terms are
retained in `LICENSE`; generated derivatives retain them too.

`contracts.json` and this provenance note are authored Hepta qualification
inputs, not files represented as upstream. The contract describes borrowed
caller-owned storage, not automatic ownership inference. The build captures
C11, `NDEBUG` and unsigned plain chars. No broader configuration or whole-C
migration claim follows from this qualification.

See `docs/C_RECORD_VIEWS.md` for the declaration denominator, boundary
obligations, independent oracle, allocation-owning Hepta caller and cost model.
