"""Fresh request-owned loading context for the isolated native build experiment."""
from experiments.c_char_boundary import build_plan
from .context import Context, Limits


def execute(request, *, limits=Limits(), seconds=60, output_bytes=2_000_000):
    return build_plan.execute(request, seconds=seconds, output_bytes=output_bytes,
                             _context_factory=lambda check: Context(limits, check))
