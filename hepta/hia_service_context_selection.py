"""Source-bound context selection; an absent selector preserves current code."""
from __future__ import annotations
import os

SELECTOR = 'HEPTA_HIA_SERVICE_CONTEXT_MANIFEST'
UNSELECTED = object()


def run_service_context(mode, service, argument, *, candidate=False):
    if SELECTOR not in os.environ:
        return UNSELECTED
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('service context selector must not be empty')
    from .hia_service_context_native import installed_service_context, ContextFrame
    image = installed_service_context(selected)
    return ContextFrame(image, mode, service, argument, candidate=candidate).finish()
