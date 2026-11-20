"""Regenerate fixed HIA objects for standalone nominal packet and constructor processes."""
from tools.build_hia_nominal_constructor import ROOT, TRANSPORT_ROLES, TRANSPORT_TEMPLATES
from tools.build_hia_nominal_json import STDIO, STDIO_TEMPLATE
from tools.generate_hia_relocatable_templates import render_objects


if __name__ == '__main__':
    external = b'.set HIA_NOMINAL_EXTERNAL_OBJECTS,1\n'
    (ROOT / STDIO_TEMPLATE).write_text(render_objects(STDIO_TEMPLATE, ((STDIO, 0, external),)))
    variants = (external, b'.set HIA_VERIFIED_PUBLISH,1\n', b'.set HIA_CONSTRUCTOR_ASSEMBLY,1\n')
    roles = [(name, index, prefix) for index, (name, prefix) in enumerate(zip(TRANSPORT_ROLES, variants, strict=True))]
    # The raw constructor record needs more scalar operations than one cold
    # module allows. Each part stays below the existing 8192-instruction cap.
    middle = 14 * 1024
    for label, selected, part in (
        ('constructor', roles[:1], slice(0, middle)),
        ('constructor-tail', roles[:1], slice(middle, None)),
        ('publication', roles[1:], slice(None)),
    ):
        path = TRANSPORT_TEMPLATES[label]
        (ROOT / path).write_text(render_objects(path, selected, record_slice=part))
