"""Regenerate fixed HIA objects for standalone nominal packet and constructor processes."""
from tools.build_hia_nominal_constructor import ROOT, TRANSPORT_ROLES, TRANSPORT_TEMPLATES
from tools.build_hia_nominal_json import STDIO, STDIO_TEMPLATE
from tools.generate_hia_relocatable_templates import render_objects


if __name__ == '__main__':
    external = b'.set HIA_NOMINAL_EXTERNAL_OBJECTS,1\n'
    (ROOT / STDIO_TEMPLATE).write_text(render_objects(STDIO_TEMPLATE, ((STDIO, 0, external),)))
    variants = (external, b'.set HIA_VERIFIED_PUBLISH,1\n', b'.set HIA_CONSTRUCTOR_ASSEMBLY,1\n')
    roles = ((name, index, prefix) for index, (name, prefix) in enumerate(zip(TRANSPORT_ROLES, variants, strict=True)))
    (ROOT / TRANSPORT_TEMPLATES).write_text(render_objects(TRANSPORT_TEMPLATES, roles))
