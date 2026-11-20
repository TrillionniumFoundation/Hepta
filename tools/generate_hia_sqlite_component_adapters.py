"""Regenerate HIA object templates for SQLite component and capture processes."""
from tools.build_hia_sqlite_components import ADAPTER_ROLES, COMPONENT_TEMPLATES, ROOT
from tools.generate_hia_relocatable_templates import render_objects


if __name__ == '__main__':
    variant = b'.set HIA_COMPONENT_EMBEDDED_OBJECTS,1\n'
    roles = ((name, role, variant) for name, role in ADAPTER_ROLES.items())
    (ROOT / COMPONENT_TEMPLATES).write_text(render_objects(COMPONENT_TEMPLATES, roles))
