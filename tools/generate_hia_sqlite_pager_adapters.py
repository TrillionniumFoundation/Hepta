"""Regenerate the retained Pager's fixed HIA transport object templates."""
from tools.build_hia_sqlite_pager import ADAPTERS, ROOT, TEMPLATES
from tools.generate_hia_relocatable_templates import render_objects


if __name__ == '__main__':
    roles = ((name, index, b'.set HIA_PAGER_EMBEDDED_OBJECTS,1\n' if index == 0 else b'')
             for index, name in enumerate(ADAPTERS))
    (ROOT / TEMPLATES).write_text(render_objects(TEMPLATES, roles))
