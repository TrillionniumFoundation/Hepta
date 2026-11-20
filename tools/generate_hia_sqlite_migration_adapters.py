"""Regenerate the native migration publication and controller object templates."""
from tools.build_hia_sqlite_migrate import ADAPTER as MIGRATE_ADAPTER
from tools.build_hia_sqlite_migration_publish import (
    ADAPTER as PUBLISH_ADAPTER, MIGRATE_ROLE, MIGRATION_TEMPLATES, PUBLISH_ROLE, ROOT,
)
from tools.generate_hia_relocatable_templates import render_objects


if __name__ == '__main__':
    source_prefix = b'.set HIA_MIGRATION_EMBEDDED_OBJECTS,1\n'
    roles = ((PUBLISH_ADAPTER, PUBLISH_ROLE, source_prefix), (MIGRATE_ADAPTER, MIGRATE_ROLE, source_prefix))
    (ROOT / MIGRATION_TEMPLATES).write_text(render_objects(MIGRATION_TEMPLATES, roles))
