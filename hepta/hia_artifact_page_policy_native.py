"""The Artifact Page policy image's exact five-field manifest contract."""
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/artifact_page.hepta')
SCHEMA = 'hepta.hia.artifact-page-native.v2'
SELECTOR = 'HEPTA_HIA_ARTIFACT_PAGE_POLICY_MANIFEST'


class NativeArtifactPagePolicy(NativeHiaJsonImage):
    """Map the admitted byte-policy image; the Page session owns its protocol."""


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
