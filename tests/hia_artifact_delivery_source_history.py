"""Root-bound historical data for the unchanged artifact Source control."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

SOURCE = 'tests/hia_artifact_delivery_source_history.py'
ORIGINAL = 'tests/fixtures/hia_artifact_delivery_original_5da589f0.json'
ORIGINAL_SHA256 = '3b6fb4c69e5923d0483b01bd368525d1e7a71575865a9913c69705001f009a42'
CALLERS = (
    'tests/test_artifact_publication.py',
    'tests/test_hia_artifact_publication_native.py',
    'tests/test_hia_artifact_publication_route.py',
    'tests/test_hia_agent_artifact_store_native.py',
)
GENERATOR = 'tools/generate_hia_artifact_publication.py'
OLD_GENERATOR = 'tests/fixtures/hia_artifact_delivery_generator_5da589f0.py.txt'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def artifact_sources(root, *, take=Path.read_bytes):
    """Capture current inputs separately from the exact original caller images."""
    from tests import hia_installed_distribution_history as installed
    from tests import hia_component_authoring_history as component
    from tools import hia_frozen_component_sources as frozen
    from tools import hia_cold_caller_sources as cold

    root = Path(root)
    physical = {}

    def capture(path):
        name = path.relative_to(root).as_posix()
        raw = take(path)
        if type(raw) is not bytes or name in physical and physical[name] != raw:
            raise ValueError('artifact historical physical source changed between captures')
        physical[name] = raw
        return raw

    try:
        for name, loaded in (
                (SOURCE, __file__),
                ('tests/hia_installed_distribution_history.py', installed.__file__),
                ('tests/hia_component_authoring_history.py', component.__file__),
                ('tools/hia_frozen_component_sources.py', frozen.__file__),
                (cold.SOURCE, cold.__file__)):
            if capture(root / name) != Path(loaded).read_bytes():
                raise ValueError('artifact historical loaded helper differs from physical root')
        original = capture(root / ORIGINAL)
        if sha256(original).hexdigest() != ORIGINAL_SHA256:
            raise ValueError('complete original artifact caller authority differs')
        value = json.loads(original)
        if (tuple(value['direct_caller_modules']) != CALLERS
                or len(value['declared_original_test_ids']) != 63
                or len(set(value['declared_original_test_ids'])) != 63):
            raise ValueError('complete original artifact caller plan differs')
        prepared = {ORIGINAL: original}
        for name in CALLERS:
            raw = capture(root / name)
            prior, _ = frozen.cold_caller_source(root, name, raw, take=capture)
            prior = installed.predecessor(name, prior, root=root, take=capture)
            expected = {key: value['source_files'][name][key] for key in ('bytes', 'sha256')}
            if pin(prior) != expected:
                raise ValueError('complete original artifact caller source differs: ' + name)
            prepared[name] = prior
        prepared[GENERATOR] = capture(root / GENERATOR)
        prepared[OLD_GENERATOR] = capture(root / OLD_GENERATOR)
        return prepared, physical
    finally:
        for name, raw in physical.items():
            if take(root / name) != raw:
                raise ValueError('artifact historical terminal physical reread differs')


@contextmanager
def historical_artifact_source_root(root, *, take=Path.read_bytes):
    """Expose historical test data without changing current source or loaded callers."""
    root = Path(root)
    prepared, physical = artifact_sources(root, take=take)
    with TemporaryDirectory(prefix='hia-artifact-source-history-') as temporary:
        stage = Path(temporary)
        for name, raw in prepared.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        try:
            yield stage
        finally:
            for name, raw in prepared.items():
                if (stage / name).read_bytes() != raw:
                    raise ValueError('artifact historical data projection changed')
            for name, raw in physical.items():
                if take(root / name) != raw:
                    raise ValueError('artifact source changed while historical control ran')
