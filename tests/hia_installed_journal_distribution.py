"""Check Journal package input custody against the ordinary cold source distribution."""
from hashlib import sha256
import json
from pathlib import Path

from tests import hia_journal_installed_preparation as journal
from tests.hia_distribution_fixture import _sources
from tests.hia_installed_distribution_history import journal_preparation_source


def prepare_resources(root, agent_resources):
    authority = (root / journal.FIXTURE).read_bytes()
    if journal.pin(authority) != journal.FIXTURE_PIN:
        raise ValueError('the original Journal package authority differs')
    original = json.loads(authority)
    if tuple(name for name in agent_resources if name in original['original_agent_resources']) != tuple(original['original_agent_resources']):
        raise ValueError('the original Journal agent resources are missing or reordered')
    capture = journal._literal((root / 'hepta/hia_executable_capture.py').read_bytes(), 'PACKAGE_RESOURCES')
    integers = tuple(name for symbol in journal.INTEGER_SYMBOLS
                     for name in journal._literal((root / 'setup.py').read_bytes(), symbol))
    if (list(capture) != original['current_executable_capture_resources']
            or list(integers) != original['current_integer_resources']):
        raise ValueError('the original capture or integer package resources differ')
    resources = tuple(agent_resources) + capture + integers
    if len(resources) != len(set(resources)):
        raise ValueError('duplicate Journal distribution member')
    files = (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in',
             'hepta/hia_agent_contract.py', 'hepta/hia_executable_capture.py')
    sources = _sources()
    pins = {name: sha256((root / name).read_bytes()).hexdigest() for name in files}
    if any(pin != sources[name] for name, pin in pins.items()):
        raise ValueError('a Journal preparation input differs from the complete admitted cold sources')
    proof = journal_preparation_source(root, (root / journal.PATH).read_bytes(), journal.ORIGINAL)
    return resources, {'resources': list(resources), 'files': pins,
                       'original_journal_source_admission': proof,
                       'current_caller': journal.pin((root / journal.PATH).read_bytes())}


def verify_staged_resources(root, staged, preparation, receipt):
    sources = _sources()
    for name, expected in preparation['files'].items():
        raw = (root / name).read_bytes()
        if sha256(raw).hexdigest() != sources[name] or sources[name] != expected or (staged / name).read_bytes() != raw:
            raise ValueError('a staged Journal source differs from its admitted file: ' + name)
    proof = journal_preparation_source(root, (root / journal.PATH).read_bytes(), journal.ORIGINAL)
    if (proof != preparation['original_journal_source_admission']
            or journal.pin((root / journal.PATH).read_bytes()) != preparation['current_caller']):
        raise ValueError('the Journal caller changed during distribution staging')
    with Path(receipt).open('xb') as output:
        output.write(journal.encoded(preparation))
