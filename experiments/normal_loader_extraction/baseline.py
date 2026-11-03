"""Load exact historical bytes into test-only namespaces, never replace hepta.

Only relative import locations change. The frozen sources are reviewed data,
not a maintained second implementation or a runtime deployment mechanism.
"""
import hashlib
from pathlib import Path
import sys
from types import ModuleType
from experiments.legacy_loader_ops.candidate import PINS

PACKAGE = __package__ + '._baseline'
namespace = ModuleType(PACKAGE)
namespace.__path__ = []
sys.modules[PACKAGE] = namespace


def _load(name):
    path = Path(__file__).resolve().parents[1] / 'legacy_loader_ops' / 'baseline' / (name + '.py')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PINS[name]:
        raise RuntimeError('historical baseline drift: ' + name)
    source = data.decode('utf-8')
    for dependency in ('ast', 'parser', 'lexer'):
        source = source.replace('from .' + dependency + ' import', 'from hepta.' + dependency + ' import')
    module = ModuleType(PACKAGE + '.' + name)
    module.__package__ = PACKAGE
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(source, str(path), 'exec'), module.__dict__)
    setattr(namespace, name, module)
    return module


packages = _load('packages')
modules = _load('modules')
