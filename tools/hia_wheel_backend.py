"""PEP 517 entry points for the ordinary Linux x86-64 HIA distribution."""
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
import zipfile

from setuptools.build_meta import (
    build_editable as build_python_editable,
    build_sdist, get_requires_for_build_editable, get_requires_for_build_sdist,
    get_requires_for_build_wheel, prepare_metadata_for_build_editable, prepare_metadata_for_build_wheel,
)


def _cold_inputs(work):
    from tools.replay_hia_selfhost_cold import cold_replay

    report = work / 'cold.json'
    cold_replay(report)
    return work / 'cold.cold/qualification.evidence/B3.image.bin', report


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    from tools.build_hia_default_release import build

    destination = Path(wheel_directory).resolve()
    with TemporaryDirectory(prefix='hia-wheel-') as tmp:
        work = Path(tmp).resolve()
        compiler, report = _cold_inputs(work)
        wheel = build(work / 'release', compiler, report)
        copyfile(wheel, destination / wheel.name)
        return wheel.name


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """Keep the Python API editable and install the same physical public ELF programs."""
    from tools.build_hia_default_release import WHEEL_TAG, _native_cli_scripts, _write_wheel
    from tools.build_hia_json_preflight import admit_cold_build

    destination = Path(wheel_directory).resolve()
    with TemporaryDirectory(prefix='hia-editable-') as tmp:
        work = Path(tmp).resolve()
        base = work / build_python_editable(str(work), config_settings, metadata_directory)
        with zipfile.ZipFile(base) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        record, = (name for name in files if name.endswith('.dist-info/RECORD'))
        distribution = record.removesuffix('/RECORD')
        compiler, report = _cold_inputs(work)
        sources = admit_cold_build(compiler.read_bytes(), report.read_bytes())
        programs, _ = _native_cli_scripts(work / 'cli', compiler, report, distribution, sources=sources)
        files.update(programs)
        current = base.name.removesuffix('.whl').rsplit('-', 3)
        tag = '-'.join(current[1:])
        wheel_name = base.name
        if tag == 'py3-none-any':
            meta = distribution + '/WHEEL'
            files[meta] = files[meta].replace(b'Root-Is-Purelib: true', b'Root-Is-Purelib: false').replace(
                b'Tag: py3-none-any', b'Tag: ' + WHEEL_TAG.encode())
            wheel_name = current[0] + '-' + WHEEL_TAG + '.whl'
        _write_wheel(destination / wheel_name, files, distribution)
        return wheel_name
