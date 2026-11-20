"""Package the pinned Agent discovery and native-app source resources.

This is a development Python wheel build hook, not native build orchestration.
It copies only explicit source-owned resources; it imports no product modules.
"""
from pathlib import Path
import ast
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py
# Load the exact local build helper even under python -I / isolated wheels.
from importlib.util import spec_from_file_location, module_from_spec
_mechanical_spec = spec_from_file_location(
    '_hepta_slot_mechanical_build', Path(__file__).resolve().parent / 'hepta/native/slot_mechanical_build.py')
_mechanical_build = module_from_spec(_mechanical_spec)
_mechanical_spec.loader.exec_module(_mechanical_build)
MechanicalBuildExt, extensions = _mechanical_build.MechanicalBuildExt, _mechanical_build.extensions

_image_spec = spec_from_file_location(
    '_hepta_native_carrier_build', Path(__file__).resolve().parent / 'hepta/native/native_carrier_build.py')
_image_build = module_from_spec(_image_spec)
_image_spec.loader.exec_module(_image_build)

class AllMechanicalBuildExt(_image_build.NativeCarrierBuildExt, MechanicalBuildExt):
    """Independent exact receipts; each original builder handles only its ABI."""
    pass

ROOT=Path(__file__).resolve().parent

# Explicit independent VM arithmetic resource; no helper registry/default switch.
VM_INTEGER_DIVREM_RESOURCES = ('examples/hia_bootstrap/vm_integer_divrem.hepta',)
VM_INTEGER_ARITHMETIC_RESOURCES = ('examples/hia_bootstrap/vm_integer_arithmetic.hepta',)
VM_INTEGER_SCALAR_RESOURCES = ('examples/hia_bootstrap/vm_integer_scalar.hepta',)

def agent_resources():
    tree=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
    values={}
    for symbol in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES'):
        declarations=[node for node in tree.body if isinstance(node,ast.Assign)
                      and any(isinstance(target,ast.Name) and target.id==symbol for target in node.targets)]
        if len(declarations)!=1:raise ValueError('one explicit Agent resource list required: '+symbol)
        names=ast.literal_eval(declarations[0].value)
        if type(names)is not tuple or any(type(n)is not str or not n for n in names):
            raise ValueError('invalid Agent resource names')
        values[symbol]=names
    if any(Path(n).name!=n for n in values['DISCOVERY_FILES']):
        raise ValueError('invalid Agent discovery resource filenames')
    names=tuple('docs/'+n for n in values['DISCOVERY_FILES'])+values['NATIVE_SOURCE_FILES']+values['SOURCE_BUILD_FILES']+values['COMPILER_BUILD_FILES']+values['PUBLICATION_BUILD_FILES']+values['BACKEND_BUILD_FILES']+values['EMITTER_BUILD_FILES']+values['BYTE_WRAPPER_BUILD_FILES']+values['MACHINE_OBJECT_BUILD_FILES']+values['EXECUTION_OBSERVATION_BUILD_FILES']+values['CONTINUATION_BUILD_FILES']
    if len(names)!=len(set(names)) or any(Path(n).is_absolute() or '..' in Path(n).parts for n in names):
        raise ValueError('invalid or duplicate Agent resource paths')
    return names

def executable_capture_resources(existing):
    """Explicit data for an independently selected component; no product import."""
    path = ROOT / 'hepta/hia_executable_capture.py'
    tree = ast.parse(path.read_text())
    declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'PACKAGE_RESOURCES'
                            for target in node.targets)]
    if len(declarations) != 1:
        raise ValueError('one executable-capture package resource tuple is required')
    names = ast.literal_eval(declarations[0].value)
    if (type(names) is not tuple or any(type(name) is not str or not name
            or Path(name).is_absolute() or '..' in Path(name).parts for name in names)
            or len(names) != len(set(names)) or set(names) & set(existing)):
        raise ValueError('invalid or duplicate executable-capture package resources')
    return names

class AgentResourceBuild(build_py):
    def run(self):
        super().run()
        self._agent_outputs=[]
        names = agent_resources()
        for name in names + executable_capture_resources(names) + VM_INTEGER_DIVREM_RESOURCES + VM_INTEGER_ARITHMETIC_RESOURCES + VM_INTEGER_SCALAR_RESOURCES:
            source=ROOT/name
            if not source.is_file():raise ValueError('missing Agent package resource: '+name)
            target=Path(self.build_lib)/'hepta/_data'/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
            self._agent_outputs.append(str(target))

    def get_outputs(self,include_bytecode=True):
        return super().get_outputs(include_bytecode)+getattr(self,'_agent_outputs',[])

setup(cmdclass={'build_py':AgentResourceBuild, 'build_ext':AllMechanicalBuildExt},
      ext_modules=extensions() + _image_build.extensions(),
      package_data={'hepta': ['native/slot_mechanical.c', 'native/slot_mechanical_build.py',
                              'native/native_image.c', 'native/cell_frame.c', 'native/native_carrier_build.py']})
