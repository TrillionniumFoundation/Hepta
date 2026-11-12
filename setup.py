"""Package the pinned Agent discovery and native-app source resources.

This is a development Python wheel build hook, not native build orchestration.
It copies only explicit source-owned resources; it imports no product modules.
"""
from pathlib import Path
import ast
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py

ROOT=Path(__file__).resolve().parent

def agent_resources():
    tree=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
    values={}
    for symbol in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES'):
        declarations=[node for node in tree.body if isinstance(node,ast.Assign)
                      and any(isinstance(target,ast.Name) and target.id==symbol for target in node.targets)]
        if len(declarations)!=1:raise ValueError('one explicit Agent resource list required: '+symbol)
        names=ast.literal_eval(declarations[0].value)
        if type(names)is not tuple or any(type(n)is not str or not n for n in names):
            raise ValueError('invalid Agent resource names')
        values[symbol]=names
    if any(Path(n).name!=n for n in values['DISCOVERY_FILES']):
        raise ValueError('invalid Agent discovery resource filenames')
    names=tuple('docs/'+n for n in values['DISCOVERY_FILES'])+values['NATIVE_SOURCE_FILES']+values['SOURCE_BUILD_FILES']+values['COMPILER_BUILD_FILES']+values['PUBLICATION_BUILD_FILES']
    if len(names)!=len(set(names)) or any(Path(n).is_absolute() or '..' in Path(n).parts for n in names):
        raise ValueError('invalid or duplicate Agent resource paths')
    return names

class AgentResourceBuild(build_py):
    def run(self):
        super().run()
        self._agent_outputs=[]
        for name in agent_resources():
            source=ROOT/name
            if not source.is_file():raise ValueError('missing Agent package resource: '+name)
            target=Path(self.build_lib)/'hepta/_data'/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
            self._agent_outputs.append(str(target))

    def get_outputs(self,include_bytecode=True):
        return super().get_outputs(include_bytecode)+getattr(self,'_agent_outputs',[])

setup(cmdclass={'build_py':AgentResourceBuild})
