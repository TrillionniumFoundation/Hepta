"""Keep explicit whole-package wheel copy fixtures complete as roles grow.

This static regression detects the actual omitted role lists seen in wire and
worker-report fixtures. It is not a replacement for executing installed wheels.
"""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class InstalledFixtureRoleInventoryTests(unittest.TestCase):
    def test_explicit_whole_package_copy_fixtures_cover_all_current_roles(self):
        module=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
        needed={target.id for node in module.body if isinstance(node,ast.Assign)
            for target in node.targets if isinstance(target,ast.Name)
            and (target.id.endswith('_BUILD_FILES') or target.id in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES'))}
        self.assertTrue({'NATIVE_SOURCE_FILES','MACHINE_OBJECT_BUILD_FILES',
                         'EXECUTION_OBSERVATION_BUILD_FILES'}.issubset(needed))
        observed=[]
        for file in sorted((ROOT/'tests').glob('*.py')):
            tree=ast.parse(file.read_text())
            strings={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value) is str}
            names={n.id for n in ast.walk(tree) if isinstance(n,ast.Name)}|{
                n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute)}
            copies=any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                and n.func.attr in ('copytree','copyfile') for n in ast.walk(tree))
            used=needed&(strings|names)
            if copies and 'setup.py' in strings and used:
                observed.append(file.name)
                with self.subTest(fixture=file.name):self.assertEqual(needed-used,set())
        self.assertIn('test_hia_json_wire_native.py',observed)
        self.assertIn('test_hia_worker_report_native.py',observed)
        self.assertGreaterEqual(len(observed),25)


    def test_standalone_entry_role_is_exact_disjoint_and_preflight_bounded(self):
        from unittest.mock import patch
        from tools import hia_candidate_preflight as preflight
        source=(ROOT/'hepta/hia_agent_contract.py').read_text()
        tree=ast.parse(source)
        names=('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES',
               'COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES',
               'EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES',
               'EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES','ENTRY_BUILD_FILES')
        values={}
        for name in names:
            nodes=[n for n in tree.body if isinstance(n,ast.Assign)
                   and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
            self.assertEqual(len(nodes),1,name)
            values[name]=ast.literal_eval(nodes[0].value)
        entry=('examples/hia_bootstrap/release_launch_policy.hepta',
               'examples/hia_bootstrap/release_launch_packer.hepta',
               'examples/hia_bootstrap/candidate_build_policy.hepta',
               'examples/hia_bootstrap/candidate_build_packer.hepta',
               'examples/hia_bootstrap/selfhost_linux_stdio.hepta',
               'examples/hia_bootstrap/linux_stdio_entry_packer.hepta',
               'examples/hia_bootstrap/selfhost_linux_process.hepta',
               'examples/hia_bootstrap/linux_process_entry_packer.hepta',
               'examples/hia_bootstrap/selfhost_linux_cli_process.hepta',
               'examples/hia_bootstrap/linux_cli_entry_packer.hepta',
               'examples/hia_bootstrap/native_cli_process.hepta',
               'examples/hia_bootstrap/selfhost_linux_file.hepta',
               'examples/hia_bootstrap/linux_file_entry_packer.hepta',
               'examples/hia_bootstrap/native_file_read.hepta',
               'examples/hia_bootstrap/file_render_checker.hepta',
               'examples/hia_bootstrap/file_render_frontend.hepta',
               'examples/hia_bootstrap/linux_file_render_entry_packer.hepta',
               'examples/hia_bootstrap/native_file_render.hepta',
               'examples/hia_bootstrap/selfhost_linux_file_render.hepta')
        self.assertEqual(values['ENTRY_BUILD_FILES'],entry)
        self.assertEqual(len(values['NATIVE_SOURCE_FILES']),92)
        previous=tuple(path for name in names[1:-1] for path in values[name])
        self.assertTrue(set(entry).isdisjoint(previous))
        expected=previous+entry
        self.assertEqual(len(expected),len(set(expected)))
        original=preflight.literal_inventory;observed=[]
        def inventory(text,symbol,**options):
            observed.append(symbol)
            return original(text,symbol,**options)
        with patch.object(preflight,'literal_inventory',inventory):
            self.assertEqual(preflight.native_source_files(source),expected)
        self.assertEqual(observed,list(names[1:]))
        for value in ((entry[0],entry[0]),('examples/hia_bootstrap/selfhost.hepta',),
                      ('examples/hia_bootstrap/unreviewed.hepta',),('/tmp/launch.hepta',),
                      ('tools/hia_release_launch_syscalls.S',),(True,)):
            with self.subTest(entry=value),self.assertRaises(ValueError):
                preflight.native_source_files('ENTRY_BUILD_FILES = '+repr(value)+'\n')
        with self.assertRaises(ValueError):
            preflight.native_source_files('ENTRY_BUILD_FILES = ()\nENTRY_BUILD_FILES = ()\n')
        with self.assertRaises(ValueError):
            preflight.native_source_files('NATIVE_SOURCE_FILES = '+repr(entry)+'\n'
                                          +'ENTRY_BUILD_FILES = '+repr(entry)+'\n')
        native=tuple('examples/hia_bootstrap/entry_boundary_'+str(i)+'.hepta'
                     for i in range(256-len(entry)))
        boundary='NATIVE_SOURCE_FILES = '+repr(native)+'\nENTRY_BUILD_FILES = '+repr(entry)+'\n'
        self.assertEqual(len(preflight.native_source_files(boundary)),256)
        with self.assertRaises(ValueError):
            preflight.native_source_files(boundary.replace(repr(native),repr(native+(
                'examples/hia_bootstrap/entry_boundary_overflow.hepta',)),1))

    def test_entry_assets_are_fresh_identity_inputs_and_missing_fails_before_backend(self):
        import tempfile
        from hashlib import sha256
        from unittest.mock import patch
        from hepta import hia_agent_contract as contract
        from hepta import hia_program_native as backend
        from hepta import hia_native_helpers as helpers
        tree=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
        role_names=[t.id for n in tree.body if isinstance(n,ast.Assign)
                    for t in n.targets if isinstance(t,ast.Name)
                    and (t.id.endswith('_BUILD_FILES') or t.id in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES'))]
        self.assertEqual(len(role_names),12)
        assets=tuple('docs/'+n for n in contract.DISCOVERY_FILES)
        for name in role_names:
            if name!='DISCOVERY_FILES':assets+=getattr(contract,name)
        self.assertEqual(len(assets),210)
        self.assertEqual(len(assets),len(set(assets)))
        with tempfile.TemporaryDirectory(prefix='hia-entry-resource-source-') as folder:
            root=Path(folder);data=root/'data'
            for name in assets:
                raw=('source fixture '+name+'\n').encode()
                path=data/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
                if name.startswith('hepta/') and name.endswith('.py'):
                    target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            entries={name:sha256((data/name).read_bytes()).hexdigest() for name in assets}
            with patch.object(contract,'ROOT',root),\
                 patch.object(contract,'_agent_resource_path',lambda name:data/name),\
                 patch.object(backend,'_implementation_hash',return_value='mechanical backend sentinel') as observed,\
                 patch.object(helpers,'native_helpers_identity',return_value={}):
                initial=contract.installation_manifest()
                self.assertEqual(initial['worker_sha256'],sha256(contract.wire(entries)).hexdigest())
                for name in contract.ENTRY_BUILD_FILES:
                    path=data/name;raw=path.read_bytes()
                    path.write_bytes(raw+b'changed')
                    changed=contract.installation_manifest()
                    self.assertNotEqual(changed['worker_sha256'],initial['worker_sha256'])
                    path.unlink();observed.reset_mock()
                    with self.assertRaises(FileNotFoundError):contract.installation_manifest()
                    observed.assert_not_called()
                    path.write_bytes(raw)
                    self.assertEqual(contract.installation_manifest(),initial)


if __name__=='__main__':unittest.main()
