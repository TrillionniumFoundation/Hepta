"""Read-only remaining-authority evidence, not implementation of a new quota."""
from pathlib import Path
import tempfile
import unittest

from .owner import Owner

TEXT='fn main()->Unit effects {} {}'


def plain_visits(value):
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise AssertionError('non-string authority map key')
        return 1+sum(plain_visits(key)+plain_visits(child) for key,child in value.items())
    if type(value) not in (str,bytes,type(None)):
        raise AssertionError('unexpected plain authority map type')
    return 1


class AuthorityAuditTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.entry=self.root/'main.hepta';self.entry.write_text(TEXT)

    def write_package(self,path,name,dependencies=(),kind='lib'):
        path.mkdir(exist_ok=True)
        entry='main.hepta' if kind=='bin' else 'lib.hepta'
        (path/entry).write_text(TEXT)
        text=f'[package]\nname="{name}"\nversion="1.0.0"\nkind="{kind}"\nsource_root="."\nentry="{entry}"\n'
        if dependencies:
            text+='[dependencies]\n'
            for alias,target in dependencies:text+=f'{alias}={{path="{target}"}}\n'
        (path/'hepta.toml').write_text(text)

    def test_standalone_three_maps_have_seven_unmetered_visits(self):
        owner=Owner();handle=owner.load(self.entry);authority=owner._handles[0][1]
        counts=[plain_visits(getattr(authority,name)) for name in
                ('source_bytes','bindings','package_state')]
        self.assertEqual(counts,[3,3,1])
        self.assertEqual(sum(counts),7)
        self.assertIsNot(authority.source_bytes,handle.project.source_bytes)
        self.assertIsNot(authority.bindings,handle.project.bindings)
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(owner.context.counts['transform_visits'],14)

    def test_generated_and_locked_snapshot_visit_formula(self):
        from hepta import packages
        self.write_package(self.root,'root',kind='bin')
        packages.write_lock(self.root)
        for locked in (False,True):
            with self.subTest(locked=locked):
                owner=Owner();handle=owner.load(self.entry,locked=locked)
                state=owner._handles[0][1].package_state
                records=state['packages'];edges=sum(len(record['dependencies']) for record in records.values())
                expected=9+12*len(records)+2*edges+2*len(state['files'])
                self.assertEqual(plain_visits(state),expected)
                self.assertEqual(expected,25)
                self.assertEqual(plain_visits(handle.project.source_bytes),1+2*len(handle.project.source_bytes))
                self.assertEqual(plain_visits(handle.project.bindings),1+2*len(handle.project.bindings))

    def test_package_dag_aliases_and_path_copies_are_distinct_remaining_work(self):
        self.write_package(self.root/'leaf','leaf')
        self.write_package(self.root/'left','left',[('leaf','../leaf')])
        self.write_package(self.root/'right','right',[('leaf','../leaf')])
        self.write_package(self.root,'root',[('a','left'),('b','right'),('c','left')],kind='bin')
        owner=Owner();handle=owner.load(self.entry)
        public=handle.project.package;private=owner._handles[0][1].package
        for package in (public,private):
            self.assertIs(package.dependencies['a'],package.dependencies['c'])
            self.assertIs(package.dependencies['a'].dependencies['leaf'],package.dependencies['b'].dependencies['leaf'])
        self.assertIsNot(private,public)
        self.assertEqual(private.root,public.root);self.assertIsNot(private.root,public.root)
        self.assertIs(private.manifest_bytes,public.manifest_bytes)
        self.assertIs(type(private.root),type(Path()))
        state=handle.project.package_state;records=state['packages']
        self.assertEqual(len(records),4)
        edges=sum(len(record['dependencies']) for record in records.values())
        self.assertEqual(edges,5)
        self.assertEqual(plain_visits(state),9+12*len(records)+2*edges+2*len(state['files']))
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(owner.context.counts['transform_visits'],14)


if __name__=='__main__':unittest.main()
