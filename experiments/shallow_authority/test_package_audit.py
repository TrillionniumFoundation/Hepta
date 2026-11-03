"""Read-only evidence for work explicitly excluded from shallow admission."""
import copy
import copyreg
from pathlib import Path
import sys
import tempfile
import unittest

from hepta import packages
from hepta.ast import HeptaError
from experiments.loader_transform import test_authority_audit as prior_audit
from .owner import Owner


class PackageProtocolAudit(unittest.TestCase):
    def fixture(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        write=prior_audit.AuthorityAuditTests.write_package
        write(self,root/'leaf','leaf')
        write(self,root/'left','left',[('leaf','../leaf')])
        write(self,root/'right','right',[('leaf','../leaf')])
        write(self,root,'root',[('a','left'),('b','right'),('c','left')],kind='bin')
        return root, packages.load_package(root)

    def observed_calls(self,value):
        calls=[];previous=sys.getprofile()
        def observe(frame,event,arg):
            if event=='call' and frame.f_code is copy.deepcopy.__code__:
                calls.append(type(frame.f_locals['x']))
        sys.setprofile(observe)
        try:result=copy.deepcopy(value)
        finally:sys.setprofile(previous)
        return result,calls

    def expected_calls(self,root):
        seen={};paths={};stack=[root]
        while stack:
            item=stack.pop()
            if id(item) in seen:continue
            seen[id(item)]=item
            for value in (item.root,item.entry,item.source_root):paths[id(value)]=value
            stack.extend(item.dependencies.values())
        unique=len(seen);edges=sum(len(p.dependencies) for p in seen.values())
        components=sum(len(p.parts) for p in paths.values())
        return 1+18*unique+2*edges+components

    def test_real_dag_copy_formula_and_aliases(self):
        root,package=self.fixture()
        reduction=package.__reduce_ex__(4)
        self.assertIs(reduction[0],copyreg.__newobj__)
        self.assertEqual(reduction[1],(packages.Package,))
        self.assertIs(reduction[2],vars(package))
        expected=self.expected_calls(package);result,calls=self.observed_calls(package)
        self.assertEqual(len(calls),expected)
        self.assertEqual(calls.count(packages.Package),6)
        self.assertEqual(calls.count(type),4)
        self.assertEqual(calls.count(dict),8)
        self.assertEqual(calls.count(type(Path())),12)
        self.assertEqual(calls.count(bytes),4)
        self.assertIs(result.dependencies['a'],result.dependencies['c'])
        self.assertIs(result.dependencies['a'].dependencies['leaf'],result.dependencies['b'].dependencies['leaf'])
        # No fixed path-dependent total: components change with fixture depth.
        owner=Owner();handle=owner.load(root/'main.hepta')
        self.assertEqual(owner.context.counts['shallow_fields'],11)
        self.assertIsNot(owner._handles[0][1].package,handle.project.package)

    def test_synthetic_package_cycle_is_memoized_not_source_admitted(self):
        root,package=self.fixture();package.dependencies['self']=package
        expected=self.expected_calls(package);result,calls=self.observed_calls(package)
        self.assertEqual(len(calls),expected)
        self.assertIs(result.dependencies['self'],result)
        self.assertEqual(calls.count(packages.Package),7)
        # Source topology cycles are a distinct earlier rejection.
        with (root/'hepta.toml').open('a') as stream:stream.write('self={path="."}\n')
        owner=Owner()
        with self.assertRaises(HeptaError) as caught:owner.load(root/'main.hepta')
        self.assertEqual(caught.exception.diagnostic.code,'E_PACKAGE_CYCLE')
        self.assertEqual(owner._handles,[])
        self.assertEqual(owner.context.counts['shallow_fields'],0)

    def test_cold_path_reduction_has_version_specific_input_effects(self):
        value=Path('/a/b')
        if sys.version_info[:2]==(3,12):
            self.assertFalse(hasattr(value,'_tail_cached'))
            result,calls=self.observed_calls(value)
            self.assertTrue(hasattr(value,'_tail_cached'))
            self.assertFalse(hasattr(result,'_tail_cached'))
        elif sys.version_info[:2]==(3,11):
            self.assertEqual(value._parts,['/','a','b'])
            result,calls=self.observed_calls(value)
            self.assertEqual(result._parts,['/','a','b'])
        else:
            self.fail('this protocol audit supports only CPython 3.11 and 3.12')
        self.assertEqual(len(calls),4)
        self.assertIsNot(result,value);self.assertEqual(result,value)


if __name__=='__main__':unittest.main()
