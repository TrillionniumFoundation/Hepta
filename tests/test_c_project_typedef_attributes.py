"""Compiler-free typedef metadata regressions; not native Clang/ABI evidence.

The separate source-bound six-case native probe retains the actual ABI oracle.
These tests isolate attribute policy, alias context and no-bundle rejection.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_translation import CTranslator

MODEL = {'long_bits':64, 'pointer_bits':64, 'char_unsigned':False}


def typedef(name, underlying='int', *, attrs=(), file='input.c', comment=False):
    children = [{'kind':'BuiltinType' if underlying=='int' else 'ElaboratedType'}]
    children += [{'kind':name} for name in attrs]
    if comment:
        children.append({'kind':'FullComment','inner':[{'kind':'TextComment','text':' documentation only'}]})
    return {'kind':'TypedefDecl','name':name,'type':{'qualType':underlying},
            'loc':{'file':file,'offset':0},'inner':children}


def record(alias):
    return {'kind':'RecordDecl','name':'Packet','tagUsed':'struct','completeDefinition':True,
            'loc':{'file':'input.c','offset':100},'inner':[
                {'kind':'FieldDecl','name':'lead','type':{'qualType':'char'}},
                {'kind':'FieldDecl','name':'value','type':{'qualType':alias,'desugaredQualType':'int'}},
                {'kind':'FieldDecl','name':'tail','type':{'qualType':'char'}}]}


def capture(root):
    return {'compiler':{'path':'MODELED_AST_NO_COMPILER'}, 'dependencies':[],
            'configurations':[{'index':0,'directory':str(root),'source':str(root/'input.c'),
                'frontend_arguments':[], 'model':dict(MODEL),
                'local_dependencies':[str(root/'input.c'),str(root/'types.h')]}]}


class ProjectTypedefAttributeTests(unittest.TestCase):
    def collect(self, nodes):
        with tempfile.TemporaryDirectory() as temp:
            translator=CTranslator(capture(Path(temp)))
            with patch('hepta.c_translation.invoke',return_value=json.dumps({'kind':'TranslationUnitDecl','inner':nodes})):
                translator.collect()
            return translator

    def reject_without_bundle(self, nodes):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'input.c').write_text('/* modeled AST unit test; no compiler invocation */\n')
            with patch('hepta.c_migration_project.capture_project',return_value=capture(root)), \
                 patch('hepta.c_migration_project.verify_capture'), \
                 patch('hepta.c_translation.invoke',return_value=json.dumps({'kind':'TranslationUnitDecl','inner':nodes})):
                result=migrate_c_project(root/'compile_commands.json',root/'out')
            self.assertFalse(result['ok'],result)
            self.assertIn('E_C_ATTRIBUTE',[d['code'] for d in result['diagnostics']])
            self.assertFalse((root/'out').exists())

    def context(self, nodes):
        translator=CTranslator({'configurations':[{'model':dict(MODEL)},{'model':dict(MODEL)}]})
        translator.typedef_types={0:{node['name']:node['type'] for node in nodes}}
        translator.typedef_declarations={0:{}}
        for node in nodes:
            translator.typedef_declarations[0].setdefault(node['name'],[]).append(node)
        return translator

    def test_plain_local_and_header_chained_aliases(self):
        for file in ('input.c','types.h'):
            with self.subTest(file=file):
                t=self.collect([typedef('Base',file=file),typedef('Wide','Base',file=file),record('Wide')])
                self.assertEqual(t.records['C_Packet'],[('f_lead','i8'),('f_value','i32'),('f_tail','i8')])

    def test_nonsemantic_typedef_comments_remain_allowed(self):
        t=self.collect([typedef('Wide',comment=True),record('Wide')])
        self.assertEqual(t.aliases['Wide'],'i32')

    def test_unqualified_declaration_attributes_never_publish(self):
        for attr in ('AlignedAttr','PackedAttr','ModeAttr','FutureABIAttr'):
            with self.subTest(attr=attr):
                self.reject_without_bundle([typedef('Wide',attrs=(attr,)),record('Wide')])

    def test_local_and_header_direct_and_chained_attributes(self):
        for file in ('input.c','types.h'):
            for chain in (False,True):
                with self.subTest(file=file,chain=chain):
                    nodes=[typedef('Base' if chain else 'Wide',attrs=('AlignedAttr',),file=file)]
                    if chain:nodes.append(typedef('Wide','Base',file=file))
                    self.reject_without_bundle(nodes+[record('Wide')])

    def test_desugared_type_cannot_hide_declaration_attribute(self):
        t=self.context([typedef('Wide',attrs=('AlignedAttr',))])
        for data in ('Wide',{'qualType':'Wide','desugaredQualType':'int'},
                     {'qualType':'const Wide','desugaredQualType':'const int'}):
            with self.subTest(data=data):
                with self.assertRaises(MigrationRejected) as error:
                    t.typ(data,unit=0)
                self.assertEqual(error.exception.code,'E_C_ATTRIBUTE')

    def test_used_system_context_attribute_is_rejected(self):
        self.reject_without_bundle([typedef('Wide',attrs=('AlignedAttr',),file='system.h'),record('Wide')])

    def test_used_system_alias_chain_is_rejected(self):
        self.reject_without_bundle([typedef('Base',attrs=('AlignedAttr',),file='system.h'),
                                    typedef('Wide','Base',file='system.h'),record('Wide')])

    def test_unused_system_attribute_does_not_reject_plain_project(self):
        t=self.collect([typedef('Unused',attrs=('AlignedAttr',),file='system.h'),
                        typedef('Wide'),record('Wide')])
        self.assertEqual(t.aliases['Wide'],'i32')
        self.assertNotIn('Unused',t.aliases)

    def test_redeclaration_cannot_erase_prior_attribute(self):
        for file in ('input.c','system.h'):
            with self.subTest(file=file):
                self.reject_without_bundle([typedef('Wide',attrs=('AlignedAttr',),file=file),
                                            typedef('Wide',file=file),record('Wide')])

    def test_typedef_attribute_context_is_per_translation_unit(self):
        t=self.context([typedef('Wide')])
        t.typedef_types[1]={'Wide':{'qualType':'int'}}
        t.typedef_declarations[1]={'Wide':[typedef('Wide',attrs=('AlignedAttr',))]}
        self.assertEqual(t.typ({'qualType':'Wide','desugaredQualType':'int'},unit=0),'i32')
        with self.assertRaises(MigrationRejected) as error:t.typ('Wide',unit=1)
        self.assertEqual(error.exception.code,'E_C_ATTRIBUTE')

    def test_cycle_still_rejects_without_attribute_recursion(self):
        t=self.context([typedef('Loop','Loop')])
        with self.assertRaises(MigrationRejected) as error:t.typ('Loop',unit=0)
        self.assertEqual(error.exception.code,'E_C_TYPE')

    def test_system_plain_aliases_and_comments_remain_type_context(self):
        t=self.collect([typedef('Base',file='system.h',comment=True),
                        typedef('Wide','Base',file='system.h',comment=True),record('Wide')])
        self.assertEqual(t.records['C_Packet'][1],('f_value','i32'))


if __name__ == '__main__':
    unittest.main()
