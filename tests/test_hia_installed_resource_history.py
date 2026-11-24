"""Controls for the complete installed-resource history and declared domains."""
from hashlib import sha256
import json
from pathlib import Path
import unittest

from tests import hia_installed_resource_history as history

ROOT=Path(__file__).resolve().parents[1]

class InstalledResourceHistoryTests(unittest.TestCase):
    def test_current_source_replays_both_complete_predecessors(self):
        data=(ROOT/history.PATH).read_bytes()
        fixture=history.records()
        self.assertEqual(history.pin(data),fixture['relations'][-1]['current'])
        middle=history._reverse(data,fixture['relations'][-1])
        self.assertEqual(history.pin(middle),fixture['relations'][0]['current'])
        original=history.reference_source(history.PATH,data)
        self.assertEqual(original,history.reference_source(history.PATH,middle))
        self.assertEqual(history.pin(original),fixture['reference_current'])
        from tests.hia_installed_distribution_history import REFERENCE_FIXTURE,_restore
        reference=json.loads((ROOT/REFERENCE_FIXTURE).read_bytes())['files'][history.PATH]
        self.assertEqual(history.pin(original),reference['current'])
        prior=_restore(original,reference)
        self.assertEqual(history.pin(prior),reference['original'])
        self.assertEqual(len(prior),74950)
        self.assertEqual(sha256(prior).hexdigest(),'5e0db72475d8aa67bdc94d3e7866f0765d9e712711eaf3df0796416b80181d8f')

    def test_unreviewed_complete_source_and_fixture_bytes_are_not_admitted(self):
        raw=(ROOT/history.PATH).read_bytes()
        for data in (raw+b'# unreviewed change\n',raw[:-1],b'X'+raw[1:]):
            self.assertEqual(history.reference_source(history.PATH,data),data)
        self.assertEqual(history.reference_source('another.py',raw),raw)
        with self.assertRaises(ValueError):
            history._parse((ROOT/history.FIXTURE).read_bytes()+b'\n')

    def test_independent_producers_cover_exactly_original261_and_added29(self):
        fixture=history.records()
        legacy=set(fixture['legacy_domain']['names'])
        sources,images,current=history.reviewed_inventory(ROOT,legacy)
        self.assertEqual(len(legacy),261)
        self.assertEqual(len(sources),26)
        self.assertEqual(len(images),3)
        self.assertEqual(len(current),290)
        self.assertTrue(legacy.isdisjoint(sources+images))
        self.assertEqual(set(current)-legacy,set(fixture['reviewed_additional']['names']))
        self.assertEqual(tuple(sources),history.NOMINAL_RESOURCES+history.NDU_RESOURCES)

    def test_missing_or_unreviewed_legacy_member_still_refuses(self):
        legacy=set(history.records()['legacy_domain']['names'])
        with self.assertRaises(ValueError):
            history.reviewed_inventory(ROOT,legacy-{min(legacy)})
        with self.assertRaises(ValueError):
            history.reviewed_inventory(ROOT,legacy|{'unreviewed-extra.bin'})
