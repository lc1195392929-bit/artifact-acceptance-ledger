import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import ledger as l

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'artifact.txt').write_text('synthetic artifact')
        (self.root/'evidence.txt').write_text('human review notes: synthetic only')
        self.spec = {'version':1,'requirements':[{'id':'R1','criterion':'heading is readable','artifact':'artifact.txt','evidence':'evidence.txt','method':'manual','status':'pass','checker':'human-review','checker_version':'1'}]}
        self.saved = l.snapshot(self.root, self.spec)
    def result(self): return l.verify(self.root, self.spec, self.saved)
    def test_current(self): self.assertTrue(self.result()['all_recorded_passes_current'])
    def test_not_mutate_spec(self): self.assertNotIn('artifact_sha256', self.spec['requirements'][0])
    def test_artifact_change(self):
        (self.root/'artifact.txt').write_text('new'); self.assertFalse(self.result()['all_recorded_passes_current'])
    def test_evidence_change(self):
        (self.root/'evidence.txt').write_text('new'); self.assertIn('evidence_changed', self.result()['requirements'][0]['issues'])
    def test_criterion_change(self):
        self.spec['requirements'][0]['criterion']='new'; self.assertFalse(self.result()['spec_current'])
    def test_new_requirement(self):
        r=copy.deepcopy(self.spec['requirements'][0]); r['id']='R2'; self.spec['requirements'].append(r)
        self.assertEqual(self.result()['missing_requirements'],['R2'])
    def test_removed_requirement(self):
        self.spec['requirements'][0]['id']='R2'; self.assertFalse(self.result()['all_recorded_passes_current'])
    def test_duplicate_id(self):
        self.spec['requirements'] *= 2
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_invalid_status(self):
        self.spec['requirements'][0]['status']='done'
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_pending(self):
        r=self.spec['requirements'][0]; r['status']='pending'; r['evidence']=None
        saved=l.snapshot(self.root,self.spec)
        self.assertFalse(l.verify(self.root,self.spec,saved)['all_recorded_passes_current'])
    def test_failed(self):
        self.spec['requirements'][0]['status']='fail'
        self.assertFalse(l.verify(self.root,self.spec,l.snapshot(self.root,self.spec))['all_recorded_passes_current'])
    def test_blocked(self):
        self.spec['requirements'][0]['status']='blocked'
        self.assertFalse(l.verify(self.root,self.spec,l.snapshot(self.root,self.spec))['all_recorded_passes_current'])
    def test_missing_evidence(self):
        self.spec['requirements'][0]['evidence']=None
        with self.assertRaises(l.Invalid): l.snapshot(self.root,self.spec)
    def test_empty_evidence(self):
        (self.root/'evidence.txt').write_text('')
        with self.assertRaises(l.Invalid): l.snapshot(self.root,self.spec)
    def test_missing_file(self):
        (self.root/'artifact.txt').unlink(); self.assertFalse(self.result()['all_recorded_passes_current'])
    def test_traversal(self):
        for p in ('../a','a/../b','/tmp/a','C:/a','a\\b','a//b','./a'):
            with self.subTest(p=p), self.assertRaises(l.Invalid): l.read_safe(self.root,p)
    def test_root_symlink(self):
        with tempfile.TemporaryDirectory() as outer:
            alias=Path(outer)/'root'
            alias.symlink_to(self.root,target_is_directory=True)
            with self.assertRaises(l.Invalid): l.read_safe(alias,'artifact.txt')
    def test_json_size_limit(self):
        (self.root/'large.json').write_bytes(b' '*(l.MAX_JSON+1))
        with self.assertRaises(l.Invalid): l.load(self.root,'large.json')
    def test_symlink_file(self):
        (self.root/'artifact.txt').unlink(); (self.root/'artifact.txt').symlink_to(self.root/'evidence.txt')
        self.assertFalse(self.result()['all_recorded_passes_current'])
    def test_symlink_directory(self):
        (self.root/'alias').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError): l.read_safe(self.root,'alias/evidence.txt')
    def test_directory_not_file(self):
        (self.root/'dir').mkdir()
        with self.assertRaises((l.Invalid,OSError)): l.read_safe(self.root,'dir')
    def test_fifo(self):
        os.mkfifo(self.root/'pipe')
        with self.assertRaises(l.Invalid): l.read_safe(self.root,'pipe')
    def test_max_size(self):
        with self.assertRaises(l.Invalid): l.read_safe(self.root,'artifact.txt',3)
    def test_duplicate_json_key(self):
        (self.root/'bad.json').write_text('{"a":1,"a":2}')
        with self.assertRaises(l.Invalid): l.load(self.root,'bad.json')
    def test_json_malformed(self):
        for value in ('{','[NaN]','\xff'):
            (self.root/'bad.json').write_text(value)
            with self.assertRaises(l.Invalid): l.load(self.root,'bad.json')
    def test_unknown_keys(self):
        self.spec['extra']=True
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_empty_requirements(self):
        self.spec['requirements']=[]
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_bool_version(self):
        self.spec['version']=True
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_bad_hash(self):
        self.saved['requirements'][0]['artifact_sha256']='x'
        with self.assertRaises(l.Invalid): self.result()
    def test_control_chars(self):
        self.spec['requirements'][0]['criterion']='test\x1b[31m'
        with self.assertRaises(l.Invalid): l.validate(self.spec)
    def test_timestamp(self):
        self.saved['recorded_at']='yesterday'
        with self.assertRaises(l.Invalid): self.result()
    def test_nested_file(self):
        (self.root/'a').mkdir(); (self.root/'a/b').write_bytes(b'test')
        self.assertEqual(l.read_safe(self.root,'a/b'),b'test')
    def test_checker_change(self):
        self.spec['requirements'][0]['checker_version']='2'; self.assertFalse(self.result()['spec_current'])
    def test_automated_preserved(self):
        self.spec['requirements'][0]['method']='automated'
        report=l.verify(self.root,self.spec,l.snapshot(self.root,self.spec))
        self.assertEqual(report['requirements'][0]['method'],'automated')
    def test_huge_integer_cli(self):
        (self.root/'bad.json').write_text('{"version":' + '9'*5000 + '}')
        result=subprocess.run([sys.executable,l.__file__,'snapshot','--root',str(self.root),'--spec','bad.json'],capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stderr)['error'],'invalid_input')
        self.assertNotIn('Traceback',result.stderr)
    def test_total_budget(self):
        with patch.object(l,'MAX_TOTAL',20):
            with self.assertRaises(l.Invalid): l.snapshot(self.root,self.spec)
    def test_digest_cache(self):
        files=l.Fingerprints(self.root)
        files.get('artifact.txt')
        used=files.used
        files.get('artifact.txt')
        self.assertEqual(files.used,used)
    def test_cli_flow(self):
        (self.root/'spec.json').write_text(json.dumps(self.spec))
        base=[sys.executable,str(Path(l.__file__).resolve())]
        shot=subprocess.run(base+['snapshot','--root',str(self.root),'--spec','spec.json'],capture_output=True,text=True)
        self.assertEqual(shot.returncode,0,shot.stderr)
        (self.root/'ledger.json').write_text(shot.stdout)
        command=base+['verify','--root',str(self.root),'--spec','spec.json','--ledger','ledger.json']
        self.assertEqual(subprocess.run(command,capture_output=True).returncode,0)
        (self.root/'artifact.txt').write_text('changed')
        self.assertEqual(subprocess.run(command,capture_output=True).returncode,1)
        (self.root/'ledger.json').write_text('bad')
        self.assertEqual(subprocess.run(command,capture_output=True).returncode,2)

if __name__=='__main__': unittest.main()
