import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prepare import select_peers, save, prepare
from extract_candidates import candidate_metadata, verify_dump


class ProposalTests(unittest.TestCase):
    def test_runbook_units_and_pending_authorization_after_implemented_budget(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); inventory = root / 'inventory'; reconciliation = inventory / 'reconciliation'
            reconciliation.mkdir(parents=True)
            (reconciliation / 'manifest-reconciliation.json').write_text('[]')
            (reconciliation / 'restrictions-preserved.json').write_text('{}')
            output = root / 'proposal'; output.mkdir(mode=0o700)
            with patch('prepare.select_peers', return_value=[]):
                prepare(inventory, output)
            runbook = json.loads((output / 'pilot-runbook.json').read_text())
            self.assertEqual(runbook['approval'], 'pending')
            self.assertEqual(runbook['state'], 'BLOCKED')
            self.assertFalse(runbook['destination_proposal']['created'])
            self.assertIsNone(runbook['binary_sha256'])
            self.assertIn('implemented', runbook['capture_budget_implementation'])
            self.assertIn('explicit pilot approval pending', runbook['blockers'])
            self.assertNotIn('feature pending', json.dumps(runbook['blockers']))
            limits = runbook['limits_proposed']
            self.assertNotIn('rpc_total_both_runs_and_bootstrap', limits)
            self.assertEqual(limits['application_and_control_admissions_total_both_runs_and_bootstrap'], 256)
            self.assertIn('initialization/retries', limits['admission_unit'])
            self.assertIn('not every internal SDK RPC', limits['admission_unit'])
            self.assertIn('not network ingress', limits['byte_unit'])
            self.assertEqual(limits['ai_cost'], 0)
            self.assertFalse(runbook['automatic_retry'])

    def test_stable_selection_preserves_conflicts_and_no_access_hash(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            rows = []
            for i in range(5):
                item = {'account': 'account', 'alias': f'alias{i}', 'checked_at': 'time',
                        'result': {'Peer': {'ChannelID': i}, 'Chats': [{'access_hash': 'NEVER_COPY'}]}}
                (root / f'seed-{i}.json').write_text(json.dumps(item))
                rows.append({'current_alias_matches': [{'account': 'account', 'native_id': str(i)}],
                             'preserved': {'conflicts': ['restriction'] if i > 2 else [], 'aliases': [f'alias{i}']}})
            (root / 'manifest-reconciliation.json').write_text(json.dumps(rows))
            peers = select_peers(root, root)
            self.assertEqual(sum(p['proposed_selection'] for p in peers), 1)
            self.assertTrue(peers[0]['proposed_selection'])
            self.assertTrue(all(not p['active'] and p['approval'] == 'pending' for p in peers))
            self.assertEqual(sum(bool(p['conflicts']) for p in peers), 2)
            self.assertNotIn('NEVER_COPY', json.dumps(peers))

    def test_refuses_no_eligible_or_wrong_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'manifest-reconciliation.json').write_text('[]')
            with self.assertRaises(ValueError):
                select_peers(root, root)

    def test_private_save_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            save(root, 'proposal.json', {'approval': 'pending'})
            self.assertEqual((root / 'proposal.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                save(root, 'proposal.json', {})

    def test_unlabeled_candidate_excludes_content_and_legacy_labels(self):
        row = {'id': 'archive-id', 'source_type': 'archive', 'source_id': 'private-source',
               'language': None, 'posted_at': None, 'collected_at': '2026-01-01T00:00:00Z',
               'content_hash': 'old-hash', 'content': 'private text', 'category': 'legacy-not-gold'}
        item = candidate_metadata(row, 1)
        self.assertEqual(item['language'], 'unknown')
        self.assertIsNone(item['relevant'])
        self.assertIsNone(item['episode'])
        self.assertIsNone(item['partition'])
        self.assertFalse(item['eligible_for_evaluator'])
        self.assertNotIn('private text', json.dumps(item))
        self.assertNotIn('legacy-not-gold', json.dumps(item))

    def test_dump_requires_matching_full_restore_receipt(self):
        import hashlib
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'db').mkdir()
            dump = root / 'db/database.dump'
            dump.write_bytes(b'private preserved bytes')
            dump.chmod(0o600)
            receipt = root / 'recovery-report.json'
            digest = hashlib.sha256(dump.read_bytes()).hexdigest()
            receipt.write_text(json.dumps({'databases': [{'manifest_exact': True, 'dump_sha256': digest}]}))
            self.assertEqual(verify_dump(dump), digest)
            dump.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                verify_dump(dump)
