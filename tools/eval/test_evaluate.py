import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from evaluate import evaluate, cp_lower, read_dataset, episode_metrics
from gold import digest, IDENTITY, example_commitment


def simulated_gold(count=100):
    """Entirely invented software fixture: never evidence of operational human review."""
    semantics = {'labels': ['fixture'], 'intent': 'fixture',
                 'observable_roles': [{'observable_id': 'o1', 'role': 'fixture'}]}
    rows = [dict(id=str(i), episode=str(i), partition='test', at='2026-01-01',
                 language='es', source='fixture', task='semantic', relevant=True,
                 input='SIMULATED offline test input', context='SIMULATED context',
                 semantic=copy.deepcopy(semantics)) for i in range(count)]
    export = dict(contract='noctis-human-gold-v1', origin='simulated_fixture',
                  dataset_sha256=digest(rows), guideline_sha256=digest('fixture guide'),
                  sampling_sha256=digest('fixture sampling'), independence_sha256=digest('fixture independence'),
                  frozen_at='2026-01-02', reviews={})
    for row in rows:
        records = []
        for person in ('fixture-a', 'fixture-b', 'fixture-adjudicator'):
            record = dict(reviewer=person, at='2026-01-03', blind=True,
                          example_sha256=example_commitment(row),
                          judgment={'relevant': True, 'semantic': copy.deepcopy(semantics)})
            record['record_sha256'] = digest(record)
            records.append(record)
        export['reviews'][row['id']] = dict(reviews=records[:2], adjudication=records[2])
    dataset = dict(metadata=dict(version='simulated-gold-test-v1', synthetic=True,
                   label_provenance='SIMULATED software fixture, no real human labels', gold=export), examples=rows)
    predictions = [dict(id=e['id'], relevant=True, schema_valid=True, citations_valid=True,
                        cost_units=1, route='fixture', model='fixture-v1', prompt='1', policy='1',
                        schema='1', price_version='fixture', semantic=copy.deepcopy(semantics),
                        example_sha256=example_commitment(e), high_priority_inferred_alert=True,
                        alert_text='SIMULATED inferred high-priority alert; fixture claim with fixture evidence.') for e in rows]
    bind_predictions(dataset, predictions)
    return dataset, predictions


def refresh(dataset, predictions=None):
    dataset['metadata']['gold']['dataset_sha256'] = digest(dataset['examples'])
    for row in dataset['examples']:
        records = dataset['metadata']['gold']['reviews'][row['id']]
        for record in [*records['reviews'], records['adjudication']]:
            record['example_sha256'] = example_commitment(row)
            resign(record)
    if predictions is not None:
        for row, prediction in zip(dataset['examples'], predictions):
            prediction['example_sha256'] = example_commitment(row)
        bind_predictions(dataset, predictions)


def bind_predictions(dataset, predictions):
    """Invented simulated audits only; never operational human adjudication."""
    audits = {}
    for p in predictions:
        audit = dict(prediction_sha256=digest(p), example_sha256=p['example_sha256'],
                     execution_sha256=digest({k: p[k] for k in IDENTITY}),
                     reviewer='fixture-adjudicator', at='2026-01-04', schema_error=False,
                     citation_error=False, unsupported_claims=0, omitted_claims=0, alert_correct=True)
        resign(audit)
        audits[p['id']] = audit
    dataset['metadata']['gold']['prediction_audits'] = audits


def resign(record):
    record['record_sha256'] = digest({k: v for k, v in record.items() if k != 'record_sha256'})


class ReplayTests(unittest.TestCase):
    def test_cli_preserves_dataset_predictions_output_interface(self):
        data, predictions = simulated_gold(100)
        inputs = {e['id']: 'SIMULATED offline test input' for e in data['examples']}
        for row in data['examples']:
            row['input'] = inputs[row['id']]
        refresh(data, predictions)
        data['metadata']['input_fixture'] = 'inputs.json'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'inputs.json').write_text(json.dumps(inputs))
            (root / 'dataset.json').write_text(json.dumps(data))
            (root / 'predictions.jsonl').write_text('\n'.join(json.dumps(p) for p in predictions))
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('evaluate.py')),
                '--dataset', str(root / 'dataset.json'), '--predictions', str(root / 'predictions.jsonl'),
                '--output', str(root / 'report.json')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / 'report.json').read_text())
            self.assertEqual(report['promotion_criterion']['status'], 'pass')
            self.assertFalse(report['promotion_authorized'])

    def test_valid_simulated_gold_pass_does_not_authorize_or_claim_quality(self):
        data, predictions = simulated_gold()
        report = evaluate(data, predictions)
        self.assertEqual(report['promotion_criterion']['status'], 'pass')
        self.assertTrue(report['promotion_criterion']['statistically_eligible'])
        self.assertFalse(report['promotion_criterion']['real_corpus_statistical_candidate'])
        self.assertFalse(report['quality_validated'])
        self.assertFalse(report['promotion_authorized'])
        self.assertEqual(report['gold_provenance']['origin'], 'simulated_fixture')
        self.assertEqual(report['human_adjudicated_errors']['status'], 'measured')

    def test_missing_gold_is_not_evaluated_and_fake_metadata_is_rejected(self):
        data, predictions = simulated_gold()
        del data['metadata']['gold']
        data['metadata']['synthetic'] = False
        self.assertEqual(evaluate(data, predictions)['promotion_criterion']['status'], 'not_evaluated')
        data['metadata']['gold'] = {'contract': 'noctis-human-gold-v1'}
        with self.assertRaisesRegex(ValueError, 'provenance'):
            evaluate(data, predictions)
        data, predictions = simulated_gold()
        data['metadata']['synthetic'] = False
        with self.assertRaisesRegex(ValueError, 'synthetic marker'):
            evaluate(data, predictions)

    def test_independence_and_insufficient_denominators(self):
        data, predictions = simulated_gold(99)
        self.assertEqual(evaluate(data, predictions)['promotion_criterion']['status'], 'fail')
        data, predictions = simulated_gold(100)
        for row in data['examples']:
            row['episode'] = 'one-correlated-family'
        refresh(data, predictions)
        report = evaluate(data, predictions)
        self.assertEqual(report['executions'][0]['criterion']['independent_test_episodes']['denominator'], 1)
        self.assertFalse(report['promotion_criterion']['statistically_eligible'])
        data, predictions = simulated_gold(100)
        predictions[-1]['relevant'] = None
        predictions[-1]['high_priority_inferred_alert'] = False
        predictions[-1]['alert_text'] = None
        bind_predictions(data, predictions)
        self.assertEqual(evaluate(data, predictions)['executions'][0]['criterion']['independent_test_episodes']['predicted_positive'], 99)
        self.assertFalse(evaluate(data, predictions)['promotion_criterion']['statistically_eligible'])

    def test_routes_models_prices_and_segments_cannot_pool(self):
        for field in IDENTITY:
            data, predictions = simulated_gold(100)
            predictions[-1][field] = 'different'
            bind_predictions(data, predictions)
            report = evaluate(data, predictions)
            self.assertEqual(len(report['executions']), 2)
            self.assertFalse(report['promotion_criterion']['statistically_eligible'])
        for dimension in ('source', 'language', 'task'):
            data, predictions = simulated_gold(100)
            data['examples'][-1][dimension] = 'other'
            refresh(data, predictions)
            report = evaluate(data, predictions)
            self.assertEqual(report['executions'][0]['criterion']['status'], 'pass')
            self.assertFalse(report['promotion_criterion']['statistically_eligible'])

    def test_provenance_review_blinding_digest_and_adjudication(self):
        for mutation in ('reviewer', 'blind', 'at', 'judgment', 'digest'):
            data, predictions = simulated_gold(1)
            record = data['metadata']['gold']['reviews']['0']['adjudication']
            if mutation == 'reviewer':
                record['reviewer'] = 'fixture-a'
            elif mutation == 'blind':
                record['blind'] = False
            elif mutation == 'at':
                record['at'] = '2020-01-01'
            elif mutation == 'judgment':
                record['judgment']['relevant'] = False
            else:
                record['record_sha256'] = '0' * 64
            if mutation != 'digest':
                resign(record)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evaluate(data, predictions)

    def test_direct_development_test_temporal_leakage_and_timestamp_offsets(self):
        data, predictions = simulated_gold(2)
        data['examples'][0]['partition'] = 'development'
        data['examples'][0]['at'] = '2026-01-02T01:00:00+02:00'
        data['examples'][1]['at'] = '2026-01-01T22:00:00Z'
        refresh(data, predictions)
        with self.assertRaisesRegex(ValueError, 'temporal'):
            evaluate(data, predictions)

    def test_missing_semantics_and_typed_metrics(self):
        data, predictions = simulated_gold()
        del predictions[0]['semantic']
        bind_predictions(data, predictions)
        report = evaluate(data, predictions)
        self.assertEqual(report['executions'][0]['criterion']['status'], 'not_measured')
        self.assertFalse(report['promotion_criterion']['statistically_eligible'])
        data, predictions = simulated_gold(1)
        predictions[0]['semantic'] = {'labels': ['wrong'], 'intent': 'wrong',
                                     'observable_roles': [{'observable_id': 'o1', 'role': 'wrong'}]}
        bind_predictions(data, predictions)
        metrics = evaluate(data, predictions)['overall']['semantic']
        for field in ('labels', 'intent', 'observable_roles'):
            self.assertEqual(sum(x['false_positive'] for x in metrics[field]['per_label'].values()), 1)
            self.assertEqual(sum(x['false_negative'] for x in metrics[field]['per_label'].values()), 1)
            self.assertEqual(metrics[field]['macro_f1'], 0)

    def test_invalid_typed_prediction_and_gold(self):
        for field, value in [('cost_units', -1), ('cost_units', True), ('cost_units', 1.5),
                             ('relevant', 1), ('schema_valid', 'true'), ('citations_valid', None),
                             ('model', 1), ('semantic', {'labels': []})]:
            data, predictions = simulated_gold(1)
            predictions[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                evaluate(data, predictions)
        data, predictions = simulated_gold(1)
        data['examples'][0]['relevant'] = 1
        with self.assertRaises(ValueError):
            evaluate(data, predictions)

    def test_human_errors_require_bound_prediction_and_typed_counts(self):
        data, predictions = simulated_gold(1)
        audit = dict(prediction_sha256=digest(predictions[0]),
                     example_sha256=predictions[0]['example_sha256'],
                     execution_sha256=digest({k: predictions[0][k] for k in IDENTITY}),
                     reviewer='fixture-adjudicator', at='2026-01-04', schema_error=False,
                     citation_error=True, unsupported_claims=2, omitted_claims=1)
        audit['record_sha256'] = digest(audit)
        data['metadata']['gold']['prediction_audits'] = {'0': audit}
        report = evaluate(data, predictions)
        self.assertEqual(report['human_adjudicated_errors']['unsupported_claims'], 2)
        self.assertEqual(report['overall']['citation_errors'], 0)
        audit['omitted_claims'] = True
        resign(audit)
        with self.assertRaisesRegex(ValueError, 'human error count'):
            evaluate(data, predictions)
        audit['omitted_claims'] = 1
        resign(audit)
        predictions[0]['cost_units'] = 2
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            evaluate(data, predictions)

    def test_gate_recall_uses_actionable_denominator(self):
        data, predictions = simulated_gold(200)
        for row in data['examples']:
            row['task'] = 'gate'
        for prediction in predictions:
            prediction['high_priority_inferred_alert'] = False
            prediction['alert_text'] = None
        refresh(data, predictions)
        for prediction in predictions[:4]:
            prediction['relevant'] = False
        bind_predictions(data, predictions)
        report = evaluate(data, predictions)
        self.assertEqual(report['promotion_criterion']['status'], 'pass')
        self.assertEqual(report['executions'][0]['criterion']['independent_test_episodes']['recall'], .98)
        predictions[4]['relevant'] = False
        bind_predictions(data, predictions)
        self.assertEqual(evaluate(data, predictions)['promotion_criterion']['status'], 'fail')

    def test_wrong_emission_cannot_hide_inside_actionable_episode(self):
        metrics = episode_metrics([
            ({'episode': 'one', 'relevant': True}, {'relevant': True}),
            ({'episode': 'one', 'relevant': False}, {'relevant': True})])
        self.assertEqual(metrics['predicted_positive'], 1)
        self.assertEqual(metrics['false_positive'], 1)
        self.assertEqual(metrics['precision'], 0)
        self.assertEqual(metrics['recall'], 1)

    def test_copied_reviews_predictions_and_changed_frozen_material_rejected(self):
        data, predictions = simulated_gold(2)
        data['metadata']['gold']['reviews']['1'] = copy.deepcopy(data['metadata']['gold']['reviews']['0'])
        with self.assertRaisesRegex(ValueError, 'review example commitment'):
            evaluate(data, predictions)
        data, predictions = simulated_gold(2)
        predictions[1] = copy.deepcopy(predictions[0])
        predictions[1]['id'] = '1'
        bind_predictions(data, predictions)
        with self.assertRaisesRegex(ValueError, 'prediction example commitment'):
            evaluate(data, predictions)
        for field in ('id', 'input', 'context'):
            data, predictions = simulated_gold(2)
            data['examples'][0][field] += '-changed'
            if field == 'id':
                data['metadata']['gold']['reviews']['0-changed'] = data['metadata']['gold']['reviews'].pop('0')
                predictions[0]['id'] = '0-changed'
            data['metadata']['gold']['dataset_sha256'] = digest(data['examples'])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'review example commitment'):
                evaluate(data, predictions)
        for field in ('input', 'context'):
            data, predictions = simulated_gold(2)
            data['examples'][1][field] += '-different'
            refresh(data, predictions)
            data['examples'][0][field], data['examples'][1][field] = data['examples'][1][field], data['examples'][0][field]
            data['metadata']['gold']['dataset_sha256'] = digest(data['examples'])
            with self.subTest(swapped=field), self.assertRaisesRegex(ValueError, 'review example commitment'):
                evaluate(data, predictions)

    def test_relevance_perfect_does_not_accredit_wrong_or_unadjudicated_alerts(self):
        for kind in ('labels', 'intent', 'observable_roles', 'unsupported', 'incorrect', 'unadjudicated', 'absent_audits', 'no_emissions'):
            data, predictions = simulated_gold()
            for p in predictions:
                if kind == 'labels':
                    p['semantic']['labels'] = ['wrong']
                elif kind == 'intent':
                    p['semantic']['intent'] = 'wrong'
                elif kind == 'observable_roles':
                    p['semantic']['observable_roles'][0]['role'] = 'wrong'
                elif kind == 'no_emissions':
                    p['high_priority_inferred_alert'] = False
                    p['alert_text'] = None
            bind_predictions(data, predictions)
            audits = data['metadata']['gold']['prediction_audits']
            for audit in audits.values():
                if kind == 'unsupported':
                    audit['unsupported_claims'] = 1
                elif kind == 'incorrect':
                    audit['alert_correct'] = False
                elif kind == 'unadjudicated':
                    del audit['alert_correct']
                resign(audit)
            if kind == 'absent_audits':
                del data['metadata']['gold']['prediction_audits']
            report = evaluate(data, predictions)
            criterion = report['executions'][0]['criterion']
            with self.subTest(kind=kind):
                self.assertEqual(report['overall']['precision'], 1)
                self.assertFalse(report['promotion_criterion']['statistically_eligible'])
                self.assertEqual(criterion['status'], 'not_measured' if kind in
                                 ('unadjudicated', 'absent_audits', 'no_emissions') else 'fail')

    def test_strict_schemas_and_audit_commitment_and_alert_types(self):
        for kind in ('row_metadata', 'prediction_metadata', 'review_metadata', 'audit_metadata', 'audit_commitment', 'alert_type', 'missing_alert_text', 'altered_alert_text'):
            data, predictions = simulated_gold(1)
            audit = data['metadata']['gold']['prediction_audits']['0']
            if kind == 'row_metadata':
                data['examples'][0]['metadata'] = {'unbound': 'escape'}
                data['metadata']['gold']['dataset_sha256'] = digest(data['examples'])
            elif kind == 'prediction_metadata':
                predictions[0]['metadata'] = {'unbound': 'escape'}
            elif kind == 'review_metadata':
                data['metadata']['gold']['reviews']['0']['adjudication']['metadata'] = {}
            elif kind == 'audit_metadata':
                audit['metadata'] = {}
            elif kind == 'audit_commitment':
                audit['example_sha256'] = '0' * 64
                resign(audit)
            elif kind == 'missing_alert_text':
                predictions[0]['alert_text'] = ''
            elif kind == 'altered_alert_text':
                predictions[0]['alert_text'] = 'SIMULATED changed claim after human adjudication'
            else:
                audit['alert_correct'] = 1
                resign(audit)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                evaluate(data, predictions)

    def test_gate_recall_does_not_require_relevance_precision_threshold(self):
        data, predictions = simulated_gold(200)
        for row in data['examples']:
            row['task'] = 'gate'
        for p in predictions:
            p['high_priority_inferred_alert'] = False
            p['alert_text'] = None
        for row in data['examples'][100:]:
            row['relevant'] = False
            item = data['metadata']['gold']['reviews'][row['id']]
            for review in [*item['reviews'], item['adjudication']]:
                review['judgment']['relevant'] = False
        refresh(data, predictions)
        report = evaluate(data, predictions)
        criterion = report['executions'][0]['criterion']
        self.assertEqual(report['overall']['precision'], .5)
        self.assertEqual(criterion['gate_recall']['recall'], 1)
        self.assertTrue(criterion['gate_recall_criterion_passed'])
        self.assertEqual(criterion['high_priority_inferred_alert_precision']['status'], 'not_measured')
        self.assertEqual(criterion['status'], 'pass')
        self.assertFalse(report['promotion_authorized'])

    def test_reviewer_disagreement_is_measured_and_gold_not_silently_changed(self):
        data, predictions = simulated_gold(1)
        review = data['metadata']['gold']['reviews']['0']['reviews'][0]
        review['judgment']['relevant'] = False
        resign(review)
        provenance = evaluate(data, predictions)['gold_provenance']
        self.assertEqual(provenance['reviewer_agreement'], 0)
        self.assertEqual(provenance['reviewer_disagreements'], 1)
        self.assertEqual(provenance['adjudication_corrections'], 1)

    def test_exact_interval_denominators_and_split_integrity(self):
        self.assertAlmostEqual(cp_lower(100, 100), .05 ** .01, places=12)
        data = read_dataset(Path(__file__).with_name('synthetic-v1.json'))
        predictions = [dict(id=e['id'], relevant=e['relevant'], schema_valid=True,
            citations_valid=True, cost_units=140, route='local-fixture', model='fixture-v1',
            prompt='1', policy='1', schema='1', price_version='synthetic-v1')
            for e in data['examples']]
        predictions[0]['relevant'] = False
        predictions[-1]['citations_valid'] = False
        report = evaluate(data, predictions)
        self.assertEqual(report['overall']['denominator'], 18)
        self.assertEqual(report['overall']['false_negative'], 1)
        self.assertEqual(report['overall']['citation_errors'], 1)
        self.assertEqual(report['overall']['cost_units'], 2520)
        self.assertFalse(report['quality_validated'])
        self.assertFalse(report['promotion_authorized'])
        changed = copy.deepcopy(data)
        changed['examples'][-1]['episode'] = changed['examples'][0]['episode']
        with self.assertRaisesRegex(ValueError, 'episode leakage'):
            evaluate(changed, predictions)
        with self.assertRaisesRegex(ValueError, 'cover every'):
            evaluate(data, predictions[:-1])


if __name__ == '__main__':
    unittest.main()
