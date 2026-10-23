#!/usr/bin/env python3
"""Versioned offline replay metrics. No network, labels or model calls are generated."""
import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from gold import (IDENTITY, DIMENSIONS, timestamp, nonempty,
                  semantic, semantic_metrics, validate_gold, human_errors, human_error_metrics,
                  example_commitment)


def read_dataset(path):
    dataset = json.loads(path.read_text())
    fixtures = json.loads((path.parent / dataset['metadata']['input_fixture']).read_text())
    if set(fixtures) != {row['id'] for row in dataset['examples']}:
        raise ValueError('input fixture IDs differ from frozen dataset')
    for row in dataset['examples']:
        row['input'] = fixtures[row['id']]
        if not isinstance(row['input'], str) or not row['input']:
            raise ValueError('nonempty versioned input fixture required')
    return dataset


def cp_lower(successes, total, alpha=0.05):
    """Exact one-sided Clopper–Pearson lower confidence limit."""
    if type(total) is not int or type(successes) is not int or not 0 <= successes <= total or not 0 < alpha < 1:
        raise ValueError('invalid binomial counts or alpha')
    if not total or not successes:
        return 0.0
    low, high = 0.0, 1.0
    for _ in range(70):
        p = (low + high) / 2
        tail = sum(math.exp(math.lgamma(total + 1) - math.lgamma(k + 1)
                   - math.lgamma(total - k + 1) + k * math.log(p)
                   + (total - k) * math.log1p(-p))
                   for k in range(successes, total + 1))
        if tail < alpha:
            low = p
        else:
            high = p
    return (low + high) / 2


def metrics(items):
    tp = sum(e['relevant'] and p.get('relevant') is True for e, p in items)
    fp = sum(not e['relevant'] and p.get('relevant') is True for e, p in items)
    fn = sum(e['relevant'] and p.get('relevant') is not True for e, p in items)
    emitted = tp + fp
    actionable = tp + fn
    return {'denominator': len(items), 'predicted_positive': emitted,
            'actionable': actionable, 'true_positive': tp, 'false_positive': fp,
            'false_negative': fn, 'precision': tp / emitted if emitted else None,
            'recall': tp / actionable if actionable else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None,
            'precision_lower_one_sided_95': cp_lower(tp, emitted),
            'recall_lower_one_sided_95': cp_lower(tp, actionable),
            'abstentions': sum(p.get('relevant') is None for _, p in items),
            'schema_errors': sum(not p.get('schema_valid', False) for _, p in items),
            'citation_errors': sum(not p.get('citations_valid', False) for _, p in items),
            'cost_units': sum(p.get('cost_units', 0) for _, p in items),
            'semantic': semantic_metrics(items)}


def episode_metrics(items):
    """One trial per episode. Any incorrect emission makes its precision trial fail."""
    groups = defaultdict(list)
    for e, p in items:
        groups[e['episode']].append((e, p))
    emitted = correct = actionable = recovered = 0
    for group in groups.values():
        positives = [(e, p) for e, p in group if p['relevant'] is True]
        emitted += bool(positives)
        correct += bool(positives) and all(e['relevant'] for e, _ in positives)
        actionable += any(e['relevant'] for e, _ in group)
        recovered += any(e['relevant'] and p['relevant'] is True for e, p in group)
    return {'denominator': len(groups), 'predicted_positive': emitted,
            'actionable': actionable, 'true_positive': correct,
            'false_positive': emitted - correct, 'false_negative': actionable - recovered,
            'precision': correct / emitted if emitted else None,
            'recall': recovered / actionable if actionable else None,
            'precision_lower_one_sided_95': cp_lower(correct, emitted),
            'recall_lower_one_sided_95': cp_lower(recovered, actionable)}


def alert_metrics(items, audits):
    emitted = [(e, p) for e, p in items if p.get('high_priority_inferred_alert') is True]
    groups = defaultdict(list)
    for e, p in emitted:
        groups[e['episode']].append((e, p))
    if not emitted or audits is None or any(audits[p['id']].get('alert_correct') is None
            or e.get('semantic') is None or p.get('semantic') is None for e, p in emitted):
        return {'status': 'not_measured', 'emitted_rows': len(emitted), 'independent_emitted_episodes': len(groups)}
    def correct(e, p):
        a = audits[p['id']]
        expected, actual = e['semantic'], p['semantic']
        semantic_match = (expected['intent'] == actual['intent']
                          and set(expected['labels']) == set(actual['labels'])
                          and {(r['observable_id'], r['role']) for r in expected['observable_roles']}
                          == {(r['observable_id'], r['role']) for r in actual['observable_roles']})
        return (a['alert_correct'] and e['relevant'] and e.get('semantic') is not None
                and semantic_match and not a['schema_error']
                and not a['citation_error'] and a['unsupported_claims'] == 0)
    successes = sum(all(correct(e, p) for e, p in group) for group in groups.values())
    return {'status': 'measured', 'emitted_rows': len(emitted),
            'independent_emitted_episodes': len(groups), 'correct_episodes': successes,
            'precision': successes / len(groups),
            'precision_lower_one_sided_95': cp_lower(successes, len(groups))}


def criterion(items, gold, audits):
    test = [(e, p) for e, p in items if e['partition'] == 'test']
    independent = episode_metrics(test)
    sem = semantic_metrics(test)
    gate = any(e['task'] == 'gate' for e, _ in test)
    gate_metrics = episode_metrics([(e, p) for e, p in test if e['task'] == 'gate'])
    recall_pass = gate_metrics['recall'] is not None and gate_metrics['recall'] >= .98
    alerts = alert_metrics(test, audits)
    alert_applicable = any(e['task'] != 'gate' or p.get('high_priority_inferred_alert') for e, p in test)
    precision_pass = (alerts['status'] == 'measured' and alerts['independent_emitted_episodes'] >= 100
                      and alerts['precision_lower_one_sided_95'] >= .95)
    status = 'pass' if (not gate or recall_pass) and (not alert_applicable or precision_pass) else 'fail'
    if alert_applicable and alerts['status'] == 'not_measured':
        status = 'not_measured'
    if gold is None:
        status = 'not_evaluated'
    if status == 'pass' and sem['status'] != 'measured':
        status = 'not_measured'
    return {'status': status, 'precision_criterion_passed': precision_pass if gold and alert_applicable else None,
            'gate_recall_criterion_passed': recall_pass if gold and gate else None,
            'gate_recall': {'status': 'measured' if gate and gold else 'not_measured', **gate_metrics},
            'high_priority_inferred_alert_precision': alerts,
            'relevance_precision_is_descriptive': True,
            'independent_test_episodes': independent, 'semantic': sem,
            'period': {'start': min((e['at'] for e, _ in test), key=timestamp, default=None),
                       'end': max((e['at'] for e, _ in test), key=timestamp, default=None)}}


def evaluate(dataset, predictions):
    metadata = dataset['metadata']
    rows = dataset['examples']
    if type(metadata.get('synthetic')) is not bool or not all(nonempty(metadata.get(k)) for k in ('version', 'label_provenance')):
        raise ValueError('typed versioned dataset provenance required')
    if not isinstance(rows, list) or not rows:
        raise ValueError('nonempty examples required')
    for row in rows:
        if not isinstance(row, dict) or not all(nonempty(row.get(k)) for k in ('id', 'episode', 'partition', 'at', *DIMENSIONS)) or type(row.get('relevant')) is not bool:
            raise ValueError('invalid typed dataset row')
        timestamp(row['at'])
        if row.get('semantic') is not None:
            semantic(row['semantic'])
    if len({e['id'] for e in rows}) != len(rows):
        raise ValueError('duplicate dataset IDs')
    episodes, times = {}, defaultdict(list)
    for row in rows:
        partition = row['partition']
        if partition not in ('development', 'selection', 'test'):
            raise ValueError('unknown partition')
        if episodes.setdefault(row['episode'], partition) != partition:
            raise ValueError('episode leakage between partitions')
        times[partition].append(timestamp(row['at']))
    for earlier, later in [('development', 'selection'), ('selection', 'test'), ('development', 'test')]:
        if times[earlier] and times[later] and max(times[earlier]) >= min(times[later]):
            raise ValueError('temporal split overlaps')
    by_id = {}
    for prediction in predictions:
        if prediction['id'] in by_id:
            raise ValueError('duplicate prediction ID')
        for key in IDENTITY:
            if not nonempty(prediction.get(key)):
                raise ValueError('missing versioned execution identity')
        if type(prediction.get('cost_units')) is not int or prediction['cost_units'] < 0:
            raise ValueError('integer nonnegative cost required')
        if 'relevant' not in prediction or prediction['relevant'] is not None and type(prediction['relevant']) is not bool:
            raise ValueError('prediction relevance must be boolean or null')
        if any(type(prediction.get(k)) is not bool for k in ('schema_valid', 'citations_valid')):
            raise ValueError('prediction validation flags must be boolean')
        if prediction.get('semantic') is not None:
            semantic(prediction['semantic'])
        by_id[prediction['id']] = prediction
    if set(by_id) != {e['id'] for e in rows}:
        raise ValueError('predictions must cover every dataset ID exactly')
    paired = [(e, by_id[e['id']]) for e in rows]
    gold = validate_gold(dataset)
    if gold is not None:
        required = {'id', 'relevant', 'schema_valid', 'citations_valid', 'cost_units',
                    'example_sha256', 'high_priority_inferred_alert', 'alert_text', *IDENTITY}
        for e, p in paired:
            if set(p) - {'semantic'} != required or type(p['high_priority_inferred_alert']) is not bool:
                raise ValueError('strict GOLD prediction schema required')
            if p['example_sha256'] != example_commitment(e):
                raise ValueError('prediction example commitment mismatch')
            if (p['high_priority_inferred_alert'] and not nonempty(p['alert_text'])
                    or not p['high_priority_inferred_alert'] and p['alert_text'] is not None):
                raise ValueError('actual emitted alert text required; null when not emitted')
    adjudicated_errors = human_errors(dataset, predictions, gold)
    audits = metadata.get('gold', {}).get('prediction_audits')
    segments = {}
    for dimension in ('partition', 'language', 'source', 'task'):
        groups = defaultdict(list)
        for e, p in paired:
            groups[e[dimension]].append((e, p))
        segments[dimension] = {key: {**metrics(group), 'human_adjudicated_errors': human_error_metrics(group, audits)}
                               for key, group in groups.items()}
    fingerprints = sorted({json.dumps({k: p[k] for k in
        ('route', 'model', 'prompt', 'policy', 'schema', 'price_version')}, sort_keys=True)
        for p in predictions})
    execution_groups = defaultdict(list)
    for e, p in paired:
        execution_groups[tuple(p[k] for k in IDENTITY)].append((e, p))
    executions = []
    for identity, group in sorted(execution_groups.items()):
        cells = defaultdict(list)
        for e, p in group:
            cells[tuple(e[k] for k in DIMENSIONS)].append((e, p))
        cell_reports = [dict(segment=dict(zip(DIMENSIONS, cell)), **criterion(items, gold, audits),
                             human_adjudicated_errors=human_error_metrics(
                                 [(e, p) for e, p in items if e['partition'] == 'test'], audits))
                        for cell, items in sorted(cells.items())
                        if any(e['partition'] == 'test' for e, _ in items)]
        aggregate = criterion(group, gold, audits)
        eligible = aggregate['status'] == 'pass' and bool(cell_reports) and all(c['status'] == 'pass' for c in cell_reports)
        executions.append({'identity': dict(zip(IDENTITY, identity)), 'overall': metrics(group),
                           'human_adjudicated_errors': human_error_metrics(group, audits),
                           'criterion': aggregate, 'segments': cell_reports,
                           'statistically_eligible': eligible})
    eligible = bool(executions) and all(e['statistically_eligible'] for e in executions)
    statuses = [c['status'] for e in executions for c in [e['criterion'], *e['segments']]]
    overall_status = ('not_evaluated' if gold is None else 'pass' if eligible else
                      'fail' if 'fail' in statuses else 'not_measured')
    return {'dataset_version': metadata['version'], 'synthetic': metadata['synthetic'],
            'label_provenance': metadata['label_provenance'],
            'quality_validated': False,
            'promotion_authorized': False,
            'limitation': ('SYNTHETIC regression only; no real-world quality claim.' if metadata['synthetic'] else
                           'Offline GOLD contract checks do not authenticate reviewers, representativeness or evidence; external human audit and policy approval required.'),
            'gold_provenance': gold or {'status': 'not_measured'},
            'human_adjudicated_errors': adjudicated_errors,
            'dataset_sha256': hashlib.sha256(json.dumps(dataset, sort_keys=True).encode()).hexdigest(),
            'execution_fingerprints': [json.loads(f) for f in fingerprints],
            'overall': metrics(paired), 'segments': segments,
            'independent_episode_metrics': episode_metrics(paired),
            'executions': executions,
            'promotion_criterion': {'status': overall_status,
                'statistically_eligible': eligible,
                'real_corpus_statistical_candidate': eligible and not metadata['synthetic'],
                'minimum_independent_adjudicated_events': 100,
                'required_precision_lower_one_sided_95': .95,
                'precision_requirement_applies_to': 'high_priority_inferred_alerts',
                'required_gate_recall': .98,
                'interval': 'Clopper-Pearson exact one-sided 95%',
                'reason': 'Gate recall >=.98; emitted high-priority inferred alert precision CP95 lower >=.95 over >=100 independent adjudicated episodes, separately per identity and cell; relevance precision descriptive; no automatic promotion or human authenticity assertion'},
            'errors': [{'id': e['id'], 'episode': e['episode'], 'kind': e.get('adversarial', 'relevance_or_validation')}
                       for e, p in paired if p.get('relevant') != e['relevant'] or
                       not p.get('schema_valid') or not p.get('citations_valid')]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--predictions', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = evaluate(read_dataset(args.dataset),
                      [json.loads(line) for line in args.predictions.read_text().splitlines() if line.strip()])
    result = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end='')
