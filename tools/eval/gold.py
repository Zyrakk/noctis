"""Offline GOLD export v1 validation; identities/signatures require external audit."""
import hashlib
import json
from datetime import datetime, timezone

IDENTITY = ('route', 'model', 'prompt', 'policy', 'schema', 'price_version')
DIMENSIONS = ('language', 'source', 'task')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode()).hexdigest()


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError('invalid ISO timestamp') from error
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def semantic(value):
    if not isinstance(value, dict) or set(value) != {'labels', 'intent', 'observable_roles'}:
        raise ValueError('semantic contract requires labels, intent, observable_roles')
    if not nonempty(value['intent']):
        raise ValueError('intent must be nonempty')
    for key in ('labels', 'observable_roles'):
        values = value[key]
        if not isinstance(values, list):
            raise ValueError('semantic sets must be lists')
        normalized = []
        for item in values:
            if key == 'labels':
                if not nonempty(item):
                    raise ValueError('labels must be nonempty strings')
                normalized.append(item)
            else:
                if not isinstance(item, dict) or set(item) != {'observable_id', 'role'} or not all(nonempty(x) for x in item.values()):
                    raise ValueError('observable roles require observable_id and role')
                normalized.append((item['observable_id'], item['role']))
        if len(set(normalized)) != len(normalized):
            raise ValueError('duplicate semantic values')
    return value


def target(row):
    return {'relevant': row['relevant'], 'semantic': row.get('semantic')}


def example_commitment(row):
    """Frozen blind material: no adjudicated labels or candidate outputs."""
    required = {'id', 'input', 'context', 'episode', 'partition', 'at', *DIMENSIONS}
    if set(row) - (required | {'relevant', 'semantic', 'adversarial'}) or not required <= set(row):
        raise ValueError('strict frozen example schema required')
    if not nonempty(row['input']) or not isinstance(row['context'], str):
        raise ValueError('frozen input and explicit textual context required')
    return digest({k: row[k] for k in sorted(required)})


def validate_gold(dataset):
    export = dataset['metadata'].get('gold')
    if 'gold' not in dataset['metadata']:
        return None
    required = {'contract', 'origin', 'dataset_sha256', 'guideline_sha256',
                'sampling_sha256', 'independence_sha256', 'frozen_at', 'reviews'}
    if not isinstance(export, dict) or set(export) - {'prediction_audits'} != required or export['contract'] != 'noctis-human-gold-v1':
        raise ValueError('invalid GOLD v1 provenance contract')
    if export['origin'] not in ('human_adjudicated', 'simulated_fixture'):
        raise ValueError('invalid GOLD origin')
    if (export['origin'] == 'simulated_fixture') != dataset['metadata']['synthetic']:
        raise ValueError('GOLD origin and synthetic marker disagree')
    for key in ('dataset_sha256', 'guideline_sha256', 'sampling_sha256', 'independence_sha256'):
        value = export[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('GOLD provenance requires SHA256 digests')
    if digest(dataset['examples']) != export['dataset_sha256']:
        raise ValueError('GOLD dataset digest mismatch')
    frozen = timestamp(export['frozen_at'])
    if any(timestamp(row['at']) > frozen for row in dataset['examples']):
        raise ValueError('GOLD corpus must be frozen after observation period')
    reviews = export['reviews']
    if not isinstance(reviews, dict) or set(reviews) != {e['id'] for e in dataset['examples']}:
        raise ValueError('GOLD reviews must cover every example')
    agreements, corrections = 0, 0
    for row in dataset['examples']:
        commitment = example_commitment(row)
        item = reviews[row['id']]
        if not isinstance(item, dict) or set(item) != {'reviews', 'adjudication'} or not isinstance(item['reviews'], list) or len(item['reviews']) != 2:
            raise ValueError('two independent blind reviews required')
        people, judgments, dates = [], [], []
        for review in [*item['reviews'], item['adjudication']]:
            if not isinstance(review, dict) or set(review) != {'reviewer', 'at', 'blind', 'judgment', 'record_sha256', 'example_sha256'}:
                raise ValueError('invalid human review record')
            if review['example_sha256'] != commitment:
                raise ValueError('human review example commitment mismatch')
            if not nonempty(review['reviewer']) or review['blind'] is not True:
                raise ValueError('blind identified human review required')
            judgment = review['judgment']
            if not isinstance(judgment, dict) or set(judgment) != {'relevant', 'semantic'} or type(judgment['relevant']) is not bool:
                raise ValueError('invalid typed human judgment')
            if judgment['semantic'] is not None:
                semantic(judgment['semantic'])
            if digest({k: v for k, v in review.items() if k != 'record_sha256'}) != review['record_sha256']:
                raise ValueError('human review digest mismatch')
            people.append(review['reviewer'])
            judgments.append(judgment)
            dates.append(timestamp(review['at']))
        if len(set(people)) != 3 or min(dates) < frozen or dates[2] < max(dates[:2]):
            raise ValueError('independent adjudicator and chronological blind reviews required')
        if judgments[2] != target(row):
            raise ValueError('adjudication differs from GOLD target')
        agreements += judgments[0] == judgments[1]
        corrections += sum(j != judgments[2] for j in judgments[:2])
    return {'contract': export['contract'], 'origin': export['origin'],
            'status': 'structurally_valid', 'reviewed_examples': len(reviews),
            'commitments': {k: export[k] for k in ('dataset_sha256', 'guideline_sha256',
                            'sampling_sha256', 'independence_sha256', 'frozen_at')},
            'reviewer_agreement': agreements / len(reviews) if reviews else None,
            'reviewer_disagreements': len(reviews) - agreements,
            'adjudication_corrections': corrections,
            'authenticity': 'Requires external verification of people, records and referenced documents'}


def human_errors(dataset, predictions, gold):
    audits = dataset['metadata'].get('gold', {}).get('prediction_audits')
    if gold is None or audits is None:
        return {'status': 'not_measured'}
    if not isinstance(audits, dict) or set(audits) != {p['id'] for p in predictions}:
        raise ValueError('human prediction audits must cover every prediction')
    errors = ('schema_error', 'citation_error', 'unsupported_claims', 'omitted_claims')
    totals = dict.fromkeys(errors, 0)
    for prediction in predictions:
        audit = audits[prediction['id']]
        required = {'prediction_sha256', 'execution_sha256', 'example_sha256', 'reviewer', 'at', 'record_sha256', *errors}
        if not isinstance(audit, dict) or set(audit) - {'alert_correct'} != required:
            raise ValueError('invalid typed human prediction audit')
        if audit['example_sha256'] != prediction['example_sha256']:
            raise ValueError('human audit example commitment mismatch')
        if 'alert_correct' in audit and audit['alert_correct'] is not None and type(audit['alert_correct']) is not bool:
            raise ValueError('human alert correctness must be boolean or null')
        adjudication = dataset['metadata']['gold']['reviews'][prediction['id']]['adjudication']
        if audit['reviewer'] != adjudication['reviewer'] or timestamp(audit['at']) < timestamp(adjudication['at']):
            raise ValueError('prediction audit requires adjudicator identity and chronology')
        if audit['prediction_sha256'] != digest(prediction) or audit['execution_sha256'] != digest({k: prediction[k] for k in IDENTITY}):
            raise ValueError('human audit prediction or execution digest mismatch')
        if digest({k: v for k, v in audit.items() if k != 'record_sha256'}) != audit['record_sha256']:
            raise ValueError('human audit record digest mismatch')
        for key in errors:
            expected = bool if key.endswith('_error') else int
            if type(audit[key]) is not expected or audit[key] < 0:
                raise ValueError('invalid human error count')
            totals[key] += audit[key]
    return {'status': 'measured', 'denominator': len(audits), **totals}


def human_error_metrics(items, audits):
    if audits is None:
        return {'status': 'not_measured'}
    return {'status': 'measured', 'denominator': len(items),
            **{key: sum(audits[p['id']][key] for _, p in items)
               for key in ('schema_error', 'citation_error', 'unsupported_claims', 'omitted_claims')}}


def semantic_metrics(items):
    provided = [(e['semantic'], p['semantic']) for e, p in items
                if e.get('semantic') is not None and p.get('semantic') is not None]
    if len(provided) != len(items) or not provided:
        return {'status': 'not_measured', 'denominator': len(provided), 'required': len(items)}
    result = {'status': 'measured', 'denominator': len(provided)}
    for field in ('labels', 'intent', 'observable_roles'):
        def values(value):
            if field == 'intent':
                return {value[field]}
            if field == 'observable_roles':
                return {(r['observable_id'], r['role']) for r in value[field]}
            return set(value[field])
        counts = {}
        for gold, prediction in provided:
            expected, actual = values(gold), values(prediction)
            for label in expected | actual:
                tp, fp, fn = counts.setdefault(label, [0, 0, 0])
                counts[label] = [tp + (label in expected & actual),
                                 fp + (label in actual - expected),
                                 fn + (label in expected - actual)]
        per_label = {}
        for label, (tp, fp, fn) in sorted(counts.items()):
            per_label[json.dumps(label, ensure_ascii=False)] = {
                'true_positive': tp, 'false_positive': fp, 'false_negative': fn,
                'precision': tp / (tp + fp) if tp + fp else None,
                'recall': tp / (tp + fn) if tp + fn else None,
                'f1': 2 * tp / (2 * tp + fp + fn)}
        result[field] = {'per_label': per_label, 'macro_f1':
                         sum(c['f1'] for c in per_label.values()) / len(per_label) if per_label else None}
    return result
