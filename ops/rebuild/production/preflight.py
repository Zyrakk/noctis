#!/usr/bin/env python3
"""Read-only exact identity gate. No apply, fallback context or unknown namespace."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

LEGACY_NS_UID = 'b567ebf0-b9a7-4b25-97d7-922c678133aa'
NODE_UID = '44ed007e-b87a-4fe9-9f00-2beb9f865fa1'


def kube(*args):
    return subprocess.check_output(['kubectl', '--context=zcloud-cluster', '--request-timeout=15s', *args], text=True)


def verify(namespace_uid=None):
    # Existing preservation gate checks context/server/account, all four exact
    # legacy resource UIDs, replicas=0, PVC bindings and unexpected mounts.
    path = Path(__file__).resolve().parents[1] / 'recovery/preflight.py'
    spec = importlib.util.spec_from_file_location('legacy_preflight', path)
    legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
    legacy_objects = legacy.verify()
    preserved_volumes = {o['spec']['volumeName'] for o in legacy_objects if o['kind'] == 'PersistentVolumeClaim'}
    old = json.loads(kube('get', 'namespace', 'noctis', '-o', 'json'))
    if old['metadata']['uid'] != LEGACY_NS_UID:
        raise ValueError('Legacy namespace UID changed')
    node = json.loads(kube('get', 'node', 'oracle1', '-o', 'json'))
    conditions = {c['type']: c['status'] for c in node['status']['conditions']}
    if node['metadata']['uid'] != NODE_UID or node['status']['nodeInfo']['architecture'] != 'arm64' or conditions.get('Ready') != 'True' or any(conditions.get(k) != 'False' for k in ('MemoryPressure', 'DiskPressure', 'PIDPressure')):
        raise ValueError('Expected healthy ARM64 node required')
    namespaces = json.loads(kube('get', 'namespaces', '-o', 'json'))['items']
    target = next((n for n in namespaces if n['metadata']['name'] == 'noctis-v2'), None)
    if namespace_uid is None:
        if target is not None:
            raise ValueError('Existing target namespace requires its independently reviewed exact UID')
    elif target is None or target['metadata']['uid'] != namespace_uid:
        raise ValueError('Target namespace missing or UID changed')
    if target is not None:
        pvs = json.loads(kube('get', 'pv', '-o', 'json'))['items']
        for pv in pvs:
            claim = pv['spec'].get('claimRef', {})
            if claim.get('namespace') == 'noctis-v2' and claim.get('name') in ('noctis-v2-postgres-data', 'noctis-v2-telegram-private-session'):
                if pv['metadata']['name'] in preserved_volumes:
                    raise ValueError('Legacy volume reuse prohibited')
                if pv['spec'].get('accessModes') != ['ReadWriteOnce']:
                    raise ValueError('Production volume must be RWO')
                # The old preservation gate rejects aliases among all NFS PVs.
    return {'result': 'pass', 'checked_at': datetime.now(timezone.utc).isoformat(), 'context': 'zcloud-cluster', 'server': 'https://api.zyrak.cloud/api/v1/k8s/proxy', 'account': 'system:admin', 'legacy_namespace_uid': LEGACY_NS_UID, 'legacy_replicas': 0, 'namespace': 'noctis-v2', 'namespace_uid': namespace_uid, 'node_uid': NODE_UID, 'mutation_performed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace-uid')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.namespace_uid)))
    except (ValueError, AssertionError, KeyError, subprocess.CalledProcessError):
        sys.exit('Production identity preflight rejected; no mutations performed.')
