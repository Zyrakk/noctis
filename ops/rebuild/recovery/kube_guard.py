"""UID-scoped, emptyDir-only ARM auxiliary and synthetic policy gates."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from preflight import verify, kube
from recover import IMAGE

NODE_UID = '44ed007e-b87a-4fe9-9f00-2beb9f865fa1'
NS_UID = 'b567ebf0-b9a7-4b25-97d7-922c678133aa'

def verify_uid(obj, expected):
    if obj['metadata']['uid'] != expected:
        raise ValueError('Resource UID changed')

def preflight():
    verify()
    namespace = json.loads(kube('get', 'namespace', 'noctis', '-o', 'json'))
    assert namespace['metadata']['uid'] == NS_UID
    node = json.loads(kube('get', 'node', 'oracle1', '-o', 'json'))
    assert node['metadata']['uid'] == NODE_UID
    assert node['status']['nodeInfo']['architecture'] == 'arm64'
    conditions = {c['type']: c['status'] for c in node['status']['conditions']}
    assert conditions['Ready'] == 'True'
    assert all(conditions.get(c) == 'False' for c in ('DiskPressure', 'MemoryPressure', 'PIDPressure'))
    assert not node['spec'].get('taints')
    return node

def pod_spec(name, run, selected=True):
    obj = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': 'noctis', 'labels': {'recovery-run': run, 'recovery-isolated': 'yes' if selected else 'probe'}}, 'spec': {
        'nodeName': 'oracle1', 'restartPolicy': 'Never', 'terminationGracePeriodSeconds': 5, 'automountServiceAccountToken': False, 'enableServiceLinks': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 70, 'runAsGroup': 70, 'fsGroup': 70, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [{'name': 'postgres', 'image': IMAGE, 'command': ['/bin/sh', '-c', 'exec sleep 86400'],
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '500m', 'memory': '1Gi', 'ephemeral-storage': '8Gi'}, 'limits': {'cpu': '2', 'memory': '3Gi', 'ephemeral-storage': '16Gi'}},
            'volumeMounts': [{'name': 'work', 'mountPath': '/work'}, {'name': 'tmp', 'mountPath': '/tmp'}]}],
        'volumes': [{'name': 'work', 'emptyDir': {'sizeLimit': '16Gi'}}, {'name': 'tmp', 'emptyDir': {'sizeLimit': '128Mi'}}]}}
    validate_pod(obj, run)
    return obj

def validate_pod(obj, run):
    spec = obj['spec']
    assert obj['metadata']['labels']['recovery-run'] == run
    assert spec['nodeName'] == 'oracle1' and spec['restartPolicy'] == 'Never'
    assert spec['automountServiceAccountToken'] is False and spec['enableServiceLinks'] is False
    assert not any(spec.get(k) for k in ('hostNetwork', 'hostPID', 'hostIPC', 'initContainers'))
    assert all(set(v) == {'name', 'emptyDir'} for v in spec['volumes']), 'Only emptyDir allowed'
    assert all(not c.get('envFrom') and not c.get('env') for c in spec['containers'])
    assert spec['securityContext']['runAsNonRoot'] and spec['securityContext']['runAsUser'] == 70
    for c in spec['containers']:
        assert c['image'] == IMAGE
        security = c['securityContext']
        assert security['readOnlyRootFilesystem'] and security['allowPrivilegeEscalation'] is False
        assert security['capabilities']['drop'] == ['ALL'] and not security.get('privileged')

class Auxiliary:
    def __init__(self, root):
        self.root = Path(root).resolve()
        assert str(self.root).startswith('/home/zyrak/.local/share/noctis-rebuild/')
        assert self.root.stat().st_mode & 0o077 == 0
        self.run = 'noctis-recover-' + uuid.uuid4().hex[:10]
        self.resources = []

    def create(self, obj):
        result = subprocess.check_output(['kubectl', 'create', '-f', '-', '-o', 'json'], input=json.dumps(obj).encode())
        created = json.loads(result)
        self.resources.append({'kind': created['kind'], 'name': created['metadata']['name'], 'uid': created['metadata']['uid']})
        (self.root / 'auxiliary-uids.json').write_text(json.dumps(self.resources, indent=2))
        return created

    def policy(self):
        return self.create({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'name': self.run, 'namespace': 'noctis'}, 'spec': {'podSelector': {'matchLabels': {'recovery-run': self.run, 'recovery-isolated': 'yes'}}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}})

    def pod(self, suffix, selected):
        obj = self.create(pod_spec(self.run + '-' + suffix, self.run, selected))
        validate_pod(obj, self.run)  # include admission-time mutations
        name = obj['metadata']['name']
        for _ in range(90):
            pod = json.loads(kube('get', 'pod', name, '-n', 'noctis', '-o', 'json'))
            verify_uid(pod, obj['metadata']['uid'])
            if pod['status'].get('phase') == 'Running':
                return name, pod['status']['podIP']
            if pod['status'].get('phase') in ('Failed', 'Succeeded'):
                raise RuntimeError('Auxiliary exited before gate')
            time.sleep(1)
        raise TimeoutError('Auxiliary pod not running')

    def exec(self, name, *args, **kwargs):
        return subprocess.run(['kubectl', 'exec', '-i', '-n', 'noctis', name, '--', *args], **kwargs)

    def gate(self):
        preflight()
        self.policy()  # created before any pod and before private bytes
        target, target_ip = self.pod('arm', True)
        first, first_ip = self.pod('probe-a', False)
        second, second_ip = self.pod('probe-b', False)
        for name in (target, first, second):
            self.exec(name, 'sh', '-ec', '(while true; do printf "HTTP/1.0 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok" | nc -l -p 18080; done) >/work/probe.log 2>&1 </dev/null & echo $! >/work/probe.pid', check=True)
        def request(name, ip):
            result = self.exec(name, 'wget', '-T', '3', '-qO-', 'http://' + ip + ':18080', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
            return result.returncode == 0 and result.stdout == b'ok'
        time.sleep(3)
        assert request(first, second_ip) and request(second, first_ip), 'Synthetic positive network control failed'
        assert request(target, '127.0.0.1'), 'Synthetic target listener failed'
        ingress_blocked = not request(first, target_ip)
        egress_blocked = not request(target, first_ip)
        report = {'positive_controls': True, 'ingress_blocked': ingress_blocked, 'egress_blocked': egress_blocked, 'private_transferred': False, 'node_exceptions': 'Kubernetes permits node-related traffic; no claim of absolute isolation', 'run': self.run}
        (self.root / 'network-policy-report.json').write_text(json.dumps(report, indent=2))
        assert ingress_blocked and egress_blocked, 'NetworkPolicy enforcement failed; private transfer prohibited'
        for name in (target, first, second):
            self.exec(name, 'sh', '-ec', 'kill "$(cat /work/probe.pid)"; if pidof nc >/dev/null; then killall nc; fi', check=True)
        runtime = self.exec(target, 'sh', '-c', 'uname -m; postgres --version; df -Pk /work; cat /proc/meminfo | head -3; pg_config --configure', check=True, stdout=subprocess.PIPE).stdout.decode()
        (self.root / 'arm-runtime.txt').write_text(runtime)
        lines = runtime.splitlines()
        assert lines[0] == 'aarch64' and lines[1].startswith('postgres (PostgreSQL) 16.')
        assert 'aarch64' in lines[-1], 'Image PostgreSQL build is not native ARM64'
        assert int(lines[3].split()[3]) > 20 * 1024 * 1024, 'Insufficient actual node disk free'
        return target

    def cleanup(self):
        proof = []
        for item in reversed(self.resources):
            plural = 'pods' if item['kind'] == 'Pod' else 'networkpolicies'
            group = '/api/v1' if plural == 'pods' else '/apis/networking.k8s.io/v1'
            path = group + '/namespaces/noctis/' + plural + '/' + item['name']
            body = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': item['uid']}}
            subprocess.run(['kubectl', 'delete', '--raw', path, '-f', '-'], input=json.dumps(body).encode(), check=True, stdout=subprocess.DEVNULL)
            subprocess.run(['kubectl', 'wait', '--for=delete', plural + '/' + item['name'], '-n', 'noctis', '--timeout=90s'], check=True, stdout=subprocess.DEVNULL)
            proof.append({**item, 'deleted_with_uid': True, 'absence_verified': True})
        (self.root / 'auxiliary-cleanup.json').write_text(json.dumps(proof, indent=2))
        preflight()

if __name__ == '__main__':
    import sys
    os.umask(0o077)
    auxiliary = Auxiliary(sys.argv[1])
    try:
        auxiliary.gate()
    finally:
        auxiliary.cleanup()
