#!/usr/bin/env python3
"""Fail closed before touching the two known, stopped Noctis PVCs."""
import json
import subprocess
import posixpath

if not __debug__:
    raise RuntimeError("Safety checks require Python without optimization")

EXPECTED = {
    ("deployment", "noctis"): "a1f3e2a9-08ca-43d5-ba66-84a3c9ea4685",
    ("statefulset", "noctis-postgres"): "dee9d276-252b-43c9-861e-d87938eb6115",
    ("pvc", "noctis-data"): "291623b4-294f-4815-a0a2-d48b111e25e1",
    ("pvc", "noctis-postgres-data"): "ff18ef6c-2ec1-40b4-baf0-3dd232850185",
}

def kube(*args):
    return subprocess.check_output(["kubectl", *args], text=True)

def verify(helper_uid=None):
    assert kube("config", "current-context").strip() == "zcloud-cluster"
    config = json.loads(kube("config", "view", "--minify", "-o", "json"))
    assert config["clusters"][0]["cluster"]["server"] == "https://api.zyrak.cloud/api/v1/k8s/proxy"
    identity = json.loads(kube("auth", "whoami", "-o", "json"))
    assert identity["status"]["userInfo"]["username"] == "system:admin"
    objects = []
    for (kind, name), uid in EXPECTED.items():
        obj = json.loads(kube("get", kind, name, "-n", "noctis", "-o", "json"))
        assert obj["metadata"]["uid"] == uid, (kind, name, "UID changed")
        if kind in ("deployment", "statefulset"):
            assert obj["spec"]["replicas"] == 0
        objects.append(obj)
    volumes = json.loads(kube("get", "pv", "-o", "json"))["items"]
    for claim in [o for o in objects if o["kind"] == "PersistentVolumeClaim"]:
        volume = next(v for v in volumes if v["metadata"]["name"] == claim["spec"]["volumeName"])
        assert volume["spec"]["claimRef"]["uid"] == claim["metadata"]["uid"], "PV binding changed"
        target = volume["spec"].get("nfs")
        assert target, "Storage backend changed"
        for other in volumes:
            source = other["spec"].get("nfs", {})
            if other["metadata"]["uid"] != volume["metadata"]["uid"] and source.get("server") == target["server"]:
                assert posixpath.commonpath([source["path"], target["path"]]) not in (source["path"], target["path"]), "Overlapping NFS PV alias"
    pods = json.loads(kube("get", "pods", "-A", "-o", "json"))["items"]
    for pod in pods:
        for volume in pod["spec"].get("volumes", []):
            claim = volume.get("persistentVolumeClaim", {})
            if pod["metadata"]["namespace"] == "noctis" and claim.get("claimName") in {"noctis-data", "noctis-postgres-data"}:
                assert pod["metadata"]["uid"] == helper_uid, "Unexpected PVC mount"
                assert claim.get("readOnly") is True
                assert all(m.get("readOnly") is True for c in pod["spec"]["containers"] for m in c.get("volumeMounts", []) if m["name"] == volume["name"])
    controllers = json.loads(kube("get", "job,cronjob,daemonset,replicaset,replicationcontroller", "-n", "noctis", "-o", "json"))["items"]
    for obj in controllers:
        spec = obj["spec"]
        if obj["kind"] == "CronJob":
            spec = spec["jobTemplate"]["spec"]
        volumes = spec.get("template", {}).get("spec", {}).get("volumes", [])
        uses = any(v.get("persistentVolumeClaim", {}).get("claimName") in {"noctis-data", "noctis-postgres-data"} for v in volumes)
        if uses:
            assert obj["kind"] in {"ReplicaSet", "ReplicationController"} and spec.get("replicas", 1) == 0, "Unexpected PVC controller"
    return objects

if __name__ == "__main__":
    verify()
    print("Verified context, server, account, UIDs, stopped workloads and absence of other mounts/controllers")
