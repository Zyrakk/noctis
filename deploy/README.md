# Noctis Deployment Guide

Deploy Noctis on a Kubernetes cluster (tested on k3s).

## Prerequisites

- Kubernetes cluster with `kubectl` access
- StorageClass `nfs-shared` available (used by PostgreSQL PVC)
- Container image built and pushed: `ghcr.io/zyrakk/noctis:latest`
- GLM API key from [open.bigmodel.cn](https://open.bigmodel.cn)

### Build and push the image

```bash
# From the noctis/ project root
make build
docker build -t ghcr.io/zyrakk/noctis:latest .
docker push ghcr.io/zyrakk/noctis:latest
```

Multi-arch (required for mixed Intel + ARM clusters):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/zyrakk/noctis:latest --push .
```

## How Config Works

Noctis reads its config from a YAML file mounted via ConfigMap. The YAML supports `${ENV_VAR}` syntax for secrets — the Go config loader replaces these tokens with environment variable values at startup. The env vars come from the Kubernetes Secret `noctis-secrets`, injected via `envFrom`.

**Example flow:**
1. Secret `noctis-secrets` has key `NOCTIS_DB_DSN` with value `postgres://noctis:mypass@noctis-postgres.noctis.svc:5432/noctis?sslmode=disable`
2. The Noctis pod gets `NOCTIS_DB_DSN` as an env var via `envFrom`
3. The ConfigMap has `dsn: "${NOCTIS_DB_DSN}"` in the YAML
4. Go's `config.Load()` reads the YAML, replaces `${NOCTIS_DB_DSN}` with the env var value
5. The daemon connects to postgres using the real DSN

**The ConfigMap never contains real credentials.** All secrets flow through the Kubernetes Secret.

## Step 1: Create Namespace

```bash
kubectl apply -f deploy/namespace.yaml
```

## Step 2: Create Secrets

Copy the example and fill in real values:

```bash
cp deploy/secrets.yaml.example deploy/secrets.yaml
# Edit deploy/secrets.yaml with real values
```

Required keys:

| Key | Description |
|-----|-------------|
| `NOCTIS_LLM_API_KEY` | GLM API key |
| `NOCTIS_DB_PASSWORD` | PostgreSQL password (used by both postgres and noctis) |
| `NOCTIS_DB_DSN` | Full connection string: `postgres://noctis:<PASSWORD>@noctis-postgres.noctis.svc:5432/noctis?sslmode=disable` |

**The password in `NOCTIS_DB_DSN` must match `NOCTIS_DB_PASSWORD` exactly.** The DSN is what the Go code uses to connect. The password is what PostgreSQL uses to authenticate.

```bash
kubectl apply -f deploy/secrets.yaml
```

**Never commit `deploy/secrets.yaml` to git.** Only `secrets.yaml.example` is tracked.

## Step 3: Deploy PostgreSQL

```bash
kubectl apply -f deploy/postgres.yaml
```

PostgreSQL reads `NOCTIS_DB_PASSWORD` from the same `noctis-secrets` secret via `secretKeyRef`. This guarantees the password is consistent between postgres and noctis.

Wait for it to be ready:

```bash
kubectl -n noctis get pods -w
# Wait until noctis-postgres-0 shows 1/1 Running
```

Verify:

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c '\l'
```

## Step 4: Deploy ConfigMap

```bash
kubectl apply -f deploy/configmap.yaml
```

The default config enables only RSS feeds (BleepingComputer, The Hacker News, Krebs on Security, CERT-EU, CISA). No special credentials needed for RSS-only mode.

The ConfigMap references `${NOCTIS_DB_DSN}` and `${NOCTIS_LLM_API_KEY}` which are resolved from env vars at runtime.

## Step 5: Deploy Noctis

```bash
kubectl apply -f deploy/noctis.yaml
```

Watch it come up:

```bash
kubectl -n noctis get pods -w
# Wait until noctis shows 1/1 Running
```

## Step 6: Verify It Works

### Check logs

```bash
kubectl -n noctis logs -f deploy/noctis
```

You should see:
```
{"level":"INFO","msg":"starting noctis","version":"..."}
{"level":"INFO","msg":"database migrations applied"}
{"level":"INFO","msg":"web/RSS collector enabled","feeds":5}
{"level":"INFO","msg":"background workers started",...}
{"level":"INFO","msg":"noctis is ready",...}
```

If you see `password authentication failed`, verify:
1. The password in `NOCTIS_DB_DSN` matches `NOCTIS_DB_PASSWORD` in the secret
2. The secret was applied: `kubectl -n noctis get secret noctis-secrets -o yaml`
3. Re-apply the secret and restart the pod: `kubectl -n noctis rollout restart deploy/noctis`

### Check health

```bash
kubectl -n noctis port-forward svc/noctis-metrics 8080:8080 &
curl http://localhost:8080/healthz   # ok
curl http://localhost:8080/readyz    # ready
```

### Check metrics

```bash
kubectl -n noctis port-forward svc/noctis-metrics 9090:9090 &
curl -s http://localhost:9090/metrics | grep noctis_
```

### Check the database has content

After a few minutes:

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT count(*) FROM raw_content;"
```

## Checking Results the Next Day

### Archive stats

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT
    count(*) AS total,
    count(*) FILTER (WHERE classified = true) AS classified,
    count(*) FILTER (WHERE entities_extracted = true) AS extracted
  FROM raw_content;"
```

### Content by source

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT source_name, count(*), max(collected_at)::date AS last_collected
   FROM raw_content GROUP BY source_name ORDER BY count DESC;"
```

### Classified findings

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT category, severity, count(*)
   FROM raw_content WHERE classified = true
   GROUP BY category, severity ORDER BY count DESC;"
```

### Extracted IOCs

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT type, count(*) FROM iocs GROUP BY type ORDER BY count DESC;"
```

### Discovered sources

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT type, identifier, status FROM sources ORDER BY created_at DESC LIMIT 20;"
```

## Troubleshooting

**`password authentication failed for user noctis`:**
- The DSN password doesn't match what postgres expects
- Check: `kubectl -n noctis get secret noctis-secrets -o jsonpath='{.data.NOCTIS_DB_PASSWORD}' | base64 -d`
- Verify the same password appears in `NOCTIS_DB_DSN`
- If you changed the password, restart postgres to pick it up: `kubectl -n noctis rollout restart sts/noctis-postgres`

**Noctis pod CrashLoopBackOff:**
- Check logs: `kubectl -n noctis logs deploy/noctis --previous`
- Common causes: wrong DB password, postgres not ready yet, missing secret

**No content being collected:**
- Check RSS feed URLs are reachable from the cluster
- Check metrics: `curl -s localhost:9090/metrics | grep collector_errors`
- Increase log level: edit `logLevel: debug` in configmap, re-apply, restart

**Classification not happening:**
- Check GLM API key: `kubectl -n noctis get secret noctis-secrets -o jsonpath='{.data.NOCTIS_LLM_API_KEY}' | base64 -d`
- Check metrics: `curl -s localhost:9090/metrics | grep llm_errors`
- Workers only classify after content is collected — wait for RSS feeds to populate first

## Scaling Up

Once RSS-only is verified, enable additional sources by editing the ConfigMap:

1. **Paste sites**: Set `paste.enabled: true`, add `NOCTIS_PASTEBIN_API_KEY` to secrets
2. **Telegram**: Set `telegram.enabled: true`, add Telegram API credentials to secrets
3. **Forums**: Set `forums.enabled: true`, configure per-forum scrapers
4. **Tor**: Add a Tor sidecar container or ensure host Tor runs at `127.0.0.1:9050`

After editing the ConfigMap, restart Noctis to pick up changes:

```bash
kubectl apply -f deploy/configmap.yaml
kubectl -n noctis rollout restart deploy/noctis
```
