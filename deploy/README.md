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

If you're on ARM64 and need multi-arch:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/zyrakk/noctis:latest --push .
```

## Step 1: Create Namespace

```bash
kubectl apply -f deploy/namespace.yaml
```

## Step 2: Create Secrets

Copy the example and fill in real values:

```bash
cp deploy/secrets.yaml.example deploy/secrets.yaml
```

Edit `deploy/secrets.yaml`:
- Set `NOCTIS_LLM_API_KEY` to your GLM API key
- Set `NOCTIS_DB_PASSWORD` to a strong password
- Update `NOCTIS_DB_DSN` to match the password you chose

```bash
kubectl apply -f deploy/secrets.yaml
```

**Important:** Never commit `deploy/secrets.yaml` to git. Only `secrets.yaml.example` is tracked.

Also create the PostgreSQL credentials secret (edit the password to match):

```bash
# Edit the password in postgres.yaml to match NOCTIS_DB_PASSWORD
kubectl apply -f deploy/postgres.yaml
```

Wait — that's done in the next step. Just make sure the password in `postgres.yaml`'s `noctis-postgres-credentials` Secret matches `NOCTIS_DB_PASSWORD` in `secrets.yaml`.

## Step 3: Deploy PostgreSQL

```bash
kubectl apply -f deploy/postgres.yaml
```

Wait for PostgreSQL to be ready:

```bash
kubectl -n noctis get pods -w
# Wait until noctis-postgres-0 shows 1/1 Running
```

Verify the database is accessible:

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c '\l'
```

You should see the `noctis` database listed.

## Step 4: Deploy Noctis ConfigMap

```bash
kubectl apply -f deploy/configmap.yaml
```

The default config enables only RSS feeds (BleepingComputer, The Hacker News, Krebs on Security, CERT-EU, CISA Advisories). This is a safe starting point that requires no special credentials.

To customize: edit the ConfigMap or create your own.

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
{"level":"INFO","msg":"starting noctis","version":"dev"}
{"level":"INFO","msg":"database migrations applied"}
{"level":"INFO","msg":"web/RSS collector enabled","feeds":5}
{"level":"INFO","msg":"background workers started","classification_workers":2,"entity_extraction_workers":1}
{"level":"INFO","msg":"noctis is ready","collectors":1,"archive":true,"discovery":true}
```

### Check health

```bash
kubectl -n noctis port-forward svc/noctis-metrics 8080:8080 &
curl http://localhost:8080/healthz
# Should return: ok

curl http://localhost:8080/readyz
# Should return: ready
```

### Check metrics

```bash
kubectl -n noctis port-forward svc/noctis-metrics 9090:9090 &
curl -s http://localhost:9090/metrics | grep noctis_
```

You should see `noctis_findings_total`, `noctis_collector_last_success_timestamp`, and other counters.

### Check the database has content

After a few minutes, RSS feeds should have been collected and archived:

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT count(*) FROM raw_content;"
```

Should return a non-zero count.

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT source_name, count(*) FROM raw_content GROUP BY source_name;"
```

Shows content per RSS feed.

## Checking Results the Next Day

After running overnight, your intelligence database will have accumulated content from all configured feeds.

### Archive stats

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT
    count(*) AS total,
    count(*) FILTER (WHERE classified = true) AS classified,
    count(*) FILTER (WHERE entities_extracted = true) AS entities_extracted
  FROM raw_content;"
```

### Content by source

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT source_name, count(*), max(collected_at)::date AS last_collected
   FROM raw_content
   GROUP BY source_name
   ORDER BY count DESC;"
```

### Classified findings by category

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT category, severity, count(*)
   FROM raw_content
   WHERE classified = true
   GROUP BY category, severity
   ORDER BY count DESC;"
```

### Extracted IOCs

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT type, count(*), min(first_seen)::date, max(last_seen)::date
   FROM iocs
   GROUP BY type
   ORDER BY count DESC;"
```

### Discovered sources

```bash
kubectl -n noctis exec -it noctis-postgres-0 -- psql -U noctis -c \
  "SELECT type, identifier, status FROM sources ORDER BY created_at DESC LIMIT 20;"
```

If source discovery found new URLs in the RSS content, they'll show up here with status `discovered`. Approve them with the CLI (requires building the binary locally):

```bash
./bin/noctis source list --status discovered -c /path/to/config.yaml
./bin/noctis source approve <id> -c /path/to/config.yaml
```

## Scaling Up

Once the RSS-only deployment is verified, you can enable additional sources by editing the ConfigMap:

1. **Paste sites**: Set `paste.enabled: true`, add Pastebin API key to secrets
2. **Telegram**: Set `telegram.enabled: true`, add API credentials to secrets
3. **Forums**: Set `forums.enabled: true`, configure site-specific scrapers
4. **Tor**: Requires a Tor sidecar or host-level Tor service at `127.0.0.1:9050`

## Troubleshooting

**Noctis pod is CrashLoopBackOff:**
- Check logs: `kubectl -n noctis logs deploy/noctis`
- Most common: wrong DB password, missing secrets, or postgres not ready yet

**No content being collected:**
- Check RSS feed URLs are reachable from the cluster
- Check `noctis_collector_errors_total` metric
- Increase log level to `debug` in the ConfigMap

**Classification not happening:**
- Check GLM API key is correct
- Check `noctis_llm_errors_total` metric
- Background workers only start classifying after content is collected

**High memory usage:**
- Reduce `classificationWorkers` and `entityExtractionWorkers` in config
- Check `maxContentLength` — default 50k chars per item
