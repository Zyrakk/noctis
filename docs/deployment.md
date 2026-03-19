# Noctis Deployment Guide

This guide covers deploying Noctis on Kubernetes and as a standalone binary.

---

## Prerequisites

- A Kubernetes cluster (k3s, kubeadm, EKS, GKE, AKS, or any distribution)
- `kubectl` configured and pointing at your cluster
- A StorageClass available for PostgreSQL persistent storage (the manifests default to `nfs-shared` — edit `deploy/postgres.yaml` to match your cluster)
- A GLM API key from [open.bigmodel.cn](https://open.bigmodel.cn) or a compatible OpenAI-format LLM provider
- (Optional) Telegram API credentials for Telegram collection — see [Telegram Setup](#telegram-setup) and [docs/telegram.md](telegram.md)

---

## Quick Start — Kubernetes

### 1. Create the namespace

```bash
kubectl apply -f deploy/namespace.yaml
```

### 2. Prepare secrets

```bash
cp deploy/secrets.yaml.example deploy/secrets.yaml
```

Edit `deploy/secrets.yaml` and fill in each field:

| Key | Description |
|-----|-------------|
| `NOCTIS_LLM_API_KEY` | Your GLM or OpenAI-compatible API key |
| `NOCTIS_DB_PASSWORD` | PostgreSQL password — pick a strong value, used in both the DB container and the DSN |
| `NOCTIS_DB_DSN` | Full connection string: `postgres://noctis:PASSWORD@noctis-postgres.noctis.svc:5432/noctis?sslmode=disable` — substitute the same password as above |
| `NOCTIS_TELEGRAM_API_ID` | (Optional) Telegram app ID from my.telegram.org |
| `NOCTIS_TELEGRAM_API_HASH` | (Optional) Telegram app hash |
| `NOCTIS_TELEGRAM_PHONE` | (Optional) Phone number in international format |
| `NOCTIS_TELEGRAM_PASSWORD` | (Optional) Telegram 2FA password, if set |
| `NOCTIS_PASTEBIN_API_KEY` | (Optional) Pastebin PRO API key |

**Important:** `deploy/secrets.yaml` contains credentials. Add it to `.gitignore` and never commit it.

```bash
echo "deploy/secrets.yaml" >> .gitignore
```

### 3. Apply secrets

```bash
kubectl apply -f deploy/secrets.yaml
```

### 4. Configure storage and deploy PostgreSQL

The default StorageClass in `deploy/postgres.yaml` is `nfs-shared`. If your cluster uses a different StorageClass (e.g., `standard`, `gp2`, `longhorn`), edit the file before applying:

```yaml
# deploy/postgres.yaml — PVC section
spec:
  storageClassName: your-storage-class  # edit this line
  resources:
    requests:
      storage: 50Gi
```

Apply the database manifests:

```bash
kubectl apply -f deploy/postgres.yaml
kubectl rollout status statefulset/noctis-postgres -n noctis
```

### 5. Configure Noctis

Edit `deploy/configmap.yaml` to configure your sources and matching rules before applying. Key sections:

- `sources.telegram.channels` — list of Telegram channels to monitor
- `sources.web.feeds` — RSS/Atom feeds to collect
- `matching.rules` — keyword and regex rules for alert matching
- `llm.provider` / `llm.model` — LLM backend settings
- `discovery.domainBlacklist` — domains to exclude from auto-discovery

```bash
kubectl apply -f deploy/configmap.yaml
```

### 6. Deploy Noctis

```bash
kubectl apply -f deploy/noctis.yaml
```

### 7. Verify the deployment

```bash
kubectl logs -f deployment/noctis -n noctis
```

Check readiness:

```bash
kubectl get pods -n noctis
```

---

## Quick Start — Standalone

### 1. Set up PostgreSQL

Install PostgreSQL locally and create the database and user:

```sql
CREATE USER noctis WITH PASSWORD 'your-password';
CREATE DATABASE noctis OWNER noctis;
```

### 2. Build the binary

```bash
go build -o noctis ./cmd/noctis/
```

Or using make:

```bash
make build
# binary written to bin/noctis
```

### 3. Create a config file

Create `config.yaml` based on `deploy/configmap.yaml`. Set the database DSN:

```yaml
noctis:
  database:
    driver: postgres
    dsn: "${NOCTIS_DB_DSN}"
```

You can supply the DSN directly or via environment variable:

```bash
export NOCTIS_DB_DSN="postgres://noctis:your-password@localhost:5432/noctis?sslmode=disable"
export NOCTIS_LLM_API_KEY="your-api-key"
```

### 4. Run

```bash
./noctis serve --config config.yaml
```

Migrations run automatically on startup.

---

## Telegram Setup

To enable Telegram collection:

1. Obtain API credentials at [my.telegram.org](https://my.telegram.org) — create an application to get `api_id` and `api_hash`.
2. Add the four Telegram fields to your secret (`NOCTIS_TELEGRAM_API_ID`, `NOCTIS_TELEGRAM_API_HASH`, `NOCTIS_TELEGRAM_PHONE`, `NOCTIS_TELEGRAM_PASSWORD`).
3. Enable Telegram in `deploy/configmap.yaml` and list the channels you want to monitor under `sources.telegram.channels`.
4. After deployment, port-forward to the health port and open the QR auth page:
   ```bash
   kubectl port-forward deployment/noctis 8080:8080 -n noctis
   # Open http://localhost:8080/auth/qr in a browser and scan with the Telegram mobile app
   ```
5. Use a dedicated or burner Telegram account — scraping channels at scale may trigger rate limits.

See [docs/telegram.md](telegram.md) for the full Telegram setup guide.

---

## Source Management

Run management commands directly in the container using `kubectl exec`:

**List discovered sources (pending approval):**

```bash
kubectl exec deployment/noctis -n noctis -- /noctis source list --status discovered -c /etc/noctis/config.yaml
```

**Add a channel at runtime (no restart required):**

```bash
kubectl exec deployment/noctis -n noctis -- /noctis source add --type telegram_channel --identifier "channelname" -c /etc/noctis/config.yaml
```

**Approve a discovered source:**

```bash
kubectl exec deployment/noctis -n noctis -- /noctis source approve <id> -c /etc/noctis/config.yaml
```

**Search collected intelligence:**

```bash
kubectl exec deployment/noctis -n noctis -- /noctis search "keyword" -c /etc/noctis/config.yaml
```

**View collection statistics:**

```bash
kubectl exec deployment/noctis -n noctis -- /noctis stats -c /etc/noctis/config.yaml
```

---

## Monitoring

The `noctis-metrics` Service exposes two ports:

| Port | Path | Description |
|------|------|-------------|
| 8080 | `/healthz` | Liveness — always returns 200 |
| 8080 | `/readyz` | Readiness — 200 when collectors are running, 503 otherwise |
| 8080 | `/auth/qr` | Telegram QR authentication page |
| 9090 | `/metrics` | Prometheus-format metrics |

Port-forward to access locally:

```bash
# Health and auth endpoints
kubectl port-forward svc/noctis-metrics 8080:8080 -n noctis

# Prometheus metrics
kubectl port-forward svc/noctis-metrics 9090:9090 -n noctis
```

---

## Updating

**Rolling restart (uses the existing image):**

```bash
kubectl rollout restart deployment/noctis -n noctis
```

**Rebuild and redeploy:**

```bash
make docker-build TAG=v1.2.3
docker push ghcr.io/zyrakk/noctis:v1.2.3
# Update the image tag in deploy/noctis.yaml, then:
kubectl apply -f deploy/noctis.yaml
kubectl rollout restart deployment/noctis -n noctis
```

Database migrations run automatically when the pod starts — no manual migration step required.

---

## Troubleshooting

**PostgreSQL authentication failure**

`NOCTIS_DB_PASSWORD` is used by both the PostgreSQL container (`POSTGRES_PASSWORD`) and the DSN in `NOCTIS_DB_DSN`. Both must be set to the same value in `deploy/secrets.yaml`. If the pod was created before you changed the password, delete the PVC and StatefulSet and redeploy.

**LLM returns invalid JSON / markdown fences**

The analyzer's `stripCodeFences` step strips backtick fences from GLM responses. If you switch to a different LLM provider, ensure it returns raw JSON without markdown formatting, or the classification pipeline will log parse errors.

**Telegram QR code expires before scanning**

QR tokens expire in approximately 30 seconds. The `/auth/qr` page auto-refreshes — keep the browser tab open and scan quickly. If it expires, refresh the page to get a new token.

**Telegram session lost after pod restart**

The default manifests now use a PVC at `/data`, so the session file persists across pod restarts and redeployments — no QR re-scan is needed. If you are running a custom manifest that uses `emptyDir` instead, the session is ephemeral and is wiped on every pod restart. In that case, port-forward to `/auth/qr` and re-authenticate after each restart, or replace the `emptyDir` with a PVC.

**Discovery produces too much noise**

Add noisy reference domains to `discovery.domainBlacklist` in the ConfigMap and redeploy. The default list includes `nvd.nist.gov`, `cwe.mitre.org`, `github.com`, and `wikipedia.org`. After editing, `kubectl apply -f deploy/configmap.yaml` and restart the pod.

**YAML config field name errors**

Config field names are camelCase. Common mistakes:
- Use `apiId` not `apiID`
- Use `baseURL` not `baseUrl`
- Use `sessionFile` not `session_file`

**Empty UUID errors on insert**

If you see UUID-related errors in logs, this indicates a race in the archive insert path. The fix is present in the CTE-based INSERT implementation. Verify you are running the latest image.

**Config not mounted / changes not picked up**

The ConfigMap is mounted read-only at `/etc/noctis`. After editing and applying the ConfigMap, restart the pod to pick up changes:

```bash
kubectl rollout restart deployment/noctis -n noctis
```
