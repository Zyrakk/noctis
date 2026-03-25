# Noctis Deployment Guide

## Prerequisites
- Kubernetes cluster (k3s or equivalent)
- kubectl configured
- PostgreSQL 16+ (deployed via postgres.yaml or external)
- API keys (see below)

## Required API Keys

| Key | Where to get | Purpose | Required? |
|-----|-------------|---------|-----------|
| NOCTIS_LLM_API_KEY | https://open.bigmodel.cn | GLM-5: summarization, extraction, librarian | Yes |
| NOCTIS_GROQ_API_KEY | https://console.groq.com | Groq: classification (free, no card) | Yes |
| NOCTIS_GEMINI_API_KEY | https://aistudio.google.com | Gemini 3.1 Pro: analyst, briefs, queries | Yes* |
| NOCTIS_DASHBOARD_API_KEY | Generate random string | Dashboard authentication | Yes |
| NOCTIS_ABUSEIPDB_KEY | https://www.abuseipdb.com/account/api | IOC enrichment for IPs (1K/day free) | No |
| NOCTIS_VT_KEY | https://www.virustotal.com/gui/my-apikey | IOC enrichment for IPs/domains/hashes (500/day free) | No |
| NOCTIS_NVD_API_KEY | https://nvd.nist.gov/developers/request-an-api-key | Faster NVD vulnerability sync (free) | No |

*If omitted, Brain falls back to GLM-5 with lower reasoning quality.

## Deployment Steps

### 1. Create namespace
```bash
kubectl apply -f deploy/namespace.yaml
```

### 2. Configure secrets
```bash
cp deploy/secrets.yaml.example deploy/secrets.yaml
# Edit deploy/secrets.yaml with your actual API keys
kubectl apply -f deploy/secrets.yaml
```

### 3. Deploy PostgreSQL
```bash
kubectl apply -f deploy/postgres.yaml
# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=noctis-postgres -n noctis --timeout=120s
```

### 4. Deploy Noctis
```bash
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/noctis.yaml
```

### 5. Verify startup
```bash
kubectl logs -f deployment/noctis -n noctis
# Look for:
# - "migrations applied successfully"
# - "background workers started"
# - "noctis is ready"
# - "dashboard server starting"
```

### 6. Access dashboard
```bash
kubectl port-forward deployment/noctis -n noctis 3000:3000
# Open http://localhost:3000
# Login with your NOCTIS_DASHBOARD_API_KEY
```

## Post-Deploy Verification

### System Status
Open the System Status page (/dashboard/system). Every module should show green:
- Collectors: Telegram, RSS/Web (if enabled)
- Processor: Classifier (groq), Summarizer (glm), IOC Extractor (glm),
  Entity Extractor (glm), Graph Bridge, Librarian (glm), IOC Lifecycle
- Brain: Correlator, Analyst (gemini), Brief Generator (gemini), Query Engine (gemini)
- Infrastructure: Vulnerability Ingestor, Source Analyzer, Enrichment

### Data flow check (first 30 minutes)
1. Findings page: new findings appearing with categories and summaries
2. IOC Explorer: IOCs being extracted with threat scores
3. Correlations: first correlation cycle at 15 minutes
4. Analytical Notes: first analyst cycle at 60 minutes
5. Enrichment: IOCs getting AbuseIPDB/VT/crt.sh badges (after 30 min)
6. Vulnerabilities: NVD/EPSS/KEV data appearing (after first vuln cycle at 6h,
   or restart to trigger immediately)

### Common issues
- Module card shows red: check last_error field on the System Status page
- "LLM call failed": API key missing or invalid — check secrets
- "rate limit exceeded": reduce maxConcurrency for that provider
- Classification not running: verify NOCTIS_GROQ_API_KEY is set
- Analyst not running: verify NOCTIS_GEMINI_API_KEY is set and analyst.enabled: true
- No RSS findings: verify web.enabled: true in configmap
