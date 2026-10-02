# Noctis architecture summary used for the presentation

The presentation is a thin, isolated visual layer over the existing React dashboard. It follows the architecture described in `docs/architecture.md` and the code paths in `internal/`:

1. **Collectors** emit `models.Finding` from Telegram MTProto, paste sites, forums and RSS/web sources.
2. **Ingest** archives every item, deduplicates by content hash, evaluates keyword/regex matcher rules and can run the alert path.
3. **Processing workers** classify and summarize content, extract IOCs, extract named entities, bridge entities/IOCs into the graph, apply librarian sub-classification and run IOC lifecycle handling.
4. **Brain** correlates cross-source patterns with four rule families, asks the Analyst LLM to evaluate candidates, produces analytical notes and generates daily briefs. The query engine is on demand.
5. **Infrastructure and dashboard** cover vulnerability feeds (NVD/EPSS/KEV), external IOC enrichment, source discovery/triage and the embedded React dashboard.

The presentation screens use synthetic, deterministic objects shaped like these domain records. They do not connect to PostgreSQL or the production dashboard API, so recording does not require credentials or expose private data.

The rebuild screen reflects the repository's F1 tooling: review and relabeling, gold-set exclusion, content deduplication, temporal splits, IOC masking and a two-stage baseline classifier. It is deliberately marked as a planned direction rather than an implemented runtime component.
