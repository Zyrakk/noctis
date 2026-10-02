# Presentation technical claims checklist

This is an internal review aid for the speaking script. It is intentionally kept outside the audiovisual flow.

| Claim used in the script | Classification | Evidence / wording guard |
|---|---|---|
| Noctis is a long-running Go threat-intelligence daemon | VERIFIED FROM CODE + DOCS | `README.md`, `docs/architecture.md`, `cmd/noctis/serve.go` |
| Sources include Telegram, paste sites, forums and RSS/web feeds | VERIFIED FROM CODE + DOCS | `internal/collector/*`, `docs/collectors.md`, architecture layer 1 |
| Raw content is archived before later processing | VERIFIED FROM CODE + DOCS | `internal/ingest/pipeline.go`, `docs/architecture.md` data flow |
| Classifier, summarizer and IOC extractor use the fast LLM / Llama 4 Scout configuration | VERIFIED FROM DOCS + CONFIG | `docs/analysis.md`, `README.md`, `internal/processor/*`; wording says “used” for the documented configuration |
| Named entities and graph relationships are extracted and written | VERIFIED FROM CODE + DOCS | `internal/processor/entity_extractor.go`, `graph_bridge.go`, migrations 002/003 |
| Dashboard exposes findings, briefs, correlations, notes, IOCs and the graph | VERIFIED FROM CODE + DOCS | `web/src/pages/*`, `docs/dashboard.md`, `internal/dashboard/*` |
| Correlator uses shared IOC, handle reuse, temporal overlap and entity-cluster rules | VERIFIED FROM CODE + DOCS | `internal/brain/correlator.go`, `docs/architecture.md` § Correlator |
| Analyst can promote, reject or defer candidates and retains context/reasoning | VERIFIED FROM CODE + DOCS | `internal/brain/analyst.go`, `prompts/evaluate_correlation.tmpl`, migrations 006/007 |
| Daily brief is generated from a collection window | VERIFIED FROM CODE + DOCS | `internal/brain/brief_generator.go`, `prompts/daily_brief.tmpl` |
| Dirty Frag appeared earlier in the user's personal view of Noctis | PERSONAL EXPERIENCE PROVIDED BY USER | Spoken explicitly as an anecdote, never shown as repository evidence |
| Roughly 20–25% noise remained | APPROXIMATE / SHOULD BE PHRASED CAREFULLY | User's empirical operating estimate; script says it is not a benchmark |
| Rebuild starts with label validation, clean dataset, IOC masking and a two-stage baseline | VERIFIED FROM CODE + DOCS | `tools/validate_relabel.py`, `tools/build_dataset.py`, `tools/mask_iocs.py`, `tools/train_baseline.py` |
| A more specialized intelligence agent was the longer-term direction | PERSONAL CONTEXT / PLANNED | No specialized agent is implemented in the current tree; script says “longer-term idea” |
| Collected decisions can become a future fine-tuning dataset | VERIFIED FROM DOCS AS FUTURE USE | `docs/database.md` and `docs/architecture.md` describe `correlation_decisions` as an audit trail / future fine-tuning dataset; do not present it as a trained model |

## Repository discrepancy

There is no standalone rebuild design document under `docs/` in the current checkout. The documented rebuild direction is distributed across the F1 tooling docstrings, tests and database/architecture notes. The presentation labels that work as **rebuild direction / planned**, not as a running replacement for the current LLM pipeline.
