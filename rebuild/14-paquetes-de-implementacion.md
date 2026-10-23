# Paquetes de implementación para reconstruir Noctis

Estado de todos los paquetes: **pendiente**. Rutas nuevas y targets son propuestas; las rutas existentes indican dónde está hoy la responsabilidad. Cada paquete entrega código, pruebas significativas, contrato/guía actualizados y evidencia saneada del gate correspondiente. Un responsable del dominio/esquema integra migraciones; agentes distintos no editan la misma migración.

## P0 — Proteger y preparar

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P0.1 / —** | Nuevos `ops/rebuild/`, `cmd/noctis/legacy_inspect.go`; despliegue existente solo lectura | Inventario saneado de versión, recursos, montajes, espacio, roles requeridos y planes de recuperación. No imprimir secretos. T00. |
| **P0.2 / P0.1** | Herramientas nuevas de export/verify, `internal/legacyimport/`; entorno de rescate | Copia física/sesión, dump+manifest y restore aislado comparado. Credenciales por mounts/passfile, no argumentos. T01–T02; G0. |
| **P0.3 / P0.2 para datos reales** | `sources_export.go`, `telegram_inventory.go`, formato `sources-manifest-v1` | Export completo config/DB/histórico y candidatos dialogs sin join; IDs/estado/procedencia/conflictos. Fixtures saneados disponibles antes del acceso real. T03–T04. |

P0.2 realiza operaciones privadas futuras que deben ejecutarse sobre recursos comprobados. En esta entrega solo se ha hecho inventario remoto de metadatos; no existe export/dump real.

## P1 — Contratos, build y runtime independiente

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P1.1 / especificación P0** | Nuevos `internal/capture/`, `evidence/`, `jobs/`, `intelligence/`; fixtures/contracts v1 | Tipos mínimos CaptureBatch, EvidenceRef, JobKey, CaseRevision, DeliveryKey y API del primer recorrido. Serialización/errores/fechas/IDs definidos. T05. |
| **P1.2 / P1.1** | `internal/database/`, nuevos `migrations/v2/`, roles y configuración DB | Nueva DB, tracker checksum+exclusión y migración explícita. SQL legacy intacto; runtime sin DDL ni escritura legacy. Bootstrap desde DB vacía y fallos transaccionales. T06–T07. |
| **P1.3 / P1.1–P1.2** | Nuevos `cmd/noctis/serve_v2.go` y modos, `internal/config/`, wiring | Runtime arranca con IA desactivada y sin llamar composición legacy. Modos API/worker/collector seleccionables; shutdown ordenado y secretos referenciados. T08. |
| **P1.4 / P1.1** | `Dockerfile`, nueva `.dockerignore`, `Makefile`, workflow CI, `web/vite.config.js`, `web/index.html` | Build Go+frontend desde lockfile, dependencias/fonts/CSS locales, exclusión de datos privados. CI antes de publicación; no basta npm build con React external. T09; G1. |

## P2 — Captura y trabajos durables

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P2.1 / P1.2–P1.3** | `internal/capture/`, `evidence/`, adaptador RSS de `collector/web.go` o nuevo | CommitBatch atómico: blob, observación/revisión, jobs y checkpoint. ACK post-commit, canonicalización/versiones y contenido sin recorte silencioso. T10–T11. |
| **P2.2 / P1.2** | `internal/jobs/`, scheduler, leases y executor | Reclamar con lock breve, heartbeat/fencing, retry-at/errores operativos, cuarentena y replay. T12–T13. |
| **P2.3 / P1.3** | Nuevo `internal/fetch/`, transportes collector y política de fuente | SSRF/DNS/redirects, tamaños/decompresión/timeouts y Tor fail-closed en todas rutas; credenciales segregadas. T14. |
| **P2.4 / P2.1–P2.3** | Métricas/health y fixtures RSS | Último commit/cursor, huecos, retraso/backpressure visibles; no «salud» solo por goroutine. Pipeline RSS recupera tras fallo DB/worker. T10–T14; G2. |

## P3 — Primer corte de producto completo sin IA

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P3.1 / P2.1–P2.2** | Nuevos `internal/observables/`, `policy/`; reutilizar validadores/matcher auditados | Extracción mecánica con spans de documento completo, UTF-8/normalización reversible; PIR/watchlists y gate conservador. T15–T16. |
| **P3.2 / P3.1** | `internal/intelligence/`, `notifications/`, outbox/sender | Expediente factual, revisión y diff material, independencia conocida/unknown; creación de outbox atómica y brief mecánico por periodo. T17–T18. |
| **P3.3 / P1.4, P3.2** | API v2, auth/middleware, `web/src/App.jsx`, `Layout.jsx`, vistas Hoy/Expediente/Evidencia | Sesión segura, navegación profunda, lista/citas/reader y fuentes/sistema mínimos; errores≠vacío≠stale. Demo aislada de base privada. T19–T20. |
| **P3.4 / P3.3** | Fixture integral y runner del binario/imagen, documentación inicial | RSS completo hasta UI y entrega a receptor falso usando PostgreSQL real y frontend compilado sin terceros. T21; G3. |

## P4 — Canales e ingest Telegram nuevo

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P4.1 / P0.3, P1.2** | `sources_import.go`, `sources_reconcile.go`, `internal/legacyimport/` | Dry-run, identidad estable, merges/conflictos e import repetible sin sobrescribir pausas/políticas posteriores. Todas fuentes con disposición, no todas activas. T03–T04. |
| **P4.2 / P2.1–P2.3, P4.1** | Adaptador nuevo Telegram y store peer/updates/cursors | Peer+msg.ID+revisión, allowlist pre-persistencia, updates/differences/inbox atómicos y bootstrap paginado separado. Identidad no basada en título. T22–T24. |
| **P4.3 / P4.2** | Control de propietario, sesión/auth, rate limits y métricas | Propiedad exclusiva; pérdida lease cancela RPC; takeover solo tras muerte confirmada, FloodWait persistente, acceso revocado pausa. T25. |
| **P4.4 / G0, G3, P4.3** | Perfil piloto privado, inventario resuelto y configuración | Piloto real con canales existentes autorizados; restauración/reinicio y progreso verificados. Nunca usar telegram-auth legacy sobre sesión preservada. T26; G4. |
| **P4.5 / P0.2, P2.1, P4.1** | Importador opcional de contenido `internal/legacyimport/`, CLI y reader histórico | Contrato probado por `(archive_id, table, legacy_id)`, identidad desconocida conservada, checkpoint de import y cero alertas; derivados antiguos solo como análisis históricos. Implementar/probar el mecanismo; ejecución masiva opcional y con cuota aparte. T03–T04/T23/T27. |

## P5 — Dominio de inteligencia, feeds e indicadores

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P5.1 / P3.2** | `internal/intelligence/`, entidades/aliases/afirmaciones/proyecciones | Claims sustentados/contradichos, hipótesis identidad reversibles, dependencias, dossiers y aristas con soporte. Retractación invalida derivados; inf. anterior no se recicla como evidencia independiente. T27. |
| **P5.2 / P3.1, P5.1** | Adaptar `internal/vuln/`, snapshots/feed cursors | NVD/KEV/EPSS con snapshots/versiones; watchlists producto/versión/exposición y desconocidos explícitos. KEV no confirma afectación local. T28. |
| **P5.3 / P3.1, P5.1** | Adaptar `internal/enrichment/`, indicators/lifecycle | Cuotas/permisos/caché TTL, reputación con timestamp, promoción por política y revocación; sighting_count desde apariciones únicas, no llamadas. T29. |
| **P5.4 / P4, P5.1–P5.3** | Fixtures A/B/C de `06`, API y proyecciones | Vuln, oferta+copias+negativa, handle+hosting compartido atraviesan dominio y UI. Semántica fixture si P6 no está. T30; G5. |

## P6 — IA económica y verificable

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P6.1 / P1, integración P5** | Nuevo `internal/inference/`, ledger/reservas y fake server | Puerto `08`, caps persistentes con reserva máxima, reconciliación/uncertain, privacy/capability gating y fallback explícito. T31–T32. |
| **P6.2 / P6.1, P5.1** | `prompts/v2/`, schemas, planner de análisis/chunks | Pasada semántica única, validación spans/IDs/esquema, caché contextual, escalado relevante, brief con citas. Errores no producen irrelevant. T33–T34. |
| **P6.3 / P6.2** | `tools/eval/`, guía/manifest de dataset, métricas y canary | Comparativa misma tarea/ruta y corpus temporal/por episodio, no entrenamiento; coste real y métricas segmentadas. Ruta escogida por medición, no precio solo. T35. |
| **P6.4 / G0, G4, G5, P6.3** | Reporte piloto y políticas de entrega evaluadas | Relanzamiento con recuperación+Telegram+dominio+IA funcional, sin exigir alta-prioridad inferida en segmentos no validados. T26/T30/T35; G6. |

## P7 — Producto profesional y autonomía

Requisito adicional core **P6.5 / P6.1–P6.3**, integración P7.1: configuración interactiva de proveedor/URL/API key/modelo por función IA, secretos de escritura exclusiva, revisiones/CAS, router efectivo y panel Sistema. Contrato y aceptación T45–T48 en [17](17-configuracion-ia-por-funcion.md); pertenecen a G6/G7.

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P7.1 / P5–P6** | UI cinco áreas, búsqueda full-text/exacta, API QueryPlan | Navegación, filtros URL, lectura/traducción, dossier y grafo acotado; consulta natural solo operaciones tipadas/vistas permitidas. T36. |
| **P7.2 / P2.3, P5** | Discovery/sources/PIR coverage | Propuestas, pruebas con cuotas/TTL, autorización separada y scoring no circular; cobertura por pregunta y caída fuente visibles. T37. |
| **P7.3 / P3.2, P5–P6** | Políticas atención/revalidación, case events/brief/export | Visto≠confirmado, silencios por condición, excepciones con acción/plazo, reapertura por evidencia y export privado sustentado. T38. |
| **P7.4 / P7.1–P7.3** | UI styles/assets locales, demo fixtures y documentación pública | Identidad visual/accesibilidad y vitrina sintética independientes; medir utilidad/atención con historias A/B/C. T39; G7. |
| **P7.5 / P2, P4** | Adaptar colectores web HTML, paste y forum existentes al contrato v2 | Conservar capacidad de conectores existentes con identidad/checkpoint explícitos y fetch seguro; fixtures de paginación/auth/parser. Desactivados por defecto hasta configurar fuente autorizada; sin nuevas cuentas ni crawling indiscriminado. T44; G7. |

## P8 — Operación, cutover y retirada del runtime anterior

| ID / depende | Archivos/áreas | Resultado esperado y aceptación |
|---|---|---|
| **P8.1 / P1–P7** | Retención/purga/audit, backup/restore, load/fault profiles | Tombstones y revalidación, backups/restore de v2, objetivos RPO/RTO/capacidad/latencia medidos; datos privados fuera de logs. T40–T41. |
| **P8.2 / P8.1, G0–G7** | Nuevos `deploy/v2/`, runbook, release manifests y receipts | Reutilización infra comprobada, un collector/sender, canary/activación por oleadas, rollback compatible y pausa ensayados. T42. |
| **P8.3 / P8.2** | Composición, rutas/API/config/docs antiguas sustituidas | Desconectar ingest/brain/promotores/SQL libre/public recent legacy del runtime productivo; mantener import/lectura histórica. No borrar base/PVC. T43. |
| **P8.4 / P8.3** | Trazabilidad `16` y documentación canónica | Rebuild completo solo con cada requisito core y gate verificados; limitaciones visibles y extensiones separadas. G8. |

## Extensiones con contratos propios

| ID | Dependencia y resultado | Pruebas necesarias |
|---|---|---|
| **X1 Zrelay real** | Contrato efectivo tras su rebuild y P6; adaptador que respeta ruta/capacidad/privacidad/precio reales | Repetir T31–T35 con ruta autorizada, consumo reconciliado y canary. |
| **X2.1 STIX/TAXII** | P5/P7, necesidad de intercambio y permisos | Serialización/roundtrip, markings/retención y no export de claims como indicators sin política. |
| **X2.2 OCR** | Necesidad de cobertura demostrada, budget y aislamiento | Fixtures imagen, límites/tipos, texto/citas con representación identificada, contenido hostil. |
| **X2.3 Embeddings** | P7 búsqueda, recall incremental medido | Recall/coste vs léxico, segregación/retención, no similitud como evidencia. |
| **X2.4 SIEM/nuevos conectores/multiusuario** | Caso explícito por conector/consumidor, acceso y límite | Contrato/retry/idempotencia, permisos, carga y efectos externos acotados. |

## Primera tanda de implementación

Empezar por P0.1 y P1.1. Tras contratos, un encargo backend P1.2–P1.3 y otro build/CI P1.4 pueden avanzar sin solapar escrituras. Recuperación P0.2 sigue una pista separada con recursos privados; su bloqueo no justifica parar dominio local. Ningún agente ejecuta comandos remotos solo por estar escritos en este plan.

No cerrar paquetes por la presencia de archivos vacíos, mocks que reproducen implementación o tests marcados skip. El recibo debe indicar caso, comando, resultado y entorno. Si falta acceso real, paquete local puede completarse, pero el gate operacional queda pendiente.
