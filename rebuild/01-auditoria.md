# Auditoría del punto de partida

Fecha: 2026-10-16. Referencia de código: `cca5cbfc2eb5da33cdd65a11408bdc61da6294ef`.
Inspección estática del checkout; no certifica el estado de una instalación remota.
Este documento describe el sistema existente. El resto de `rebuild/` propone el futuro.

## Cobertura documental

Se revisan los **16 Markdown existentes**, aproximadamente 6.038 líneas. No se consideran los nuevos documentos de este directorio como evidencia histórica.

| Documento | Qué aporta y qué debe cambiar en el rebuild |
|---|---|
| `README.md` | Visión, configuración y rutas; sustituir «todo pasa por IA» y confirmación por LLM por inteligencia sustentada y reglas verificables. |
| `docs/architecture.md` | Flujo completo y concurrencia; separar observaciones de contenido, ejecutar trabajos durables y eliminar confianza aritmética presentada como certeza. |
| `docs/analysis.md` | Proveedores, prompts y poison items; errores operativos no pueden convertirse en etiquetas semánticas. |
| `docs/collectors.md` | Adaptadores y descubrimiento; especificar contrato de confirmación, recolección incremental y aislamiento. |
| `docs/configuration.md` | Referencia de opciones; regenerar desde contrato validado y ejemplos ejecutables cuando se implemente. |
| `docs/database.md` | Esquema y consultas; preservar procedencia y revisiones, sin borrar historia por cambio de juicio. |
| `docs/deployment.md` | Guía operativa; corregir configuración divergente y recomendación destructiva de borrar PVC por contraseña. |
| `docs/development.md` | Extensiones y pruebas; unificar contrato de cierre de canales con collectors y comprobar CI realmente existente. |
| `docs/dashboard.md` | API y pantallas; organizar por tareas del analista y separar publicación de lectura privada. |
| `docs/telegram.md` | Sesión, catchup, descubrimiento y OPSEC; conservar como evidencia de complejidad operativa, limitar autonomía de nuevas fuentes. |
| `deploy/README.md` | Instrucciones Kubernetes; unificar con deployment y runbook nuevo. |
| `deploy/DEPLOY.md` | Segundo recorrido de despliegue; sustituir duplicación por una guía canónica con perfiles. |
| `docs/presentation/README.md` | Demo sintética aislada; conservar este principio en la nueva vitrina. |
| `docs/presentation/architecture-summary.md` | Resumen del sistema actual; actualizar solo cuando el rebuild exista. |
| `docs/presentation/technical-claims.md` | Distingue verificado, experiencia y plan; conservar rigor, retirar promesas de entrenamiento como objetivo futuro vigente. |
| `docs/presentation/theagilemonkeys-noctis-script.md` | Historia del proyecto; 20–25 % de ruido es estimación personal, no benchmark. No reescribir retroactivamente la experiencia. |

## Hallazgos comprobados en código

| Problema | Evidencia | Consecuencia | Corrección exigida |
|---|---|---|---|
| Dedupe global fusiona apariciones | `internal/archive/store.go`, `Insert`, conflicto en `content_hash` | Una copia idéntica desde otra fuente no crea una nueva observación con su propia procedencia | Dedupe del payload separado de identidad de observación. |
| Fallo de archivado devuelve éxito | `internal/ingest/pipeline.go`, `Process` | El llamante no puede distinguir pérdida de evidencia de ingest correcto | Confirmar solo después del commit; error y reintento seguro con cursor coherente. |
| Ruta de alertas ejecuta IA en ingest | `internal/ingest/pipeline.go` | Latencia, dependencia de proveedores y duplicación de trabajo frente a workers | Persistencia rápida; políticas y entrega desacopladas con outbox. |
| Cinco fallos pueden producir `irrelevant` | `internal/processor/workers.go` | Una caída del proveedor puede convertirse en descarte analítico | Estados `retryable`, `blocked`, `quarantined`, nunca etiqueta inventada. |
| Presupuesto solo en memoria | `internal/llm/spending.go` | Reinicio pierde contadores; llamadas concurrentes pueden exceder el límite comprobado antes de consumir | Ledger persistente y reserva transaccional del máximo autorizado. |
| Correlación se confirma por conteo | `internal/brain/correlator.go` | Tres fuentes no prueban tres orígenes independientes ni atribución | Separar patrón observado, dependencia de fuentes y afirmación analítica. |
| Confianza por fórmula de conteo | `internal/brain/correlator.go` | Un número calculado puede parecer una probabilidad calibrada | Puntaje de ranking explicable, separado de confianza evaluada. |
| LLM promueve candidatos | `internal/brain/analyst.go` | El modelo puede elevar una hipótesis a confirmación | LLM propone; política evidencial determina elegibilidad. |
| SQL generado se ejecuta en pool de aplicación | `internal/brain/query_engine.go` | Filtro de cadenas no es una frontera de privilegios; no comprueba allowlist real de tablas | Consultas tipadas y parametrizadas; SQL libre fuera del camino normal. |
| Resúmenes privados se sirven sin autenticación | `internal/dashboard/server.go`, `queryPublicRecent` en `queries.go` | Truncar 100 caracteres no anonimiza contenido sensible | Vitrina desde artefactos sintéticos o publicación explícita separada. |
| Navegador conserva API key compartida | `web/src/context/AuthContext.jsx`, `internal/dashboard/middleware.go` | Sin identidad individual ni revocación por sesión | Sesiones de navegador y credenciales de máquina separadas. |
| Prioridad CVE sin exposición local | `internal/vuln/priority.go` | KEV produce critical universal; no determina relevancia para la infraestructura del operador | Watchlists, producto/versión, exposición y evidencia separados. |
| Tor solicitado puede usar HTTP directo | `internal/collector/web.go`, `clientFor` | Sin cliente Tor, cae al cliente ordinario | Fallo cerrado y salida de red impuesta por perfil. |
| Build de imagen no construye frontend | `Dockerfile`, `.github/workflows/build.yaml` | Puede empaquetar estáticos previos; workflow inspeccionado no ejecuta tests | Build reproducible frontend/backend y gates CI. |
| Salud no comprueba progreso | `internal/health/health.go`, `cmd/noctis/serve.go` | Readiness es una bandera, no cobertura de vigilancia | Separar disponibilidad API, salud por fuente y retraso de jobs. |

No se ha demostrado pérdida histórica concreta, explotación remota ni importe real facturado. Son propiedades del código inspeccionado y riesgos derivados.

## Conservar, transformar, retirar

- **Conservar:** Go, PostgreSQL, React, binario con frontend embebido, interfaz de colectores, experiencia Telegram, feeds CVE/KEV/EPSS, métricas, fixtures y presentación sintética.
- **Transformar:** ingest, unidades de trabajo, esquema de evidencia, normalización de observables, reglas de correlación, autenticación, presupuestos, UI y despliegue.
- **Retirar del camino de producción nuevo:** extracción sintáctica de IOCs por LLM, subclasificación obligatoria como llamada independiente, SQL libre generado por IA, confirmación basada solo en conteo/confianza del modelo y entrenamiento propio como prerrequisito.
- **Reutilizar con auditoría:** herramientas de muestreo, validación y deduplicación de `tools/`. Las etiquetas antiguas y las decisiones de modelos son sugerencias, no verdad de referencia.

## Límites de la revisión

En la revisión inicial no se inspeccionó infraestructura remota. La ronda de planificación posterior comprobó metadatos del clúster y PVC/configuración: ver [inventario actual](12-preservacion-infra-y-canales.md). Siguen sin comprobarse contenido histórico, integridad de volúmenes, sesión, recuperación e incidentes reproducibles. No se ejecutan migraciones, despliegues, llamadas pagadas ni benchmarks. La evidencia permite rediseñar; los objetivos numéricos deben medirse en un piloto.
