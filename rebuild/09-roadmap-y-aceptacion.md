# Roadmap de implementación y relanzamiento

Este encargo entrega diseño y documentación. No implementa el rebuild ni despliega el sistema. El backlog siguiente está ordenado por dependencias y valor verificable; no presupone permisos de publicación, gasto o cambios en infraestructura.

Este documento conserva las **tres fases de producto**. Su desglose canónico para ejecutar es ahora [P0–P8 y paquetes](11-roadmap-ejecutable.md), con preservación, testeo, arranque y trazabilidad detallados en `12`–`16`. No son dos roadmaps alternativos.

## Fase 1 — Base y primer recorrido completo

**Resultado:** RSS autorizado → PIR/watchlist → observación durable → expediente con citas y cambios → alerta factual deduplicada → brief mecánico. Frontend mínimo privado con evidencia y estado real. Sin esperar a escoger modelo ni a terminar Zrelay.

| Encargo | Áreas actuales | Entrega | Aceptación |
|---|---|---|---|
| Inventario operativo | Configuración, `deploy/`, fuentes existentes | Recursos, objetivos, volumen/retención, accesos y presupuesto explícitos; copia recuperable del archivo previo | Config válida sin secretos; fuentes autorizadas y prueba de restauración aislada. |
| Contrato de captura y observación | `internal/collector`, `ingest`, `archive`, migraciones | Blob separado de observación; identidad/revisión/cursor, confirmación tras commit | Mismo texto en dos fuentes = un blob/dos observaciones; replay de una observación no duplica; fallo DB no confirma. |
| Jobs, reglas y outbox | `processor`, `matcher`, `dispatcher`, nuevas tablas | Adjudicación durable, fencing, parseo mecánico, prioridad y entregas idempotentes | Dos workers no duplican resultados; caída antes/después de commit recuperable; reintento no rejuvenece sightings. |
| Corte UI y seguridad | `dashboard`, `web`, `health`, build | Hoy y expediente, lector de evidencia, fuentes/salud básica, auth y frontend compilado | Error ≠ vacío ≠ cero; enlace profundo abre objeto; sin CDN runtime ni datos privados públicos. |

Casos de aceptación end-to-end obligatorios: noticia con CVE, mismo texto en otra fuente, IP benigna de referencia, mensaje corto relevante, cambio material, fallo de worker y entrega repetida. El brief inicial es determinista; la síntesis IA puede incorporarse después.

**Gate de salida:** operación representativa restaurable y los casos anteriores pasan. Es un primer corte técnico, no todavía el relanzamiento completo de Noctis.

## Fase 2 — Inteligencia contextual y piloto distintivo

**Resultado:** piloto Telegram autorizado, interpretación estructurada económica, afirmaciones/contradicciones, independencia de orígenes, dossiers y cambios útiles. Noctis vuelve a aportar contexto underground con procedencia.

| Encargo | Áreas actuales | Entrega | Aceptación |
|---|---|---|---|
| Telegram incremental | `collector/telegram*`, sesión/catchup, configuración | Cursor durable, credencial aislada, sesión persistente, backoff y políticas de acceso | Desconexión/reinicio no pierde ni duplica; QR administrativo protegido; no autojoin fuera de política. |
| Dominio CTI | `models`, `archive`, `brain`, proyecciones | Observables/roles/claims/expedientes, aliases, dependencia de fuente y retractación | Copias no confirman; homónimos no se fusionan; retractación actualiza derivados y timeline. |
| Gateway y presupuesto | `llm`, `analyzer`, `processor` | Puerto, servidor falso, schema local, ledger/reservas, una pasada y escalado limitado | Reinicio conserva gasto; timeout incierto conserva exposición; 401/400 no se reintentan ciegamente; agotamiento no descarta contenido. |
| Evaluación y selección | `tools/`, fixtures nuevos | Guía de etiquetas, corpus y comparativa Luna/OSS20/OSS120 o rutas efectivas disponibles | Prueba separada por tiempo/episodio; métricas por segmento e intervalos, costes reales y fallo adversarial visibles. |
| Producto diario | Expedientes, alertas y briefs | Qué cambió/por qué importa/evidencia/qué falta, novedades y silencios por política | Ver un expediente no confirma; nueva evidencia material rompe silencio conforme a regla; no repetir el mismo rumor cada día. |

**Gate de relanzamiento funcional:** recorrido Telegram autorizado completo, backup/restauración, datos privados protegidos, observabilidad útil y periodo piloto acordado con carga representativa. Una propuesta de ensayo es 14 días; extender si no cubre fallos, segmentos y volumen necesarios. No es evidencia estadística por duración solamente.

Las alertas inferidas de alta prioridad se habilitan por segmento cuando cumplen el protocolo de `04-reglas-ia-y-calidad.md`. Mientras tanto se permite uso privado con hipótesis claramente rotuladas y avisos factuales deterministas. Las metas de precisión nunca justifican borrar señales no evaluadas.

## Fase 3 — Autonomía, experiencia profesional y expansión medida

**Resultado:** cinco áreas coherentes, operación sostenible, demo pública aislada, investigación avanzada y conectores solo por valor demostrado.

| Encargo | Entrega | Aceptación |
|---|---|---|
| Hoy/Expedientes/Explorar/Fuentes/Sistema | Navegación por tareas, filtros compartibles, búsqueda tipada, dossiers y grafo contextual acotado | Recorridos medidos, accesibilidad, estados vacíos/degradados y evidencia disponibles. |
| Fuentes y cobertura | Pruebas limitadas, scoring no circular, métricas por PIR y alertas de pérdida de vigilancia | Fallo de fuente visible; discovery respeta acceso/cuotas y no bloquea dominios irreversiblemente por opinión LLM. |
| Release y operación | CI completa, build desde fuentes, migraciones controladas, runbooks únicos | Restauración y rollback compatibles ensayados; documentación antigua reconciliada. |
| Zrelay real | Adaptador conectado al contrato que exista tras su rebuild | Cuenta/ruta/catálogo/capacidades y coste verificados con autorización correspondiente; misma batería de contrato. |
| Vitrina | Demo sintética, historia de producto, recorrido evidencia y documentación honesta | Sin consultas a base privada, secretos, conexiones de producción ni promesas de precisión no medida. |
| Ampliaciones | Exportación STIX/TAXII, embeddings, OCR o SIEM seleccionados | Caso de uso, licencia, coste incremental y beneficio comprobados antes de incorporarlos. |

## Migración del sistema anterior

1. **Preservar.** Backup y restauración de prueba; inventario de fuentes, sesiones, configuraciones y volumen. Congelar definiciones históricas y mantener identificadores de importación.
2. **Importar sin elevar certeza.** Cada fila `raw_content` aporta como mínimo la observación superviviente que realmente contiene. No inventar otras fuentes eliminadas por dedupe. Clasificaciones, IOCs, entidades y correlaciones anteriores se importan como resultados históricos con método/versión conocidos o `unknown`, nunca como hechos verificados. Reprocesar gradualmente lo relevante.
3. **Comparar y cambiar.** Ejecutar shadow sobre corpus/export/inbox ya capturado, sin doble entrega externa ni segundo cliente Telegram compartiendo sesión. Comparar conservación de observaciones, calidad, coste y atraso. Cutover con checkpoint y outbox claros. Mantener el origen legible hasta verificar importación y rollback v2 compatible; no realizar escrituras duales indefinidas, reactivar automáticamente collector legacy ni borrar la base antigua como requisito.

Lo que se perdió por deduplicación no se recupera de la nada. Recolectar de nuevo solo cuando la fuente y sus permisos lo permitan, etiquetando esa adquisición como tal.

## Orden y paralelismo para una implementación posterior

La fase 1 desbloquea las demás. Esquema/ingest/jobs y UI pueden prepararse en paralelo solo una vez fijados contratos y con archivos separados. En fase 2, Telegram y evaluación/gateway son encargos independientes hasta integración. No paralelizar rediseños rivales del dominio ni hacer que varios agentes editen la misma migración.

Las fases no son estimaciones de semanas: faltan inventario, disponibilidad y volumen. El avance se determina por aceptación. Completar una pantalla o cambiar un modelo no equivale a terminar una fase.

## Decisiones que faltan antes de implementar

- Primeras 3–5 necesidades/PIR y watchlists; qué notificaciones merecen interrumpir al operador.
- Recursos reales, infraestructura disponible, retención y destino de backups.
- Fuentes autorizadas y clases de datos permitidas en proveedores externos.
- Presupuesto mensual máximo y carga semanal humana tolerable.
- Ruta de inferencia disponible para piloto; Zrelay puede seguir pendiente sin bloquear fase 1.

No impidieron completar este diseño. Deben fijarse al inicio de implementación para hacer las políticas y costes ejecutables.
