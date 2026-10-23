# Estrategia de pruebas y gates de aceptación

Estado: plan; **ninguna prueba de implementación nueva ni recuperación se ha ejecutado** en esta tarea. Se ha inspeccionado cobertura existente y verificado el inventario remoto mediante lecturas filtradas. La documentación se comprueba aparte; no certifica el runtime.

## Punto de partida real

`make test` ejecuta `go test -race -count=1 ./...`. Las pruebas inspeccionadas de database comprueban archivos/orden, archive conversiones/helpers, ingest/pipeline/processor mocks y Telegram conversiones/dedupe/helpers. No acreditan transacciones, leases, aislamiento PostgreSQL o continuidad MTProto reales. Un test llamado EndToEnd con stores falsos no equivale al producto completo.

Playwright actual verifica presentación sobre Vite dev. CI actual construye/publica imagen sin gates de tests; Dockerfile no construye frontend y Vite externaliza React y otras dependencias. `npm run build` puede terminar y seguir requiriendo terceros.

Comandos **existentes** aprovechables, no ejecutados en este encargo:

```sh
make test
make lint
make build
npm --prefix web ci
npm --prefix web run build
npm --prefix web run presentation:qa
python3 -m unittest discover -s tools -p 'test_*.py'
```

`make lint` requiere herramienta disponible; Python requiere dependencias declaradas. Registrar entorno y errores de setup; no convertir una suite sin dependencias o con skips en verde. Los scripts antiguos de entrenamiento no son dependencia del runtime nuevo.

## Harness nuevo y entornos

| Nivel | Entorno | Qué demuestra |
|---|---|---|
| Unitario/contrato | Fixtures sintéticas, reloj controlado y servidores falsos | Parsers, políticas, schemas, serialización y errores. |
| Integración | PostgreSQL de la versión aceptada, DB/roles temporales, conexiones independientes | Transacciones, unicidad, permisos, migraciones, concurrencia y recuperación durable. |
| Fallos/crash | Procesos separados contra la misma DB, puntos de fallo controlados | Reanudación antes/después de commits y efectos externos inciertos. |
| E2E privado | Binario/imagen compilados, PostgreSQL, feed/receptor/gateway falsos | Recorrido completo de datos hasta UI y entrega sin proveedores reales. |
| Piloto real | Infra protegida y fuentes autorizadas, caps/epoch explícitos | Acceso efectivo, captura, reinicio, coste y operación representativa. |

Targets nuevos propuestos: `test-unit`, `test-integration`, `test-faults`, `test-e2e`, `test-security`, `eval-replay`, `release-check`. P1/P2 deben implementarlos con setup/teardown y salida reproducibles antes de usarlos. Ningún target genérico conecta a Telegram, proveedores pagados o producción por defecto.

Aislar test DB por ejecución, fijar versiones/digests cuando se adopten, timezone UTC y seeds. Usar barreras deterministas para concurrencia y límites de tiempo para fallos; sleeps arbitrarios no prueban interleavings. Guardar reports saneados con commit, configuración, versión de contratos y dataset. Material privado nunca como fixture público.

## Casos mínimos trazables

IDs T00–T44 son especificaciones nuevas; nombres de tests orientativos, no archivos ya implementados.

| ID | Prueba y fallo relevante | Criterio verificable |
|---|---|---|
| **T00** | Inventario/preflight de recursos y secretos | Contexto/namespace/UID/montajes/versiones registrados; salida sin credenciales. |
| **T01** | Copia física y sesión offline; copia incompleta | Hash/inventario y cero escritores; error bloquea recuperación. |
| **T02** | Restore lógico real del mismo snapshot | Restore sin errores; esquema/conteos/digests y consultas coinciden. `pg_restore --list` solo no vale. |
| **T03** | Export/import de fuentes y replay | IDs completos, merges/conflictos reportados; segundo import no duplica ni alerta. |
| **T04** | Fuente desconocida/pausada, username reasignado, import posterior | No inventa identidad ni habilita; respeta política modificada después de import. |
| **T05** | Contratos/JSON/fechas/IDs Unicode | Versionado, errores y límites; IDs nativos sin pérdida en navegador. |
| **T06** | Migración DB vacía y upgrade v2, fallo parcial/checksum | Aplicación transaccional, checksum inválido rechazado y recuperación explícita. |
| **T07** | Migradores concurrentes y roles | Exclusión mutua; runtime no hace DDL ni escribe legacy. PostgreSQL real. |
| **T08** | Arranque/shutdown sin IA y wiring | Solo modos seleccionados; ningún componente legacy o dependencia IA implícita. |
| **T09** | Build limpio/contexto Docker/CI/offline assets | Artefacto desde fuentes, privados excluidos, dependencias locales; fallo de tests impide release. |
| **T10** | Commit observación/jobs/cursor, crash pre/post-commit pre-ACK | Sin ACK prematuro; replay tras commit no duplica ni pierde trabajo. |
| **T11** | Dos fuentes mismo texto, edición y normalización | Un blob reutilizable/dos observaciones, identidad de revisión y original conservados. |
| **T12** | Dos workers, lease expirado, finalización obsoleta | Un resultado vigente por JobKey; fencing bloquea escritor obsoleto. |
| **T13** | Caída worker/retry/quarantine/presupuesto | Recuperación al reiniciar; error operativo nunca genera etiqueta irrelevant o éxito ficticio. |
| **T14** | SSRF/DNS rebinding/redirects/cuerpo/Tor | Privadas/metadatos bloqueados en conexión/redirect; límites efectivos; Tor falla cerrado. |
| **T15** | Parsers, IPv6/defanged/wallet/UTF-8/documento largo | Valor validado, span exacto/unidad explícita y IOC al final detectado; no malicia inferida por formato. |
| **T16** | PIR, gate, ruido corto y mensaje sin IOC | Relevante no se pierde por longitud; reglas versionadas/reversibles y muestra de descartes. |
| **T17** | Expediente/revisión/materialidad/origen | Copias no suman corroboración; cambio y política explican novedad. |
| **T18** | Outbox atómica; crash tras envío antes de receipt | Una entrega lógica estable; efecto único solo si destino idempotente. Incierto visible si no. |
| **T19** | Auth, expiración/revocación, CSRF, QR/XSS y datos públicos | Privilegios efectivos y ningún contenido privado servido sin permiso. |
| **T20** | UI carga/vacío/error/stale y URL profunda | Ninguna caída se representa como cero amenazas; refresh/atrás/filtros/selección funcionan. |
| **T21** | E2E RSS→DB→caso→outbox→brief→UI | Artefacto compilado y PostgreSQL real completan recorrido sin IA/Internet externo. |
| **T22** | Update autorizado/excluido y lote mixto | Excluidos sin payload en inbox/observations; disposición mínima permite avanzar protocolo coherentemente. |
| **T23** | Frontera epoch/live/bootstrap/import legacy | Histórico no aparece como nuevo ni alerta; cursores separados, live no adelantado por backfill. |
| **T24** | Reconnect, diferencias, edición/eliminación/reenvío, gaps | Identidad peer+msg/revisión, recuperación idempotente y huecos conocidos visibles. |
| **T25** | Lease sesión, cierre RPC, takeover, FloodWait/revocación | Dueño antiguo realmente terminado antes del nuevo; espera persiste y permisos revocados pausan. |
| **T26** | Telegram real autorizado con reinicio controlado | Acceso/captura/progreso demostrados; registrar límites del historial y fuentes no recuperables. |
| **T27** | Claims/aliases/retractación y feedback circular | Homónimos no fusionados, hipótesis sustentadas/revisadas; derivados retractados no vuelven como evidencia. |
| **T28** | Feeds/snapshots y aplicabilidad CVE desconocida | EPSS/KEV con fecha/origen; versión desconocida no significa ni afectación ni seguridad. |
| **T29** | Enrichment/TTL/cuotas/privacidad/lifecycle/replay | Datos permitidos; caduca/revoca; retries no inflan sightings ni actualizan fecha de observación. |
| **T30** | Historias A/B/C integradas | Vuln contextual, oferta+copias+negativa y handle+hosting no generan confirmaciones falsas. |
| **T31** | Gateway 401/400/429/schema/truncamiento/alias/usage | Errores clasificados; campos desconocidos no inventados y fallback no autorizado bloqueado. |
| **T32** | Reservas concurrentes/reinicio/timeout facturable/cancel | Cap de exposición respeta reservas, ledger durable y consumo incierto conservado. |
| **T33** | Prompt injection, cita/entidad inexistentes, data class | Modelo sin poderes; output inválido no publica claims y datos prohibidos no salen. |
| **T34** | Chunking/cache/contexto/escalado/brief | Cobertura y spans válidos; cache no reutiliza juicio dependiente de fuente/fecha; cita sustenta predicado. |
| **T35** | Evaluación temporal/episodio/modelo/ruta/política | Corpus congelado, segmentos/intervalos/coste, errores adjudicados y privilegios solo demostrados. |
| **T36** | Cinco áreas, búsquedas/QueryPlan/dossier/grafo | Consulta tipada/parametrizada, límites efectivos y aristas con evidencia; sin SQL libre. |
| **T37** | Discovery/fuente caída/cobertura/PIR/TTL | Ningún privilegio nuevo implícito; propuestas limitadas/reversibles, pérdida de vigilancia visible. |
| **T38** | Atención/silencio/revalidación/exports | Visto no confirma; cambio elegible reabre; vencimiento sin respuesta no confirma; export respeta datos/permisos. |
| **T39** | Accesibilidad/demo aislada/usabilidad | Teclado/foco/zoom/móvil/contraste; demo funcional con backend privado bloqueado y cero requests a él. |
| **T40** | Retención/tombstone/purga/auditoría | No prometer texto verificable cuando expiró; revalidar derivados y conservar trazabilidad permitida. |
| **T41** | Restore v2/capacidad/carga/fallo/degradación | RPO/RTO, backlog/latencia/memoria/disco y atención medidos con carga representativa. |
| **T42** | Cutover y rollback candidato | Un dueño captura/entrega; inbox/cursores/ledger conservados; volver a release v2 compatible o pausar. |
| **T43** | Retirada legacy y documentación/config | Rutas peligrosas y composición vieja no invocables en runtime nuevo; histórico preservado; referencias coherentes. |
| **T44** | Adaptadores web HTML/paste/forum en fixtures | Identidad fallback versionada, paginación/auth/cursor y replay; HTML hostil, cambio de parser y límites sin pérdida silenciosa. |

## Suites UI propuestas

Ampliación core del 18-10-2026: T45–T48 de [17](17-configuracion-ia-por-funcion.md) verifican configuración IA por función, credenciales/SSRF, routing efectivo y panel integrado. T45–T47 se añaden a G6; T48 a G7. No hacen llamadas pagadas por defecto.

`private-evidence.spec`, `navigation.spec`, `degraded-states.spec`, `attention.spec`, `offline-assets.spec`, `demo-isolation.spec`. Ejecutar contra el producto compilado y PostgreSQL de aceptación. Las pruebas puntuales con API simulada complementan, no reemplazan, ese recorrido.

Bloquear conexiones a terceros manteniendo backend local accesible para demostrar recursos locales. Para demo, bloquear endpoints privados, contar solicitudes y exigir cero; que no aparezca un error visible no prueba aislamiento. Incluir evidencia editada, traducción identificada, original expirado y tres historias de `06`.

## Gates y recibos

| Gate | Evidencia mínima |
|---|---|
| **G0** | T00–T02 y parte export/inventario de T03–T04: snapshot/copia/dump/restore y manifest; privados protegidos. Importación v2 completa se verifica en G4, no bloquea construir P1. |
| **G1** | T05–T09: contratos, DB fresca/upgrade, roles, build limpio y CI bloqueante. |
| **G2** | T10–T14: invariantes PG real, crash/replay/concurrencia y red. |
| **G3** | T15–T21: recorrido RSS privado completo, auth y assets locales; restore/pausa mínimos ensayados. |
| **G4** | T03–T04/T22–T26: import/canales, sesión exclusiva y piloto real; gaps explícitos. |
| **G5** | T27–T30: dominio y tres historias, feeds/enrichment revocables. |
| **G6** | T31–T35 + G0/G4/G5: gateway/ledger/calidad y operación piloto integrada. |
| **G7** | T36–T39/T44: cinco áreas y autonomía/demos privadas/públicas, conectores existentes adaptados. |
| **G8** | T40–T43 y repetición de gates afectados sobre release: operación/restore/rollback, requisitos core completos. |

Cada recibo: ID, versión/commit, entorno e imagen/DB, fixtures/dataset/política, comandos exactos, resultados, artefactos saneados, limitaciones y aprobaciones de promoción necesarias. Estados `pendiente`, `implementado sin verificar`, `verificado`, `bloqueado`, `condicionado`. Skip o ausencia de entorno no cuentan como verificado.

## Calidad semántica y promoción de autonomía

Corpus adversarial pequeño desde P1/P3, selección orientativa 300–500 ejemplos humanos en P6 y ampliación según cobertura. Separación por tiempo y episodio/familia de copias; LLM juez no es gold. Medir extracción, relevancia, roles, claims, agrupación, novedades, alertas, resúmenes, coste y atención, por idioma/fuente/tarea.

Gate de descarte: recall puntual ≥98 % de accionables con intervalo y errores reportados. Alta prioridad inferida: límite inferior unilateral Clopper–Pearson al 95 % de precisión ≥95 %, con al menos 100 eventos independientes adjudicados y segmentos explicitados. Cien ejemplos, catorce días o coincidencia de modelos no prueban el objetivo por sí solos. Noticias/copias correlacionadas no son muestras independientes.

Avisos factuales deterministas tienen política separada. Segmentos no validados conservan estado provisional; no se bloquea captura ni brief. Cambio de modelo/ruta/prompt/política/esquema reabre evaluación afectada y exige replay/canary; no se adoptan aliases nuevos silenciosamente.

## Orden razonable de ejecución de checks

Por paquete: unitarios/contrato → integración de la responsabilidad → fault/security si toca ese límite → E2E del recorrido afectado. Release: suites obligatorias completas, build desde fuentes, restore y rollback en destino aislado. No repetir suites grandes sin cambios o nueva incertidumbre, ni añadir tests que solo reflejen triviales asignaciones de campos.

Captura real, recuperación privada y benchmark pagado son ejercicios operativos identificados, nunca consecuencias automáticas de ejecutar `make test`.
