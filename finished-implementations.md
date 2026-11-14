# Implementaciones terminadas de Noctis

Veinte propuestas aceptadas, implementadas en ramas independientes desde `dev` y fusionadas secuencialmente. Cada sección fue escrita por un agente Astra en `max` tras contrastar el código final y los recibos de su rama.

Integración de las veinte ramas: `e3a2080f424b6aac7cddd8ee5344caad514aa1ba`. Las verificaciones de cada sección corresponden a su integración. La validación conjunta de CI, imagen y despliegue sigue en curso.

La validación conjunta conserva además los estados completos de trabajo derivado en las pruebas de rollback y comprueba el lease original en recuperación SIGKILL. La PK nueva de transiciones usa UUID para mantener backups sin secuencias; backup y restauración sintéticos de las trece migraciones fueron verificados.

## 01- RSS/Atom caducado sin bloquear noticias nuevas

Rama `feat/avance-01`. Implementación: `16cdb28ae46566d2932a2dccace6c3bc8da9eeb0`. Integración: `d19b7bbc53d03bbb27fe8a07abd90013e8bcc7ca`. Ajuste posterior de regresiones: `034d71f194a0c6108227881513d60f7605a0c3c2`.

Un feed que repite una entrada caducada permite capturar noticias nuevas sin duplicarlas ni reactivar la evidencia antigua. También confirma feeds completamente caducados y admite nuevas revisiones del mismo identificador.

[Store.Poll](internal/capture/rss.go) valida el lote original antes de filtrarlo, conservando límites de entradas y bytes. Dentro de la transacción, tras bloquear la proyección y revalidar autorización, política y epoch, excluye únicamente coincidencias caducadas exactas de fuente, identificador, revisión, hash y representación. Las incompatibilidades siguen siendo errores. Conserva el checkpoint del feed completo, CAS y recibos incluso con un lote vacío. [CommitBatchTx](internal/capture/store.go) mantiene el rechazo de replay caducado para otros consumidores.

Las regresiones de [capture](internal/capture/rss_retention_test.go) y [runtimev2](internal/runtimev2/rss_retention_test.go) cubren rollback, límites, autorización, CAS, purga concurrente, revisiones, deduplicación y blobs compartidos. La evidencia caducada conserva tombstone y HTTP 410.

El ajuste posterior adapta exclusivamente el helper al trabajo de aplicabilidad creado por la migración 010: mantiene exactamente un trabajo `parse` y las demás invariantes, y compara snapshots completos de todas las filas/columnas de `jobs` y `applicability_requests` antes/después del sondeo fallido.

**Verificación:** código contrastado con `dev`. `integration-01-followup-race.jsonl` acredita focalizadas con `-race`, 13 migraciones y PostgreSQL16/HTTP(S) sintéticos: 8 pruebas principales y 11 subpruebas aprobadas, sin fallos ni omisiones.

**Límites:** CI global aún en curso; estas pruebas no acreditan despliegue ni fuentes productivas.


## 02- Recuperación de canales antes de confirmar el cursor global de Telegram

Rama: `feat/avance-02`. Implementación: `77f94909e8154a3f0ee16ed64a76108bddab73c3`. Integración: `992068c30924d957d51713fd1216bcd4cbbcd939`.

La sincronización global recupera ahora los canales señalados por `UpdateChannelTooLong` antes de confirmar cada página y avanzar su cursor. Deduplica los avisos por canal y página, evitando que una reconexión se considere completada mientras queda contenido pendiente de un canal sin nuevas actualizaciones. El comportamiento está presente en [rpc.go](internal/telegramv2/rpc.go#L311).

Si falla una recuperación, el cursor global permanece intacto y se conserva el progreso durable de los canales ya recuperados para el siguiente intento. La confirmación mantiene la autorización original de la respuesta global; continúan las comprobaciones de permisos, generación, ownership, presupuestos y `access_hash`. Los canales excluidos no generan RPC ni contenido. Los snapshots históricos productivos `UpdatesChannelDifferenceTooLong` siguen rechazándose y requieren intervención explícita.

La integración no necesitó resolver conflictos. Las regresiones quedaron en [difference_test.go](internal/telegramv2/difference_test.go), [production_test.go](internal/telegramv2/production_test.go) y [budget_test.go](internal/telegramv2/budget_test.go); el fixture final conserva múltiples canales y su compatibilidad con la rama 03.

Verificación registrada sobre la integración: `go test -race -json` focalizado con PostgreSQL16 sintético aprobó 17 pruebas principales y 23 subpruebas de Telegram, captura y runtime, sin fallos, omisiones ni carreras; incluye preservación RSS/Atom de 01. Recibo contrastado: `/tmp/noctis-avance-20261114/integration-02-focused.jsonl`. Cubre reintentos, fallos parciales, revocación, límites y autorización obsoleta. Esta evidencia no acredita Telegram real, reparación de discontinuidades productivas anteriores ni despliegue.


## 03- Transición auditada de generación Telegram

Rama `feat/avance-03`; implementación `900ed6b604f6f8fa1555ab77b73bdbdf12fc9081`; integración `5f53a6bab1ab73232f3698da337a5ed1e6077819`.

Los comandos `v2 telegram capture-generation-propose` y `capture-generation-transition` permiten revisar y aplicar el cambio de generación. La autenticación prepara B conservando el consentimiento A; la captura v1/v2 queda bloqueada hasta completar la transición y establecer el consentimiento B ([CLI](cmd/noctis/channels_v2.go), [admisión](internal/telegramv2/budget.go)).

La [transición](internal/telegramv2/generation.go) exige cierre confirmado, bloqueo de sesión, CAS sobre generación, consentimiento, revisión y fence, y ausencia de fallos pendientes. Revocación, cambio de generación y auditoría se confirman atómicamente. Repetir identificador y contenido es idempotente; reutilizarlo con contenido distinto falla. La [migración 008](migrations/v2/008_capture_generation_transition.sql) añade el registro inmutable y la marca pendiente. También admite reparar explícitamente cuenta B/consentimiento A.

El [sucesor](internal/telegramv2/production.go) exige transición exacta, inventario y autorización B. Conserva ancla, ventana y límites; espera hasta la siguiente frontera horaria original o cualquier cuota/FloodWait posterior, sacrificando cuota restante. La [reimportación](internal/runtimev2/operations_api.go) pausa la fuente, conserva epoch/cursor y requiere política explícita. El merge preservó las regresiones Difference de 02 y adaptó las fixtures piloto/productivas.

Verificación registrada en `integration-03-focused.jsonl`: 41 pruebas Go principales y 18 subpruebas con `-race`, sin fallos ni omisiones; PostgreSQL sintético. Los recibos de integración acreditan compilación, ayudas CLI, 41 pruebas Python y ocho checksums de migraciones.

Límites: presupuestos piloto v1 rechazados; sin migración de pilotos, reconocimiento de fallos, reparación de discontinuidades ni recuperación histórica. No se probó Telegram real ni se activó producción. La exclusión de sesiones copiadas entre hosts sigue siendo operativa.


## 04- Inferencia manual con activación explícita independiente

Rama `feat/avance-04`; implementación `36b7608be9c808a202f400de97cfad4b0427a9b4`; integración `315b835ac4b3d29ca141e0ac0d0f4d3562a02100`, sin conflictos.

El worker permite ejecutar solicitudes manuales mediante `--manual-inference`, sin activar la planificación automática. Ambos flags siguen desactivados por defecto: el worker realiza trabajo mecánico sin ejecutar ni planificar IA. Con automático desactivado y manual activado atiende solicitudes manuales elegibles, incluidas las anteriores al opt-in; con automático activado conserva la ejecución de ambas procedencias y la planificación, independientemente del flag manual. La API puede seguir encolando solicitudes con ambos desactivados. Implementado en [CLI](cmd/noctis/v2.go#L53) y [runtime](internal/runtimev2/runtime.go#L273).

[OnceManual](internal/inference/jobs.go#L228) excluye el actor reservado `system:semantic-planner` en trabajos en cola, reintentos y ejecuciones con lease vencido. Conserva `Store.Once`, presupuestos, pausa, cancelación, reservas y separación por actor de agrupación/caché. Los intentos abandonados de cualquier procedencia siguen reconciliándose como inciertos, reteniendo exposición sin autorizar un reenvío automático. El código final mantiene el rechazo explícito de administradores y sesiones con identidad reservada en [api.go](internal/runtimev2/api.go#L45).

La [guía operativa](deploy/v2/README.md#L53) documenta el gasto y backlog habilitados: los flags afectan únicamente a su worker y no cancelan solicitudes enviadas ni otros procesos.

Verificación de integración: el registro `integration-04-focused.jsonl` acredita `go test -race` focalizado sobre cuatro paquetes, con PostgreSQL y HTTPS sintéticos: 28 pruebas principales y 49 subpruebas aprobadas, cero fallos/omisiones; salida 0. Cubre las cuatro combinaciones y garantías anteriores. Esta evidencia no acredita inferencia con proveedores reales ni activación productiva.


## 05- Bloquear reintentos ante éxitos HTTP no admitidos

Rama `feat/avance-05`; implementación `85aab5dd26c6`; integración `e613a3fa229b`. Merge sin conflictos ni ajustes; sus cuatro archivos permanecen idénticos en el código final inspeccionado.

Chat y Responses solo aceptan HTTP 200. Tras completar la lectura limitada, cualquier 201–299 devuelve `response_status_invalid`, permanente e incierto, con `RetryAfter=0` y sin resultado ni uso aceptados. Un cuerpo aparentemente válido, `Location` o `Retry-After` no permiten publicar, sondear ni reenviar. El trabajador conserva la exposición máxima del intento, lo marca `uncertain` y deja el trabajo `dependency_blocked`, excluido de nuevos intentos automáticos. Un éxito HTTP no demuestra que el proveedor no haya ejecutado o facturado la solicitud.

Se conservan autorización previa, límites de cuerpo/tiempo, incertidumbre de lectura, bloqueo de redirecciones y clasificación de los demás estados; HTTP 429 mantiene su reintento permitido. Código y contrato: [transporte](internal/inference/transport.go#L188), [reconciliación](internal/inference/jobs.go#L465), [contrato](rebuild/08-contrato-zrelay.md#L40).

Verificación registrada en `integration-05-focused.jsonl`: selección focalizada con `go test -race`, 25 pruebas principales y 86 subpruebas aprobadas, sin omisiones ni carreras. La [matriz de transporte](internal/inference/transport_test.go#L18) cubre ambos adaptadores; la [regresión PostgreSQL/HTTPS sintética](internal/runtimev2/ai_test.go#L324) acredita que 202 conserva 67584 unidades de exposición, no publica y no se reenvía después de dos ciclos de otra instancia, incluso con plazo de reintento vencido. También se comprobó recuperación tras 429.

Estos recibos no acreditan proveedor real ni despliegue. Resolver una exposición incierta requiere intervención operativa; no se añadió soporte asíncrono ni corrección retroactiva del ledger.


## 06- Tarifa explícita antes de habilitar inferencia

Rama `feat/avance-06`; implementación `284e73a940ce225ce4173e5e4a54fa49dca35291`; integración `e94d818e40f082af3d51b04568a63d09293d0f5b`.

[El validador compartido](internal/inference/config.go#L170) impide habilitar bindings cuya `price.version` esté vacía, contenga solo espacios o equivalga a `unconfigured`, sin distinguir mayúsculas ni espacios exteriores. La comparación conserva exactamente la identidad persistida. Las tarifas explícitas pueden tener importes cero para rutas deliberadamente gratuitas; esto no verifica el precio remoto. Se mantienen los límites existentes de importes, longitud y presupuestos.

[Validación y guardado API](internal/runtimev2/ai_api.go#L55) reutilizan esta comprobación. `Save` rechaza antes de conectar a PostgreSQL o procesar credenciales, evitando nuevas revisiones y cambios de secretos o promociones. Los valores predeterminados deshabilitados siguen siendo válidos.

[La documentación operativa](deploy/v2/README.md#L106) exige revisar las tarifas heredadas: las configuraciones antiguas ya habilitadas **no se neutralizan automáticamente**. Siguen pudiendo leerse, deshabilitarse y guardarse con el marcador; posteriormente pueden habilitarse con una tarifa explícita. El merge no necesitó ajustes de código y conservó las restricciones de ejecución de ramas anteriores.

Verificación registrada en `integration-06-focused.jsonl`, sobre el commit de integración: `go test -race` focalizado en cuatro paquetes, con PostgreSQL y HTTPS sintéticos; **31 pruebas principales y 106 subpruebas PASS**, sin fallos, omisiones ni avisos de carrera. Incluye [límites y gratuidad](internal/inference/config_test.go) y [rechazos API sin efectos y recuperación heredada](internal/runtimev2/ai_price_test.go). Se contrastó su permanencia en el código final de `dev`. Este recibo no acredita proveedores reales ni despliegue.


## 07- Aplicabilidad vigente y retractación de afectaciones obsoletas

Rama `feat/avance-07`: implementación `4e0f3ee`; merge `dcd8629`; ajustes de integración `902d030` y `a86b089`.

[La migración 009](migrations/v2/009_applicability_current.sql) selecciona primero la revisión NVD por CVE y después comprueba caducidad, sin resucitar snapshots anteriores. Revisiones contradictorias o nuevas sin fecha fiable producen `unknown`. Retracta afectaciones por versión, evidencia, membresía o TTL y conserva el historial; `local_exposure` permanece `unknown`.

[La publicación](internal/vulnv2/applicability_projection.go) comprueba generación/revisión y evita duplicados. Cualquier afectación válida domina; excluir exige cobertura completa y no vacía. [API y briefs](internal/runtimev2/api.go) y [contexto IA](internal/inference/inputs.go) consultan soporte vigente incluso sin worker; nuevas revisiones conservan el agregado. Cola, paginación, leases y progreso pertenecen a rama08.

`902d030` consulta `select_current_nvd($1)` directamente y expone `c.cve` en la vista: [EXPLAIN](internal/runtimev2/applicability_plan_test.go) verificó resultados equivalentes y **1000→1 iteración** sobre 1000 CVEs.

`a86b089` cambia la PK de transiciones a UUID en 009, aún no desplegada al corregirse, preservando el backup sin secuencias. El ID no constituía contrato de ordenación/consumo; el contador del expediente permanece independiente. [La regresión](internal/runtimev2/applicability_schema_test.go) comprueba UUID distintos con LOGIN restringido.

El recibo `integration-07-schema-fix.md` registra **18 pruebas principales y 50 subpruebas con race aprobadas**, sin fallos, omisiones ni carreras. Backup cifrado y restauración reales sobre PostgreSQL16 sintético: **13 migraciones, 79 tablas, 19 filas y cero secuencias**; esquema, checksums, conteos, digests y consultas coinciden exactamente. No acredita CI global, proveedores reales, capacidad productiva ni despliegue.


## 08- Aplicabilidad mediante páginas durables y recuperables

Rama `feat/avance-08`; implementación `aa9c8c647286db89311002ab668db5329a3b6248`, integración `119a9c9431e14f96bdd5112d4966ef22e079c813`.

Guardar inventario o capturar snapshots NVD confirma la entrada, el cursor correspondiente y solicitudes idempotentes sin calcular toda la matriz. La [API](internal/runtimev2/domain_api.go) y la [interfaz](web/src/v2/product.jsx) muestran cálculo pendiente, completo o fallido, progreso y el job recuperable.

La [cola](internal/vulnv2/applicability_queue.go) recorre claves estables con cotas fijadas tras confirmar la entrada: hasta 25 parejas o expedientes por página, con un job independiente para cada continuación. Resultados, progreso y siguiente página se confirman atómicamente mediante `FinishTx`, protegido por lease/fence. Respeta la pausa global y funciona sin inferencia. El límite corresponde a unidades procesadas, no a escrituras físicas.

La [migración 010](migrations/v2/010_applicability_queue.sql) añade solicitudes, índices y disparadores de evidencia/membresía. Los padres esperan a sus hijos; un hijo fallido expone su ID para `noctis v2 replay JOB_ID`. La caducidad admite siete días de espera sin crear el job hasta el vencimiento, preservando el horizonte de reintentos de 13. La selección y vigencia siguen perteneciendo a 07; `Claim` variádico ya existía. El merge solo requirió conciliar checksums.

Verificación: código final contrastado; recibo de integración con PostgreSQL sintético y `-race`: 50 pruebas principales y 127 subpruebas aprobadas, ninguna omitida ni carrera detectada. Incluye 999/1000/1001 entradas, concurrencia, lease vencido, replay, TTL y 77 expedientes; además, 17 pruebas operativas y diez checksums correctos. Estas mediciones no acreditan capacidad productiva ni duración del CI global.


## 09- Sustitución atómica de la pregunta gobernante

Rama `feat/avance-09`. Implementación: `79288bdf15f3fede15fcfc87606d1e2c473f38ac`; integración: `1c4362f3c3f98f5781a9068ef887ad5309a16fa2`.

Cada fuente admite cero preguntas gobernantes con política independiente, o una pregunta vigente. [La resolución y sustitución](internal/runtimev2/source_governance.go) y [el handler](internal/runtimev2/operations_api.go) actualizan política y asociación en la misma transacción, con bloqueo de proyección, CAS e idempotencia. El servidor rechaza identidades incompatibles y revisiones obsoletas. Omitir la política conserva la asignación; elegir una independiente elimina la asociación.

Tras A→B, editar o pausar A deja de afectar a la fuente; permanecen la pausa propia y las barreras contra publicación con políticas antiguas. Discovery mantiene su procedencia y revocación independiente, y activa con la revisión vigente. Reasignar una fuente ya activada no renueva su consentimiento Telegram.

La [migración 011](migrations/v2/011_source_governance.sql) impone unicidad por fuente y conserva los metadatos de la relación canónica. Aborta transaccionalmente, identificando las fuentes afectadas, ante ambigüedad, incoherencia o si retirar una pausa antigua ampliaría la autorización, incluso latente. Conserva políticas y referencias históricas; los rechazos requieren [conciliación explícita](docs/source-governance.md), sin activación automática. La integración regeneró el fixture de checksums sin modificar SQL anterior.

Verificación: contrastado el código final de `dev`; el recibo `integration-09-focused.jsonl` registra 19 pruebas principales y 12 subpruebas aprobadas con `-race`, PostgreSQL16/HTTPS sintéticos, sin fallos ni omisiones. El recibo de integración acredita once checksums y diff limpios. No se ejecutó conciliación ni migración de datos productivos; estas pruebas no acreditan Telegram real ni despliegue.


## 10- Admisión de autenticación antes de PostgreSQL

Rama `feat/avance-10`; implementación `2718c935`, integración `87945496`.

La API rechaza localmente cookies ausentes o distintas de 64 hexadecimales minúsculos (`401`), JSON inválido y credenciales incorrectas, evitando conexiones innecesarias. Método y Origin mantienen precedencia. El login admite diez intentos iniciales y repone uno cada seis segundos por instancia; todos consumen presupuesto, incluidos éxitos. El agotamiento devuelve `429` con `Retry-After`. Solo acepta un objeto JSON de hasta 4096 bytes, sin campos desconocidos ni contenido adicional, y compara hashes de credenciales en tiempo constante ([admisión](internal/runtimev2/api_admission.go#L19)).

La fase DB admite como máximo dieciséis solicitudes simultáneas, sin cola: la saturación devuelve `503`. El permiso abarca el handler y el cierre de su conexión, con contexto independiente y plazo de dos segundos. Se conservan expiración de ocho horas, hash persistido, cookies seguras, CSRF, revocación e identidad reservada ([API](internal/runtimev2/api.go#L86)). La integración adaptó también fixtures de tarifas, aplicabilidad y cola al token y constructor actuales.

Verificación registrada: `go test -race` focalizado sobre `internal/runtimev2`, con PostgreSQL 16 sintético: **33 pruebas principales y 34 subpruebas PASS**, sin omisiones ni avisos de carrera; incluye admisión, cancelación y regresiones de autenticación. Once checksums de migraciones y `git diff --check` correctos (`integration-10-focused.jsonl`, `integration-10-final-checks.json`).

El límite mide solicitudes, no conexiones ni sockets globales. No cubre sondas, workers o collectors. Reinicios y réplicas alteran el presupuesto; ataques sostenidos pueden agotar admisión. Los umbrales requieren carga representativa ([límites operativos](deploy/v2/README.md#L77)).


## 11- Validación temprana de TLS y origen canónico

Rama `feat/avance-11`; implementación `2534115`, integración `edca0ce`.

La API rechaza configuraciones HTTP inválidas antes de consultar PostgreSQL o abrir puertos. [http_config.go](internal/runtimev2/http_config.go) exige certificado y clave juntos, carga el par una vez y rechaza archivos ilegibles, inválidos o incompatibles. [Run](internal/runtimev2/runtime.go) entrega ese material precargado a `ServeTLS`, sin releer archivos ni degradar silenciosamente a HTTP.

El origen debe ser HTTP(S) canónico, con DNS ASCII/punycode o IP válida, sin credenciales, ruta, query, fragmento ni espacios; rechaza mayúsculas, puertos predeterminados y otras representaciones que difieren del navegador. [NewHandler](internal/runtimev2/api.go) comparte la validación y mantiene la comparación exacta de peticiones.

Omitir ambos archivos permite HTTP interno detrás de un proxy HTTPS. El origen público y las cabeceras reenviadas no seleccionan el transporte. Se conservan cookies `Secure`/`HttpOnly`/`SameSite=Strict` y CSRF. Worker, collector y [migrate](cmd/noctis/v2.go) no adquieren requisitos HTTP.

Verificación registrada: integración 11, 30 pruebas principales y 97 subpruebas con `-race`, sin fallos ni omisiones; incluye matrices TLS/origen, HTTPS efectivo, proxy autenticado y migración sin configuración HTTP. La integración 12 ajustó [la prueba TLS](internal/runtimev2/http_config_test.go) para observar el bloqueo exacto mediante `pg_locks`, borrar certificado/clave antes de desbloquear y comprobar HTTPS y cierre. Su recibo final (`48b5231`) confirma PASS con `-race`; el código final conserva esa prueba.

Pruebas sintéticas: no acreditan despliegue. Confianza pública, SAN y vigencia del certificado siguen requiriendo comprobación operativa.


## 12- Readiness basada en esquema efectivo y permisos del runtime

Rama `feat/avance-12`: implementación `16a0cb8`, merge `fb8b674` e integración corregida `48b5231`.

[`Check`](internal/runtimev2/runtime.go) valida conexión, nombres/checksums exactos de migraciones, estructura y permisos efectivos en un plazo de tres segundos. `schema` se activa después del ledger y la estructura; `functional`, `ai_enabled` y capacidades por modo, únicamente tras completar también la lectura de configuración IA. `/readyz` y `/healthz` devuelven 503 ante fallos coherentes con esos indicadores. Una base recién migrada funciona sin fuentes ni IA configurada; `/livez` permanece independiente de PostgreSQL.

El [contrato operativo](internal/runtimev2/readiness_contract.go) comprueba privilegios heredados, `USAGE`, lectura del ledger y `EXECUTE` de funciones por modo; exige `INSERT` de sesiones solo a API. Usa consultas agrupadas y una transacción de solo lectura, sin conceder permisos ni ejecutar escrituras de ensayo.

El [manifiesto final](internal/runtimev2/schema_contract.json) contiene **826 entradas**: 72 relaciones, 539 columnas, 187 restricciones, 10 triggers, 15 funciones y tres vistas. Incluye definiciones y estado efectivo; excluye índices de rendimiento. Los ajustes de integración incorporaron dependencias previas y cuatro entradas de reintentos de la rama 13. La integración 18 contrastó las trece migraciones y conservó el manifiesto: el historial reutiliza permisos existentes.

Verificación registrada en PostgreSQL16 sintético: `integration-18-go-final.jsonl` contiene cuatro pruebas de readiness y 32 subpruebas PASS, sin omisiones, sobre contrato, roles directos/heredados, derivas HTTP y operaciones restringidas. El recibo final de integración 12 acredita además tres pruebas PASS con `-race`, incluida TLS.

La sonda comprueba disponibilidad puntual; no certifica mínimo privilegio ni comportamiento productivo futuro.


## 13- Conservar el horizonte de reintentos durante pausas

Rama `feat/avance-13`. Implementación `65aaf4673cc3`; integración `deac958b2994`.

Los trabajos `parse` en `queued` o `retry_wait` conservan el tiempo pendiente de su horizonte de 24 horas durante una pausa de fuente. [Pausa y reanudación](internal/runtimev2/source_resume.go#L13) registran el aparcado durable y desplazan el vencimiento por ese intervalo una sola vez, sin renovar el presupuesto ni adelantar un backoff pendiente. La congelación no descuenta ejecución previa, pausa global ni indisponibilidad del worker.

El [ciclo de jobs](internal/jobs/store.go#L26) aplica el reloj en Claim, Fail, FinishTx, recuperación de leases y Replay. Mantiene cinco intentos, fallos permanentes, fences y exclusiones por autorización o evidencia obsoleta. Finish devuelve el intento interrumpido antes de publicar; los fallos reales y leases vencidos conservan su consumo. Los barridos usan `SKIP LOCKED`. Se preserva el Claim variádico preexistente y su aislamiento por stage.

La [migración 012](migrations/v2/012_job_retry_pause.sql) deriva el vencimiento de `created_at`, congela únicamente saldo antiguo demostrable y bloquea casos vencidos ambiguos con `retry_horizon_unknown`. Solo el replay explícito reinicia reloj e intentos. La integración añadió al [contrato de readiness](internal/runtimev2/schema_contract.json) ambas columnas, función y trigger, con cuatro regresiones de deriva.

Verificación registrada en `integration-13-focused.jsonl` y `integration-13-final.jsonl`: PostgreSQL16 sintético, race, 34 pruebas y 54 subpruebas, después tres pruebas finales; cero fallos u omisiones. También quedaron verificados doce checksums de migraciones. Contraste estático realizado contra `dev` final.

Antes de producción, el [runbook](ops/rebuild/operations/source-retry-horizon.md) exige conteos previos y evaluación individual del backlog ambiguo; estos recibos no acreditan despliegue productivo.


## 14- Validación del destino antes de consumir una entrega del outbox

Rama `feat/avance-14`; implementación `268509786433cb185a7f4c1805c89240dea2c8dc`; integración `1b7ef3aab52ac0925957758f689f27c72d1aefee`.

Una configuración de destino sintácticamente inválida ya no inmoviliza entregas. El [validador compartido](internal/intelligence/delivery.go#L23) exige URL absoluta HTTP/HTTPS, host válido, puerto dentro de 1–65535 cuando se indica y escapes correctos; conserva IPv6, rutas y query válidos. Dispatcher, [worker](internal/runtimev2/runtime.go#L116) y [CLI](cmd/noctis/v2.go#L189) lo ejecutan antes de conectar a PostgreSQL. El destino vacío sigue deshabilitando entregas en el worker y se rechaza al invocar directamente el dispatcher.

El dispatcher prepara petición, cuerpo y cabeceras antes de confirmar `uncertain`; un error local conserva `queued`. El envío ocurre después del commit. Permanecen la revalidación de evidencias, el bloqueo de sesión hasta cerrar la respuesta y registrar el ACK, y la prohibición de reenvío automático de estados inciertos. La integración preservó el preflight API/TLS y ambas pruebas CLI anteriores y nuevas.

Según los recibos `integration-14-test-command.json`, `integration-14-focused.jsonl` e `integration-14-summary.json` en `/tmp/noctis-avance-20261114/`, las pruebas focalizadas con PostgreSQL16 sintético y `-race` aprobaron 23 casos principales y 70 subpruebas, sin fallos, omisiones ni carreras. Cubrieron veinte llamadas con destinos inválidos sin cambios ni solicitudes, recuperación con identidad original, preparación fallida, transporte incierto, ACK perdido, SIGKILL y revocación. El recibo de migraciones confirma doce checksums intactos.

Código contrastado con `dev`; sin pruebas nuevas durante esta documentación. DNS, TLS y conectividad siguen pudiendo producir incertidumbre tras la admisión. La evidencia sintética no acredita entregas reales ni despliegue; no quedan pendientes propios.


## 15- Paginación sin solicitudes duplicadas ni respuestas obsoletas

Rama `feat/avance-15`; implementación `580d475`; integración `5760c5c`, sin conflictos ni correcciones posteriores propias.

[Paged](web/src/v2/Operations.jsx#L5) asigna una generación a cada carga y la invalida y cancela al cambiar de recurso o desmontarse. Comprueba su vigencia antes de aplicar filas, metadatos, errores o estados de carga: volver de A→B→A no permite recuperar respuestas antiguas.

Cada continuación adquiere un bloqueo inmediato y captura su cursor. Las activaciones rápidas no duplican solicitudes; una respuesta obsoleta tampoco libera una continuación nueva. Un fallo vigente conserva filas y cursor para reintentar; el éxito limpia el error. «Load more records» queda deshabilitado durante la petición y comunica la carga mediante `aria-busy` y un estado accesible. Se mantienen firma, orden y formato de resultados.

Las [19 regresiones de paginación](web/tests/v2-paged.spec.js) cubren concurrencia, cursor codificado, reintentos, éxitos y errores tardíos, desmontaje y remontaje. El transporte sintético ignora deliberadamente la cancelación para comprobar las guardas. La [configuración final](web/playwright.v2.config.js) conserva esta suite junto con las incorporadas después; `Paged` y sus pruebas permanecen idénticos a la implementación revisada.

Verificación registrada en `integration-15-playwright.json`: **19 pruebas de paginación + 11 de producto aprobadas**, sin omisiones, fallos ni reintentos. El build combinado de esa integración terminó correctamente, con aviso de chunks superiores a 500 kB. Son pruebas con respuestas sintéticas; queda pendiente la validación E2E del conjunto final, incluida la paginación real 50→51. Esta rama no acredita despliegue.


## 16- Recuperar conflictos operativos conservando la edición

Rama `feat/avance-16`. Implementación: `f10af286d7d43cbcea57d91873b664b0fae7ae75`; integración: `99809cfa75ef564268882657a2cd8b38ba637716`.

Los editores de fuente, control global y retención separan borrador/intención, estado confirmado y conflicto en [Operations.jsx](web/src/v2/Operations.jsx#L57). Recargar conserva la edición y solo lee; nunca reenvía automáticamente una escritura. Únicamente `stale_revision` activa la recuperación CAS, preservando las causas de otros conflictos. Pausar/reanudar mantiene la intención original y reconoce cuando ya está satisfecha. Las fuentes utilizan la revisión devuelta por el servidor, actualizan su fila sin borrar otros borradores y distinguen un guardado confirmado de un refresco fallido.

[La API](internal/runtimev2/operations_api.go#L118) incorpora lectura autenticada de retención con permiso específico, parámetros validados y transacción de solo lectura. Distingue política ausente —revisión 0—, fuente inexistente y errores. Retención invalida vista previa y UUID al cambiar revisión o contexto; descarta respuestas tardías incluso A→B→A y bloquea envíos simultáneos. La integración conserva gobernanza, cercas de Telegram y paginación existentes.

**Verificación registrada:** recibos `integration-16-*`: build correcto; 11 pruebas Go y 6 subpruebas con PostgreSQL sintético; 37/37 Playwright simuladas —7 conflictos, 19 paginación, 11 producto—, sin fallos ni omisiones. Cubren CAS, permisos, lecturas sin efectos, borradores y exclusión de escrituras duplicadas; las purgas usan exclusivamente fixtures sintéticas.

**Pendiente global:** ejecutar el [escenario de dos sesiones reales](web/tests/v2-operations-real.spec.js#L68) mediante el harness HTTPS+PostgreSQL `--product`. Su presencia en el código no acredita ejecución; no se afirma despliegue.


## 17- Ejecución fiel del plan de consulta revisado

Rama `feat/avance-17`. Implementación: `c2e94e839dee264dfc798377f1109c931086ad89`; integración: `30ab68a12984158b0939fa1101b788e62bbb9c9f`.

[TypedQuery](web/src/v2/Consumers.jsx#L17) ejecuta el plan revisado conservando texto literal, entidad, modo, filtros, límite y cursor. La [conversión URL](web/src/v2/typed-query.js#L14) restaura esos valores al recargar y recorrer el historial. `run_query=1` distingue una consulta vacía explícita de Explore sin iniciar; las URLs antiguas conservan el límite implícito 50. El formulario muestra el límite efectivo. Aceptar un plan conserva su cursor; enviar criterios lo elimina; «Next page» modifica únicamente el cursor.

Los límites explícitos inválidos y contratos incompatibles producen errores visibles, sin correcciones silenciosas. La API mantiene la validación de identificadores y cursor. El texto vacío o blanco permite búsqueda, pero no ofrece planificación IA. Endpoints y contrato Go se conservan.

El conflicto de integración en [Playwright](web/playwright.v2.config.js#L3) se resolvió acumulando las suites anteriores y TypedQuery. Los recibos de integración registran build correcto y **49/49 pruebas UI**: 12 TypedQuery, 19 paginación, 7 conflictos y 11 producto; sin omisiones, reintentos ni casos inestables. Cinco pruebas Go y 24 subpruebas pasaron con PostgreSQL/HTTPS sintéticos, incluyendo [páginas 7/3, persistencia idéntica y entradas inválidas](internal/runtimev2/typed_query_test.go#L14).

El timeout histórico no se reprodujo, ni aislado ni en la suite combinada; su causa sigue sin probarse. Persiste el aviso de bundle superior a 500 kB. Los resultados pueden cambiar con el archivo consultado. Esta evidencia no acredita inferencia real ni despliegue.


## 18- Recuperación y cancelación de trabajos IA

Rama `feat/avance-18`; implementación `ce349f6a897b386ed2b068ecaf8d5e6acf52219a`; integración `32240c86f29b8599f8558ba1633bf816af44d7bb`.

Sistema incorpora un historial de trabajos propios, compartido entre sesiones del mismo actor. La selección mediante URL permite navegar, recargar y recuperar un trabajo persistido incluso cuando se perdió la respuesta inicial, sin reenviar la inferencia ni ejecutar sus planes. [AIJobs.jsx](web/src/v2/AIJobs.jsx) detiene el sondeo en estados terminales e invalida respuestas pendientes al cambiar selección o sesión; no guarda resultados en almacenamiento del navegador.

[ListJobs](internal/inference/history.go) devuelve únicamente ID, función, fecha y estado durable. Filtra por el actor autenticado, valida cursores propios y pagina por `(created_at,id)` descendente, con límite predeterminado 50 y rango 1–100. La [API](internal/runtimev2/ai_api.go) rechaza parámetros ajenos o duplicados y conserva `no-store`. Abrir el detalle revalida la evidencia mediante `Store.Job`; un éxito histórico puede quedar bloqueado. Cancelar conserva `Store.Cancel`, su protección contra publicaciones posteriores y la contabilidad: una llamada ya enviada puede continuar y generar coste.

La [migración 013](migrations/v2/013_ai_job_history.sql) añade el índice por actor y fecha. La integración regeneró el fixture de migraciones, adaptó fixtures al nuevo GET y al constructor `newAPI`, preservando consultas, fuentes y permisos anteriores.

Verificación registrada en `integration-18`: build correcto, 56/56 pruebas UI y 15 pruebas Go principales más 48 subpruebas, sin omisiones. Incluyen aislamiento, paginación, recuperación, cancelación y evidencia caducada/revocada. UI interceptada; motor con PostgreSQL16 y gateway HTTPS falso: una invocación, sin resultado tras cancelar y coste conservado. No acredita inferencia real ni despliegue.


## 19- Publicar la configuración restaurada solo después de validarla

Rama `feat/avance-19`; implementación `ca6fc6b8d2fd5b5f613bf443f86068072e6f23a9`; integración `c40d647a21d839fa33792bd2e8693f3804b02e86`, sin ajustes de integración.

`restore-config` prepara un directorio privado `.incomplete` antes de descifrar. Valida archivos, manifest y comprobaciones correspondientes al formato, y escribe `restore-receipt.json` con cobertura y resultados sin valores secretos. Solo entonces publica todo mediante `renameat2(RENAME_NOREPLACE)`: el destino final aparece completo, los destinos existentes —incluidos los creados concurrentemente— se conservan y los intentos fallidos quedan identificados para diagnóstico privado. Los directorios mantienen permisos 0700 y los archivos 0600.

La implementación está en [backup.py](ops/rebuild/operations/backup.py#L155), con regresiones en [test_restore_config.py](ops/rebuild/operations/test_restore_config.py) y procedimiento en [README.md](ops/rebuild/operations/README.md#L174). Conserva bytes y alcance de v1–v4: v1/v2 mantienen el DSN compartido histórico; v3 no exige política de captura; v4 verifica mappings y hashes.

La integración registró **25 pruebas Python correctas, sin omisiones**, incluyendo entradas inválidas, concurrencia, destinos existentes e interrupciones SIGKILL antes/después de publicar. El ensayo CLI con **age v1.2.1 real e identidad sintética nueva** restauró v1–v4 preservando bytes y permisos, rechazó repeticiones y cifrado corrupto, y comprobó stdout/recibo sin secretos fixture (`integration-19-unittest.log` e `integration-19-age-receipt.json`).

Requiere Linux, libc, kernel y filesystem compatibles; sin esa primitiva falla explícitamente. Garantiza visibilidad atómica ante interrupciones del proceso, no durabilidad ante pérdida eléctrica. El recibo no autoriza servicios ni captura: cada recuperación requiere validación semántica y binding Telegram; los DSN conservan su destino original. No se usaron servicios externos ni secretos reales.


## 20- Exigir E2E del binario AMD64 de imagen antes de publicar

Rama `feat/avance-20`; implementación `68be97a0bffcd24073bf6575a54c114352a427bb`, integración `e3a2080f424b6aac7cddd8ee5344caad514aa1ba`. Fusión limpia; conservadas las pruebas de restauración y garantías operativas anteriores.

El [gate de imagen](ops/rebuild/operations/image_checks.py) ejecuta el harness con navegador, producto e IA sintética sobre `/noctis` extraído de la imagen AMD64 candidata. Exige éxito y un recibo nuevo y completo; enlaza commit, versión, IDs de ambas imágenes y SHA256 de archivos, ejecutables y recibo del harness. Contrasta commit/versión con valores esperados independientes y comprueba que los artefactos no cambien durante el E2E.

Antes del primer `docker push`, valida ambos archivos, carga sus imágenes y vuelve a extraer y contrastar los ejecutables. La promoción reutiliza los archivos probados sin reconstruirlos y conserva la comprobación de digests y manifests remotos. [CI](.github/workflows/build.yaml) mantiene eventos y jobs existentes, ejecuta una sola vez el E2E canónico sobre el candidato y transporta sus recibos; [Makefile](Makefile) incorpora `image-check`/`image-verify` y conserva `make ci`.

Verificación registrada en `integration-20-verification.json` y logs asociados: **63 pruebas Python aprobadas, sin omisiones**, incluidas 16 del gate con Docker/harness simulados; actionlint 1.7.7 sin diagnósticos, 13 checksums de migraciones correctos y simulaciones `make -n` satisfactorias. Se inspeccionó el código integrado en `dev`; no se repitieron pruebas para esta documentación.

Pendientes del principal: imágenes reales, E2E completo del candidato final, `image-verify` y CI global. Esta evidencia no acredita publicación, despliegue ni ejecución ARM64; aquí ARM64 conserva validación ELF/manifests.
