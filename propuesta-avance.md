# Propuestas de avance de Noctis

Base: `9374936`, rama `dev`. Primera ronda: 20 agentes Astra en ultra. Estado: pendientes de revisión crítica independiente.

## 1- Evitar que una entrada RSS caducada bloquee noticias nuevas

**Propuesta.** Filtrar en `Store.Poll`, dentro de su transacción y antes de `CommitBatchTx`, las entradas RSS/Atom cuya identidad y contenido coincidan exactamente con una observación ya caducada. Conservar el tombstone y procesar las novedades del mismo feed.

**Evidencia vigente.**

- `docs/review-2026-11-13.md:80` identifica este bloqueo.
- `internal/capture/rss.go:126` analiza el feed completo y `rss.go:146` envía todas sus entradas al almacén.
- `internal/capture/store.go:90` consulta si una identidad está caducada; `store.go:94` devuelve un error que aborta el lote antes de actualizar checkpoint y recibo (`store.go:144–155`). Una entrada antigua que siga publicada impide capturar las noticias nuevas.
- La caducidad preserva referencias y elimina los bytes cuando ninguna observación vigente los necesita (`internal/runtimev2/retention.go:90–103`).
- El rechazo del replay directo está protegido expresamente en `internal/runtimev2/core005_regression_test.go:646–648`. Por ello, conviene conservar el contrato estricto de `CommitBatchTx` y resolver la repetición normal del feed en su adaptador.

**Alcance.** Cambiar `internal/capture/rss.go` y ampliar sus pruebas PostgreSQL. Consultar las identidades caducadas del lote de forma agrupada, usando `source_id`, `native_id` y `revision`; excluir únicamente coincidencias de `hash` y `representation`. Una identidad repetida con contenido incompatible debe seguir fallando. Mantener la comprobación de autorización, el bloqueo transaccional y el CAS existentes (`rss.go:136–146`). Sin migraciones ni cambios en otros adaptadores.

**Aceptación.**

1. Tras caducar A, un feed que contenga A y una noticia B confirma el lote, avanza el checkpoint y crea exactamente una observación y un job para B.
2. A conserva `retention_expired_at`, tombstone y bytes eliminados; no recibe jobs nuevos ni se reactiva.
3. Un feed compuesto solo por entradas caducadas termina correctamente y registra la captura sin reconstruir contenido.
4. Repetir el feed no duplica observaciones/jobs; un conflicto real de identidad o checkpoint conserva el rollback completo.
5. El replay directo rechazado por la regresión de retención mantiene su comportamiento.

**Verificación prevista.** Añadir pruebas de integración del sondeo con un servidor HTTP sintético para feed mixto, totalmente caducado y repetido; comprobar persistencia, checkpoint, jobs y contenido. Ejecutar `go test ./internal/capture ./internal/runtimev2` con PostgreSQL sintético configurado y verificar que las regresiones pertinentes no se omitan.

**Estado y riesgo.** Inspección realizada; no se implementó ni se ejecutaron pruebas. El riesgo principal es filtrar fuera de la transacción y competir con la caducidad: el filtrado debe compartir el bloqueo vigente. La elección del límite adaptador/almacén merece validación de Astra antes de implementar por su efecto sobre compatibilidad.


## 2- Recuperar los canales señalados antes de confirmar el cursor global de Telegram

**Prioridad alta.** Corregir la ruta `Difference` para que un aviso `UpdateChannelTooLong` provoque la recuperación del canal autorizado antes de confirmar la página global. Evita que una reconexión parezca completada mientras quedan mensajes pendientes de un canal que después permanece silencioso.

**Evidencia vigente (`dev`, `9374936`).** El hallazgo de `docs/review-2026-11-13.md` sigue presente:

- `internal/telegramv2/rpc.go:115` transforma `UpdateChannelTooLong` en un evento `protocol_disposition`.
- `Handle` recupera expresamente ese canal mediante `channelDifferenceByID` antes de confirmar sus eventos (`rpc.go:217`).
- `difference` convierte los mismos avisos, confirma directamente `Next` y puede terminar con éxito sin recuperar el canal (`rpc.go:304–324`).
- El marcador no lleva `PtsCount`; su persistencia como `protocol_only` no recupera ni avanza por sí sola el cursor del canal (`store.go:406`, `store.go:486`). El arranque y el sondeo periódico utilizan precisamente `Difference` (`client.go:324`, `client.go:340`).

**Cambio propuesto.** En cada página de `difference`, identificar los canales señalados y llamar una vez por canal a `channelDifferenceByID` antes de `CommitUpdates`. Reutilizar sus comprobaciones actuales de autorización, generación, `access_hash`, presupuesto y cursor durable (`rpc.go:339–370`). Propagar cualquier error y conservar sin confirmar el cursor global de esa página. Mantener el rechazo productivo de `UpdatesChannelDifferenceTooLong`, que exige intervención explícita (`rpc.go:390–396`).

El alcance comprende `rpc.go` y regresiones del coordinador con PostgreSQL y RPC sintético. No requiere migraciones ni cambios de sesión, consentimiento, política histórica o despliegue. Tampoco resuelve automáticamente una discontinuidad productiva ya declarada.

**Criterios de aceptación y pruebas propuestas.**

1. Una diferencia final y una `UpdatesDifferenceSlice` que incluyan el aviso recuperan todas las páginas del canal. Sin recibir actualizaciones posteriores, quedan persistidos los mensajes recuperados y los cursores global y de canal esperados.
2. Avisos repetidos del mismo canal dentro de una página generan una sola recuperación. Un canal excluido no provoca RPC de canal ni materialización de contenido.
3. Si la recuperación falla por RPC, cancelación o presupuesto, la página global no avanza. Una ejecución posterior parte de los cursores durables y no duplica observaciones.
4. Si un canal ya avanzó y falla otro de la misma página, se conserva aquel progreso; la repetición completa la recuperación sin exigir una transacción que abarque llamadas de red.
5. La respuesta productiva `UpdatesChannelDifferenceTooLong` mantiene el error y no incorpora el snapshot histórico ni confirma la página global. Ampliar la regresión existente de `production_test.go:69`, que hoy llama directamente a `ChannelDifference`.

**Verificación prevista:** pruebas focalizadas con `NOCTIS_V2_TEST_DATABASE_URL`, comprobando ejecución efectiva sin omisiones, y suite canónica requerida antes de integrar. Este informe procede de inspección de código; no se modificaron archivos ni se ejecutaron pruebas.


## 3- Permitir la sustitución de sesión mediante una transición de consentimiento auditada

**Problema y evidencia.** Al autenticar con otra clave, [`client.go:291`](internal/telegramv2/client.go#L291) actualiza `auth_generation` y conserva `active_capture_consent`. La instalación posterior exige que el nuevo consentimiento use la generación vigente y tenga al consentimiento activo como predecesor; después rechaza que el predecesor pertenezca a otra generación ([`production.go:136`](internal/telegramv2/production.go#L136), [`production.go:152`](internal/telegramv2/production.go#L152)). En esas condiciones, proponer otro consentimiento no permite recuperar la captura. El bloqueo coincide con [`docs/review-2026-11-13.md:44`](docs/review-2026-11-13.md#L44).

**Mejora propuesta.** Introducir una transición explícita de generación que cierre el consentimiento anterior y permita instalar uno nuevo mediante una autorización revisable. La renovación ordinaria debe seguir rechazando cambios de generación. La transición registraría cuenta, generaciones anterior/nueva, consentimiento previo, actor, motivo y fecha, conservando versiones y consumo históricos.

La actualización debe ejecutarse transaccionalmente, con exclusión de sesión, cierre efectivo del transporte y comprobación de generación/fence esperados. Tras cambiar de generación, la captura seguirá bloqueada hasta disponer de inventario y autorización de fuentes de esa generación y de un consentimiento instalado explícitamente. No se deberá considerar una sesión autenticada como autorización de captura.

**Alcance.** `internal/telegramv2/client.go`, `production.go`, comando v2 correspondiente, nueva migración de auditoría, pruebas focalizadas y contrato operativo. Mantener fuera la recuperación de diferencias y la reparación de cursores. Resolver expresamente la compatibilidad con presupuestos piloto: el trigger de [`006_native_capture_budget.sql:33`](migrations/v2/006_native_capture_budget.sql#L33) impide cambiar la generación de una cuenta con presupuesto v1 vinculado; no debe esquivarse eliminando sus registros.

**Aceptación y pruebas previstas.**

- Prueba PostgreSQL que reproduzca consentimiento de generación A → autenticación B → transición explícita → instalación de consentimiento B, sin modificaciones SQL manuales de recuperación.
- Antes de instalar B, las políticas y propietarios de A no pueden admitir llamadas ni escrituras de captura.
- La operación exige cierre confirmado; caducar el lease no basta. Dos solicitudes concurrentes producen una sola transición y repetir la misma operación es idempotente.
- Generación o revisión obsoleta, inventario antiguo y fallo transaccional dejan el estado cerrado y coherente, sin transición parcial.
- Se conservan auditoría, políticas y consumo anteriores. Definir y comprobar continuidad del presupuesto durante el periodo vigente para que rotar sesión no permita recuperar cuota gastada.
- La renovación dentro de la misma generación mantiene sus garantías actuales; el caso con presupuesto piloto obtiene una transición soportada o un rechazo explícito previo a modificar la cuenta.

**Validación y decisión pendiente.** Inspección estática del commit `9374936`; no se ejecutaron pruebas ni se modificaron archivos. Consultar a Astra sobre el límite transaccional, continuidad de cuotas y compatibilidad del piloto antes de implementar.


## 4- Permitir inferencia manual sin activar la planificación automática

**Problema y evidencia.** El worker no puede atender una solicitud manual mientras `--automatic-inference=false`: tanto ejecución como planificación retornan antes de trabajar ([runtime.go:222](internal/runtimev2/runtime.go#L222)). La API acepta el job durable ([ai_api.go:85](internal/runtimev2/ai_api.go#L85)), pero este queda en cola. El bloqueo coincide con [review-2026-11-13.md:56](docs/review-2026-11-13.md#L56).

Eliminar simplemente el gate de `Store.Once` sería incompatible con la garantía productiva actual: el arranque mecánico promete cero inferencia incluso después de configurar un proveedor ([README de producción:174](deploy/v2/production/README.md#L174)), y existe una regresión que exige mantener el job manual en cola ([mechanical_worker_test.go:15](internal/runtimev2/mechanical_worker_test.go#L15)). Además, `claim` selecciona cualquier trabajo elegible sin distinguir su origen ([jobs.go:271](internal/inference/jobs.go#L271)); podría consumir backlog automático creado anteriormente.

**Mejora propuesta.** Añadir un opt-in explícito `--manual-inference`, desactivado por defecto, y una modalidad de consumo limitada a solicitudes manuales. Con ambos flags desactivados se conserva el comportamiento mecánico; con manual activado y automático desactivado se consumen únicamente solicitudes manuales; con automático activado se conserva el funcionamiento actual de ejecución y planificación.

El selector manual puede aprovechar la procedencia durable existente: el planificador usa exclusivamente el actor reservado `system:semantic-planner` ([planner.go:53](internal/inference/planner.go#L53)), mientras la API utiliza el actor autenticado. Centralizar ese identificador y aplicar la exclusión sobre todas las ramas elegibles del selector —cola, reintento y lease vencido— evita que un job automático antiguo atraviese el nuevo modo. La clasificación debe permanecer bajo control del servidor.

**Alcance.** Cambios acotados en configuración/CLI, `runtime.go`, selección de jobs y sus pruebas; actualización de la documentación de operación y revisión. Reutilizar ejecución, agrupación y ledger existentes. Mantener intactas las reservas transaccionales, límites globales y por función ([jobs.go:365](internal/inference/jobs.go#L365)), cancelación y cuarentena de ejecuciones inciertas. No modificar transportes, credenciales ni contratos de resultados. No habilitar flags en producción como parte del cambio.

**Aceptación y pruebas propuestas.**

- Con ambos flags desactivados, el worker sigue procesando trabajos mecánicos y produce cero llamadas e intentos IA.
- En modo manual, una solicitud autenticada termina usando el proveedor HTTPS sintético; no se planifican trabajos automáticos ni se consume backlog del actor reservado, aunque sea más antiguo.
- Cubrir el filtro con jobs automáticos en `queued`, `retry_wait` y leases vencidos; una ejecución incierta conserva su exposición y nunca se reenvía.
- Con automático activado, conservar planificación idempotente y consumo existentes.
- Comprobar que el modo manual respeta presupuestos, cancelación y pausa general usando las fixtures actuales.

**Prioridad alta.** Desbloquea funciones solicitadas por el usuario conservando el arranque sin gasto. La semántica nueva requiere revisión explícita de compatibilidad y consumo. Análisis realizado por inspección sobre `9374936`; sin modificaciones ni pruebas ejecutadas.


## 5- Impedir reintentos tras respuestas HTTP de éxito no interpretables

**Problema y evidencia.** En `dev` (`9374936`), `internal/inference/transport.go:196–214` solo interpreta HTTP 200 como resultado. Para 201, 202 o 204 devuelve `upstream_error` con `Permanent=false` y `Uncertain=false`. La clasificación afirma implícitamente que repetir es seguro, aunque el proveedor podría haber aceptado o ejecutado la inferencia sin entregar el resultado síncrono esperado.

La consecuencia se observa en el consumidor existente: `internal/inference/jobs.go:503–507` convierte precisamente esa combinación en `retry_wait`. Además, la reconciliación sin uso y con error no incierto libera la reserva (`jobs.go:465–479`). Es un riesgo deducido del flujo actual; no se ha reproducido ni consta un incidente real. El contrato ya exige no asumir idempotencia remota por disponer de un header (`rebuild/08-contrato-zrelay.md:32`).

**Mejora propuesta.** Clasificar los estados 2xx distintos de 200 como respuesta incompatible con el protocolo síncrono y ejecución incierta: error estable, `Uncertain=true`, sin resultado publicable. Conservar el comportamiento actual de respuestas 200 válidas, autenticación, redirecciones, rate limit y errores 5xx. El cambio queda limitado al transporte compartido por Chat y Responses; no modifica colas, credenciales ni políticas de proveedores.

**Alcance.** `internal/inference/transport.go` y pruebas en `internal/inference/transport_test.go`. Incorporar al contrato de transporte la regla explícita: un código HTTP de éxito sin respuesta admitida no acredita ausencia de ejecución ni permite repetir automáticamente.

**Aceptación y pruebas previstas.**

- Servidor local sintético, para ambos adaptadores: 201, 202 y 204 producen error incierto, sin `GatewayResult` publicable y con una única petición física.
- Casos de control: 200 válido conserva resultado y uso; 401, 403, 429, redirección y 500 conservan su clasificación.
- Las pruebas comprueban los campos de `GatewayError`, no únicamente que exista un error.
- Ejecutar `go test ./internal/inference`; revisar que la clasificación nueva activa las garantías ya existentes del consumidor, sin cambiarlo.

**Estado y límites.** Análisis por inspección, sin modificaciones ni pruebas ejecutadas. Se leyó `docs/review-2026-11-13.md`; esta propuesta concreta un fallo adicional de clasificación HTTP. No acredita compatibilidad con un proveedor real y no incorpora soporte para ejecución asíncrona.


## 6- Exigir una tarifa explícita antes de habilitar inferencia

**Mejora propuesta.** Impedir que una función IA se habilite conservando la tarifa inicial `unconfigured`. El objetivo es evitar que una configuración incompleta aparente tener protección presupuestaria mientras contabiliza cada solicitud a coste cero.

**Evidencia vigente.** En `9374936`, `DefaultConfig()` asigna `Price{Version: "unconfigured"}` y deja ambas tarifas en cero (`internal/inference/config.go:31–35`). `Store.Validate()` admite esos valores: exige una versión no vacía y tarifas no negativas; al habilitar un binding comprueba modelo, conexión y presupuestos positivos, pero no que la tarifa haya sido configurada (`config.go:164–168`). Por inspección, completar esos campos permite conservar accidentalmente la tarifa inicial.

La reserva se calcula multiplicando límites de tokens por tarifas, y el presupuesto compara esa reserva con la exposición acumulada (`internal/inference/jobs.go:365–393`). Con ambas tarifas iniciales a cero, estas llamadas no incrementan la exposición monetaria calculada. Esto no elimina otros límites, como concurrencia, pero desactiva en la práctica la protección económica para esa ruta. La revisión ya identifica tarifas y presupuestos como requisitos pendientes y advierte contra asumir presupuesto disponible (`docs/review-2026-11-13.md:50–66`).

**Alcance.** Modificar únicamente la validación de configuración para rechazar bindings habilitados cuyo `price.version`, normalizado para la comparación, esté vacío o sea `unconfigured`. Mantener ese marcador en bindings deshabilitados. Documentar que una tarifa cero necesita una versión explícita correspondiente a una ruta deliberadamente gratuita: exigir tarifas positivas indiscriminadamente excluiría proveedores locales gratuitos. Se conservan el contrato JSON y las tarifas existentes con versión válida; no se modifican transporte, ejecución de jobs ni UI.

**Aceptación y pruebas previstas.**

- Una configuración predeterminada deshabilitada continúa siendo válida.
- Habilitar una función con conexión, modelo y presupuestos válidos, conservando `unconfigured`, falla tanto en validación como al guardar.
- Versiones vacías, solo espacios y variantes normalizadas del marcador se rechazan; una versión explícita con tarifas válidas se acepta.
- Una tarifa explícitamente gratuita sigue admitiendo cero; precios negativos o superiores al máximo continúan rechazados.
- Pruebas unitarias tabuladas en `internal/inference`; regresión de los endpoints de validación y guardado en `internal/runtimev2/ai_test.go`, comprobando que el rechazo no crea una revisión ni modifica secretos.

**Límites.** Esta mejora previene configuraciones nuevas o editadas incompletas; no acredita tarifas del proveedor ni corrige automáticamente revisiones persistidas. Antes de habilitar producción debe comprobarse la configuración vigente. Solo se ha inspeccionado código: no se ejecutaron pruebas ni llamadas externas.


## 7- Reconciliar la aplicabilidad vigente y retractar afectaciones obsoletas

**Prioridad alta.** Evitar que un expediente conserve `affected_version` después de actualizar un activo, recibir una corrección NVD o caducar su evidencia. El historial debe conservarse, pero distinguirse del estado vigente.

**Evidencia actual (`dev`, `9374936`).** El hallazgo de `docs/review-2026-11-13.md:81` sigue respaldado por el código:

- `internal/vulnv2/applicability.go:221` cruza cada activo vigente con **todos** los snapshots NVD del CVE. Ordenarlos por fecha no selecciona una única revisión vigente.
- En `applicability.go:254–258`, la inserción usa `ON CONFLICT DO NOTHING` y solo publica resultados `affected_version`. Una reevaluación caducada tampoco modifica una fila previamente insertada.
- `applicability.go:291` deduplica cambios por expediente, CVE, activo, revisión y estado afectado, sin identificar el snapshot. `applicability.go:308–311` fija el expediente como afectado; no hay transición inversa en esa función.
- `internal/runtimev2/domain_api.go:101` degrada a `unknown` las filas caducadas al leer aplicabilidad, pero esa corrección no se propaga al estado materializado del expediente.
- La prueba `internal/runtimev2/stories_test.go:121–177` cubre versión desconocida → `1.5` afectada y consulta el expediente. No cubre la salida posterior de afectación.

**Mejora propuesta.** Introducir una reconciliación de aplicabilidad vigente que seleccione determinísticamente el último registro NVD conocido **por CVE**, junto con la última revisión de cada activo. Como la ingesta utiliza ventanas incrementales (`internal/vulnv2/feeds.go:254–255`), la ausencia de un CVE en una página nueva no debe interpretarse como retirada.

Separar los resultados históricos del estado efectivo y publicar transiciones tanto hacia `affected_version` como hacia `not_affected_version` o `unknown`, indicando motivo, snapshot y revisión del activo. La reconciliación debe ejecutarse tras cambios de inventario, correcciones NVD y vencimiento de evidencia, conservando los eventos anteriores e invalidando los briefs derivados.

El estado resumido del expediente debe recalcularse a partir de todas sus parejas CVE/activo vigentes: actualizar un activo no puede borrar otra afectación todavía válida. Mantener siempre `local_exposure: unknown`. Resolver la caducidad mediante un disparador durable y asegurar que la lectura no presente afectaciones caducadas mientras ese trabajo está pendiente.

**Alcance.** Proyección en `internal/vulnv2`, integración con sus disparadores y lectura del expediente; migración adicional solo si hace falta representar el estado vigente. No ampliar comparadores de versiones/CPE ni abordar paginación o capacidad.

**Aceptación y pruebas previstas.**

1. Activo `1.5` → `2.0` fuera del rango: retractación visible, motivo actualizado e historial conservado.
2. Snapshot A afectado → B excluyente: B gobierna; reprocesar A no resucita la afectación.
3. Caducidad: estado efectivo `unknown`, transición registrada una sola vez y briefs invalidados.
4. Dos activos: remediar uno conserva la afectación del otro.
5. Repetición y concurrencia entre inventario/ingesta: sin revisiones duplicadas ni regresión a snapshots antiguos.

Extender las pruebas PostgreSQL/API de `stories_test.go` y `feeds_domain_test.go`. **Verificación realizada:** inspección del código, esquema y pruebas existentes; sin ejecutar pruebas ni modificar archivos.


## 8- Procesar la aplicabilidad por lotes durables sin bloquear el inventario

**Problema confirmado en `9374936`.** Guardar un activo inserta su revisión y recorre todos los CVEs dentro de la misma transacción; al encontrar 1.001 CVEs devuelve `inventory refresh limit exceeded` y revierte también el activo ([domain_api.go:322](/home/zyrak/github_repos/noctis/internal/runtimev2/domain_api.go:322)). Además, `RefreshApplicabilityTx` limita el producto snapshots NVD × activos a 1.000 filas y falla incluso cuando hay exactamente 1.000; el orden por `as_of` carece de desempate para paginar ([applicability.go:221](/home/zyrak/github_repos/noctis/internal/vulnv2/applicability.go:221), [applicability.go:250](/home/zyrak/github_repos/noctis/internal/vulnv2/applicability.go:250)). La captura NVD llama a esa función antes de confirmar snapshot y cursor, por lo que el crecimiento también puede detener la ingestión ([feeds.go:306](/home/zyrak/github_repos/noctis/internal/vulnv2/feeds.go:306)). Sigue vigente el hallazgo de la [revisión:82](/home/zyrak/github_repos/noctis/docs/review-2026-11-13.md:82).

**Mejora propuesta.** Separar la persistencia de inventario/feed del cálculo mediante una cola durable de aplicabilidad, procesada con lotes acotados y paginación por clave.

- Confirmar juntos la nueva revisión o snapshot y su solicitud de cálculo. La respuesta distingue «guardado, cálculo pendiente» de «cálculo completo».
- Para modificaciones de inventario, recorrer CVEs únicamente para la revisión afectada; para feeds, recorrer los activos correspondientes al snapshot recibido. Evitar recalcular todas las combinaciones históricas en cada modificación.
- Persistir identidad de entrada, cursor compuesto, estado y progreso. Usar orden total con claves estables, nunca únicamente `as_of`; delimitar cada recorrido para que cambios concurrentes generen trabajo nuevo sin saltar elementos.
- Confirmar cada lote, sus resultados y la continuación en una misma transacción. Reutilizar las garantías de lease/fence de `jobs` ([store.go:58](/home/zyrak/github_repos/noctis/internal/jobs/store.go:58)); el progreso normal entre páginas no debe consumir el presupuesto de reintentos.
- Mantener evaluación, procedencia e idempotencia actuales. La selección del snapshot vigente y las retractaciones pertenecen a la propuesta separada; esta implementación debe compartir su contrato de entradas para evitar resultados incompatibles.

**Alcance.** `internal/vulnv2`, mutación/lectura de estado en `runtimev2/domain_api.go`, integración del consumidor mecánico y una migración nueva para progreso e índices necesarios. Actualizar las pruebas que actualmente esperan aplicabilidad inmediatamente después del POST ([stories_test.go:159](/home/zyrak/github_repos/noctis/internal/runtimev2/stories_test.go:159)). No basta con aumentar o eliminar los límites: conservaría transacciones crecientes y el bloqueo global de proyección.

**Aceptación y pruebas previstas.**

1. Con 999, 1.000 y 1.001 CVEs, crear y actualizar un activo funciona y todo el trabajo termina; comprobar los mismos bordes para combinaciones snapshot/activo y un recorrido de varias páginas.
2. Detener el worker antes y después del commit de un lote y reiniciarlo: sin omisiones ni duplicados de aplicabilidad, cambios de expediente o revisiones.
3. Ejecutar dos workers y actualizar un activo/feed durante el recorrido: ningún lease vencido publica y las entradas nuevas quedan procesadas por su trabajo correspondiente.
4. Verificar que captura NVD confirma snapshot/cursor aunque exista cálculo pendiente, que una cola fallida sea visible y que resultados incompletos no se presenten como completos.
5. Medir filas procesadas por lote y duración de transacciones con fixtures crecientes; comprobar equivalencia con el resultado actual para un conjunto pequeño.

**Verificación realizada:** inspección de código y pruebas existentes; no se ejecutaron pruebas ni se modificaron archivos.


## 9- Sustituir de forma atómica la pregunta que gobierna una fuente

**Mejora propuesta.** Definir una única pregunta gobernante por fuente y hacer que cambiar de A a B sustituya esa relación en la misma transacción que cambia la política. Evita que una pregunta abandonada detenga la captura o vuelva a imponer sus términos.

**Evidencia vigente (`9374936`).** El hallazgo de `docs/review-2026-11-13.md:83` continúa presente:

- `internal/runtimev2/operations_api.go:362–372` actualiza `sources.policy_version`, pero únicamente añade la asociación nueva mediante `INSERT … ON CONFLICT DO NOTHING`; conserva las anteriores.
- `internal/intelligence/authorization.go:12` deniega autorización si **cualquiera** de las preguntas asociadas está pausada.
- `internal/runtimev2/operations_api.go:289–294` modifica la política y crea trabajos para todas las fuentes asociadas cuando se edita una pregunta.
- `migrations/v2/005_operations.sql:9` admite varias preguntas por fuente, mientras `sources.policy_version` identifica una sola política efectiva.

Por tanto, después de A→B, pausar A puede bloquear la fuente y editar A puede reemplazar la política B. Además, el endpoint acepta `question_id` explícito sin comprobar que corresponde a la pregunta codificada en `policy_version`.

**Alcance.** Backend, contrato y pruebas; sin UI. Validar coherencia entre pregunta y política antes de modificar estado; sustituir la relación gobernante bajo el bloqueo y control de revisión existentes (`operations_api.go:206,330`); conservar recibos e idempotencia. Establecer la cardinalidad en esquema mediante una migración nueva, sin modificar migraciones publicadas. Para asociaciones múltiples existentes, identificar la gobernante por la política vigente cuando sea inequívoca; detener la migración con diagnóstico si no lo es, sin eliminar relaciones arbitrariamente ni habilitar fuentes.

La cardinalidad es una decisión de compatibilidad: requiere consulta Astra antes de implementar. La recomendación aprovecha el modelo actual de política singular; introducir políticas combinadas para varias preguntas sería otro proyecto.

**Aceptación y pruebas previstas.**

1. Regresión PostgreSQL/HTTPS A→B→editar/pausar A: la fuente conserva B, su autorización y sus trabajos; editar B sí actualiza la política.
2. Pausar B bloquea captura/publicación; reanudar B no revoca la pausa propia de la fuente. Preservar las garantías cubiertas por `TestCore005PIRRevisionPauseOwnSourceAndDiscoveryRevokePostgresHTTPS`.
3. Pregunta y política incompatibles producen un rechazo explícito sin cambios; revisión obsoleta conserva `409`; repetir `request_id` no duplica relaciones ni trabajos.
4. Carrera entre reasignación y edición de A: resultado coherente con el orden transaccional, sin política o trabajos de A publicados tras el relevo.
5. Migración sobre datos con cero, una y varias asociaciones: preserva pausas y permisos, y detecta ambigüedades.

**Verificación realizada:** inspección de código, esquema y regresiones existentes. No se modificaron archivos ni se ejecutaron pruebas; el escenario A→B requiere una regresión específica.


## 10- Acotar la admisión de autenticación antes de acceder a PostgreSQL

**Problema y evidencia.** La revisión identifica conexiones prematuras e intentos de login sin límite (`docs/review-2026-11-13.md:90`). El código vigente lo confirma: `handle` abre una conexión nueva mediante `pgx.Connect` antes de comprobar la cookie (`internal/runtimev2/api.go:93–109`); el login también llega con la conexión abierta y compara las credenciales después (`api.go:165–180`). Así, una petición sin sesión o con contraseña incorrecta consume una conexión aunque pueda rechazarse localmente. El timeout de diez segundos limita duración, pero no concurrencia ni frecuencia de admisión (`api.go:81`). No se ha medido la saturación.

**Mejora propuesta.** Introducir una fase de admisión previa a PostgreSQL, manteniendo las sesiones existentes y las respuestas actuales de autenticación:

- Rechazar con `401` las rutas privadas sin cookie o con un token que no cumpla el formato emitido por `random` —64 caracteres hexadecimales— antes de conectar.
- En login, aplicar un presupuesto temporal acotado por proceso, validar el JSON y comparar credenciales antes de abrir la conexión necesaria para insertar la sesión. Al agotar el presupuesto, devolver `429` con `Retry-After`. El presupuesto debe consumir también intentos correctos para limitar creación masiva de sesiones.
- Añadir un máximo concurrente para las conexiones abiertas por este handler, adquiriendo capacidad antes de `pgx.Connect` y liberándola después de cerrar la conexión. Ante saturación, responder `503` sin acumular una cola ilimitada.

Un presupuesto global resulta coherente con el único administrador actual y evita depender de cabeceras de IP no autenticadas. Deben documentarse sus valores y recuperación; no introducir bloqueos permanentes de cuenta.

**Alcance.** `internal/runtimev2/api.go`, un helper pequeño de admisión y pruebas focalizadas. Mantener firma pública de `NewHandler`, expiración de ocho horas, hash de token, cookies, Origin, CSRF y revocación. No requiere migración ni sustitución general por un pool; excluye TLS y readiness.

**Aceptación y comprobaciones previstas.**

1. Con PostgreSQL inaccesible, ausencia/cookie malformada devuelve `401` y credenciales incorrectas devuelven `401`, sin intentar conectar; unas credenciales válidas conservan el `503` de dependencia.
2. Con reloj controlado, verificar ráfaga admitida, `429`, `Retry-After` y recuperación del presupuesto sin esperas reales.
3. Con conexión controlada, comprobar bajo concurrencia que nunca se supera el máximo, que saturación no abre conexiones y que error/cancelación libera capacidad.
4. Reutilizar las regresiones de login, hash, flags de cookie, CSRF, logout y expiración de `internal/runtimev2/product_test.go:171–221`; ejecutar pruebas nuevas con `-race` e integración sobre la base sintética.

**Límite material.** Los presupuestos en memoria se reinician con el proceso y se multiplican con réplicas; además, un atacante puede consumir temporalmente el presupuesto global de login. Debe explicitarse este comportamiento antes de escalar y validar los umbrales con carga representativa.

**Estado:** análisis por inspección de `dev` en `9374936`; sin modificaciones ni pruebas ejecutadas.


## 11- Validar el contrato TLS y Origin antes de abrir la API

**Problema y evidencia.** En `dev`, commit `9374936`, [runtime.go:104](internal/runtimev2/runtime.go#L104) selecciona HTTPS únicamente cuando existen ambas referencias TLS; configurar solo certificado o solo clave activa HTTP silenciosamente. El hallazgo de [review-2026-11-13.md:89](docs/review-2026-11-13.md#L89) sigue vigente. Además, [api.go:29](internal/runtimev2/api.go#L29) únicamente exige `Origin` no vacío, aunque posteriormente lo compara literalmente con las peticiones ([api.go:89](internal/runtimev2/api.go#L89)); una URL con ruta o credenciales puede aceptarse al arrancar y dejar las mutaciones inutilizables.

**Mejora propuesta.** Incorporar una validación coherente de configuración HTTP para el modo API antes de consultar PostgreSQL y abrir el listener:

- Rechazar certificado o clave aislados con un error explícito; con ambos configurados, cargar y verificar el par sin posibilidad de degradación a HTTP.
- Validar que `Origin` tenga formato de origen HTTP/HTTPS: esquema y autoridad válidos, sin credenciales, ruta, query ni fragmento. Mantener la comprobación exacta existente.
- Conservar el caso de ambos archivos TLS ausentes para terminación TLS externa, documentando claramente que el listener sirve HTTP. El origen público HTTPS no implica que el salto interno también use TLS; tampoco debe deducirse el modo de cabeceras `Forwarded`.

**Alcance y compatibilidad.** Cambios acotados a configuración, arranque API, validación del origen y documentación CLI/despliegue. Los modos worker y collector siguen sin requerir configuración HTTP. No modificar autenticación, readiness, protocolos públicos ni esquema SQL. El despliegue documentado con TLS en la API y verificación del upstream por Traefik ([production/README.md:114](deploy/v2/production/README.md#L114)) conserva su funcionamiento. También debe conservarse el despliegue deliberado con HTTPS en el proxy y HTTP interno; no imponer TLS directo universalmente.

**Aceptación y pruebas previstas.**

1. Matriz unitaria: TLS ausente, completo, certificado aislado, clave aislada, archivos ilegibles y par incompatible; errores antes de acceder a DB o abrir puerto.
2. Orígenes válidos con puerto y casos inválidos: vacío, `null`, host ausente, credenciales, ruta, query y fragmento.
3. Integración local con certificado sintético: negociación HTTPS efectiva y ausencia de servicio HTTP utilizable cuando se configura TLS.
4. Proxy HTTPS sintético hacia backend HTTP: conservar origen público y funcionamiento de las rutas existentes, sin depender de cabeceras reenviadas.
5. Regresión focalizada de configuración/runtime y checks obligatorios existentes antes de integrar.

**Estado.** Hallazgo contrastado por lectura; no se modificaron archivos ni ejecutaron pruebas. La política final de validación y compatibilidad debe entrar en la consulta central a Astra antes de implementar.


## 12- Readiness basada en esquema efectivo y permisos del runtime

**Mejora propuesta.** Convertir `Check` en una comprobación coherente del contrato de base de datos que necesita el binario: migraciones compatibles, objetos necesarios presentes y permisos efectivos suficientes. Solo entonces publicar `Functional=true` y capacidades operativas.

**Evidencia actual.** El hallazgo sigue vigente en `dev`, commit `9374936`, y coincide con `docs/review-2026-11-13.md:91`:

- `internal/runtimev2/runtime.go:45` comprueba únicamente cinco tablas. El ledger se contrasta correctamente con nombres y checksums embebidos (`:54–74`), pero ese registro no demuestra que una restauración conservase las demás tablas, columnas o restricciones.
- `Functional` se activa antes de consultar `ai_configs` (`:76–78`). Si esa consulta falla, la respuesta contiene un error y `functional:true`.
- `/readyz` y `/healthz` devuelven directamente ese estado y responden 503 ante errores (`internal/runtimev2/api.go:46–56`). El defecto afecta tanto al arranque como a las sondas.
- Los grants deben reaplicarse después de migraciones aditivas (`deploy/v2/runtime-grants.sql:14–19` y `deploy/v2/production/README.md:79–83`). Una migración registrada puede coexistir con permisos insuficientes en objetos nuevos.

**Alcance.** Mantener la validación exacta del ledger y añadir un contrato explícito, versionado junto al esquema, con las relaciones, columnas/tipos y restricciones indispensables para las operaciones soportadas. Comprobarlo mediante consultas de catálogo de solo lectura y verificar los privilegios efectivos necesarios del usuario conectado, incluidos `USAGE` del esquema y lectura del ledger. Los requisitos de escritura deben corresponder a operaciones reales de cada modo, evitando exigir privilegios adicionales únicamente para superar la sonda.

El contrato debe verificarse contra una base creada con las migraciones embebidas para impedir que quede desactualizado. No analizar SQL con expresiones regulares ni ejecutar escrituras de prueba durante readiness.

Conservar los campos JSON existentes: `Schema=true` únicamente tras validar ledger y estructura; `Functional=true` y capacidades únicamente al completar todos los checks. Un fallo posterior puede conservar `Database=true` y `Schema=true` si esas comprobaciones fueron satisfactorias. No ejecutar migraciones o grants automáticamente. TLS y el flujo de autenticación quedan fuera del cambio; `sessions` se utiliza como objeto de regresión.

**Aceptación y pruebas propuestas.**

1. Base migrada y vacía, con conexión real mediante rol restringido: readiness 200 y `functional:true`, también sin IA configurada.
2. Revocar a ese rol un permiso requerido sobre `sessions`, preservando acceso a las cinco tablas actuales y al ledger: readiness 503 y `functional:false`; recuperar readiness al restaurarlo.
3. Mantener el ledger intacto y retirar una tabla adicional o una columna/restricción requerida: detectar restauración incompleta.
4. Cubrir migración pendiente, adicional y checksum alterado; ningún caso debe anunciar funcionalidad.
5. Forzar fallo al consultar `ai_configs`: 503 con `functional:false`. Mantener `/livez` independiente de PostgreSQL.

Reutilizar las bases aisladas y roles LOGIN de `runtime_test.go:15` y `product_test.go:74`, junto a la comprobación HTTP de `operations_acceptance_test.go:333`. **Estado:** análisis por inspección; no se modificaron archivos ni se ejecutaron pruebas.


## 13- Pausar el reloj de reintentos junto con los trabajos de captura

**Mejora propuesta.** Hacer que una pausa de fuente conserve el presupuesto pendiente de sus trabajos `parse`: aparcar también `retry_wait` y excluir el tiempo aparcado del horizonte de 24 horas. Mantener los intentos ya consumidos y las cuarentenas por fallos reales.

**Evidencia actual.** El hallazgo de [docs/review-2026-11-13.md:93](docs/review-2026-11-13.md#L93) sigue presente en `9374936`. La ruta correcta es `internal/runtimev2/source_resume.go`, no `internal/capture/source_resume.go`:

- [source_resume.go:13](internal/runtimev2/source_resume.go#L13) aparca únicamente trabajos `queued` cuyo error está vacío o es `source_resumed`; deja fuera `retry_wait`.
- [source_resume.go:21](internal/runtimev2/source_resume.go#L21) reanuda mediante el marcador `source_resumed`. [jobs/store.go:38](internal/jobs/store.go#L38) permite una reclamación pese a la antigüedad y elimina ese marcador.
- [jobs/store.go:101](internal/jobs/store.go#L101) vuelve a comprobar `created_at` al registrar un fallo. Por tanto, el primer fallo transitorio después de una pausa larga puede provocar cuarentena, aunque queden intentos disponibles.
- La regresión existente [core005_regression_test.go:345](internal/runtimev2/core005_regression_test.go#L345) cubre pausa prolongada y finalización correcta, pero no comienza desde `retry_wait` ni introduce un fallo transitorio después de reanudar.

**Alcance implementable.** Ajustar `internal/jobs/store.go` y `internal/runtimev2/source_resume.go`, con una migración adicional si se persisten el instante de aparcado y el vencimiento efectivo. Usar un único criterio temporal en `Claim` y `Fail`, independiente del marcador de error; conservar `created_at` como fecha de creación. Mantener el bloqueo de publicación, los fences y las exclusiones actuales de trabajos cancelados, cuarentenados, obsoletos o con evidencia expirada. No afecta a `ai_jobs`.

La semántica recomendada es conservar el tiempo restante, no regalar otras 24 horas en cada reanudación. Antes de implementar debe concretarse el tratamiento de trabajos ya aparcados: el esquema actual no conserva el inicio de su pausa, por lo que no permite reconstruir su duración exacta.

**Aceptación y pruebas previstas.**

1. Un `retry_wait` válido pasa a `dependency_blocked/source_paused`; no consume intentos ni entra en cuarentena mientras permanece aparcado.
2. Tras una pausa superior a 24 horas, un fallo transitorio vuelve a `retry_wait` si quedan tiempo activo e intentos. El quinto intento o un fallo permanente sigue produciendo cuarentena.
3. Pausas repetidas conservan exactamente el presupuesto restante; trabajos que ya agotaron el horizonte no se rehabilitan.
4. Reanudaciones repetidas y carreras con `Finish` no duplican análisis, pierden despertares ni reviven evidencia expirada.
5. Ampliar las regresiones PostgreSQL existentes y ejecutar después `go test -race -count=1 ./internal/capture ./internal/runtimev2`, con la base sintética configurada y comprobando que los casos de integración no se omiten. Validar también la migración con `python3 tools/check_v2_migrations.py`.

**Estado:** análisis e inspección completados; sin modificaciones ni pruebas ejecutadas.


## 14- Validar el destino antes de consumir una entrega del outbox

**Problema y evidencia.** En `dev` (`9374936`), `DispatchOnce` cambia la fila de `queued` a `uncertain` y confirma la transacción **antes** de construir la petición HTTP (`internal/intelligence/delivery.go:73–80`). Una URL mal formada puede dejar una salida irrecuperable por el dispatcher automático aunque no se haya intentado contactar con el consumidor. Una URL relativa o con protocolo no soportado también debe rechazarse explícitamente: construir una petición no garantiza que el transporte pueda enviarla. El hallazgo continúa vigente respecto a `docs/review-2026-11-13.md:94`.

El impacto puede repetirse: el worker llama a `DispatchOnce` en cada iteración mientras `DeliveryEndpoint` esté configurado (`internal/runtimev2/runtime.go:169–171`), por lo que una configuración incorrecta puede ir pasando sucesivas salidas a `uncertain`.

**Mejora propuesta.** Añadir una validación determinista compartida del destino y ejecutarla antes de abrir la transacción o seleccionar una salida. Exigir una URL absoluta HTTP/HTTPS con host y puerto válidos; preservar los endpoints HTTP locales empleados por las pruebas. Construir la petición con su cuerpo antes de confirmar `uncertain`, manteniendo esa transición durable inmediatamente anterior a cualquier envío.

Validar también el destino configurado al arrancar el worker para presentar un error de configuración claro. `dispatch-once ENDPOINT` debe conservar la misma defensa mediante `DispatchOnce` (`cmd/noctis/v2.go:187–195`).

**Alcance.** Backend de entrega y puntos de entrada v2; sin migración, frontend ni nuevos estados. Se conservan el bloqueo de proyección, la revalidación de evidencia y la prohibición de reproducir automáticamente entregas inciertas. Los fallos de red y las respuestas ambiguas siguen siendo `uncertain`: esta corrección solo evita consumir eventos por errores detectables antes del envío.

**Aceptación y pruebas propuestas.**

- Pruebas unitarias del validador: URL mal formada, relativa, sin host, esquema ajeno a HTTP/HTTPS y puerto inválido; aceptación de destinos HTTP/HTTPS válidos.
- Regresión PostgreSQL con varias salidas válidas en cola: llamadas repetidas con destino inválido producen error, cero solicitudes y conservan filas, cuerpos, claves y estado `queued`.
- Corregir después el destino y comprobar una única recepción, el `Idempotency-Key` original y la transición a `delivered`.
- Ejecutar las regresiones existentes de ACK perdido, SIGKILL tras aceptación, revocación y orden de admisión: `product_test.go:52`, `process_faults_test.go:40`, `process_faults_test.go:123` y `core005_regression_test.go:496`.

**Estado de comprobación.** Hallazgo contrastado mediante lectura del código y la revisión; no se modificaron archivos ni se ejecutaron pruebas. La aceptación requiere ejecutar esas regresiones con la base sintética PostgreSQL configurada y comprobar que no se omiten.


## 15- Evitar duplicados y respuestas obsoletas en la paginación

**Problema y evidencia.** El hallazgo de [docs/review-2026-11-13.md:95](/home/zyrak/github_repos/noctis/docs/review-2026-11-13.md:95) sigue presente en `9374936`. En [Operations.jsx:8](/home/zyrak/github_repos/noctis/web/src/v2/Operations.jsx:8), `more()` solicita el cursor sin bloqueo ni cancelación y añade la respuesta al estado que exista cuando termine. Dos pulsaciones pueden solicitar la misma página y duplicar filas. Si cambia `path` mientras llega una continuación, sus resultados y cursor pueden incorporarse al recurso nuevo.

La carga inicial sí usa `AbortController`, pero su rama de éxito no comprueba vigencia ([Operations.jsx:7](/home/zyrak/github_repos/noctis/web/src/v2/Operations.jsx:7)). El componente se reutiliza en discovery y cobertura al cambiar la pregunta seleccionada ([Operations.jsx:41](/home/zyrak/github_repos/noctis/web/src/v2/Operations.jsx:41)), además de afirmaciones, timelines y dossiers. La mezcla puede presentar propuestas de otra pregunta bajo el filtro actual.

**Mejora propuesta.** Hacer que `Paged` gestione una única continuación pendiente y vincule todas sus respuestas a una generación del recurso:

- Identificar cada carga de `path` con una generación, invalidada al cambiar de recurso o desmontar. Comprobarla antes de modificar filas, metadatos, errores o estado de carga; comparar solamente `path` no cubre una navegación A→B→A.
- Cancelar la carga inicial y las continuaciones cuando pierdan vigencia, manteniendo la comprobación de generación aunque la cancelación llegue tarde.
- Bloquear inmediatamente solicitudes concurrentes del mismo cursor y deshabilitar «Load more records» mientras carga, con estado accesible.
- Ante un fallo de continuación, conservar filas y cursor para permitir reintento; limpiar el error tras recuperación. Una respuesta obsoleta tampoco debe liberar el bloqueo de una petición nueva.

Alcance limitado al componente y sus regresiones; conserva contrato API y cursores. Quedan fuera políticas, retención y otras mutaciones.

**Aceptación y pruebas.** Ampliar [v2-product.spec.js](/home/zyrak/github_repos/noctis/web/tests/v2-product.spec.js), reutilizando sus rutas simuladas y respuestas diferidas:

1. Dos activaciones rápidas generan una sola solicitud por cursor y añaden una sola página.
2. Una continuación de A resuelta después de cargar B no modifica filas, cursor ni errores de B; repetir con A→B→A.
3. Un fallo mantiene los registros previos; el reintento exitoso añade la página una vez, retira el error y permite continuar.
4. Sin `next_cursor` desaparece el botón; cambiar de recurso durante carga cancela/invalida la solicitud anterior.

Validación prevista: `npm run build` y `npx playwright test --config playwright.v2.config.js` desde `web/`. La prueba real existente ([v2-operations-real.spec.js:60](/home/zyrak/github_repos/noctis/web/tests/v2-operations-real.spec.js:60)) comprueba pasar de 50 a 51 afirmaciones, pero no estas carreras.

**Estado:** análisis e inspección completados; sin cambios ni pruebas ejecutadas.


## 16- Recuperar conflictos de revisión sin perder la edición operativa

**Propuesta.** Completar el ciclo «leer estado vigente → editar → guardar → reconciliar» en políticas de fuente, control global y retención. El operador debe poder resolver un conflicto dentro de la pantalla, conservar su borrador y decidir explícitamente si vuelve a guardar.

**Evidencia actual (`dev`, `9374936`).** El hallazgo de `docs/review-2026-11-13.md:96` sigue presente:

- `web/src/v2/Operations.jsx:28` incrementa localmente la revisión de fuente, pero no actualiza la fila visible. `web/src/v2/App.jsx:69–71` no recibe ninguna señal de guardado ni recarga. Tras un 409 se recomienda recargar, aunque el editor no ofrece esa acción.
- `Operations.jsx:46–48` carga el control global solo al montar el componente. Un cambio desde otra sesión deja el botón trabajando con la revisión antigua.
- La retención pide al usuario introducir la revisión manualmente. La vista previa recibe `policy_revision` del servidor (`internal/runtimev2/retention.go:44`), pero el formulario no la incorpora. Además, revisión y UUID de ejecución sobreviven al cambiar fuente o clase.
- El transporte ya expone `error.currentRevision` (`web/src/v2/api.js:7`). No todo 409 significa revisión obsoleta: la activación de Telegram también puede fallar por baseline o inventario (`operations_api.go:340–351`).

**Alcance.** Modificar los editores de `Operations.jsx` y la integración de `Sources` en `App.jsx`, manteniendo separados el borrador y el último estado confirmado. Tras guardar una fuente, refrescar su estado visible; tras `stale_revision`, ofrecer recarga del estado vigente y mostrarlo junto al borrador, sin reenviar automáticamente la mutación. Conservar el código estructurado del error para distinguir otros conflictos.

Para retención, añadir una lectura autenticada y autorizada de la política por fuente/clase: actualmente `GET /retention` no tiene rama de lectura (`operations_api.go:117–184`). Mostrar la revisión como dato del servidor, invalidar el contexto previo al cambiar de destino y conservar la ejecución solo para su fuente/clase. Mantener intactas las comprobaciones CAS y los permisos del backend. No incluye paginación, asociaciones entre preguntas y fuentes ni cambios en el algoritmo de purga.

**Aceptación y pruebas propuestas.**

1. Guardar pausa/política actualiza la fila y utiliza la revisión confirmada; un guardado posterior correcto no deja avisos contradictorios.
2. Dos sesiones provocan un 409 de revisión: fuente, control y retención pueden recargarse sin perder el borrador ni efectuar una segunda escritura automática.
3. Un error de baseline/inventario conserva su causa específica; una recarga fallida mantiene el conflicto y el borrador.
4. Cambiar fuente o clase no reutiliza revisión, vista previa o ejecución anterior. La nueva lectura respeta permisos y representa explícitamente la ausencia de política.
5. Añadir regresiones Playwright en `web/tests/v2-product.spec.js` y escenarios reales en `web/tests/v2-operations-real.spec.js`, además de pruebas API para la lectura de retención. Verificar una purga únicamente con fixtures sintéticas.

**Estado:** propuesta contrastada mediante inspección; sin modificaciones ni pruebas ejecutadas.


## 17- Ejecutar fielmente el plan de consulta revisado

**Mejora propuesta.** Conservar el plan tipado completo al pulsar «Run this typed plan», incluida su paginación, y reproducirlo al recargar o navegar. El usuario debe ejecutar la consulta que acaba de revisar.

**Evidencia vigente (`dev`, `9374936`).** El hallazgo de `docs/review-2026-11-13.md:97` sigue presente:

- `web/src/v2/Consumers.jsx:22` reconstruye siempre el plan con `limit:50`.
- `Consumers.jsx:25–26` elimina el cursor y copia únicamente texto, entidad, modo y filtros del plan propuesto.
- La API sí admite ambos campos: `internal/inference/contracts.go:103–111`; valida límites de 1–100 y cursor UUID en `internal/inference/inputs.go:262–274`, y los utiliza en la consulta y la continuación (`inputs.go:338–361`).
- Además, un plan con texto vacío es válido para la API y permite consultar por filtros (`inputs.go:338`), pero la UI impide ejecutarlo mediante `if(!q)return` (`Consumers.jsx:24`). Por tanto, conservar únicamente `limit/cursor` dejaría otro caso válido del mismo contrato sin resolver.

**Alcance.** Ajustar la conversión entre plan, URL y formulario dentro del flujo `TypedQuery`. Mantener el valor predeterminado 50 para consultas manuales sin límite explícito; conservar el límite y cursor de un plan aceptado; distinguir una consulta todavía no iniciada de un plan válido con texto vacío. Al editar texto o filtros, reiniciar el cursor; al avanzar de página, conservar el resto del plan. Mostrar el límite efectivo para que la ejecución sea revisable. Mantener la validación autoritativa del servidor y rechazar parámetros inválidos sin sustituirlos silenciosamente. No requiere migraciones, nuevos endpoints ni cambios en el historial de jobs.

**Criterios de aceptación y pruebas propuestas.**

1. Una propuesta sintética con `limit:7`, cursor UUID y filtros produce un `POST /api/v2/query` semánticamente idéntico al plan mostrado.
2. Recargar, volver atrás y avanzar de página conserva límite y filtros; «Next page» cambia únicamente el cursor. Editar la consulta elimina el cursor anterior.
3. Un plan válido de texto vacío y filtros explícitos se ejecuta; abrir la búsqueda sin iniciarla sigue sin consultar.
4. Playwright intercepta las peticiones y comprueba sus cuerpos, evitando inferencia externa. Añadir regresiones API para límite 0/101 y cursor inválido; con PostgreSQL sintético, verificar límite y continuación sobre filas de identificadores únicos.
5. Compilar el frontend y ejecutar las pruebas focalizadas; conservar la búsqueda manual exacta y de texto completo.

**Verificación realizada:** inspección del código y del documento de revisión; rama y commit comprobados. No se modificaron archivos ni se ejecutaron pruebas.


## 18- Recuperar y cancelar trabajos IA después de navegar

**Problema y evidencia.** En `9374936`, `AIAction` conserva `job` y `requestID` únicamente en memoria del componente; desmontarlo aborta la petición y elimina la posibilidad de consultar o cancelar desde esa pantalla (`web/src/v2/Consumers.jsx:10–16`). El backend conserva el trabajo, pero ofrece creación y acceso por ID, sin listado recuperable (`internal/runtimev2/ai_api.go:86–142`). La revisión identifica exactamente esta carencia (`docs/review-2026-11-13.md:98`). Navegar durante una inferencia deja al usuario sin un acceso visible al trabajo; volver a pulsar puede crear otra solicitud con un `request_id` nuevo.

**Mejora propuesta.** Añadir un historial paginado de trabajos propios, accesible desde Sistema, con consulta de estado, apertura del resultado y cancelación de los pendientes. Debe recuperar trabajos desde PostgreSQL después de navegar o recargar, incluso cuando el navegador perdió la respuesta inicial del POST.

**Alcance.**

- Incorporar `GET /api/v2/ai/jobs` con paginación estable y límite acotado, siempre filtrado por el actor autenticado. Devolver metadatos suficientes para identificar función, fecha, ID y estado; no incluir snapshots, prompts ni resultados en el listado.
- Añadir el cliente correspondiente en `web/src/v2/ai.js` y una sección «Trabajos IA» en Sistema, con acceso directo desde `AIAction` al historial. Un trabajo seleccionado usa el endpoint de detalle existente y permite cancelar si está pendiente.
- Reutilizar `Store.Job`, que filtra por actor y revalida la evidencia antes de devolver resultados (`internal/inference/jobs.go:136–182`), y `Store.Cancel`, que invalida la ejecución mediante `fence` (`:184–199`). No reconstruir resultados directamente desde el listado.
- Al recuperar estado, ejecutar exclusivamente lecturas: ninguna nueva inferencia ni reenvío automático. La cancelación debe indicar que una petición ya enviada al proveedor puede seguir teniendo coste; el test existente conserva esa contabilidad (`internal/runtimev2/ai_test.go:169–192`).
- Quedan fuera el plan de consultas de la propuesta 17, la planificación automática y cambios de presupuestos.

**Aceptación y pruebas propuestas.**

1. Crear un trabajo con proveedor sintético retenido, navegar, recargar Sistema y recuperar el mismo ID; cancelar y verificar estado `cancelled`, resultado no publicado y ausencia de una segunda solicitud.
2. Simular pérdida de respuesta tras persistir el POST: el historial permite encontrar el trabajo sin repetirlo.
3. Probar listado, detalle y cancelación con dos actores: ninguno puede enumerar ni operar trabajos ajenos.
4. Probar paginación sin duplicados, límites inválidos, historial vacío y error de consulta visible.
5. Conservar la revalidación: un resultado cuya evidencia cambió aparece bloqueado al abrirlo; los estados terminales detienen el sondeo.

Extender las pruebas Go de `internal/runtimev2/ai_test.go` y Playwright de `web/tests/v2-ai-real.spec.js`, aprovechando fixtures sintéticos existentes. **Estado:** análisis por inspección; no se modificaron archivos ni se ejecutaron pruebas.


## 19- Publicar la configuración restaurada solo después de validarla

**Mejora propuesta:** hacer transaccional `restore-config`: descifrar y validar en staging privado; entregar el directorio final únicamente cuando todos los archivos hayan superado las comprobaciones. Conservar los intentos fallidos como diagnóstico privado e inequívocamente incompleto.

**Evidencia actual (`dev`, `9374936`):** [backup.py:153](/home/zyrak/github_repos/noctis/ops/rebuild/operations/backup.py:153) crea directamente el destino y extrae allí DSN, claves y sesión antes de comprobar formato, archivos requeridos, mappings, hashes y cuenta Telegram. Estas validaciones ocurren en las líneas 171–189. Si fallan, quedan archivos recuperados en la ruta final, sin marcador `FAILED` ni recibo de restauración: la función carece de manejo de fallos y devuelve el resultado correcto únicamente por stdout. Esto permite confundir un intento incompleto con configuración recuperada si se pierde su salida o termina la sesión del operador.

Los tests actuales sí rechazan mappings, hashes y políticas inválidos, pero solo comprueban la excepción; no verifican el estado del destino tras el fallo ([test_operations.py:125](/home/zyrak/github_repos/noctis/ops/rebuild/operations/test_operations.py:125)). El runbook documenta que `FAILED` identifica una recuperación incompleta, aunque ese mecanismo actualmente pertenece a las operaciones de base de datos ([README.md:97](/home/zyrak/github_repos/noctis/ops/rebuild/operations/README.md:97)).

**Alcance:** limitar el cambio a `restore_config`, sus tests y la sección de recuperación de configuración. Mantener formatos v1–v4, layout final, permisos 0700/0600, rechazo de destinos existentes y las advertencias sobre DSN originales y validación semántica Telegram. No iniciar PostgreSQL, Telegram ni otros servicios. No borrar automáticamente claves, archivos originales ni diagnósticos.

**Aceptación y pruebas:**

- Descifrado fallido, tar truncado, archivo inseguro, JSON inválido, hash/mapping incorrecto y cuenta incompatible nunca dejan configuración publicada en la ruta final.
- Un fallo o interrupción conserva staging privado identificable como incompleto; no produce recibo de éxito.
- El éxito publica todos los archivos juntos, preserva sus bytes y deja un recibo saneado con versión, cobertura y comprobaciones realizadas, sin secretos.
- Un destino existente permanece intacto, incluso ante un conflicto durante la publicación.
- Ampliar los tests sintéticos existentes para comprobar archivos, permisos y estados finales; añadir un ensayo con `age` y clave sintética para éxito y cifrado corrupto. No requiere infraestructura ni CI nueva.

**Verificación realizada:** inspección estática del código, pruebas existentes y runbook; no se ejecutaron pruebas ni se modificaron archivos.


## 20- Exigir E2E del artefacto exacto antes de publicar

**Problema y evidencia.** CI ejecuta el E2E con `bin/noctis`, compilado en el runner (`Makefile:20-22,32-33`); después Docker recompila el ejecutable y los assets (`Dockerfile:1-18`). La comprobación de imagen valida arquitectura, usuario, versión, ayuda y rechazo de configuración ausente, pero no los flujos funcionales (`ops/rebuild/operations/image_checks.py:16-56`). La publicación conserva correctamente los archivos de imagen ya comprobados y sus manifests (`image_checks.py:58-111`), aunque esos archivos todavía no tienen un E2E obligatorio asociado. El despliegue premium realizó manualmente ese E2E del binario extraído (`docs/deployment-premium-2026-11-13.md:25-32`): conviene convertir esa práctica en requisito automatizado.

**Mejora propuesta.** Incorporar una puerta de publicación que ejecute el harness existente con el binario AMD64 extraído de la imagen candidata, sin reconstruirlo: `go run ./ops/rebuild/e2e --binary RUTA_EXTRAÍDA --browser --product --ai`. Utilizar PostgreSQL y gateways HTTPS sintéticos. Registrar en el recibo el SHA del commit, versión, hash del binario, hash del archivo de imagen y resultado del E2E; comprobar esa asociación antes de cualquier `docker push`. `.github/workflows/build.yaml` debe exigir esta puerta y conservar sus recibos junto con los de publicación. Exponer el mismo procedimiento mediante Makefile para la preparación local.

Reutilizar las instalaciones y servicios del job de validación cuando se reorganice el flujo, evitando repetir preparaciones costosas. Mantener los checks Go/race, migraciones, frontend y contratos existentes. El trabajo queda acotado a workflow, Makefile, `image_checks.py`, recibos/pruebas asociados y documentación operativa.

**Aceptación y verificación prevista.**

- Un candidato válido supera el E2E canónico contra su ejecutable extraído; los hashes enlazan ese resultado con los archivos publicados.
- Recibo ausente, resultado fallido, SHA/versión diferentes o binario/archivo alterados bloquean la publicación antes del primer efecto externo.
- Pruebas unitarias con Docker simulado cubren esos rechazos; una ejecución sintética completa acredita el camino correcto y los flujos de navegador, producto e IA.
- Inspección del workflow y `actionlint`, si está disponible, verifican dependencias y condiciones. No se reconstruye la imagen entre validación y publicación.
- ARM64 conserva su comprobación ELF/manifest y su verificación nativa durante el rollout; el E2E AMD64 no acredita ejecución ARM64.

**Destino y procedimiento documentados.** Producción corresponde a `zcloud-cluster`, cuenta `system:admin`, namespace `noctis-v2`, nodo `oracle1` ARM64 y origen `https://noctis.zyrak.cloud` (`deploy/v2/production/README.md:3,52-90`). Para una actualización sin cambios de esquema, el último recibo documenta preflight, JSONPatch exclusivo de imagen con precondiciones de UID/resourceVersion/contenedor/imagen anterior, rollout y comprobación funcional (`docs/deployment-premium-2026-11-13.md:11-39`). Es evidencia documental; esas identidades deben volver a comprobarse antes de actuar.

**Límite.** Esta mejora garantiza promoción del artefacto probado, no reconstrucción idéntica bit a bit: las bases del Dockerfile siguen usando etiquetas mutables. Análisis realizado sobre `9374936`, árbol limpio; sin pruebas, escrituras, consultas al clúster ni lectura de secretos.
