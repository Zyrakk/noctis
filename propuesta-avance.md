# Propuestas de avance de Noctis

Base de código: `9374936`. Dos rondas independientes de veinte agentes Astra en ultra.

Resultado: **20 aceptadas, 0 denegadas**, con ajustes de alcance y garantías. Las secciones siguientes son la decisión final; las propuestas originales se conservan al final. Implementación y verificación todavía pendientes.

## 1- Evitar que una entrada RSS caducada bloquee noticias nuevas

**Estado: ACEPTADA**

**Propuesta final.** En `Store.Poll`, filtrar únicamente repeticiones exactas de observaciones RSS/Atom ya caducadas antes de llamar a `CommitBatchTx`. Consultar conjuntamente las identidades `(source_id, native_id, revision)` del lote y excluir una entrada solo cuando también coincidan `hash` y `representation`. Mantener cualquier incompatibilidad como error y permitir nuevas revisiones del mismo identificador nativo.

Construir y validar el lote original con `Batch.Validate` **antes del filtrado**, conservando sus límites de entradas, bytes e integridad. Ejecutar la consulta y el filtrado dentro de la transacción existente, después del bloqueo de proyección y de revalidar autorización, política y epoch. Confirmar el lote resultante, incluso vacío, mediante el CAS actual, conservando el hash del feed completo como checkpoint y el recibo habitual. No modificar el rechazo de replay caducado en `CommitBatchTx`.

**Justificación de la revisión.** El fallo continúa presente en el árbol inspeccionado (`1eacfc7`): `internal/capture/rss.go:126–146` entrega todo el feed y `internal/capture/store.go:89–95` aborta al encontrar una identidad caducada. El límite del adaptador es adecuado: una repetición normal de RSS no debe autorizar reconstrucciones mediante otros consumidores. El bloqueo común de `rss.go:136` y `internal/runtimev2/operations_api.go:206` serializa sondeo y retención; no hace falta otra política de concurrencia ni una migración.

Se corrigen dos imprecisiones de la propuesta inicial. Filtrar primero permitiría eludir los límites de `internal/capture/contracts.go:53` con entradas descartadas. Además, la garantía de bytes debe respetar contenido compartido: `internal/runtimev2/retention.go:103` conserva blobs usados por observaciones vigentes, y una nueva identidad legítima puede requerir esos mismos bytes. La entrada excluida nunca debe restaurar contenido por sí misma ni volver a estar disponible. Las veinte propuestas se han revisado: ninguna duplica este cambio; las propuestas 7 y 13 tratan otras consecuencias de la caducidad.

**Alcance.** `internal/capture/rss.go`, helper privado si resulta necesario, y regresiones PostgreSQL en `capture`/`runtimev2`. Sin migraciones ni cambios en Telegram, web, política de retención o contrato general de captura.

**Aceptación.**

1. Tras caducar A, el feed A+B confirma checkpoint y recibo y crea una sola observación/job para B; repetirlo no duplica ninguno.
2. A conserva expiración y tombstone, no recibe jobs y sigue indisponible. Si ninguna observación vigente necesita su blob, permanece vacío; cubrir también contenido compartido legítimo.
3. Un feed completamente caducado confirma correctamente sin reconstrucciones. Una revisión nueva del mismo `native_id` se captura.
4. Incompatibilidad de hash/representación, autorización revocada y CAS obsoleto producen rollback completo. Un lote original que exceda límites se rechaza aunque el filtrado lo reduciría.
5. Una purga concurrente con el sondeo queda serializada sin reactivar A; se mantiene la regresión de replay directo de `core005_regression_test.go:646`.

**Verificación pendiente.** Pruebas con servidor HTTP y PostgreSQL sintéticos; ejecutar `go test ./internal/capture ./internal/runtimev2` con `NOCTIS_V2_TEST_DATABASE_URL` y comprobar que las regresiones de integración se ejecutan sin omisiones. Esta revisión es estática: no se implementó ni se ejecutaron pruebas.


## 2- Recuperar los canales señalados antes de confirmar el cursor global de Telegram

**Estado: ACEPTADA**

**Propuesta final.** En cada página de `Coordinator.difference`, detectar los avisos `UpdateChannelTooLong`, deduplicarlos por ID de canal y ejecutar `channelDifferenceByID` para cada canal antes de confirmar los eventos y `Next` de esa página global. Identificar expresamente ese constructor evita convertir futuros marcadores de protocolo ajenos en solicitudes de recuperación. Reutilizar el helper privado: llamar al método público `ChannelDifference` desde `difference` intentaría adquirir de nuevo el mutex del coordinador.

La recuperación conserva sus commits por página. Si falla un canal, devolver el error sin confirmar la página global; mantener el progreso durable de canales ya recuperados. No introducir una transacción abierta durante llamadas de red ni intentar deshacer capturas confirmadas. En el siguiente intento, consultar nuevamente los cursores durables.

Conservar íntegramente la autorización original de la respuesta global (`Envelope.Authorization: admission`) y su revalidación al confirmar. Las llamadas de canal obtienen su propia admisión vigente; esta no debe reemplazar la autorización global ni legitimar retrospectivamente una respuesta recibida bajo otra política. Mantener generación, ownership/fence, `access_hash`, límites, prohibición de bootstrap histórico productivo y error de `UpdatesChannelDifferenceTooLong`.

**Justificación y evidencia.** La inspección vigente en `1eacfc7` confirma el fallo: `internal/telegramv2/rpc.go:115` convierte el aviso en un marcador sin `PtsCount`; `Handle` recupera el canal en `:217`, mientras `difference` confirma directamente en `:320`. `store.go:406` solo actualiza el cursor del canal con `PtsCount > 0`, y `:487` guarda ese marcador como `protocol_only`. Por tanto, persistirlo no resuelve la recuperación pendiente. El helper ya excluye canales no autorizados y consulta generación, hash y cursor en `rpc.go:347`; la admisión y confirmación vuelven a comprobar las garantías relevantes (`admission.go:62–105`, `store.go:213–238`).

Es una corrección pequeña con valor alto: evita dar por completada una reconexión que omitió contenido de un canal después silencioso. Bloquear el avance global ante una recuperación fallida es deliberado; los presupuestos existentes acotan el trabajo. Revisadas las veinte propuestas, no duplica otra: la transición de sesión de la propuesta 3 es independiente. Tampoco subsana una discontinuidad productiva ya declarada.

**Alcance y aceptación.** Limitar los cambios a `rpc.go` y regresiones sintéticas del coordinador/producción, sin migraciones, nuevos permisos ni despliegue.

1. Diferencia final y `UpdatesDifferenceSlice` con avisos recuperan todas las páginas del canal antes de avanzar el cursor global, aunque no lleguen actualizaciones posteriores.
2. Avisos repetidos producen una sola invocación de recuperación por canal y página global; un canal excluido produce cero RPC de canal y cero contenido materializado.
3. RPC fallido, cancelación, agotamiento del presupuesto o límite de páginas conservan el cursor global. Reintentar desde el progreso durable no duplica observaciones.
4. Con dos canales, el primero conserva su progreso si falla el segundo; el siguiente intento completa la página correctamente.
5. Revocación/cambio de política durante la recuperación impide confirmar la respuesta global obsoleta. Ownership o generación obsoletos mantienen el rechazo.
6. `UpdatesChannelDifferenceTooLong` productivo sigue rechazando snapshot histórico y avance global; ampliar `production_test.go:69` desde la entrada `Difference`.

**Verificación pendiente.** Ejecutar regresiones con PostgreSQL sintético, confirmar que no se omiten, y después los checks canónicos requeridos. Esta revisión solo inspeccionó código y documentos; no implementó ni ejecutó pruebas.


## 3- Sustituir la sesión mediante una transición auditada que mantenga bloqueada la captura

**Estado: ACEPTADA**

**Propuesta final.** Añadir una operación explícita de transición de generación para cuentas productivas v2. La autenticación verifica la identidad y prepara la nueva sesión; no cambia silenciosamente la generación de una cuenta con consentimiento instalado. Después del cierre confirmado del transporte, la transición aplica CAS sobre cuenta, generaciones, consentimiento, revisión y fence esperados, bajo bloqueo de sesión y de fila. Registra identificador idempotente, actor, motivo, generaciones y consentimiento anterior; revoca este consentimiento, retira su puntero activo y deja una marca durable de captura pendiente. El cambio de generación, cierre del consentimiento y auditoría se confirman juntos. El inventario sigue disponible; ninguna política v1/v2 puede admitir captura mientras exista esa marca.

Instalar el primer consentimiento de B exige esa transición pendiente exacta, inventario y autorizaciones de B, conserva el predecesor auditado y retira el bloqueo en la misma transacción. La renovación ordinaria mantiene la prohibición de cruzar generaciones. Debe admitirse también la reparación explícita del estado ya producido por el código actual: cuenta B con consentimiento A. No se permite asumir cierre por vencimiento del lease ni reconocer implícitamente fallos pendientes.

**Justificación contrastada.** `internal/telegramv2/client.go:291` cambia la generación durante el cliente, conservando el consentimiento. `production.go:136–152` exige simultáneamente generación vigente y predecesor de esa generación: confirma el bloqueo. Además, `production.go:225–229` separa consumo por generación; permitir simplemente otro sucesor recuperaría cuota gastada. `store.go:89` y `failure.go:112` muestran que hay que preservar también el bloqueo por fallos y su reconocimiento. Es una mejora operativa necesaria y distinta de la recuperación de diferencias de la propuesta 2.

**Cuotas y compatibilidad.** Acotar esta entrega con una regla conservadora: suspender captura hasta la siguiente frontera del periodo original de una hora, conservando ancla, ventana y límites globales/por fase. Mantener cualquier espera de cuota o FloodWait posterior. Así no reaparece cuota dentro del periodo consumido, sin copiar contadores ni rediseñar el ledger; el coste es perder la cuota restante de esa hora. Conservar intactos consumo, consentimientos y fallos históricos. Toda cuenta con `active_capture_budget` piloto v1 se rechaza en preflight, antes de modificar cuenta o sesión; no borrar registros ni debilitar el trigger de `006_native_capture_budget.sql:33–38`. Migrar pilotos queda fuera.

**Alcance y migración.** `internal/telegramv2` —autenticación, consentimiento, admisión y comprobaciones de cierre—, CLI en `cmd/noctis/channels_v2.go`, contrato operativo y migración aditiva para transición/auditoría y bloqueo pendiente. No modificar migraciones publicadas ni reparar automáticamente cuentas existentes. No incluye recuperación histórica ni resolución de discontinuidades.

**Aceptación.**

1. PostgreSQL sintético: A→autenticación B→cierre→transición→inventario/autorización B→consentimiento B funciona sin SQL manual; cubrir también cuenta B/consentimiento A preexistente.
2. Antes de completar la transición y el consentimiento, políticas/owners antiguos y rutas v1 no realizan captura ni escrituras; inventario antiguo falla.
3. Dos transiciones concurrentes producen una ganadora; repetir identificador y contenido devuelve el mismo resultado; reutilizarlo con otro contenido falla. CAS obsoleto, cierre incierto, fallo pendiente o rollback no dejan autorización parcial. Un fallo de inventario B no se atribuye al consentimiento A.
4. Rotaciones repetidas, cambio de periodo, cuota agotada y FloodWait no recuperan cuota ni acortan esperas; historial intacto y renovación normal conservada.
5. Piloto rechazado sin cambios. Ejecutar pruebas focalizadas Go/PostgreSQL sin omisiones, comprobador de migraciones y checks canónicos antes de integrar.

**Revisión realizada:** lectura de las veinte propuestas, código, esquema y regresiones. Consulta crítica Astra completada; sin implementación, ejecución de pruebas ni acciones externas.


## 4- Permitir inferencia manual mediante un opt-in separado

**Estado: ACEPTADA**

**Propuesta final.** Añadir `--manual-inference`, desactivado por defecto, para ejecutar solicitudes manuales sin planificar ni consumir trabajos automáticos. Definir expresamente las cuatro combinaciones: ambos flags desactivados conservan el worker mecánico; solo manual ejecuta solicitudes manuales; automático activado, con cualquiera de los valores de manual, conserva ejecución y planificación actuales.

**Justificación contrastada.** La API admite y persiste solicitudes (`internal/runtimev2/ai_api.go:85`), pero el gate compartido impide ejecutarlas (`internal/runtimev2/runtime.go:222`). El problema es real y no está resuelto por las propuestas de tarifas, transporte o historial. Quitar simplemente ese gate rompería la garantía productiva de cero inferencia (`deploy/v2/production/README.md:174`) y su regresión (`internal/runtimev2/mechanical_worker_test.go:15`). El nuevo opt-in permite recuperar utilidad sin cambiar el comportamiento de instalaciones existentes.

**Diseño y alcance revisados.** Mantener `Store.Once` compatible y añadir una selección interna explícita para el modo manual. Centralizar el actor `system:semantic-planner`, único productor automático actual (`internal/inference/planner.go:33,53`). Aplicar su exclusión a la expresión completa, entre paréntesis, de elegibilidad en `claim`: `queued`, `retry_wait` y `running` con lease vencido (`internal/inference/jobs.go:271`). No clasificar por prefijos de `request_id` ni por parámetros enviados por el cliente: el actor procede de la sesión y `Submit` no expone ese campo (`internal/runtimev2/api.go:109`, `internal/inference/contracts.go:93`). Documentar el identificador como reservado; una configuración administrativa que colisione debe diagnosticarse explícitamente, sin reinterpretar sus trabajos como automáticos o manuales.

La agrupación y la caché ya exigen el mismo actor (`jobs.go:326,345`); conservar esa separación. Mantener la reconciliación de intentos abandonados (`jobs.go:267`), incluso automáticos: reconocer incertidumbre no autoriza otro envío. Reutilizar reservas, límites, autorización previa al envío, fences y cancelación. No crear una cola, ledger o migración nuevos. Alcance: configuración/CLI, ejecución/selector, diagnóstico de identidad reservada, documentación y regresiones focalizadas.

El opt-in habilita también las solicitudes manuales antiguas todavía elegibles: declararlo en ayuda y operación, sin borrar ni reenviar trabajos para vaciar la cola. Los flags son por worker y no cancelan peticiones ya enviadas ni deshabilitan otros procesos. No activar producción ni contactar proveedores reales durante esta mejora. La validación de tarifas permanece en la propuesta 6.

**Aceptación verificable.**

1. Probar las cuatro combinaciones con PostgreSQL y proveedor HTTPS sintéticos. Ambos flags desactivados mantienen procesamiento mecánico y cero llamadas/intentos IA.
2. Solo manual completa una solicitud autenticada sin planificar; backlog automático más antiguo no impide atenderla ni produce intentos nuevos, incluidos reintentos y leases vencidos.
3. Intentos inciertos mantienen exposición y bloqueo; agrupación/caché no incorporan trabajos automáticos. Campos de procedencia suministrados en el POST se rechazan y la identidad administrativa reservada obtiene diagnóstico explícito.
4. Preservar pausa general, presupuestos, cancelación y planificación automática idempotente, incluyendo solicitudes manuales anteriores al opt-in y ausencia de duplicados después de reiniciar.
5. Ejecutar regresiones focalizadas de `internal/inference`, `internal/runtimev2` y configuración/CLI, comprobando que PostgreSQL no provoque omisiones.

**Verificación de esta revisión:** inspección de las veinte propuestas y del código vigente en `1eacfc7`; consulta crítica Astra completada. Sin implementación, pruebas ejecutadas ni acciones externas. Aceptación del diseño; su implementación sigue pendiente.


## 5- Impedir reintentos tras respuestas HTTP de éxito no admitidas

**Estado: ACEPTADA**

**Propuesta final.** En el transporte compartido por Chat y Responses, clasificar cualquier estado HTTP entre 201 y 299 como respuesta incompatible con el protocolo síncrono: `GatewayError` con código estable `response_status_invalid`, `Permanent=true`, `Uncertain=true` y `RetryAfter=0`, sin resultado ni uso aceptados. Mantener HTTP 200 como único estado admitido por los decodificadores actuales. Un cuerpo aparentemente válido, `Location` o `Retry-After` en otra respuesta 2xx no autoriza publicación, sondeo ni reenvío.

Conservar los límites de cuerpo y tiempo, errores inciertos de lectura, autorización previa, bloqueo de redirecciones y clasificación de 400/401/403/429/5xx. No añadir soporte asíncrono, fallbacks ni cambios al consumidor de trabajos. Documentar que éxito HTTP no demuestra ausencia de ejecución cuando falta una respuesta admitida.

**Justificación y evidencia vigente.** Inspección de `1eacfc7`, posterior a la base citada en la propuesta. `internal/inference/transport.go:196` asigna a 2xx distintos de 200 `Permanent=false` y `Uncertain=false`. Sin uso, `jobs.go:473` libera la reserva; `jobs.go:503` programa reintentos. Por tanto, el defecto puede repetir una solicitud ya aceptada y ocultar su exposición, aunque no se haya acreditado un incidente real. El contrato prohíbe asumir idempotencia remota por un header (`rebuild/08-contrato-zrelay.md:32`).

La corrección aprovecha mecanismos existentes: `jobs.go:475` conserva exposición incierta y `jobs.go:506` bloquea el trabajo; el selector de `jobs.go:271` no reclama ese estado. HTTP 200 inválido ya utiliza errores permanentes e inciertos (`transport.go:233`). No se pierde una respuesta actualmente soportada. El coste es conservar reservas y exigir resolución operativa cuando el proveedor incumpla el contrato, comportamiento coherente con la incertidumbre. No duplica las propuestas de habilitación manual, tarifas, historial ni entrega del outbox: corrige exclusivamente clasificación del transporte IA.

**Alcance.** `internal/inference/transport.go`, sus pruebas, una regresión focalizada reutilizando la fixture de `internal/runtimev2/ai_test.go` y el contrato de transporte. Sin migraciones, cambios de colas o corrección retroactiva del ledger. Se amplía la verificación original porque una única llamada a `wire` no demuestra que el worker deje de reintentarlo.

**Aceptación y verificación prevista.**

1. Para ambos adaptadores, servidor sintético con 201, 202, 204 y representantes adicionales de 201–299: comprobar código, ambos flags, `RetryAfter=0`, resultado/uso vacíos y una solicitud física. Incluir 201 con envelope válido y 202 con `Location`/`Retry-After`; ninguna cabecera provoca otra petición.
2. HTTP 200 válido conserva resultado/uso; 200 inválido, 400, 401, 403, 429, redirecciones y 500 conservan su clasificación, incluido el reintento permitido de 429.
3. Con PostgreSQL sintético, una respuesta 202 deja el trabajo `dependency_blocked`, el intento `uncertain`, la exposición máxima reservada y ningún resultado publicado. Repetir `Once` desde una instancia nueva no crea otro intento ni llamada.
4. Ejecutar `go test ./internal/inference ./internal/runtimev2` con la base sintética configurada y comprobar que la regresión de integración se ejecuta sin omisión.

**Verificación realizada:** lectura de las veinte propuestas, código y pruebas existentes; sin implementación, ejecución de pruebas ni acciones externas.


## 6- Exigir una tarifa explícita antes de habilitar inferencia

**Estado: ACEPTADA**

**Propuesta final.** Rechazar en `Store.Validate` todo binding habilitado cuya `price.version`, tras `strings.TrimSpace`, esté vacía o coincida con `unconfigured` mediante `strings.EqualFold`. Normalizar exclusivamente para comparar: no reescribir la versión persistida ni cambiar la identidad histórica de una tarifa. Mantener el marcador predeterminado en bindings deshabilitados y conservar las demás restricciones actuales de precios, límites y presupuestos.

Permitir tarifas cero con una versión explícita: ese valor representa una decisión del operador sobre una ruta gratuita, no una comprobación del precio remoto. Exigir importes positivos impediría casos legítimos y tampoco demostraría que la tarifa indicada es correcta.

**Justificación y evidencia.** En el árbol revisado (`1eacfc7`), `DefaultConfig` introduce el marcador con ambos importes cero (`internal/inference/config.go:34`); la validación solo exige actualmente una versión no vacía y precios dentro del intervalo admitido (`:164–168`). Por ello, completar conexión, modelo y presupuestos permite habilitar una función sin sustituir la tarifa inicial. El máximo reservado y el coste liquidado multiplican tokens por esos importes (`internal/inference/jobs.go:365`, `:469`): con ambos a cero, las llamadas no incrementan la exposición monetaria calculada.

La defensa pertenece a la validación compartida: `Save` la ejecuta antes de conectar o iniciar cambios (`config.go:173–179`), y los endpoints de validación y guardado ya llegan a ella (`internal/runtimev2/ai_api.go:66`, `:79`). No hacen falta comprobaciones duplicadas en el handler, migraciones ni cambios del transporte. La UI ya permite editar versión e importes (`web/src/v2/AISettings.jsx:20`). Revisadas las veinte propuestas, esta corrige una precondición de configuración distinta del consumo manual de la 4 y de la clasificación HTTP de la 5.

**Alcance y compatibilidad.** Validador, pruebas focalizadas y documentación del requisito. Conservar el JSON, `ErrInvalid`, revisiones, CAS, cifrado y ledger. Una configuración heredada con el marcador debe poder leerse y guardarse después de deshabilitar sus bindings afectados; no añadir validación al leer que impida esa recuperación. El cambio no neutraliza automáticamente configuraciones antiguas ya habilitadas: antes de activar inferencia debe revisarse su tarifa vigente, sin modificar datos persistidos mediante esta propuesta.

**Aceptación.**

1. La configuración predeterminada deshabilitada sigue siendo válida. Habilitar una función completamente configurada salvo su tarifa falla con `unconfigured`, variantes de mayúsculas/espacios y versión vacía o solo espacios.
2. Una versión explícita permite precios válidos, incluido cero; negativos, valores superiores al máximo y versiones demasiado largas siguen rechazados. El contenido de versiones válidas permanece intacto.
3. `POST /api/v2/ai/validate` y `PUT /api/v2/ai/config` rechazan la misma configuración. El guardado rechazado no crea revisión ni modifica secretos o promociones, incluso si la petición intenta cambiar una credencial; no contacta al proveedor.
4. Una configuración heredada puede deshabilitarse y guardarse conservando el marcador; una tarifa explícita permite habilitarla posteriormente.

**Verificación prevista.** Pruebas unitarias tabuladas en `internal/inference` y regresión API/PostgreSQL sintética en `internal/runtimev2`, comprobando ejecución efectiva sin omisiones. Revisión realizada por inspección; no se implementó ni ejecutaron pruebas.


## 7- Reconciliar la aplicabilidad vigente y retractar afectaciones obsoletas

**Estado: ACEPTADA**

**Propuesta final.** Mantener `local_applicability` como historial y añadir una proyección vigente por CVE/activo, con snapshot, revisión del activo, generación de cálculo, estado, motivo y vencimiento. Publicar transiciones idempotentes hacia `affected_version`, `not_affected_version` y `unknown`; conservar procedencia e historial, sujeto a la retención existente. Siempre `local_exposure: unknown`.

Seleccionar primero el registro NVD vigente **por CVE** y después comprobar su TTL: un vigente caducado produce `unknown`, nunca recuperación de otro snapshot antiguo todavía fresco. Usar `lastModified` válido como revisión; para legado sin ese dato, recurrir a `as_of` únicamente cuando ningún registro del CVE tenga revisión válida. Un registro nuevo sin revisión fiable frente a datos versionados, o un empate de revisión con cuerpos contradictorios, exige `unknown` y diagnóstico; no decidir por orden de procesamiento. Desempatar representaciones equivalentes mediante claves persistidas. La ausencia del CVE en páginas incrementales no lo retira.

Revalidar evidencia del inventario y pertenencia al expediente antes de publicar. Agregar todas las parejas vigentes: cualquier afectación válida mantiene `affected_version`; `not_affected_version` requiere cobertura completa, no vacía y sin desconocidos; los demás casos son `unknown`. No perder esta proyección al incorporar observaciones o crear otra revisión del expediente.

La caducidad debe producir trabajo durable e idempotente, recuperable después de reiniciar. Mientras haya resultados obsoletos, caducados o pendientes, las lecturas de aplicabilidad y expedientes deben distinguir estado efectivo de historial. Aplicar la misma vigencia al preparar contexto derivado y a briefs: invalidarlos al cambiar soporte y evitar que regenerarlos convierta una afectación histórica en afirmación actual.

**Justificación contrastada.** En `1eacfc7`, `internal/vulnv2/applicability.go:221` cruza todos los snapshots; `:254` conserva filas mediante conflicto ignorado y `:308` solo establece afectación. `internal/runtimev2/domain_api.go:101` únicamente comprueba TTL, incluso para revisiones superadas; `api.go:240` devuelve el expediente materializado sin esa defensa. Además, `internal/intelligence/worker.go:199` reconstruye su cuerpo y `:237` genera briefs desde cambios históricos. Corregir solamente la inserción o añadir una transición inversa dejaría inconsistencias visibles. El valor es eliminar falsas afectaciones actuales sin convertir falta de datos en seguridad demostrada.

**Alcance y coordinación con 8.** Esta propuesta posee selector, proyección efectiva, agregación, identidad de transición, caducidad e invalidación; cambios focalizados en `vulnv2`, lecturas/consumidores y migración aditiva. La 8 posee cola, progreso, leases/fence, paginación y límites, incluido el recorrido de expedientes. Compartir entradas `CVE + snapshot/revisión NVD + activo/revisión + generación` y comprobarlas al confirmar resultados: un trabajo obsoleto no publica. Inventario, ingesta y cambios de membresía generan trabajo mediante esa única maquinaria. Integrar ambas sobre este contrato; no duplicar schedulers, cambiar comparadores CPE/versiones ni modificar los reintentos generales de la 13.

**Aceptación.**

1. Activo afectado → versión excluida: retractación visible e historial conservado; otro activo afectado mantiene el agregado.
2. Corrección A→B y replay de A, empates, revisión ausente y páginas sin el CVE: selección estable y conservadora.
3. TTL, evidencia retirada y caída del worker: lecturas nunca afirman vigencia obsoleta; recuperación genera una sola transición e invalida/regenera briefs correctamente.
4. Dos workers, inventario/ingesta concurrentes y nueva membresía: sin publicaciones antiguas, revisiones duplicadas ni pérdida del agregado.
5. Migración preserva historial; pruebas PostgreSQL/API amplían `stories_test.go` y `feeds_domain_test.go`, incluyendo contexto derivado y estados incompletos.

**Verificación realizada:** inspección de código, esquema y las veinte propuestas; sin implementación, pruebas ni acciones externas.



## 8- Procesar la aplicabilidad por lotes durables sin bloquear el inventario

**Estado: ACEPTADA**

**Propuesta final.** Separar la confirmación del inventario y los snapshots NVD de su cálculo de aplicabilidad mediante trabajo durable, acotado y recuperable. Implantar después del contrato de vigencia de la propuesta 7; esta propuesta aporta ejecución y progreso, sin redefinir qué evidencia gobierna una afectación.

**Justificación contrastada.** `internal/runtimev2/domain_api.go:325–346` enumera todos los CVEs dentro de la transacción del activo y revierte con más de 1.000. `internal/vulnv2/applicability.go:221–251` cruza snapshots históricos con activos y rechaza incluso exactamente 1.000 filas. `internal/vulnv2/feeds.go:298–317` ejecuta ese cálculo antes de confirmar snapshot y cursor. Elevar los límites conserva transacciones crecientes bajo el bloqueo global de proyección. La separación resuelve un bloqueo real de capacidad; el coste es introducir consistencia eventual explícita.

**Alcance y contrato con 7.**

- Confirmar revisión/snapshot, cursor de captura y solicitud idempotente en su transacción correspondiente. Guardar identidad de entrada y versión del cálculo; conservar CAS, validación de evidencia y campos existentes de respuesta. Añadir estado consultable de cálculo pendiente, completo o fallido. El consumidor es mecánico, respeta la pausa global y funciona con inferencia desactivada.
- Un cambio de activo recorre CVEs para esa revisión; un snapshot recorre activos para sus CVEs. Paginar por claves estables con orden total y cota superior fijada al iniciar el recorrido después de su confirmación. Todo cambio posterior genera trabajo propio; las carreras entre ambas direcciones deben cubrir también los elementos insertados detrás del cursor. No materializar el producto completo al guardar ni mantener una transacción abierta entre páginas.
- Usar un job independiente por página y `jobs.FinishTx` para confirmar conjuntamente resultados, progreso y siguiente página. `jobs.Claim` incrementa intentos en cada reclamación (`internal/jobs/store.go:38`): reciclar el mismo job por página consumiría indebidamente sus cinco intentos. Mantener reintentos por fallos y recuperación visible de cuarentenas; no cambiar la semántica general de `parse` ni la propuesta 13.
- Acotar también las publicaciones de expedientes: `applicability.go:268–290` actualmente recorre todos los expedientes coincidentes por cada pareja. El progreso incluye esa continuación; no declarar completado un cálculo con publicaciones pendientes. Mantener transacciones breves y comprobar lease/fence al confirmar.
- La propuesta 7 selecciona snapshot/revisión vigentes, agrega estados, retracta e invalida derivados. Antes de publicar cada lote, comprobar esas identidades, generación y vigencia; el backlog obsoleto nunca restaura un resultado antiguo. 8 expone progreso/generación para que 7 degrade lecturas no acreditadas a `unknown` con cálculo pendiente. Los disparadores semánticos de caducidad o membresía definidos por 7 reutilizan esta maquinaria.

Migración adicional para progreso e índices; adaptación del worker, API, pruebas y presentación mínima del estado. Sin ampliar comparadores CPE/versiones ni construir otro sistema genérico de colas.

**Aceptación verificable.**

1. Con 999, 1.000 y 1.001 CVEs/activos y más de cinco páginas, guardar y capturar terminan sin calcular toda la matriz; el trabajo alcanza cobertura completa.
2. Caídas antes/después del commit, dos workers y lease vencido: sin omisiones, publicaciones duplicadas ni continuación perdida.
3. Altas y revisiones concurrentes a ambos lados del cursor: cobertura final vigente, sin resurrecciones; fallos y pendientes visibles.
4. Acotar filas por transacción incluyendo expedientes; medir duración con fixtures crecientes. Comparar resultados pequeños con el contrato corregido de 7.
5. Adaptar `stories_test.go` y `feeds_domain_test.go`; verificar migración y regresiones PostgreSQL sin omisiones, conservando campos API anteriores.

**Verificación de esta revisión:** inspección estática; sin implementación, pruebas ejecutadas ni acciones externas.


## 9- Sustituir de forma atómica la pregunta que gobierna una fuente

**Estado: ACEPTADA**

**Propuesta final.** Establecer **cero o una pregunta gobernante por fuente**, conservando las fuentes con políticas independientes. Al reasignar A→B, sustituir la asociación y la política en una misma transacción, bajo el bloqueo de proyección, CAS e idempotencia existentes. Una pregunta gobierna tantas fuentes como corresponda. Documentar `question_sources` como relación vigente; la procedencia de discovery y los productos históricos mantienen sus referencias originales.

Resolver la identidad de la pregunta y su política vigente desde el servidor. Rechazar un `question_id` incompatible y una asignación explícita con revisión de política obsoleta, sin modificar estado. Si se omite la política, conservar la asignación actual; cambiar explícitamente a una política independiente elimina la relación gobernante. No aceptar una pregunta acompañada de una política independiente. Aplicar la misma invariancia a la activación discovery, que ya selecciona la revisión actual.

Añadir una migración nueva con unicidad de `question_sources.source_id`. Para datos existentes, identificar la relación vigente mediante la política canónica y conservar sus metadatos. Abortarla transaccionalmente con diagnóstico de las fuentes afectadas ante identidad ambigua, política incoherente o cualquier reconciliación que **amplíe la autorización efectiva**. No basta con conservar `sources.enabled`: eliminar una asociación antigua pausada puede autorizar captura sin cambiar ese campo. Los casos bloqueados requieren conciliación explícita previa, sin elección arbitraria ni activación automática. Conservar políticas, preguntas, recibos y procedencia histórica.

**Justificación.** El defecto está confirmado: `operations_api.go:362–372` acumula asociaciones; `:289–294` permite a cualquiera de ellas sobrescribir política y generar trabajos; `authorization.go:12` permite a cualquiera bloquear captura. La política efectiva es singular y `source_resume.go:27` ya crea trabajos para esa política. Una gobernante única resuelve la contradicción sin introducir combinación de políticas ni nuevas reglas de análisis. La cardinalidad es compatible con políticas independientes solo si admite cero relaciones; exigir exactamente una rompería esos casos. La migración original omitía el riesgo de ampliar autorización al retirar asociaciones pausadas.

Las autorizaciones discovery y el consentimiento Telegram son independientes de esta reasignación: sus revocaciones siguen bloqueando la fuente. No convertir el cambio analítico en concesión de permisos. Sin frontend ni cambios al reloj de reintentos de la propuesta 13; la propuesta 16 aborda únicamente recuperación de conflictos en pantalla.

**Aceptación.**

1. A→B seguido de editar/pausar A no cambia política, autorización ni trabajos vigentes de B; editar B sí los actualiza. Pausar B bloquea captura/publicación y reanudarla conserva la pausa propia de la fuente.
2. Combinaciones incoherentes, política obsoleta y CAS fallido no producen cambios; repetir `request_id` conserva un solo efecto.
3. Carrera con edición de A y trabajos antiguos: resultado serializable por el bloqueo vigente, sin publicación de A después del relevo.
4. Cubrir política independiente↔pregunta, activación discovery y revocación de su permiso tras reasignar.
5. Migrar fixtures con cero, una y varias asociaciones; verificar unicidad, conservación de metadatos y rollback ante ambigüedad o ampliación de autorización. Ejecutar regresiones PostgreSQL/HTTPS y comprobador de migraciones antes de integrar.

**Verificación realizada:** lectura de las veinte propuestas y contraste estático con código, esquema y `TestCore005PIRRevisionPauseOwnSourceAndDiscoveryRevokePostgresHTTPS`. Sin implementación, pruebas ejecutadas ni acciones externas.


## 10- Acotar la admisión de autenticación antes de acceder a PostgreSQL

**Estado: ACEPTADA**

**Propuesta final.** Introducir admisión local previa a PostgreSQL conservando `NewHandler`, el contrato de sesiones y las comprobaciones actuales de método y Origin:

- Para rutas privadas, devolver `401 authentication_required` sin conexión ante cookie ausente o token distinto del formato emitido por `random`: 64 caracteres hexadecimales minúsculos. El formato válido nunca sustituye la consulta de expiración y revocación.
- Para login, consumir un presupuesto temporal global por instancia API antes de leer el cuerpo. Aplicarlo también a JSON inválido y credenciales correctas; al agotarse, devolver `429` con `Retry-After` positivo y coherente con la recuperación. Rechazar cuerpo superior a 4096 bytes, campos desconocidos o contenido adicional tras el objeto. Comparar credenciales localmente en tiempo constante; solo un login válido puede conectar e insertar la sesión.
- Limitar, mediante adquisición inmediata sin cola, las solicitudes concurrentes que entran en la fase de base de datos. Devolver `503` al saturarse; conservar el permiso hasta terminar el handler y cerrar su conexión, con cierre acotado también tras cancelación. Documentar capacidad, ráfaga y reposición; usar reloj inyectable y estado sincronizado, sin bloquear una cuenta permanentemente ni confiar en cabeceras de IP.

**Justificación y corrección del alcance.** El defecto está confirmado: `internal/runtimev2/api.go:93` conecta antes de comprobar cookie (`:103`) y credenciales (`:173`). El cambio elimina trabajo de PostgreSQL para rechazos decidibles localmente y acota la admisión restante. No se ha medido saturación.

El límite se debe expresar en **solicitudes admitidas**, no como máximo total de conexiones: `api.go:140` delega manteniendo su conexión; `internal/inference/jobs.go:38,119,141` abre conexiones adicionales para `Submit` y `Job`. Esta mejora no requiere convertir los almacenes a un pool ni garantiza capacidad global de PostgreSQL. Tampoco cubre sondas, workers o collectors.

La restricción de token conserva las sesiones emitidas por el servidor, pero obliga a corregir fixtures que insertan UUID como token (`internal/runtimev2/stories_test.go:135` y `feeds_domain_test.go:136`), empleando `random()`. La UI ya distingue `429` (`web/src/v2/LoginScreen.jsx:7`); no necesita rediseño.

**Alcance final.** `api.go`, helper privado, pruebas focalizadas/fixtures y documentación operativa. Mantener ocho horas de expiración, hash persistido, cookies Secure/HttpOnly/SameSite, Origin, CSRF y logout. Sin migraciones, cambios TLS/readiness —propuestas 11 y 12— ni limitador distribuido.

**Aceptación.**

1. Con conector instrumentado, cookie ausente/malformada, JSON inválido y credenciales incorrectas realizan cero conexiones; credenciales válidas con DB caída devuelven `503`. Preservar la precedencia de `405` y `403` por método/Origin.
2. Reloj controlado demuestra ráfaga, reposición, `429`, `Retry-After` y consumo por todos los intentos admitidos, incluidos éxitos, sin esperas reales.
3. Concurrencia instrumentada demuestra el máximo de solicitudes en fase DB, rechazo inmediato y recuperación de permisos tras error/cancelación; ejecutar estas pruebas con `-race`.
4. Regresiones PostgreSQL verifican login, cookies, hash, CSRF, revocación y expiración, incluyendo fixtures actualizadas y ausencia de omisiones inesperadas.

**Límites y verificación.** El presupuesto se reinicia al reiniciar y se multiplica con réplicas. Un atacante sostenido puede impedir nuevos logins mientras agote el presupuesto global; cookies falsas bien formadas también pueden competir por la capacidad DB. Documentar estos límites y ajustar umbrales con carga representativa antes de producción. Revisión de las veinte propuestas e inspección estática completadas; sin implementación ni pruebas ejecutadas.


## 11- Validar TLS y el origen canónico antes de abrir la API

**Estado: ACEPTADA**

**Justificación y evidencia.** La mejora evita una degradación silenciosa de seguridad y errores de configuración detectables antes del arranque. En el árbol revisado (`1eacfc7`), `internal/runtimev2/runtime.go:104–107` sirve HTTP cuando solo se configura certificado o clave. Además, abre el listener antes de cargar el par y consulta PostgreSQL antes de comprobar la configuración HTTP (`:84–105`). `api.go:29` admite cualquier `Origin` no vacío, aunque después exige coincidencia literal (`:89`); una URL con ruta inutiliza las mutaciones del navegador. Las veinte propuestas se han contrastado: esta conserva un objetivo independiente de admisión/autenticación (10) y readiness (12).

**Propuesta final.** Validar la configuración HTTP exclusivamente al arrancar `serve --mode api`, antes de consultar PostgreSQL o abrir puertos:

- Rechazar certificado o clave aislados. Con ambos presentes, cargar y comprobar el par criptográfico una sola vez y utilizar ese mismo material para servir TLS. Un fallo de lectura, formato o correspondencia impide arrancar; nunca habilita HTTP. La carga no debe confundirse con una certificación de confianza pública, SAN o vigencia.
- Exigir un origen HTTP/HTTPS canónico: esquema y host válidos, puerto válido si aparece, sin credenciales, ruta —incluida `/`—, query, fragmento ni espacios. Rechazar formas no canónicas con un diagnóstico explícito; cubrir mayúsculas y puertos predeterminados para que una configuración aparentemente válida no difiera de la serialización del navegador. Admitir hosts DNS ASCII/punycode, IPv4 e IPv6 válidos. Mantener la comparación exacta de las peticiones, sin normalizarlas ni añadir coincidencias por sufijo.
- Reutilizar el validador del origen en `NewHandler`, que también se instancia directamente en pruebas y otros consumidores. La precarga TLS pertenece al arranque del servidor; construir un handler no obliga a suministrar certificados.
- Con ambos archivos ausentes, conservar HTTP interno para terminación TLS externa y documentarlo expresamente. El origen público HTTPS y el TLS del salto interno son decisiones independientes: no inferir el modo mediante `Forwarded`, `X-Forwarded-*` o el esquema del origen, ni exigir que el certificado interno coincida con este último.

**Alcance y compatibilidad.** Limitar cambios a configuración HTTP, `Run`, validación de origen, pruebas y documentación CLI/despliegue. No imponer estos requisitos en `configv2.Load`: `cmd/noctis/v2.go:64` lo utiliza también para `migrate`. Worker, collector y comandos administrativos conservan sus requisitos. Mantener cookies `Secure`, CSRF, autenticación y contratos SQL; no habilitar HTTP público como solución para el acceso autenticado. Preservar el despliegue TLS API/Traefik descrito en `deploy/v2/production/README.md:111–117`.

**Aceptación y verificación prevista.**

1. Matriz TLS ausente/completo/incompleto, archivos ilegibles, PEM inválido y par incompatible: los errores se detectan antes de DB/listener; las rutas no HTTP siguen funcionando sin estos campos.
2. Matriz de origen válido DNS/IP/puerto y rechazos anteriores, incluidos vacío, `null`, puerto fuera de rango, query/fragmento vacíos y formas no canónicas. Un origen distinto conserva `403`.
3. Integración con certificado sintético: HTTPS efectivo, ningún endpoint de aplicación utilizable mediante HTTP y cierre correcto del servidor.
4. Proxy HTTPS sintético hacia backend HTTP: login y mutación autenticada funcionan con el origen público, cookies y CSRF existentes, sin confiar en cabeceras reenviadas.
5. Ejecutar pruebas focalizadas de configuración/runtime y regresiones existentes de autenticación antes de integrar.

**Comprobación de esta revisión:** inspección estática de código, documentación y pruebas; sin implementar cambios ni ejecutar pruebas. La aceptación aprueba el diseño acotado, no acredita su implementación.


## 12- Readiness basada en esquema efectivo y permisos del runtime

**Estado: ACEPTADA**

**Propuesta final.** Hacer que `Check` anuncie disponibilidad únicamente después de verificar el ledger exacto, la estructura indispensable y los privilegios efectivos del modo solicitado. Mantener los campos JSON y `/livez` independiente de PostgreSQL. No exigir configuración IA ni contenido de usuario para considerar disponible una base recién migrada.

**Justificación crítica.** El defecto sigue presente en el código inspeccionado: `internal/runtimev2/runtime.go:45` comprueba cinco tablas; `:46` anuncia esquema antes de validar el ledger; `:76` activa funcionalidad antes de consultar `ai_configs`. Así, un error posterior puede producir `functional:true` junto a HTTP 503 (`api.go:46`). Además, el login necesita insertar en `sessions` (`api.go:180`), permiso que la comprobación actual no verifica. Los grants posteriores a migraciones están expresamente documentados en `deploy/v2/runtime-grants.sql:14` y `deploy/v2/production/README.md:79`.

Se acepta con un contrato acotado: una sonda no debe convertirse en un comparador general de backups ni exigir permisos adicionales para superar sus propias consultas. Tampoco basta con comprobar nombres de restricciones: la ausencia o desactivación de invariantes críticos puede permitir operaciones inseguras; por ejemplo, la inmutabilidad de configuraciones IA depende de triggers (`migrations/v2/004_inference.sql:12`).

**Alcance final.**

- Conservar compatibilidad exacta de nombres/checksums de migraciones. Añadir un manifiesto explícito de relaciones, columnas/tipos y claves, restricciones y triggers críticos requeridos por las operaciones soportadas; comprobar su definición y estado efectivo cuando corresponda. Excluir índices meramente de rendimiento y objetos ajenos al contrato.
- Verificar mediante catálogos y consultas agrupadas, exclusivamente de lectura, sin escrituras de ensayo ni análisis del SQL mediante expresiones regulares. Mantener el límite temporal de readiness; no recorrer datos de negocio ni añadir una consulta por objeto.
- Declarar privilegios por modo y operación real, incluidos `USAGE` del esquema y lectura del ledger. Evaluar los permisos efectivos de la conexión y su herencia, sin depender del nombre del rol ni exigir CRUD universal. La sonda no concede permisos, cambia roles ni ejecuta migraciones. La revisión no rediseña los grants existentes ni certifica mínimo privilegio.
- Establecer `Schema=true` solo después de ledger y estructura; `Functional=true` y capacidades operativas únicamente después de todas las comprobaciones, incluida `ai_configs`. Un fallo de permisos puede conservar `Database=true` y `Schema=true` si ambas fases concluyeron correctamente.
- Mantener el manifiesto junto al código y contrastarlo con una base creada mediante todas las migraciones embebidas. Actualizar pruebas y documentación de diagnóstico; evitar exponer detalles de credenciales en respuestas públicas.

**Aceptación.**

1. Base vacía migrada y LOGIN restringido real: éxito para cada modo, sin IA configurada; cubrir permisos heredados.
2. Revocar `INSERT` de `sessions` bloquea readiness de API; restaurarlo recupera disponibilidad. No exigir ese permiso a modos que no lo utilizan.
3. Ledger intacto con tabla/columna requerida ausente, restricción crítica alterada o trigger crítico desactivado: rechazo sin funcionalidad.
4. Migración pendiente/adicional, checksum alterado o error consultando `ai_configs`: rechazo coherente; `/livez` sigue disponible.
5. Verificar aislamiento de roles y ejecución efectiva de regresiones PostgreSQL/HTTP, sin omisiones; confirmar que las sondas no modifican datos ni requieren DDL.

**Límites y comprobación.** Inspección de las veinte propuestas y del código vigente; sin implementación ni pruebas ejecutadas. No duplica autenticación/TLS (10–11), publicación de configuración restaurada (19) ni validación del artefacto (20). La disponibilidad es una comprobación puntual del contrato, no garantía de futuras operaciones ni auditoría completa de seguridad.


## 13- Conservar el horizonte pendiente de los trabajos aparcados por pausa

**Estado: ACEPTADA**

**Propuesta final.** Aparcar los trabajos `parse` elegibles tanto desde `queued` como desde `retry_wait` y excluir del horizonte de 24 horas únicamente el tiempo documentado en estado aparcado. Persistir un vencimiento efectivo y el comienzo del aparcado, usando el mismo criterio en `Claim`, `Fail` y reanudación. Al despertar, desplazar el vencimiento por la duración de ese aparcado y limpiar su comienzo una sola vez. No conceder 24 horas nuevas, modificar `created_at` ni rehabilitar trabajos cuyo presupuesto ya estaba agotado al aparcar.

**Justificación contrastada.** `internal/runtimev2/source_resume.go:13` solo aparca `queued`; `:21` despierta mediante `source_resumed`. `internal/jobs/store.go:38` permite entonces una reclamación fuera del horizonte, pero elimina ese marcador; `:101` vuelve a decidir por `created_at`. Un fallo transitorio tras una pausa larga puede agotar artificialmente el trabajo. La regresión `core005_regression_test.go:345` prueba finalización correcta tras pausa, sin cubrir ese fallo. La mejora tiene valor operativo y no duplica otras propuestas: afecta al procesamiento mecánico posterior a captura, sin alterar transporte, aplicabilidad ni inferencia IA.

**Alcance y garantías.** Nueva migración aditiva, `source_resume.go`, ciclo de vida de `internal/jobs/store.go`, regresiones y contrato operativo. `FinishTx` (`store.go:69`) debe iniciar el mismo reloj al aparcar; `Replay` (`:117`) debe inicializarlo correctamente, manteniendo su carácter de reinicio explícito autorizado. Retirar la excepción temporal de `source_resumed`; un código de error no concede presupuesto. Conservar intentos por fallos reales, límite de cinco, fallos permanentes, fences, autorización y exclusiones por política, revisión, época o evidencia caducada. La pausa no debe adelantar un `retry_at` todavía pendiente.

Mantener el orden de bloqueos y `SKIP LOCKED`: esperar por una fila cuyo `Finish` espera el guard de proyección puede causar interbloqueo (`source_resume.go:17`). Cubrir también la salida por `Fail` y recuperación de leases vencidos, para que una carrera no deje reintentándose trabajo de una fuente todavía pausada. Un intento realmente fallido conserva su consumo. La congelación empieza en la transición durable a aparcado; no se promete descontar retrospectivamente tiempo de ejecución en vuelo, pausa global ni indisponibilidad del worker.

**Compatibilidad y migración.** Para filas existentes, inicializar el vencimiento con `created_at + 24 horas`. En filas antiguas `source_paused`, congelar desde la migración únicamente el saldo positivo así demostrable; no inventar una fecha histórica de pausa. Si ese plazo ya venció, o una fila antigua `source_resumed` dependía de la excepción, conservarla bloqueada con diagnóstico de horizonte desconocido y requerir el `replay` explícito existente para reiniciarla. Documentar y contar estos casos antes de migrar. No resetear masivamente intentos ni despertar cancelados/cuarentenados. Esta política conservadora puede exigir intervención sobre backlog antiguo; evita presentar una reconstrucción imposible como exacta.

**Aceptación.** Probar en PostgreSQL: `retry_wait` → pausa superior a 24 horas → reanudación → fallo transitorio con presupuesto restante; pausas repetidas sin ganancia temporal; horizonte agotado antes de pausa; quinto intento y fallo permanente; backoff pendiente; carreras pausa/reanudación con `Finish`, `Fail` y lease vencido; migración de filas normales y antiguas ambiguas; `Replay` explícito; ausencia de duplicados y de resurrección de evidencia. Ejecutar las regresiones focalizadas con `-race`, comprobar integración sin omisiones y validar migraciones con `tools/check_v2_migrations.py`.

**Comprobación realizada:** lectura de las veinte propuestas y contraste estático del código vigente. Sin implementación, ejecución de pruebas ni acciones externas.


## 14- Validar el destino antes de consumir una entrega del outbox

**Estado: ACEPTADA**

**Propuesta final.** Incorporar una validación compartida y determinista del endpoint antes de conectar a PostgreSQL en `DispatchOnce`. Admitir URLs absolutas HTTP/HTTPS con autoridad utilizable y puerto numérico dentro de rango cuando esté presente; cubrir explícitamente URL relativa, host ausente, escapes malformados, protocolo incompatible, puerto vacío o fuera de rango y sintaxis IPv6 incorrecta. Conservar HTTP local, HTTPS, IPv6 válido, puertos implícitos, rutas y query de destinos existentes. La cadena vacía continúa deshabilitando entregas en la configuración del worker; invocar directamente el dispatcher con ella produce error.

Aplicar el mismo validador al comienzo de `runtimev2.Run` para un worker con destino configurado, antes de `Check`, y en `dispatch-once` antes de su conexión preliminar. Dentro de `DispatchOnce`, seleccionar y revalidar la evidencia bajo los bloqueos actuales; después construir íntegramente la petición, cuerpo y cabeceras antes de actualizar y confirmar `uncertain`. El primer envío al receptor debe ocurrir después de ese commit. Conservar el lock de sesión hasta cerrar la respuesta y registrar el ACK.

**Justificación y evidencia.** Inspección del código vigente en `1eacfc7`: `internal/intelligence/delivery.go:73` cambia el estado y confirma antes de `http.NewRequestWithContext` en la línea 80. El bucle de `internal/runtimev2/runtime.go:169` puede repetir ese consumo para sucesivas filas. El comando manual abre además una conexión propia antes de entrar al dispatcher (`cmd/noctis/v2.go:188`). El defecto es concreto y la corrección evita inmovilizar entregas por configuración sintácticamente inválida.

La garantía crítica procede del lock de sesión de `delivery.go:34`, que sobrevive al commit y ordena entrega frente a revocación. Adelantar la construcción de la petición conserva esa garantía y reduce el intervalo entre admisión durable y envío. DNS, TLS, conectividad y respuestas remotas siguen perteneciendo al envío: cualquier fallo posterior al commit conserva `uncertain`, incluso si no puede acreditarse recepción. Las filas ya inciertas permanecen intactas. Se mantiene el comportamiento actual del cliente respecto a redirects y proxies; la validación no necesita consultas de red ni cambios en políticas de destinos.

**Alcance.** `internal/intelligence/delivery.go`, arranque worker, comando manual y pruebas focalizadas. Sin migración ni estados nuevos. Es independiente de la propuesta 5, dedicada al protocolo de inferencia, y de la 11, dedicada al listener de la API; no requiere unificar sus validadores ni políticas HTTP.

**Aceptación.**

1. Matriz unitaria de URLs inválidas y válidas, incluyendo IPv6, rango de puerto y configuración vacía. Los tres puntos de entrada rechazan un destino inválido antes de intentar conectar a DB.
2. Con PostgreSQL sintético y varias filas autorizadas, llamadas inválidas repetidas producen cero solicitudes y conservan estado, cuerpo y clave de todas ellas. Al corregir el destino, una ejecución entrega una sola fila con su `Idempotency-Key` original.
3. Un fallo al preparar la petición deja la fila en cola; un fallo de envío conserva incertidumbre sin replay automático.
4. Mantener las regresiones de ACK perdido (`product_test.go:222`), SIGKILL (`process_faults_test.go:40`), revocación previa (`process_faults_test.go:123`) y orden de admisión (`core005_regression_test.go:496`), comprobando ejecución efectiva con PostgreSQL.

**Verificación de esta revisión:** lectura de las veinte propuestas, código y pruebas existentes; sin implementación, ejecución de pruebas ni acciones externas. La verificación ejecutable queda pendiente de implementar el cambio.


## 15- Evitar duplicados y respuestas obsoletas en la paginación

**Estado: ACEPTADA**

**Propuesta final.** Corregir exclusivamente `Paged` para que cada carga de recurso tenga una identidad nueva y cada continuación pertenezca a esa identidad y al cursor solicitado. Invalidar y cancelar las peticiones al cambiar `path` o desmontar; comprobar vigencia antes de aplicar cualquier resultado, error, metadato o transición de carga. La cancelación reduce trabajo pendiente, pero no sustituye esa comprobación: debe funcionar también si la respuesta ya se resolvió o el transporte no atiende el aborto.

Adquirir el bloqueo de continuación sin esperar al siguiente render —por ejemplo, mediante una referencia— y admitir solo una petición pendiente. Capturar su cursor al iniciarla; únicamente esa petición vigente puede incorporar su página y liberar el bloqueo. Deshabilitar «Load more records» durante la carga y comunicar ese estado de forma accesible. Un fallo vigente conserva filas y cursor para reintentar; el éxito elimina el error. Una petición antigua tampoco puede desbloquear una continuación nueva.

**Justificación y evidencia.** La inspección del árbol vigente (`1eacfc7`) confirma el defecto: `web/src/v2/Operations.jsx:8` inicia continuaciones sin exclusión y añade resultados al estado existente cuando terminan. Dos activaciones pueden duplicar una página; cambiar pregunta puede mezclar propuestas de recursos distintos. La carga inicial de `:7` también publica éxitos sin comprobar vigencia. `:41` cambia los filtros de discovery y cobertura sin desmontar necesariamente `Paged`; otros consumidores comparten el componente. La comparación de `path` no distingue A→B→A. La solución es pequeña, conserva interfaces y mejora la corrección visible sin cambiar autorizaciones.

**Alcance y compatibilidad.** Modificar `web/src/v2/Operations.jsx` y añadir regresiones en `web/tests/v2-product.spec.js`; mantener firma, orden de resultados, metadatos y cursores existentes. No introducir deduplicación genérica por ID: algunos consumidores no tienen una identidad uniforme y eso ocultaría errores en lugar de impedir solicitudes duplicadas. No cambia la consistencia del listado ante modificaciones concurrentes del servidor.

La propuesta 16 trata la reconciliación de ediciones y comparte ambos archivos: integrar sus cambios secuencialmente y ejecutar la validación sobre la combinación final, sin incluir aquí editores, retención ni `api.js`. La propuesta 17 conserva planes de consulta en `Consumers.jsx`; su paginación es otro flujo y queda fuera.

**Aceptación y verificación requerida.**

1. Dos activaciones rápidas antes de resolver la continuación originan una sola solicitud y una sola incorporación; después se permite solicitar el siguiente cursor.
2. Éxitos y errores tardíos, tanto iniciales como de continuación, no alteran filas, cursor, error ni carga tras A→B o A→B→A. Cubrir desmontaje/remontaje y comprobar que una respuesta antigua no desbloquea trabajo nuevo.
3. Incluir una respuesta controlada que sobreviva a la cancelación para acreditar la comprobación de vigencia, sin depender exclusivamente del aborto de `fetch`.
4. Fallo de continuación conserva lo ya mostrado; reintento correcto añade una página, limpia el error y mantiene el cursor siguiente. Sin cursor desaparece el botón.
5. Ejecutar `npm run build` y `npx playwright test --config playwright.v2.config.js` desde `web/`, con respuestas sintéticas controladas y sin esperas temporales arbitrarias. La prueba real existente de 50→51 afirmaciones (`web/tests/v2-operations-real.spec.js:60`) sigue siendo compatible; no cubre estas carreras por sí sola.

**Límite de la revisión.** Código y propuestas contrastados por lectura; no se implementó ni se ejecutaron pruebas. La aceptación aprueba el diseño acotado, no acredita su implementación.


## 16- Recuperar conflictos de revisión sin perder la edición operativa

**Estado: ACEPTADA**

**Propuesta final.** Completar la reconciliación explícita de políticas de fuente, control global y retención. Separar borrador, estado confirmado y conflicto; conservar la intención del operador y permitir leer el estado vigente antes de decidir un nuevo guardado. Nunca reenviar automáticamente una mutación ni sustituir el CAS por la revisión incluida en un error.

**Justificación y correcciones.** El problema sigue presente en el árbol inspeccionado (`1eacfc7`). `SourcePolicy` incrementa localmente la revisión y `Sources` no refresca su fila (`web/src/v2/Operations.jsx:28`, `web/src/v2/App.jsx:69`). Además, la respuesta del POST **no contiene revisión** (`internal/runtimev2/operations_api.go:379`): añadir `policy_revision` de forma compatible, obtenido de la actualización confirmada, y reconciliar la fila con una lectura vigente. Refrescar la lista no debe desmontar ni borrar los borradores de otras fuentes; si falla esa lectura, distinguir «guardado confirmado» de «vista pendiente de actualizar».

En control global, preservar una acción explícita —pausar o reanudar— durante el conflicto: recalcular el toggle tras recargar podría convertir la intención original en la contraria (`Operations.jsx:48`). Si el estado vigente ya cumple la intención, indicarlo sin otra escritura.

Conservar `error.code` en `web/src/v2/api.js:7` y activar la recuperación CAS únicamente para `stale_revision`. Los conflictos de baseline, inventario, identidad de petición o ejecución de retención deben mantener su causa; `current_revision:0` no los convierte en conflictos CAS (`operations_api.go:97`, `:338`, `:350`).

**Alcance y contrato.** Editores operativos, integración de `Sources`, transporte de errores y extensiones aditivas mínimas de API. Añadir `GET /retention?source_id=…&data_class=…`, autenticado y sujeto al permiso `retention`, validando ambos parámetros. Devolver política y revisión; representar explícitamente la ausencia para una fuente existente, con revisión inicial 0. Fuente inexistente, permiso denegado y fallo de lectura deben distinguirse de esa ausencia. La lectura no crea políticas, recibos ni ejecuciones.

Mostrar la revisión como dato del servidor. Vincular borrador, vista previa y ejecución a fuente/clase; invalidar respuestas tardías al cambiar contexto, incluso A→B→A. Cambiar la revisión confirmada invalida la vista previa y la ejecución anterior. Impedir envíos simultáneos del mismo editor y conservar los contratos actuales de idempotencia, autorización y purga. Una recarga solo lee; crear o continuar una purga sigue requiriendo una acción explícita.

**Aceptación.**

1. Dos guardados sucesivos actualizan fila y revisión confirmadas, sin incrementar revisiones en el cliente ni perder ediciones de otras fuentes.
2. Dos sesiones provocan `stale_revision` en los tres controles: recargar conserva borrador/acción, muestra diferencias y no escribe. Una recarga fallida conserva el conflicto; una nueva concurrencia vuelve a producir 409.
3. Baseline/inventario y demás conflictos conservan su código específico; no se presentan como una revisión recuperable.
4. Lecturas de retención cubren política presente/ausente, fuente inexistente, parámetros inválidos, 401/403 y fallo de dependencia. Cambios rápidos de destino o revisión nunca reutilizan vista previa, UUID ni respuestas anteriores.
5. Regresiones Playwright simuladas y reales comprueban cuerpos y número de escrituras; pruebas API verifican permisos y CAS. Purga exclusivamente con fixtures sintéticas.

**Límites compartidos.** La propuesta 15 conserva la propiedad de `Paged`; aquí solo se protegen peticiones de editores. La 9 conserva asociaciones pregunta/fuente y migración; coordinar el pequeño cambio de respuesta de política sin alterar esa semántica. Sin refactor general, nuevo historial de ejecuciones ni cambios del algoritmo de purga.

**Verificación realizada:** lectura de las veinte propuestas, código y pruebas existentes; sin implementación ni ejecución de pruebas.


## 17- Ejecutar fielmente el plan de consulta revisado

**Estado: ACEPTADA**

**Propuesta final.** Hacer reversible la conversión entre el plan tipado vigente, la URL y el formulario de `TypedQuery`, de modo que «Run this typed plan» ejecute todos los valores revisados, incluidos límite y cursor. Restaurar esos mismos parámetros al recargar o recorrer el historial del navegador. Esta reproducción conserva la consulta, no garantiza resultados idénticos si cambia el archivo consultado.

**Justificación y evidencia.** El defecto está confirmado: `web/src/v2/Consumers.jsx:22` impone `limit:50`; `:25–26` elimina el cursor y copia solo parte del plan. Además, `:24` y el formulario de `:28` impiden texto vacío, aunque `ValidatePlan` lo admite y la consulta omite el predicado textual cuando está vacío (`internal/inference/inputs.go:262–285,338`). El contrato incluye límite y cursor (`internal/inference/contracts.go:103–112`), y el servidor los aplica a resultados y continuación (`inputs.go:339–361`). Corregir únicamente los dos campos de paginación dejaría incumplido el mismo contrato para planes válidos sin texto.

La propuesta aporta fidelidad entre revisión y ejecución con un cambio localizado. No duplica la 15, centrada en concurrencia de `Paged`, ni la 18, centrada en recuperar y cancelar trabajos IA. Compartir `Consumers.jsx` exige coordinar las escrituras, no fusionar los objetivos.

**Alcance y compatibilidad.**

- Limitar la implementación a `TypedQuery`, una conversión local comprobable si resulta necesaria y sus regresiones. Mantener endpoints, esquema SQL y contrato de `QueryPlan`.
- Conservar las URLs antiguas con `q` no vacío y límite implícito 50. Introducir un estado URL inequívoco de consulta iniciada para aceptar texto vacío sin que abrir Explore dispare una consulta. Una aceptación explícita también puede ejecutar un plan válido sin texto ni filtros; no imponer una restricción ausente del servidor.
- Serializar todos los campos variables admitidos. `version:1` y `operation:search` pueden permanecer constantes porque son las únicas opciones actuales, rechazando valores incompatibles en vez de reinterpretarlos. Mostrar el límite efectivo; distinguir límite ausente de límite explícito inválido, sin truncamiento ni sustitución silenciosa.
- Al enviar una edición de texto, filtros, entidad, modo o límite, reiniciar el cursor. Al aceptar el plan conservar su cursor; «Next page» reemplaza únicamente ese campo. Conservar texto y filtros sin normalizaciones que cambien su significado.
- Mantener la validación autoritativa de la API. La búsqueda vacía no habilita «Propose plan with AI»: la entrada de `query.plan` exige texto no blanco (`inputs.go:189–193`). Recuperación de jobs y cambios de paginación SQL quedan fuera.

**Aceptación y verificación prevista.**

1. Playwright intercepta un plan sintético con `limit:7`, cursor UUID y filtros y verifica igualdad semántica del cuerpo enviado con el plan mostrado; repetir con texto vacío.
2. Recarga, atrás y adelante restauran el plan; paginar modifica solo cursor; cada cambio de criterio lo elimina. Las URLs antiguas conservan búsqueda exacta/fulltext y límite 50.
3. Explore sin iniciar no consulta; una ejecución vacía explícita sí lo hace. Límite vacío, fraccionario, 0, 101 y cursor inválido muestran error sin ejecución corregida silenciosamente.
4. Ampliar regresiones API de validación y comprobar límite/continuación con PostgreSQL sintético y filas de identificadores únicos; compilar frontend y ejecutar las pruebas focalizadas existentes.

**Comprobación realizada:** inspección de las veinte propuestas, implementación y pruebas pertinentes; sin implementar ni ejecutar pruebas. La aceptación corresponde al diseño; su implementación y validación quedan pendientes.


## 18- Recuperar y cancelar trabajos IA después de navegar

**Estado: ACEPTADA**

**Justificación crítica.** El problema sigue presente: `AIAction` guarda ID y clave de idempotencia únicamente en memoria (`web/src/v2/Consumers.jsx:10–14`); la API permite crear y consultar por ID, pero no enumerar trabajos (`internal/runtimev2/ai_api.go:84–119`). La persistencia existente permite resolverlo sin rehacer el motor. Aporta valor independiente de la propuesta 17: recuperar una ejecución no debe ejecutar su plan ni crear otra inferencia.

La propuesta necesita concretar privacidad, paginación y estados. El actor actual es el `username` obtenido de la sesión (`internal/runtimev2/api.go:109,140`): «propios» significa ese actor, compartido entre sus sesiones; no supone introducir usuarios, roles o permisos nuevos. `Job` distingue resultados vigentes de históricos y considera terminales también los bloqueados (`internal/inference/jobs.go:149–179`); un estado `succeeded` en el listado no acredita que su resultado siga siendo utilizable. El esquema dispone de índice de cola, pero no del índice necesario para este historial (`migrations/v2/004_inference.sql:3–4`).

**Propuesta final.** Añadir `GET /api/v2/ai/jobs` y una sección «Trabajos IA» en Sistema, enlazada desde `AIAction`, con selección de trabajo mediante URL para sobrevivir a recargas. Filtrar siempre por el actor autenticado, sin aceptar un actor solicitado por el cliente. Devolver exclusivamente ID, función, fecha y estado durable de ejecución; excluir entrada, `request_id`, snapshot, prompt, resultado, credenciales y errores internos. Mantener `Cache-Control: no-store` y evitar persistir resultados en almacenamiento del navegador.

Usar paginación por clave `(created_at,id)` descendente, cursor validado y límite predeterminado 50, permitido entre 1 y 100; añadir mediante migración nueva el índice `(actor,created_at,id)`. Las altas posteriores se descubren al refrescar desde la primera página. No cargar ni revalidar todos los resultados para construir el listado.

Abrir el detalle exclusivamente mediante `Store.Job`, preservando su comprobación de actor y revalidación de evidencia. Recuperar y sondear realizan únicamente lecturas: nunca reenviar el POST, rehabilitar trabajos bloqueados ni ejecutar planes. La cancelación conserva `Store.Cancel`, su fence y contabilidad; mostrarla para `queued`, `running` y `retry_wait`, y detener el sondeo según `terminal`, incluidos bloqueados. Explicar que cancelar impide publicación posterior pero no garantiza detener una llamada ya enviada ni eliminar su coste. Invalidar respuestas pendientes y estado visible al cambiar selección o cerrar sesión.

**Aceptación.**

1. Con gateway sintético retenido, crear, navegar, recargar y abrir el mismo ID; cancelarlo mantiene `cancelled`, sin resultado publicado ni segunda invocación, y conserva la contabilidad real existente.
2. Perder la respuesta del POST después de su commit permite localizar el trabajo desde el historial sin reenviarlo; no se promete recuperar una solicitud que nunca se persistió.
3. Dos actores sintéticos: listado, cursores, detalle y cancelación no revelan ni alteran trabajos ajenos; nuevas sesiones del mismo actor recuperan sus trabajos.
4. Cubrir páginas con fechas iguales, altas concurrentes, historial vacío, límites/cursor inválidos y errores visibles; sin duplicados ni consultas automáticas tras un estado terminal.
5. Evidencia revocada o caducada bloquea el resultado al abrirlo; cambiar de selección no mezcla respuestas. Verificar privacidad del JSON y ausencia de reenvíos mediante pruebas Go y Playwright sintéticas.

**Verificación y límites.** Inspeccionadas las veinte propuestas y el código citado; sin implementación ni pruebas ejecutadas. Quedan fuera planificación, presupuestos, ejecución de planes y cambios de identidad/autorización.


## 19- Publicar la configuración restaurada solo después de validarla

**Estado: ACEPTADA**

**Propuesta final.** Separar preparación y publicación de `restore-config`: descifrar y validar todos los archivos en un área privada identificada como incompleta; publicar el directorio final mediante una única operación atómica que rechace cualquier destino existente. Conservar los intentos incompletos para diagnóstico privado. La publicación acredita las comprobaciones del formato restaurado, no que la configuración autorice iniciar servicios.

**Justificación y evidencia contrastada.** En el árbol actual (`1eacfc7`), `ops/rebuild/operations/backup.py:155` crea inmediatamente el destino y las líneas 168–170 extraen secretos allí; las comprobaciones de formato, archivos requeridos, mappings, hashes y cuenta Telegram llegan después (`:171–189`). La función no registra fallos ni deja un recibo persistente. Las regresiones de `test_operations.py:124–166` comprueban excepciones, pero no el estado residual. El riesgo confirmado es confundir una recuperación incompleta con una utilizable; no se demuestra una filtración pública, pues el directorio ya es privado. La mejora tiene valor operativo y no duplica las otras diecinueve propuestas; la publicación de imágenes de la 20 es un flujo independiente.

**Correcciones necesarias al diseño inicial.** Un `rename` ordinario precedido por `exists()` no garantiza conservar un destino que aparezca concurrentemente. Usar una primitiva de publicación atómica sin reemplazo, dentro del mismo sistema de archivos; si no está disponible, fallar explícitamente, sin recurrir a copia gradual ni reemplazo. El identificador de intento incompleto debe existir antes del descifrado: un `except` no puede marcar una terminación abrupta. Preparar el recibo de validación junto con el contenido; solamente su presencia en el destino final acredita publicación. Una interrupción posterior a esa publicación deja una restauración válida aunque se pierda stdout; no debe reclasificarse como fracaso ni repetirse sobrescribiendo el destino. Esta garantía cubre visibilidad e interrupción del proceso, sin prometer durabilidad ante pérdida eléctrica.

**Alcance.** `restore_config`, helpers estrictamente necesarios, sus pruebas y el runbook. Mantener formatos v1–v4, nombres y bytes recuperados, permisos 0700/0600, rechazo de symlinks y destinos existentes. El recibo nuevo incluye versión, cobertura y comprobaciones, sin valores secretos. Mantener explícitas las limitaciones históricas y las advertencias de `README.md:130–147`: validación semántica y binding Telegram pendientes, DSN originales y ninguna autorización de captura implícita. No iniciar servicios, cambiar credenciales, borrar originales ni eliminar diagnósticos automáticamente.

**Aceptación verificable.**

1. Descifrado fallido, tar truncado/inseguro, JSON inválido, hash/mapping incorrecto y cuenta incompatible dejan ausente el destino solicitado y conservan únicamente staging privado inequívocamente incompleto.
2. Inyectar interrupciones durante descifrado, extracción y antes de publicar; comprobar permisos y ausencia de configuración final. Después del commit, todos los archivos y el recibo están presentes conjuntamente.
3. Destino preexistente o creado durante la publicación —archivo, directorio vacío/no vacío o symlink— permanece intacto; dos restauraciones concurrentes tienen como máximo un ganador.
4. Casos válidos v1–v4 preservan bytes y cobertura; no aparecen secretos en stdout ni en el nuevo recibo. Las validaciones actuales siguen siendo obligatorias.
5. Ampliar pruebas sintéticas existentes y realizar un ensayo real con `age`, clave nueva y cifrado corrupto, sin infraestructura ni secretos reales.

**Verificación de esta revisión:** inspección de código, pruebas y documentación; no se implementó ni se ejecutaron pruebas. Aceptada como propuesta de trabajo, con la publicación sin reemplazo y la semántica de interrupción anteriores como requisitos.


## 20- Exigir E2E del binario AMD64 de la imagen antes de publicar

**Estado: ACEPTADA**

**Problema confirmado.** El E2E de CI ejecuta un binario compilado en el runner (`Makefile:20-22,32-33`), mientras Docker recompila ejecutable y frontend (`Dockerfile:1-18`). `image_checks.py:16-56` comprueba imagen, arquitectura y arranque básico, pero no los flujos funcionales. La promoción ya conserva los archivos de imagen y verifica manifests: esta mejora completa esa garantía existente, sin sustituirla. No duplica las propuestas 1–19, centradas en comportamiento funcional y recuperación.

**Propuesta final.** Ejecutar el harness existente con `--browser --product --ai` sobre `/noctis` extraído de la imagen AMD64 candidata, sin recompilarlo, con PostgreSQL y gateways HTTPS sintéticos. Los assets, migraciones v2 y prompts v2 están embebidos (`internal/webassets/assets.go:8`, `migrations/v2/embed.go:5`, `prompts/v2/embed.go:13-16`), por lo que esta ejecución comprueba los contenidos funcionales empaquetados en ese binario.

Asociar el resultado a commit, versión, ID de imagen, SHA256 del ejecutable y SHA256 de ambos archivos de imagen. El orquestador debe generar un recibo nuevo únicamente después del éxito del proceso y comprobar que el recibo del harness acredita los tres modos y datos sintéticos; usar un destino nuevo evita aceptar residuos de una ejecución anterior. El recibo actual solo contiene nombre del binario y flags (`ops/rebuild/e2e/main.go:398`), por lo que no basta por sí solo. Verificar la estabilidad de los hashes durante la ejecución y contrastar SHA/versión con valores esperados proporcionados por CI, no exclusivamente con campos del mismo recibo.

Antes del primer `docker push`, validar **ambas** imágenes, archivos, identidades y asociación con el E2E. Actualmente `publish` carga, valida y publica AMD64 antes de validar ARM64 (`image_checks.py:66-77`); una corrupción ARM64 podría causar publicación parcial. Separar preflight completo y publicación. Mantener las comprobaciones actuales de digests y manifests remotos y no reconstruir entre prueba y promoción.

En CI, trasladar el E2E canónico al candidato para ejecutarlo una sola vez, conservando flags, historias cubiertas, Go/race, casos obligatorios, fallos, migraciones, Python y frontend. Reutilizar servicios e instalaciones del runner; conservar eventos PR/main/tags y nombres de checks requeridos al reorganizar jobs. Mantener `make ci` utilizable y exponer mediante Makefile la validación local del candidato. Guardar recibos de prueba y publicación juntos. El alcance queda en workflow, Makefile, script, pruebas asociadas y documentación; sin despliegues ni nueva infraestructura. No se afirma ahorro sin medir duración y ejecuciones.

**Aceptación.** Pruebas con Docker simulado deben rechazar recibos ausentes, antiguos, fallidos o incompletos, SHA/versión incorrectos, ejecutable alterado, corrupción de cualquiera de los dos archivos y discrepancias de imagen, con cero llamadas de publicación. Una ejecución sintética completa debe acreditar navegador, producto e IA sobre el candidato y enlazar sus hashes; verificar promoción sin reconstrucción. Revisar dependencias, condiciones y conservación de checks del workflow, con `actionlint` si está disponible.

**Justificación y límites.** Cierra una brecha real con infraestructura existente. Es E2E del binario AMD64 y smoke del contenedor, no prueba funcional del contenedor ni ejecución ARM64. ARM64 conserva ELF/manifest y su validación nativa independiente; no se acredita reproducibilidad bit a bit. Revisión por inspección en `1eacfc78b00fb833522657bacc31cc6eb16e3be8`; sin implementación, pruebas ni acciones externas.


# Propuestas originales anteriores a la revisión

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
