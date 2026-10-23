# Recuperación del arranque Telegram (2026-10-21)

Estado observado en `zcloud-cluster`, Deployment `noctis-v2/noctis-v2-telegram`
(UID `6c18d091-740f-41b9-ae45-0ae07892cabc`): 109 reinicios e imagen
`ghcr.io/zyrakk/noctis@sha256:d89718be8f2f8a023adadd20c0685b87e91683620eee29a2c7a39c99d5538a51`.
El error actual de ownership es compatible con el bloqueo deliberado por fallo
sin reconocimiento: revisión de fallo 1 y reanudación 0, según la evidencia del
incidente. No significa que deba eliminarse el fencing.

El binario extraído de ese digest usa gotd v0.141.0. Su desensamblado de
`Store.runCaptureClient` coincide con las líneas del código investigado y muestra
el retorno temprano sin unir el error del resolver. El hash local anterior de
`startup.go` es `4d83fd757d7d3135a2d23838b8dd4f9dbf1227966a4925f58108deed54b5b74e`.
La imagen carece de etiquetas de procedencia: esta comprobación acredita el
defecto en esa función, no la identidad completa del árbol de fuentes.

gotd puede convertir una cancelación en un retorno nil. El parche preserva la
denegación del resolver también antes de ready y el error de establecimiento
que pueda precederla. No permite reconectar, migrar ni abrir conexiones media/CDN.
No activa el logger general del SDK, que registra usernames. Una caída después
de abrir el transporte puede seguir sin revelar su causa interna: la reconexión
rechazada y el fallo de red inicial de producción aún no están demostrados.

## Secuencia autorizada

El operador autorizó publicación, despliegue y reanudación en esta conversación
el 2026-10-21. La revisión nueva de fallo nunca se reconoce automáticamente.

1. Construir y revisar una imagen ARM64 del cambio aprobado, registrar su digest
   y comprobar compatibilidad exacta de migraciones. El árbol local contiene
   cambios ajenos: revisar los inputs de build antes de publicar una imagen.
   Verificar contexto, servidor, cuenta, namespace y UID del Deployment. Tras
   autorización, detener únicamente este collector y comprobar que no queda
   transporte/owner activo. No desactivar alertas ni modificar SQL, sesión,
   consentimiento, límites o cursores.
2. Instalar el nuevo digest manteniendo el collector detenido. Consultar
   `telegram capture-status` con los archivos protegidos vigentes; comprobar
   revisión exacta, cierre, ausencia de owner/lease, generación, consentimiento
   vigente y cuotas. Ejecutar una sola vez, con autorización de reanudación,
   el mecanismo existente desde un entorno autorizado con el binario nuevo:

   ```sh
   noctis v2 --database-secret-file "$DB_FILE" telegram \
     --capture-policy-file "$POLICY_FILE" capture-resume \
     --failure-revision 1 --actor "$OPERATOR" --reason "$DIAGNOSIS"
   ```

   Las variables son referencias a archivos protegidos y texto de auditoría,
   nunca valores de DSN o credenciales. Usar 1 solo si sigue siendo la revisión
   observada. No reutilizar una revisión distinta ni renovar consentimiento
   implícitamente. `ResumeProduction` comprueba CAS y escribe el recibo sin
   reiniciar cuotas ni cursores. No arrancar otro cliente con la misma sesión.
3. Restaurar la réplica autorizada y comprobar digest efectivo, arranque y
   ownership exclusivo, auditoría de reanudación, continuidad de cursores y
   contadores, y una operación de captura permitida por la política. Un proceso
   vivo sin ready no basta. Si aparece otra revisión de fallo, conservar logs y
   detener la recuperación para diagnosticarla; no reconocerla automáticamente.

## Ejecución en producción

Preflight de identidad aprobado para namespace UID
`c4e880f8-db41-4823-9582-aaae2810d4b0`, cuenta `system:admin` y nodo ARM64
`oracle1`. Las siete migraciones coinciden por nombre y checksum exactos.
El backend del snapshot previo al cambio de panel del 20 de octubre solo difiere
en `startup.go` y `startup_test.go`; no hay inputs Go nuevos ni ausentes. El
snapshot aislado contiene 241 inputs congelados y 26 assets del panel ya aprobado,
que el collector no sirve. No se modificó el árbol de trabajo para construir.

Imagen publicada y desplegada solo en Telegram:
`ghcr.io/zyrakk/noctis@sha256:fb2ce6f9b51cda1d7473e80593727daa3c202f5d12610e20ded50efbf3ea1327`.
Manifest ejecutable ARM64:
`sha256:8b2169353e56c04d02eb972a69a3f03b1b006c48b776be0064cac109e9c1e28d`.
Config:
`sha256:7288c3fc66e05ae37821e8090ef56fbe399892bbfe9b080a2b582610f7bfd035`.
La imagen deriva del digest anterior y reemplaza solo `/noctis`, preservando
configuración, usuario, runtime, prompts y migraciones externos. El binario usa
Go1.25.14, gotd v0.141.0 y versión `rebuild-20261021-telegram-startup-fix`;
su ejecución nativa en `oracle1` está comprobada.

Con Telegram a cero réplicas y sin pods, se comprobó cierre durable, ausencia de
owner/lease y consentimiento vigente hasta el 2026-10-27T10:54:35.730315Z.
Los Jobs `noctis-v2-telegram-status-20261021` y
`noctis-v2-telegram-resume-20261021` terminaron una vez cada uno, sin reintentos;
no montan la sesión ni credenciales API de Telegram. El segundo ejecutó
`capture-resume --failure-revision 1 --actor zyrak` con un motivo que declara
desconocida la causa inicial. El recibo único reconoce 1/1 sin modificar cuotas,
cursores, inbox, commits ni observaciones, comprobados antes de volver a arrancar.

Se restauró una réplica. La primera sincronización adquirió owner/lease válidos,
avanzó el cursor nativo y añadió diez entradas de inbox y un commit, sin reinicios.
La comprobación final del 2026-10-21T09:24:19Z confirma el cierre y reapertura
planificados tras la ventana de 300 segundos (fence 132 a 133) y commits posteriores
a esa reapertura. El mismo pod sigue con cero reinicios y revisiones 1/1.
El incremento total observado es de 24 commits de sincronización y diez entradas
de inbox; no hubo observaciones nuevas durante este intervalo. Los cursores
nativos y de peers/canales y los contadores durables no retroceden; los cursores
de histórico permanecen intactos.
Los demás Deployments y el StatefulSet de PostgreSQL mantienen sus UID y specs.
Los recibos privados de build están en
`/home/zyrak/.cache/noctis-telegram-release-20261021/`, incluido
`production-recovery-receipt.json`; las evidencias de operación y snapshots de
metadatos se preservan en su subdirectorio privado `operations/`.

## Validación local

Pasan las pruebas `TestNativeStartup*` y los casos de `failure_test.go` con
PostgreSQL16 sintético independiente, también con `-race` (36,888 s).
Cubren la conservación de ambas causas, cancelación y timeout, denegación de
Primary/Media/CDN, admisión durable y reanudación por revisión exacta, incluidos
consentimiento caducado y fallo al persistir el fencing. El enlace inicial con
race agotó la cuota de `/tmp`; la ejecución final usó `GOTMPDIR` en `/home`.
La conectividad y sincronización con Telegram real se comprobaron en la
recuperación autorizada descrita arriba. El fallo de transporte inicial del
incidente continúa sin determinarse.

## Incidente del 22 de octubre y corrección de cancelaciones

La comprobación del 22 de octubre encontró 107 reinicios del mismo pod. El
segundo fallo terminal se registró el 2026-10-21T22:04:38.630851Z, con revisión
de fallo 2 y reanudación 1. Loki conservó `callback: context deadline exceeded`,
el error genérico de presupuesto y otro timeout; PostgreSQL registró una
consulta cancelada por el cliente. El consentimiento seguía vigente y el periodo
tenía 41 admisiones live de 192 y seis control de 64, por debajo del límite
global de 256. El último commit precede al fallo en menos de un segundo.

Se reprodujo localmente un defecto concreto del código anterior: cancelar una
consulta bloqueada de presupuesto añade artificialmente `ErrBudget`. Esa unión
impide reconocer una cancelación planificada y puede crear un fallo terminal.
Los registros históricos no permiten distinguir si en producción venció la
ventana de proceso de 300 segundos o una operación de 20 segundos; no se atribuye
el incidente a una de ellas sin esa evidencia.

El segundo parche fija la causa y la etapa de cada cancelación al observarla,
incluidos los casos de origen desconocido. Un timeout de operación no se vuelve
planificado al vencer después el contexto padre. Solo la ventana planificada o
un apagado demostrado del contexto raíz permiten el cierre por cancelación;
una cancelación interna del SDK, un error real de negocio/SQL/lease o un error
mixto siguen bloqueando la captura. El error del callback se conserva aunque
gotd devuelva nil. El heartbeat diferencia cancelación de cierre y pérdida real
de propiedad. No cambian consentimiento, cuotas, exclusividad, CAS de reanudación
ni esquema.

Los eventos `native_capture_start` y `native_capture_end` incluyen causas,
etapas y tiempos fijos; las operaciones solo añaden un evento cuando fallan.
No incluyen texto del error, DSN, SQL, identificadores de cuenta o mensajes.
La limpieza del guard compartido evita ejecutar unlock sobre una sesión ya
cerrada únicamente ante cancelación pura y conserva los errores mixtos o reales.

El operador autorizó el despliegue del segundo parche el 22 de octubre. Se
verificaron de nuevo identidad, cierre, consentimiento y revisión vigente; no se
reutilizó el Job anterior ni su reconocimiento de la revisión 1.

Validación del segundo parche: la regresión de consulta cancelada falla contra
el snapshot anterior con `ErrBudget` y pasa con la corrección. Las suites completas
de `internal/telegramv2` e `internal/intelligence` pasan con PostgreSQL16 sintético,
también con `-race`: 76 casos/subcasos, cero fallos y cero omisiones en cada pasada.
Se compiló el CLI y se ejecutaron sus pruebas de política y estado. Las nuevas
regresiones cubren SQL realmente bloqueado, cierre planificado, timeout de
operación, cancelación tardía del padre, cancelación interna del SDK, apagado
externo, heartbeat, errores mixtos, callback ocultado por gotd y privacidad de
diagnósticos. Las pruebas existentes de revocación, caducidad, cuota, reinicio y
reanudación auditada permanecen activas; no se eliminaron aserciones existentes.

Las primeras pasadas completas agotaron la cuota de `/tmp`; las pasadas verdes
usaron `TMPDIR` y `GOTMPDIR` en `/home`. Los recibos JSON, el diff contra el snapshot
previo y los manifiestos de hashes están en
`/home/zyrak/.cache/noctis-telegram-timeout-patch-20261022/`.

### Despliegue del segundo parche

La imagen publicada y desplegada solo en Telegram es
`ghcr.io/zyrakk/noctis@sha256:4e3a029dca35d2dca5a3bf9267d3c1c2bbc83857a0fe87d9857164be7e7ce99f`.
Manifest ejecutable ARM64:
`sha256:cc2e86b605f9875e274545cbdf4d672adbaa12643c226cdf1e3322b899aef8f7`.
Config:
`sha256:b7feb7b8d5c0aa441008d447cef838ab64ad1e91b66dd8c0d01f1cecf1919d32`.
El snapshot aislado de 269 archivos coincide con los hashes de los doce archivos
del parche validado; no incorpora diferencias ajenas. Deriva de la imagen
anterior y solo sustituye `/noctis`. La configuración del contenedor permanece
idéntica. Versión nativa comprobada en ARM64:
`rebuild-20261022-telegram-timeout-fix` (Go1.25.14, gotd v0.141.0).

Con el collector a cero réplicas y sin pods, los Jobs
`noctis-v2-telegram-status-20261022` y `noctis-v2-telegram-resume-20261022`
terminaron una vez cada uno, sin errores ni reintentos. No montan la sesión ni
credenciales API. La reanudación auditada reconoce exactamente la revisión 2;
se comprobaron cuotas, cursores, inbox, commits y observaciones intactos antes
de restaurar una réplica. Las siete migraciones coinciden exactamente; no se
ejecutó ninguna migración ni SQL correctivo.

Se restauró el collector con revisiones 2/2, owner y lease válidos y cero
reinicios. El primer cierre de 300 segundos quedó registrado como
`kind=process_window cause=process_window` a las 08:37:36 UTC y reabrió con
fence 262. La recuperación sostenida **no quedó verificada**: a las
2026-10-22T08:41:14.601587Z, tras 217 segundos de la segunda ventana, apareció
la revisión de fallo 3.

Loki conserva `production channel gap requires explicit intervention;
historical snapshot excluded`, junto al diagnóstico
`kind=mixed_failure cause=unproven stage=callback`. El error demuestra una
respuesta `UpdatesChannelDifferenceTooLong` en un canal autorizado; no es un
vencimiento de la ventana de proceso. El código la rechaza antes de procesar el
snapshot histórico o avanzar el cursor de ese canal. Los logs existentes no
identifican qué canal respondió TooLong ni permiten atribuir su origen a volumen
o antigüedad del cursor.

El observador conservó evidencia y detuvo únicamente Telegram a cero réplicas.
Estado final comprobado: cero pods, cuenta cerrada, sin owner ni lease,
revisiones 3/2. No se reconoció la revisión 3. Los demás Deployments y el
StatefulSet conservan UID y specs. Antes de detenerse se registraron 73 commits,
60 entradas de inbox y 43 observaciones adicionales bajo la política existente.

No hay un procedimiento existente que repare explícitamente el gap de un canal
ya activado. Reanudar la revisión 3 conservaría el cursor y podría repetir el
fallo. Inventariar solo obtiene candidatos/baselines; reimportar o pausar/reactivar
una fuente no rebasa su cursor, y renovar consentimiento no resuelve el gap.
El siguiente trabajo requiere identificar el canal y preparar una recuperación
auditada que registre la discontinuidad y, con decisión explícita del operador,
establezca un baseline actual sin importar histórico; alternativamente,
excluir explícitamente la fuente afectada. No usar SQL correctivo ni avanzar
cursores sin ese procedimiento y su autorización.

Recibos privados de publicación:
`/home/zyrak/.cache/noctis-telegram-timeout-release-20261022/`.
Evidencia de despliegue y observación:
`/home/zyrak/.cache/noctis-telegram-deploy-20261022/`.
El resultado fallido de la recuperación sostenida queda en
`production-deployment-receipt.json`; no es un recibo de servicio recuperado.
