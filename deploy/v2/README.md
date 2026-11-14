# Preparación operativa v2

Plantillas locales, sin aplicar al clúster. No crean DB, PVC, secretos, accesos,
NetworkPolicy, políticas de inteligencia ni activan fuentes. `workloads.yaml`
mantiene las tres réplicas a cero y la migración suspendida. El digest cero y
`https://noctis.invalid` son sentinelas que deben sustituirse antes de promoción.
El directorio `deploy/` superior describe infraestructura histórica y no es el
procedimiento v2.

`serve --mode collector` captura RSS. Telegram usa el proceso independiente de
`telegram.yaml`, también a cero réplicas: `v2 telegram collect`, sin admin, TLS ni
master IA. Sus credenciales API y `capture-policy.json` se copian0600 a un
directorio0700 en memoria, desde Secrets diferentes. `--capture-policy-file`
es obligatorio; validar offline con `telegram capture-policy-validate` antes de
cualquier arranque. La política006 fija cuenta, generación, peers, epochs y
límites; el primer binding PostgreSQL conserva counters y expiración tras reinicio.
La unidad API es una admisión por operación pública de aplicación más una por
establecimiento de control (incluye inicialización/retries SDK), no cada RPC
interno, paquete ni retransmisión MTProto.
El archivo no concede autorización de captura por sí solo: debe coincidir con
la autorización y binding durable de la DB. El template no contiene valores ni
crea ese binding. Su PVC privado debe
aprovisionarse con la sesión existente0600, directorio0700 y propietario65532.
El init rechaza sesión ausente, enlace o propietario distinto de65532; después
del montaje (fsGroup puede ampliar a0660), fija archivo0600 y directorio0700
sin reescribir bytes. No crea, importa ni autentica una sesión. Recreate y un solo proceso por
cuenta complementan el owner/fence PostgreSQL: antes de takeover debe probarse
el cierre del dueño anterior y de cualquier cliente legacy u otro host. SIGTERM
usa el cierre coordinado existente; no hay probe HTTP en este proceso.
No reutilizar el PVC legacy ni arrancar otro cliente con la misma autorización.
Inventarios `resolve`/`dialogs` usan un modo sin updates ni escrituras, una copia
privada de sesión y exclusividad comprobada; tampoco autorizan `collect`.

API, worker, collector RSS y Telegram tienen cuatro DSN diferentes y Secrets segregados. Sólo API
recibe admin y TLS; API y worker reciben el master key IA, collector no. Ningún
runtime recibe la credencial propietaria/migradora. `runtime-grants.sql` es una
plantilla explícita para DB nueva: DML sobre v2, lectura del registro y sin DDL,
superusuario ni ownership. Las cuatro identidades LOGIN comparten privilegios DML v2;
no se afirma aislamiento SQL por tabla. Deben carecer de CONNECT al archivo
legacy; comprobarlo con sus credenciales antes de arrancar.

El loader del master key exige0600. Un initContainer no root copia el Secret
0440 a un emptyDir en memoria, propiedad65532 y modo0600; el proceso principal
sólo monta esta copia read-only. Su imagen busybox también tiene digest sentinel:
debe elegirse y revisarse explícitamente. No se ha ejecutado este init en clúster.

La API tiene liveness `/livez` independiente de DB y readiness `/readyz` HTTPS;
estos contratos requieren el backend005. Worker/collector son bucles sin HTTP:
Kubernetes supervisa el proceso y el operador comprueba progreso/cursor/backlog;
no hay probes HTTP inventadas. Los límites son hipótesis, no sizing certificado.
Sin destinos IA/entrega ni fuentes habilitadas no existe efecto externo implícito.
Para entrega, autorizar un único worker sender y añadir su endpoint privado;
mantener collector único y demostrar cierre de dueño anterior antes de takeover.

`/readyz` y `/healthz` conservan los campos JSON de salud. La comprobación tiene
un plazo total de tres segundos: conexión y aislamiento de DB, ledger exacto de
nombres/checksums, contrato estructural y permisos efectivos del modo. `schema`
solo es verdadero después de validar ledger y estructura; `functional`,
`ai_enabled` y las capacidades operativas se publican al terminar todas las
fases, incluida la lectura de `ai_configs`. Las capacidades corresponden al modo:
collector anuncia captura; worker, procesamiento; la API conserva sus capacidades
de acceso y operación. Una base recién migrada queda lista
sin fuentes, sesiones ni configuración IA. La sonda usa una transacción de solo
lectura y consultas agrupadas de catálogos; no ejecuta DDL, grants ni escrituras
de prueba. `/livez` continúa disponible aunque PostgreSQL falle.

Diagnóstico: `database=true, schema=false` exige comprobar las migraciones y los
objetos requeridos; `schema=true, functional=false` puede señalar permisos del
runtime o una configuración IA ilegible. Inspeccionar con la conexión del modo
afectado y revisar los grants posteriores a migración. Por ejemplo, la API
necesita `INSERT` en `sessions`; worker y collector no lo necesitan. Se consideran
los privilegios heredados, `USAGE` en los esquemas y lectura del ledger. La
respuesta pública no incluye errores SQL ni credenciales. Las plantillas de
grants siguen siendo responsabilidad del operador; readiness no certifica
mínimo privilegio ni disponibilidad futura.

El contrato está en `internal/runtimev2/readiness_contract.go` y su manifiesto
`schema_contract.json`: relaciones operativas, columnas/tipos/defaults,
claves y restricciones con su estado, triggers críticos y sus funciones. Excluye
índices meramente de rendimiento y tolera objetos adicionales ajenos al contrato.
Al añadir una operación o migración, revisar los permisos por modo y regenerar
desde **todas** las migraciones embebidas en una DB sintética aislada:

```sh
NOCTIS_V2_UPDATE_READINESS_CONTRACT=1 go test ./internal/runtimev2 -run '^TestReadinessContractPostgres$' -count=1
go test ./internal/runtimev2 -run '^TestReadiness.*Postgres$' -count=1
```

Ambos comandos requieren `NOCTIS_V2_TEST_DATABASE_URL` local. La prueba crea una
base nueva, no copia el esquema de producción y comprueba el manifiesto exacto
sin la variable de regeneración. Revisar su diff; no regenerarlo para ocultar
deriva de una base existente ni modificar migraciones ya publicadas.

Antes de cualquier cambio externo: comprobar cuenta/contexto/host, namespace,
UID y propietarios de DB/PVC, rollback exacto y backup/restore; preparar revisión
concreta. Un template válido no autoriza `apply`, migración, escala ni red real.
El runbook y comandos locales están en
[operations/README.md](../../ops/rebuild/operations/README.md).

La migración007 añade el flujo de proyecto vacío e incorporación de canales
actuales: detener y demostrar cierre de todos los clientes de esa autorización,
ejecutar `v2 telegram inventory-import --actor OPERADOR`, seleccionar candidatos
en Fuentes e importarlos en pausa. La política PIR y la activación se guardan
explícitamente después. Los canales privados usan el snapshot protegido, sin
username ni access hash en la UI; no se importan1781fuentes antiguas, historial,
observaciones, presupuestos o trabajos legacy. Un candidato sin baseline actual
permanece pausado. Reimportar conserva las decisiones de pausa del operador.

La propuesta `capture-consent-propose --account CUENTA --actor OPERADOR --reason
MOTIVO` escribe el archivo protegido para revisión; no activa captura. Tras
revisarlo, `capture-consent-install` instala o renueva por CAS y exige owner
cerrado. La versión2 usa períodos horarios y consentimiento de siete días por
defecto, con los límites globales006 por hora y bootstrap deshabilitado. Renovar
conserva ancla, límites y uso de período. `capture-status` permite verificar
agotamiento, próximo período y expiración; `capture-consent-revoke` revoca la
versión exacta. El supervisor sólo reabre tras cierre demostrado y una espera
autorizada; DB inaccesible, cierre incierto, revocación o expiración fallan
cerrados. Detalles y limitaciones en el
[contrato nativo](../../rebuild/native-capture-contract.md#production-consent-and-current-channel-onboarding-007).
Esta documentación describe código y pruebas locales, sin afirmar un despliegue
o una captura real en producción.

Un fallo incierto de captura v2 persiste una revisión terminal junto con el
cierre del cliente. Reiniciar el proceso o renovar consentimiento no la elimina:
`capture-status` informa `blocked` y `failure_revision`. Tras diagnosticar y
demostrar el cierre, `capture-resume --failure-revision REVISION --actor
OPERADOR --reason DIAGNÓSTICO`, con la política protegida actual, registra una
reanudación manual por CAS sin reiniciar cuotas ni cursores. Rechaza identidad
distinta, dueño sin cerrar y consentimiento revocado o vencido. Un fallo nuevo
vuelve a bloquear. Si no puede persistirse el fallo, no se registra cierre y
ningún reemplazo puede apropiarse automáticamente de la sesión.
