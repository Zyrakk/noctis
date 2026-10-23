# Recibo operacional local — 18-10-2026

## Candidato006 aceptado y QA local final

Binario canónico `noctis-native-startup-final`, SHA256
`2cbf233e5d8348ed4f17933716a95437a624518061aaee530f2a500e0fcc8a60`;
SQL006 `abf256d884fd564880b83cd423d7bd6fc24de193a293742bca75e34c65689ab1`.
Astra aceptó presupuesto/arranque y OPS antes del freeze y de estas pruebas.
La única corrección posterior fue el fake de un test legacy, sin cambios de
producción, prompts, SQL, assets ni binarios. El guard de CI exige69 tests
críticos y el binario compilado para CLI; admite sólo tres helpers hijos.

La primera suite Go/race006 terminó con502 eventos PASS y un único fallo:
`TestPipeline_EndToEnd` devolvió Category vacía y Confidence0. Astra identificó
colisión del fake por substring `Assess` dentro del prompt de clasificación y
orden aleatorio del map. Sol corrigió sólo routing del fake por encabezado
completo, preservó asserts/prompts y añadió regresión. Su foco100 repeticiones y
paquete race10 pasaron. La repetición global autorizada terminó **PASS:509 eventos
test,252 tests de primer nivel,69 obligatorios, cero fallos/skips reales**,
PostgreSQL16, race y fallos Docker. No se oculta la primera ejecución fallida.
Recibos: `/tmp/noctis-rebuild-wI06WY/go-race006-initial-summary.json` y
`go-race006-final-summary.json`, con ambos JSONL conservados.
Python operaciones17, evaluación18 y gates6 pasaron. Gates incluye el nuevo test
de unidades y autorización pendiente; su generador expresa admisiones públicas
de aplicación más establecimiento de control, no cada RPC interno/paquete SDK.
Las cuatro dependencias indirectas nuevas de tests usan gotd fijado0.141.0 y
el recibo backend verificó su ausencia del árbol de dependencias runtime.

Canónico compilado sobre ese hash: HTTPS y LOGIN restringido,9 tests navegador
(1 baseline,7 producto/Core005,1 IA), dos gateways falsos, reinicio API y sin
llamadas pagadas. Recibo `canonical006-2cbf233e-receipt.json` y log conservados.
Probes con el binario exacto en DB y proxy propios: live/ready/health200; cortar
sólo proxy DB conservó live200 y devolvió ready/health503; recuperación200.
Checksum falso y migración extra devolvieron ready503/live200; registro restaurado
recuperó200. Worker y RSS collector corrieron sin listener HTTP y cerraron Exit0.
DB/rol/DSN propios eliminados. Recibo `ops-probes006.json`.

Backup006:68 tablas/283 filas, seis migraciones; IA no vacía con2 attempts,
2 jobs,2 products y4 secrets; presupuesto nativo sintético revocado con counters
API/payload/metadata no vacíos, cuenta cerrada/pausada y source/peer deshabilitados.
Age descifrado/hash completo verificado. Restore aislado sin red512MiB/1CPU,
38,696s, comparó esquema/checksums/conteos/digests/consultas exactamente,
incluidos policy/digest/account/binding/counters/inicio/expiración contra archivo
protegido recuperado. Config v4:12 archivos byte a byte0600, cuatro DSN LOGIN
segregados, master/admin/TLS y política; sesión deliberadamente sintética sin
autenticación. Roles propios y contenedor/volumen de restore eliminados.
El primer harness confundió lista de relaciones migration con número de filas;
abortó antes de restore. Se corrigió sólo el assert y se reanudó el export ya
verificado, sin reseed ni nuevo backup. Recibo `ops-backup006.json`.
El CLI final validó cuatro políticas y rechazó once fallos críticos offline,
sin credenciales/sesión/DB/cliente: `ops-policy006-final-cli.json`.
Los fallos PostgreSQL restore004 siguen siendo evidencia histórica reutilizada:
la lógica PostgreSQL no cambió. Los cambios config v4 sí tienen fallos nuevos.

Imágenes `rebuild006-2cbf233e`: AMD64 ejecutado nonroot/offline, versión correcta y
default sin secretos fail-closed; ARM64 ELF183 exportado, sin ejecución ARM64.
`images006-2cbf233e/receipt.json` conserva IDs y SHA256 de binarios y `docker save`
exactos usados por CI. No publicación ni digest de registro productivo.
El binario de imagen tiene flags/version de build distintos del canónico.

Propuestas privadas actualizadas y nuevo snapshot006-final-session-bound cifrado/full-decrypt
verificado. Hash real, schema006, plantillas actuales no desplegables y archives
locales identificados; digest productivo null. Política estricta offline validada,
cuenta/peer de inventario privado y UUIDs propuestos explícitamente sin autoridad
DB. `auth_generation` se derivó offline de la copia de sesión preservada mediante
la misma operación UUID SHA1 namespaceOID+AuthKey de `ProtectedSession.Generation`,
sin imprimir clave ni generación; hash de sesión idéntico antes/después y CLI
final estricto PASS. Source/budget/epochs siguen propuestos hasta provisión
aislada; custodia/cierre/exclusividad y aprobación siguen pendientes.
Unidades aplicación/control correctas; cero peers activos, aprobación pendiente.
Los400 candidatos siguen UNLABELED, fuera del evaluador. No G4 real, G6 humano,
G7 utilidad ni G8 cutover acreditados; no RPC/inferencia/activación/apply/push.

Fixture canónica propia y sus secretos temporales eliminados tras los recibos;
PG compartido conserva ID, running y SELECT1. Ninguna otra DB ni copia P0 detenida
tocada; backups privados conservados separados de sus claves, sólo en este host.
Todos los procesos/PTY propios finalizaron. Recibo de cleanup `ops006-cleanup.json`.
Inspección de inputs confirma producción intacta tras freeze, sólo test legacy
cambió; whitespace de archivos propios tracked/untracked y YAML parseados PASS.

## Integración de configuración006, previa al freeze final

`backup-config` v4 incluye `capture-policy.json` obligatorio para Telegram,
mapping de política, los cuatro DSN segregados y SHA256 de cada archivo.
Once archivos sintéticos se cifraron y restauraron offline, byte a byte y0600;
quitar política o cualquiera de los cuatro DSN rechazó antes de crear destino o
cifrar. Restore rechaza mapping/digest alterado, política ausente o cuenta
distinta. Los archivos históricos v1/v2 conservan alcance DSN compartido; v3 se
lee con alcance explícito sin política requerida006. El backup verifica custodia,
envelope y cuenta; la semántica completa se valida con el CLI nativo y el binding
PostgreSQL debe verificarse aparte. No se interpreta restaurar como autorización.

El CLI compilado provisional `e03af600f90d4a68d56fc8da62293ab91b284b6c65a548b6aeac4fc438c85f14`
validó original y restaurado sin credenciales, sesión, DB ni cliente Telegram.
Once fallos de campos críticos/permisos/ausencia/trailing/consent antiguo se
rechazaron. Es evidencia del contrato local durante revisión; no sustituye la
QA sobre binario congelado final. Recibo privado saneado:
`/tmp/noctis-rebuild-wI06WY/ops-policy006-validation.json`.

Template Telegram sigue a réplicas0 y recibe política de un Secret separado;
init copia política y credenciales a memoria0700/0600. Su shell exacto se ejecutó
como UID65532 en un contenedor propio sin red: permisos y bytes de sesión
correctos, política ausente rechazada; contenedor eliminado. No apply ni secretos
reales. Recibo `/tmp/noctis-rebuild-wI06WY/ops-policy006-template.json`.

CI requiere explícitamente Python operaciones17, gates5 y evaluación18, y compila
el binario usado por tests CLI. Esas tres suites Python pasaron; también
`git diff --check`. La suite Go/race global, E2E, nuevas imágenes, probes y restore006
esperan aprobación Astra y freeze del candidato completo. No se atribuyen los
recibos005 posteriores como evidencia006.

## Revisión independiente005 y preparación Telegram real

Correcciones OPS posteriores a revisión Astra, ejecutadas localmente el18-10:
el init Telegram valida archivo regular, no enlace y propietario65532, y corrige
0660 tras fsGroup a0600 con directorio0700. En PG16 sintético propio, UID65532
cargó la sesión mediante el loader protegido gotd sin modificar bytes ni login;
ausencia, symlink y propietario incorrecto se rechazaron. Réplicas siguen0.
Los cuatro LOGIN API/worker/RSS/Telegram del SQL ejecutado tienen DML y lectura
del registro; CREATE/ALTER se rechazaron, sin ownership ni privilegios elevados.
Contenedor exclusivo `network none` eliminado; no SQL remoto ni cambio al PG compartido.

`backup-config` v3 registra `database_files`: cuatro archivos DSN distintos por
modo. Diez archivos sintéticos se cifraron y restauraron offline byte a byte,
todos0600; quitar cualquiera de los cuatro DSN rechazó antes de cifrar. Quince
tests Python pasaron, incluidos alcance compartido v1/v2 y mapping v3 inválido.
El primer harness se inició antes de terminar la compilación y falló al copiar
su binario; un segundo intento directo omitió umask077 y el guard rechazó el
archivo cifrado0644. Se corrigió el harness para usar la misma umask077 que CLI;
la ejecución final completa pasó. No se contabilizaron fallos como validaciones.
Artefactos finales privados: `operations-synthetic/config-four-dsns005b/`;
recibo saneado `/tmp/noctis-rebuild-wI06WY/ops-fixes-validation.json`.

`RunInventory` dispone de transporte sin updates, sesión sólo en memoria,
allowlist RPC, límite128 y plazo de dos minutos. Carece de Store/PostgreSQL:
no crea owner, cuenta, cursores, observaciones ni políticas. Los cuatro tests
`TestInventory*` pasaron con race; incluyen bloqueo de state/Difference/history/
join/send/login/logout, cuota, sesión idéntica tras cancelación, errores sin
persistencia y paginación con IDs de mensaje iguales en peers diferentes.
El runner operacional compiló; su invocación real terminó satisfactoriamente.

Antes de RPC se revalidaron usuario `zcloud-user`, contexto `zcloud-cluster`,
servidor esperado, namespace y ambos UID originales: réplicas0, ningún pod ni
otro controlador en noctis; ningún cliente local y sólo PostgreSQL sintético
en Docker. Se utilizó una copia independiente de la sesión preservada con
0700/0600 y lock local exclusivo, y únicamente API_ID/API_HASH del Secret en
un archivo privado. La identidad autenticada, cinco semillas resueltas y53
diálogos activos/archivados quedaron en evidencia privada. No hubo login,
updates, Difference, captura, joins, envíos ni conexión a PostgreSQL.

La reconciliación offline conserva1.781 sources,1.823 identidades históricas,
las restricciones y cuatro conflictos. Las coincidencias de alias sólo prueban
la identidad actual; la histórica/account scope sigue sin verificar y se marca
posible reasignación. No se generó manifiesto importable ni se activó política.
SHA256 de original y copia de sesión siguen idénticos tras RPC. IDs, access
hashes y hashes de evidencia permanecen privados bajo
`$HOME/.local/share/noctis-rebuild/telegram-inventory-20261018-final/`.
Se cifró la evidencia completa con age y se verificó descifrado streaming/hash;
clave nueva separada en el directorio hermano terminado en `-keys`. Sigue en
este host; no es offsite. Este ensayo prepara G4; no acredita captura/reinicio
real, calidad humana G6, utilidad G7 ni candidata/cutover G8.

CI conserva y publica los mismos archivos de imagen probados: SHA256 del
archivo e ID/arquitectura al cargar, y comparación de digests del manifest remoto.
No reconstruye tras smoke. Dos tests Python rechazan archivo corrupto e imagen
cargada diferente antes de push. Workflow inspeccionado; publicación no ejecutada.
`backup-config --mode` exige conjuntos API/worker/RSS/Telegram; Telegram incluye
sesión y credenciales API. El ensayo anterior cifró y restauró offline siete
archivos con un único DSN compartido, byte a byte y0600: no acreditaba cuatro
credenciales segregadas. Sus trece tests pasaron con ese alcance limitado;
lo sustituye el ensayo v3 de diez archivos descrito arriba.

`deploy/v2/telegram.yaml` prepara `v2 telegram collect` separado de collector RSS,
con réplicas0, Recreate, sesión PVC privada0700/0600 y credenciales API segregadas.
No recibe admin/TLS/master IA; no hay probes HTTP. Son cinco documentos YAML
pausados contando workloads y Telegram. No se aplicó configuración de clúster.

Suite Go005 sobre snapshot `51aad9e8`:451 eventos test PASS (incluye subtests),
36 obligatorios, cero test skip/fail, con PostgreSQL16, race y fallos Docker reales.
El recibo JSON es `/tmp/noctis-rebuild-wI06WY/go-race005-final.jsonl`; pese al
nombre, precede la corrección final de retención de `legacy_records.body` y
no se presenta como prueba de ese cambio posterior. El build de imagen de ese
snapshot se interrumpió al revocarse freeze: Exit143, sin imagen validada.

Backup/restore SQL005 reutilizó la fixture canónica sintética conservada:
67 tablas,250 filas, registro completo de cinco migraciones; ledger IA con dos
attempts, dos jobs y dos productos, cuatro secretos cifrados. Age descifrado/hash
completo verificado. Restore aislado `network none`,512MiB/1CPU,29,63s comparó
esquema/checksums/conteos/digests completos/consultas exactamente y eliminó su
contenedor y volumen propios. No cambió la DB canónica ni detuvo PG compartido.
Recibo `/tmp/noctis-rebuild-wI06WY/ops-backup005.json`; staging privado en
`operations-synthetic/database005-backup` y `database005-restore`.
Los fallos de restore004 siguen siendo evidencia histórica; no se repitieron
porque no cambió la lógica de backup/restore de PostgreSQL.

Snapshot `f11a6754` (incluye retención legacy/history/query plan, anterior al
nuevo hallazgo de revocación discovery; no es candidata aprobada):
probes HTTPS ejecutados con LOGIN runtime restringido en DB propia SQL005 y
proxy TCP exclusivamente loopback. API sana live/ready/health200; al cortar sólo
el proxy DB, live200 y ready/health503; al reabrir, los tres200. Checksum erróneo
y migración extra rechazaron readiness503 conservando live200; restaurar registro
exacto devolvió200. Worker y collector arrancaron vivos sin listener HTTP y
cerraron SIGTERM/Exit0. DB, rol y archivos DSN temporales propios eliminados;
DB canónica y PG compartido intactos. Recibo saneado:
`/tmp/noctis-rebuild-wI06WY/ops-probes005.json`.

Suite global de `f11a6754` pasó con452 eventos test PASS (incluidos subtests),
37 obligatorios y cero skips reales, PG16,
race y fallos Docker. JSON `/tmp/noctis-rebuild-wI06WY/go-race005-f11a6754.jsonl`.
Imágenes de ese snapshot completadas: AMD64 ejecutado offline/nonroot, versión
`rebuild005-f11a6754` y default sin secretos rechazado; ARM64 ELF183 exportado,
sin ejecución nativa. Ambos `docker save` conservados con IDs y SHA256 de
archivo/binario en `/tmp/noctis-rebuild-wI06WY/images005-f11a6754/receipt.json`.
Son imágenes de snapshot anterior al hallazgo discovery; no se publicaron.
No se reutilizan recibos004 como
éxito005. No se repitió E2E completo tras el único cambio Go de retención: el
canónico anterior compilado acreditó1 baseline,6 producto y1 IA; el nuevo foco
PG/race de importación→retención→history/query plan acredita el cambio posterior.

## Evidencia histórica004

**Parcial, esquema004. No es candidata final ni cierre G8.** La revisión005 y
sus comprobaciones afectadas siguen pendientes. No hubo despliegue, publicación,
commit/push, tráfico Telegram real, inferencia pagada ni cambio global QEMU.

| Alcance | Evidencia ejecutada | Resultado y límite |
|---|---|---|
| Imagen | `image_checks.py`, buildx AMD64/ARM64 desde fuentes | AMD64 nonroot, CLI sin red y default v2 sin secretos rechazado; ARM64 ELF183 exportado, **sin ejecución ARM64**. Snapshot provisional durante trabajo004, no digest promocionado. |
| CI | Workflow/Makefile inspeccionados,10 tests Python | PG16+fault image explícitos;22 tests Go críticos obligatorios y cero skips de tests, helpers hijos permitidos. Paquetes sin tests se reconocen correctamente. No se ejecutó GitHub Actions ni publicación. |
| Suite Go004 | Ejecutada por principal con `ci_checks.py` y PG16/race |419 tests PASS, cero skips reales; único fallo `TestMigrationsPostgres`, fixture con nombres002/003 desordenados tras004. Backend005 corrige el fixture; no se debilitó el guard. La suite completa **no está verde**. |
| E2E canónico | Binario congelado `noctis-p6`, `--browser --product --ai --keep` |6 tests navegador PASS, HTTPS, restart API, login runtime restringido, dos gateways falsos.26,41s; no rutas pagadas. |
| Backup v2 IA | P0 snapshot+manifest+age reutilizados sin editar P0 |54 tablas/162 filas,22,40s de export; configuración/credenciales/jobs/ledger IA no vacíos. Descifrado completo del cifrado y hash exactos. |
| Restore v2 IA | Contenedor PG16.15 nuevo `network none`,512MiB/1CPU |26,01s, esquema/registro migraciones/conteos/digests/consultas exactos. Contenedor y volumen propios eliminados. |
| Configuración | `backup-config`+`restore-config` |Admin/master/DSN/TLS: cinco archivos exactos,0700/0600, age separado. Master recuperado descifró cuatro API keys sintéticas del dump restaurado; master incorrecto rechazado. No se usaron claves reales. |
| Fallos | `operations/integration.py` contra backup real sintético |Destino existente, cifrado corrupto, archivo incompleto, dump PostgreSQL malformado y fallo tras restore rechazados; cero contenedores propios restantes. Guards de ID/propietario/red/symlink/permisos cubiertos por unidades. |
| Plantillas | Cuatro documentos YAML parseados/inspeccionados localmente |API/worker/collector a cero, migración suspendida, digest sentinel, sin token/capacidades/escalada; Secret segregados. No Kubernetes API, apply ni SQL grants ejecutados. Probes API dependen del contrato005. |

Perfil pequeño del runner existente:9 observaciones,14.109 bytes de payload,
5 casos,9 checkpoints,12 jobs mecánicos succeeded;2 jobs IA succeeded y2
intentos settled,240 unidades sintéticas de exposición; outbox1 delivered/5 queued.
DB10.312.727 bytes. Consulta real de revisiones:20 muestras, mediana0,185ms,
p95 0,283ms y máximo0,295ms de ejecución PostgreSQL. Edad de job mecánico
desconocida porque004 no contiene created_at; no se inventó cero. No había jobs
IA pendientes, de ahí null para su edad mínima.

`time -v` midió RSS máximo189.000KiB del conjunto launcher/Go/navegador, no
RSS aislado del proceso. El PG compartido de fixtures no tenía cuotas CPU/memoria;
restore sí tuvo512MiB/1CPU. No se ensayó carga sostenida ni I/O de producción.
RPO24h/RTO4h y sizing productivo continúan sin certificar. Archivo, cifrado y
clave están en este host, en directorios privados separados; no existe recibo
de offsite. Persisten cinco avisos npm high en dependencias de build; la imagen
final no contiene Node/npm/node_modules, pero no se afirma supply chain segura.

Se eliminaron únicamente las dos DB sintéticas propias y sus directorios
temporales de secretos. El contenedor PG compartido, otras DB y las copias
privadas P0 detenidas no se tocaron. Artefactos sintéticos privados retenidos:
`$HOME/.local/share/noctis-rebuild/operations-synthetic/`; age key en directorio
hermano `operations-synthetic-keys/`. El informe de trabajo saneado está en
`/tmp/noctis-rebuild-wI06WY/sol-operations.txt`.

Trazabilidad: R36/T41 verificado para este fixture local y condicionado en carga,
RPO/RTO/offsite; R37/T42 preparado con pausa y rollback de esquema exactamente
compatible, cutover no ejecutado; R38/T43 documentación v2 actualizada y default
Docker v2, retirada CLI legacy corresponde al backend005. R35/T40, probes005,
repetición afectada sobre imagen final y candidato/G8 siguen pendientes. Los
pilotos reales, calidad humana y operación útil de G4/G6/G7 no se acreditan aquí.

Fallos iniciales conservados como fallos: guard de padre no0700 rechazó backup;
primer restore abortó porque pg_isready aceptaba conexión mientras DB aún no
existía. Se sustituyó por SELECT1 sobre la DB exacta y el retry pasó. El primer
ensayo de fallos tenía una captura de excepción incompleta; se corrigió y el
ensayo real se repitió satisfactoriamente. Ninguno se contó como éxito.
