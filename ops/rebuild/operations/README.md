# Operación v2: preparación y ensayos locales

Estas herramientas no despliegan ni habilitan fuentes. Separan la preservación
legacy P0 de los datos nuevos v2. La imagen por defecto ejecuta `v2`, nunca
`serve` legacy. [Recibo ejecutado](receipt.md),
[plantillas pausadas](../../../deploy/v2/README.md).

El [contrato de horizonte y pausa](source-retry-horizon.md) describe la
congelación durable de trabajos `parse` y los conteos obligatorios antes de
aplicar la migración 012 a backlog antiguo.

El runner `go run ./ops/rebuild/operations/telegram` consulta sólo identidad,
cinco semillas y, con `--dialogs`, diálogos activos/archivados. Requiere copia de
sesión en directorio0700/archivo0600, credenciales protegidas y exclusividad
comprobada entre hosts antes de invocarlo; no usa PostgreSQL. `RunInventory`
deshabilita updates, prohíbe login/Difference/history/joins/envíos mediante
allowlist, limita128 RPC y dos minutos, y conserva la sesión únicamente en
memoria. `--credentials`, `--session`, `--seeds` y `--output` aceptan rutas;
el resultado completo incluye access hashes y debe permanecer privado.
`reconcile_telegram.py` compara offline el inventario1781/1823 preservado con
esos resultados; conserva restricciones y conflictos y no produce un manifiesto
importable ni verifica identidades históricas a partir de aliases actuales.

## Build y CI

`make build` genera frontend desde el lockfile y compila Go. `make ci` requiere
PG16 sintético loopback, base cuyo nombre contiene `v2_test` e imagen Docker16
explícita en `NOCTIS_V2_FAULT_DOCKER_IMAGE`. `ci_checks.py` ejecuta toda la suite
Go con race, conserva eventos JSON y falla con test obligatorio ausente o skip
inesperado, incluso si `go test` sale0. Los69 tests críticos incluyen Core005,
I/O, presupuesto y arranque SDK; el test CLI usa `NOCTIS_V2_TEST_BINARY`, compilado
por `v2-check`. Python operaciones, gates y evaluación se ejecutan explícitamente.
Sólo admite skip de tres helpers hijos de
crash; los tests padres de fallo siguen siendo obligatorios. No contar un helper
mockeado de los tests Python como una suite Go real.

El runner único `ops/rebuild/e2e` usa el binario compilado, PostgreSQL aislado,
HTTPS y frontend real, `--browser --product --ai`, con gateways sintéticos. En CI
`NOCTIS_V2_E2E_RECEIPT` conserva el recibo saneado después del cleanup. No usar
`--keep` en CI. La publicación depende de Go/faults/E2E y de la construcción y
smoke de imagen. `image_checks.py --output NUEVO_DIRECTORIO` construye AMD64 y
ARM64, ejecuta sólo AMD64 sin red y exporta/verifica ELF ARM64; no instala ni
modifica QEMU/binfmt. Exportar un ELF ARM64 no acredita ejecución ARM64 nativa.
La versión integrada es el SHA del commit. CI guarda los dos `docker save`
probados con sus SHA256 e IDs; publicación descarga esos archivos y rechaza
hash/ID/arquitectura diferentes. Etiqueta y publica esas mismas imágenes, crea
el manifest y verifica que sus digests remotos coincidan. No reconstruye después
del smoke. El recibo de publicación conserva la correspondencia exacta.

Persisten cinco avisos npm de severidad alta asociados a la cadena de build
Tailwind/micromatch/braces. Node, npm y node_modules no se copian a distroless;
el runtime recibe JS/CSS/font empaquetados. Esto acota la exposición directa,
pero no prueba ausencia de riesgo de supply chain ni corrige las dependencias.
No ejecutar el servidor de desarrollo sobre contenido no confiable ni publicar
una afirmación de auditoría cero. Revisar actualización del lockfile por separado.

## Backup cifrado y restore

La conexión se hace al socket Unix de un contenedor ya arrancado e identificado
por ID exacto; la herramienta nunca inicia preservaciones detenidas. El origen
debe ser una DB nueva `noctis_v2_*`, sin tablas legacy públicas. Se reutilizan sin
modificaciones `recovery/recover.snapshot`, `manifest.manifest/compare` y
`protect.protect_artifacts` (age). La herramienta fija el usuario sólo para
conectar al socket; no acepta contraseñas en argumentos.

Preparar un directorio privado0700 bajo
`$HOME/.local/share/noctis-rebuild/`, padre también0700, en almacenamiento cifrado;
guardar la clave age en **otro** directorio0700 con archivo0600. No reutilizar
claves actuales para fixtures. Los destinos deben ser nuevos y no atravesar
symlinks. La interfaz actual de cifrado P0 exige ese prefijo local; no simula
soporte para S3 ni almacenamiento externo.

Ejemplos de interfaz, con nombres/ID/rutas previamente verificados; no son
despliegues ejecutados ni contienen secretos:

```sh
python3 ops/rebuild/operations/backup.py backup \
  --container "$NOCTIS_OPS_CONTAINER" --container-id "$NOCTIS_OPS_CONTAINER_ID" \
  --user "$NOCTIS_OPS_DATABASE_USER" --database "$NOCTIS_OPS_DATABASE_NAME" \
  --destination "$NOCTIS_OPS_NEW_BACKUP_DIRECTORY" --key "$NOCTIS_OPS_AGE_KEY_FILE"
python3 ops/rebuild/operations/backup.py restore \
  --archive "$NOCTIS_OPS_ENCRYPTED_ARCHIVE" --key "$NOCTIS_OPS_AGE_KEY_FILE" \
  --destination "$NOCTIS_OPS_NEW_RESTORE_DIRECTORY"
python3 ops/rebuild/operations/backup.py backup-config \
  --mode api --mode worker --mode collector --mode telegram \
  --source-directory "$NOCTIS_OPS_PRIVATE_CONFIG_DIRECTORY" \
  --destination "$NOCTIS_OPS_NEW_CONFIG_BACKUP_DIRECTORY" --key "$NOCTIS_OPS_AGE_KEY_FILE"
python3 ops/rebuild/operations/backup.py restore-config \
  --archive "$NOCTIS_OPS_CONFIG_ARCHIVE" --key "$NOCTIS_OPS_AGE_KEY_FILE" \
  --destination "$NOCTIS_OPS_NEW_CONFIG_RESTORE_DIRECTORY"
```

El dump, esquema, filas y consultas comparten snapshot REPEATABLE READ. Se
comparan todas las tablas, migraciones y checksums, cantidades, digests completos,
large objects y muestras de casos/revisiones/claims/observaciones/checkpoints,
cursores Telegram, jobs, outbox y ledger IA. No se restauran passwords, ownership
ni ACL del origen. La v2 actual usa UUID; si aparecen secuencias, el backup
rechaza el ensayo porque su estado no comparte aislamiento MVCC. Una exportación
con secuencias necesita una pausa revisada por separado.

El cifrado se verifica por descifrado completo y hash del plaintext. Restore
comprueba membership exacto del tar, archivo dump y hash antes de arrancar PG.
Crea un nombre aleatorio nuevo, `network none`, 512MiB/1CPU y sin publicar
puertos; no permite elegir un contenedor o una DB destino existentes. Valida
label de propiedad, ID y aislamiento antes de operar/eliminar. Sólo elimina su
contenedor y volumen propios; los documentos de trabajo quedan en0700 para
diagnóstico. Un `FAILED` significa incompleto, jamás recuperación verificada.

Los artefactos de trabajo incluyen plaintext privado. Tras revisar un restore,
el operador debe custodiar o eliminar **sólo esas copias propias** según política,
preservando el cifrado verificado. No borrar copias P0 ni contenedores privados.
Transferir cifrado y clave por rutas separadas a otro dominio de fallo requiere
una operación autorizada y un nuevo recibo: almacenarlos separados en este host
no es offsite. RPO24h/RTO4h son objetivos; el pequeño fixture no los certifica.

El master key IA (`key_id` incluido), configuración TLS/admin, DSN y sesiones del
collector necesitan backup protegido independiente. PostgreSQL contiene API keys
cifradas: sin el master key correcto no se recuperan. No colocar master key en
dump, Git, logs ni argumentos. Verificar recuperación y descifrado con una clave
sintética nueva antes de promover. La pérdida de claves puede exigir rotación;
no se debe sustituirla silenciosamente ni reenviar jobs de consumo incierto.

`backup-config` exige uno o varios `--mode`: api requiere master/admin/DSN/TLS;
worker master/DSN; collector RSS sólo DSN; telegram DSN, `collector.session`,
`telegram-credentials.json` (account/api_id/api_hash) y `capture-policy.json`.
Rechaza faltantes antes de
cifrar; para un sistema completo indicar los cuatro modos. `runtime-config.json`
es opcional. Cada modo tiene un archivo DSN distinto: `database-api.secret`,
`database-worker.secret`, `database-collector.secret` y `database-telegram.secret`.
El formato v4 registra los modos, mapping `database_files`, mapping
`capture_policy_files` y SHA256 de cada archivo; exige todos los
DSN seleccionados y política Telegram0600 antes de cifrar. Restore verifica
mappings y hashes, además de que la cuenta coincida con las credenciales.
La semántica completa del archivo se verifica offline antes y después con
`noctis v2 telegram capture-policy-validate --capture-policy-file /ruta/absoluta/capture-policy.json`:
no inicia cliente ni requiere sesión/credenciales/DB. Restaurar el archivo no
autoriza captura ni reinicia presupuesto: verificar también cuenta, generación,
epochs y binding/counters/expiración006 en la DB restaurada antes de uso.
Las cuotas API cuentan operaciones públicas de aplicación y una admisión de
control por establecimiento, que incluye inicialización y retries internos SDK.
No cuentan cada RPC interno, paquete ni retransmisión MTProto; los bytes de
payload representan persistencia por observación nueva, no ingress de red.
Los archivos históricos v3 se leen con alcance explícito
`selected-mode-specific-dsns-without-required-capture-policy`; no acreditan
recuperación completa de Telegram006. La lectura de
archivos v1/v2 conserva su alcance `legacy-shared-dsn-only`: el antiguo
`database.secret` no acredita la recuperación de cuatro credenciales segregadas.
Acepta sólo nombres conocidos (master/admin/DSN/TLS/config/sesión/API/política),
todos0600 en directorio0700; `restore-config` exige membership exacto y restaura
a otro directorio nuevo sin iniciar servicios. Antes de descifrar crea un staging
privado hermano `.DESTINO.restore-config-ID.incomplete`; cualquier fallo o
interrupción anterior a la publicación conserva allí el diagnóstico y deja
el destino solicitado sin crear. Esas copias pueden contener plaintext y nunca
deben usarse como configuración publicada ni eliminarse automáticamente.

Tras todas las comprobaciones prepara `restore-receipt.json`0600, con versión,
cobertura histórica y checks realizados, sin valores secretos. Publica contenido
y recibo mediante una sola operación Linux `renameat2(RENAME_NOREPLACE)` en el
mismo sistema de archivos: cualquier destino existente, incluso creado durante
la restauración, se conserva intacto. Si la plataforma, libc o filesystem no
soportan esa operación, falla explícitamente y conserva el staging; no copia
gradualmente ni reemplaza el destino. Sólo el recibo **en el destino final**
acredita publicación. Si el proceso termina después de ese commit y se pierde
stdout, el destino y recibo siguen siendo válidos: inspeccionarlos antes de
repetir; un nuevo intento nunca los sobrescribe. Esta garantía cubre visibilidad
e interrupción del proceso, no durabilidad ante pérdida eléctrica.

El recibo acredita comprobaciones del formato, no validación semántica completa
ni autorización para iniciar servicios o capturar Telegram. Mantener las
verificaciones offline y de binding indicadas arriba. El DSN recuperado sigue
apuntando al origen: preparar credenciales nuevas para la DB restaurada antes de uso.
El ensayo histórico004 verificó los cinco archivos admin/master/DSN/TLS byte a byte
y descifró cuatro credenciales del dump con el master recuperado; una clave
incorrecta falló. No se leyeron claves privadas reales.

## Pausa, promoción y rollback

Preparación, sin acciones externas automáticas:

1. Verificar cuenta/contexto/namespace, UID, recursos, release por digest, DB/PVC
   y ausencia de escritores legacy. Respaldar/restaurar v2 y secretos aparte.
   Repetir checks afectados sobre la imagen/esquema final. Ejecutar migración
   explícita con credencial propietaria y exclusión; runtime sin DDL ni acceso
   de escritura al archivo. Reaplicar grants explícitos de tablas nuevas.
2. Habilitar API privada y comprobar liveness independiente de DB y readiness
   dependiente de esquema/dependencias. Revisar progreso de worker/collector,
   backlog, edad y errores; no tienen listener HTTP. Un único collector y sender,
   sin `delivery-endpoint` hasta autorización de destino. Activar fuentes por
   política y epoch explícitos; no importar política/colas de entrega legacy.
3. Para pausar, detener primero el sender y luego collector/worker; confirmar
   cierre del propietario real y observar leases. Preservar inbox, observaciones,
   checkpoints/cursores, jobs, outbox y reservas/ledger. Entrega incierta no se
   reintenta a ciegas. Retomar sólo después de revisar progreso y propiedad.

Rollback significa cambiar a un binario v2 cuya lista ordenada de migraciones
y checksums sea **exactamente idéntica** a la DB actual. El migrador/health actual
rechaza esquemas adicionales: «migración aditiva» no basta para autorizar imagen
anterior. Si no existe ese binario probado, mantener pausa. Nunca downgrade de
SQL, borrar PVC, reiniciar legacy ni descartar el ledger. Restaurar backup a otra
DB es recuperación con posible pérdida dentro del RPO, no rollback binario.

Las plantillas mantienen cero réplicas y Job suspendido. Su YAML se inspecciona
localmente; el digest cero, Origin `.invalid` y helper busybox deben reemplazarse
en una revisión concreta. No se realizó `kubectl apply`, escala, migración remota,
envío Telegram ni inferencia pagada en este paquete. G4/G6/G7/G8 requieren los
recibos operativos y humanos respectivos.
