# Producción vacía e independiente

Este paquete prepara una release para `noctis-v2`, origen `https://noctis.zyrak.cloud`.
No ejecuta despliegues. La autorización de despliegue no sustituye la comprobación
de cuenta/contexto/UID antes de cada fase. Una respuesta `InternalError` del proxy
del clúster bloquea todas las mutaciones, el cutover y la copia de secretos reales.

El renderer está en `ops/rebuild/production/release.py`; necesita Python 3 y PyYAML
ya usado por los manifiestos existentes. Escribe JSON Kubernetes, válido también
como YAML, con permisos `0600` en un directorio nuevo `0700`. No acepta imágenes
mutables, digests vacíos/sentinela, campos desconocidos ni cambios de puertos.

La entrada JSON de `render --input RELEASE_INPUT --directory RELEASE_OUTPUT`
requiere estos campos, obtenidos de recursos comprobados; solo admite además
el campo opcional indicado:

| Campo | Valor necesario |
| --- | --- |
| `image` | Imagen final Noctis por digest, manifest ARM64 comprobado |
| `busybox_image` | Imagen BusyBox por digest, con `sh`, `stat`, `cp`, `chmod`, `mkdir` |
| `postgres_image` | `postgres:16-bookworm@sha256:…` o versión menor explícita, ARM64 |
| `tls_secret` | Secret TLS existente/provisionado en **noctis-v2**, certificado válido para el origen |
| `storage_class` | Clase comprobada con RWO y capacidad suficiente |
| `postgres_size`, `session_size` | Tamaño positivo explícito con unidad Gi/Mi |
| `traefik_namespace`, `traefik_labels` | Namespace y etiquetas de pods Traefik observados |
| `traefik_hostnetwork_sources` (opcional) | Lista de orígenes efectivos revisados, exclusivamente IPv4 `/32` o IPv6 `/128` |

No se proporciona un manifiesto con digests falsos que pueda aplicarse por accidente.
`render-receipt.json` incluye hashes de cada archivo. Revisar el contenido y sus
hashes antes del despliegue; el renderer no consulta ni modifica el clúster.

La release crea PostgreSQL 16, un PVC de datos y otro PVC de sesión nuevos. Usa
UID/GID `65532`, `fsGroup=65532`, filesystem raíz de solo lectura, sin token del
ServiceAccount ni RBAC adicional. Todos los pods se seleccionan para `oracle1`
ARM64, cuyo UID se verifica en preflight. PostgreSQL crea su subdirectorio `pgdata` con
ese UID; comprobar que el provisionador hace efectivo `fsGroup` antes de usarlo.
Ningún volumen ni backup de `noctis` se reutiliza, restaura o borra.

`private-config --directory PRIVATE_OUTPUT` genera contraseñas aleatorias para
cuatro LOGIN (`api`, `worker`, `collector`, `telegram`) y el propietario `noctis`,
cinco DSN en archivos privados, credenciales admin y una clave maestra **nueva**.
No importa ninguna clave AI, sesión, observación, fuente, política, trabajo,
presupuesto ni recibo de un proyecto anterior. `secrets.json` es secreto; nunca
mostrarlo, añadirlo a Git ni pasarlo por logs. La contraseña admin se consulta
localmente en `admin.secret`, fuera de terminales grabados.

Los LOGIN de ejecución pertenecen a un grupo NOLOGIN con CRUD en `noctis_v2` y
lectura del registro de migraciones; no son propietarios, superusuarios ni tienen
CREATE/TEMP en la base. Las credenciales del propietario solo se montan en PG y
en los Jobs puntuales de migración/grants. Nunca en API/worker/collectors.

## Fases con identidad verificada

1. Ejecutar `python ops/rebuild/production/preflight.py`. Debe confirmar contexto
   `zcloud-cluster`, servidor exacto del proxy, cuenta `system:admin`, UID de nodo
   ARM64 y namespace legacy, los cuatro UID legacy preservados, workloads legacy
   con cero réplicas y ausencia de montajes no autorizados. Si ya existe
   `noctis-v2`, **es obligatorio** `--namespace-uid UID_REVISADO`; nunca aceptar
   un namespace desconocido automáticamente. Guardar la salida como recibo.
2. Crear solamente el namespace nuevo desde el objeto renderizado si todavía no
   existe; guardar su UID devuelto y volver a ejecutar el preflight con ese UID.
   En cada comando usar `--context=zcloud-cluster -n noctis-v2`. Revisar primero
   PV/PVC nuevos: bindings distintos de legacy, RWO real, sin alias/rutas NFS
   solapadas. Revisar storage, cuota/capacidad, capacidad ARM64 y enforcement CNI.
3. Aplicar `01-infrastructure.json`, manteniendo sus nombres exactos y UID
   revisados. Antes de aportar secretos comprobar la NetworkPolicy de PG y su
   enforcement: solo pods API/worker/collector/Telegram/migrate/grants del mismo
   namespace alcanzan TCP/5432; un pod no autorizado debe fallar con un control
   positivo de red. No aplicar otra vez recursos con UID cambiado. Aplicar
   `PRIVATE_OUTPUT/secrets.json` y provisionar el Secret TLS en `noctis-v2`
   mediante archivos privados; no imprimir DSN, contraseña, clave ni datos TLS.
4. Esperar PG `Ready`, comprobar versión 16, imagen/digest efectivo y UID/GID
   real `65532`, propietario/modo `pgdata`, PVC/PV exactos y ausencia de tablas
   legacy. No arrancar aplicaciones antes de migrar. Aplicar `02-migrate.json`;
   comprobar identidad y desuspender **solo** `noctis-v2-migrate` con
   `kubectl --context=zcloud-cluster -n noctis-v2 patch job noctis-v2-migrate
   --type=merge -p '{"spec":{"suspend":false}}'`. Esperar `Complete` y comprobar
   registro/checksums de todas las migraciones embebidas, incluida 007.
5. Aplicar `03-grants.json`, comprobar identidad y desuspender de la misma forma
   **solo** `noctis-v2-grants`. Esperar `Complete`. Probar realmente los cuatro
   LOGIN: conexión/lectura permitidas y `CREATE TABLE noctis_v2.…` rechazado,
   sin usar el propietario ni `SET ROLE` para simularlos. Reaplicar grants tras
   futuras migraciones aditivas antes de actualizar los runtimes.
6. Aplicar `04-applications.json`. Solo API tiene una réplica; worker, RSS y
   Telegram quedan a cero. Comprobar rollout, `imageID` efectivo, UID/GID,
   propietario `65532` y modos `0700/0600` de `owned/master.json`, /livez y
   /readyz, login admin y UI vacía. Los counts de fuentes, observaciones, casos,
   trabajos, presupuestos y outbox deben ser cero (el estado de configuración
   inicial del esquema no es un fixture). La disponibilidad de IA no es requisito
   de readiness. No insertar fixtures para hacer pasar las comprobaciones.

Los Jobs quedan suspendidos y sin reintentos automáticos. Una migración fallida
requiere diagnóstico; no borrarla/recrearla ni reintentar efectos a ciegas.
Los manifiestos son fases revisables; no ejecutar `apply -f` sobre todo el árbol.

Los Jobs migrate y grants incluyen un initContainer PostgreSQL con el mismo Pod,
IP, etiquetas y selección de NetworkPolicy del proceso principal. Espera hasta
120 segundos a un `SELECT 1` autenticado mediante el Secret bootstrap; solo esa
consulta de lectura se reintenta. Si no responde, el init termina y no arranca
DDL. La migración/grants se ejecuta una sola vez tras esa barrera, con
`backoffLimit=0`. Esto cubre disponibilidad de SQL y propagación inicial de red
sin debilitar políticas ni reintentar migraciones. Antes de recrear un Job fallido,
guardar estado/UID y comprobar registro/tablas para conocer qué llegó a ejecutar.

Readiness/startup de PG comprueban TCP hacia su Pod IP real mediante Downward API,
en lugar de limitarse al Unix socket. Este cambio de template no debe aplicarse
a un PG vivo sin revisar el reinicio que produce; actualizar primero los Jobs no
requiere reiniciar PG.

## Ruta HTTPS y cutover exacto

Antes del cutover probar el Service ClusterIP `noctis-v2-api:8443` hacia
HTTPS/8081, SAN/cadena/vigencia del certificado y Host/origen correcto. La API
termina TLS y Traefik verifica el certificado upstream mediante ServersTransport
con SNI `noctis.zyrak.cloud` y `insecureSkipVerify=false`. Comprobar previamente
que existe la CRD `serverstransports.traefik.io` y que Traefik observa el namespace
nuevo. Si falta, resolver la infraestructura explícitamente; no debilitar TLS.
La NetworkPolicy permite TCP/8081 solo desde las etiquetas Traefik revisadas.

`serve --mode api` valida el origen y carga el par TLS antes de consultar
PostgreSQL o abrir el listener. Certificado y clave deben configurarse juntos;
un archivo ausente, ilegible, inválido o incompatible impide el arranque, sin
degradar a HTTP. La carga comprueba el par criptográfico, no confianza pública,
SAN ni vigencia: conservar las comprobaciones operativas anteriores. El mismo
material cargado se utiliza para servir; cambiar archivos requiere reiniciar.

`--origin` es el origen **público** exacto: esquema y host en minúsculas, host DNS
ASCII/punycode o IP canónica (IPv6 entre corchetes), puerto sin ceros iniciales
si no es el predeterminado. No admite credenciales, espacios, ruta —tampoco `/`—,
query ni fragmento. Ejemplos: `https://noctis.zyrak.cloud` y
`https://noctis.example:8443`. Los puertos predeterminados `:443` en HTTPS y `:80`
en HTTP se omiten porque el navegador los omite en `Origin`. La comparación de
peticiones sigue siendo exacta.

Otros despliegues pueden terminar HTTPS en un proxy y usar HTTP interno
omitiendo **ambos** archivos TLS. Esto es independiente del esquema del origen
público y no cambia el TLS API/Traefik de estos manifiestos. El acceso autenticado
del navegador sigue necesitando HTTPS: las cookies conservan `Secure`,
`HttpOnly`, `SameSite=Strict` y CSRF. `Forwarded` y `X-Forwarded-*` no seleccionan
el transporte ni sustituyen el origen configurado; tampoco se exige que el
certificado interno cubra el origen público. Worker, collector, `migrate` y
comandos administrativos no adquieren requisitos HTTP.

Si Traefik usa `hostNetwork`, el origen que recibe la API puede ser una dirección
de nodo o de la ruta CNI y no coincidir con el selector de pods. Conservar ese
selector y, únicamente tras comprobar el origen efectivo desde cada instancia
Traefik, configurar `traefik_hostnetwork_sources` con sus hosts exactos. El renderer
añade esos `ipBlock` solo al ingress TCP/8081 de `noctis-v2-api-only`; omitir el
campo o usar una lista vacía conserva la política previa. Rechaza subredes,
direcciones sin prefijo, entradas inválidas y duplicados, incluidos IPv6
equivalentes. No deducir permisos de todo el PodCIDR o del rango de nodos.
Estas excepciones autorizan también a otros procesos que salgan con esos mismos
orígenes; requieren revisión y comprobaciones positivas desde todas las instancias
Traefik y negativas desde un origen no autorizado después de aplicar únicamente
esa NetworkPolicy. Una dirección o topología nueva exige revisar la lista; no
cambia la política de PG ni la configuración global de Traefik.

Guardar el Ingress legacy y su UID en un archivo revisable, junto con la ausencia
de otras rutas `Ingress`/`IngressRoute` para ese host. Con la API ya sana, retirar
**solo** esa ruta legacy usando DeleteOptions con precondición UID; después
aplicar `05-cutover.json`. No mantener dos Ingress para el mismo host durante
una supuesta prueba. Comprobar la ruta pública, certificado, redirección/login,
assets, readiness y una lectura autenticada representativa. Guardar UID y estado
de la ruta nueva y de todos los objetos creados. No cambiar réplicas, PVC,
sesión, base de datos ni backups legacy durante el cambio de ruta.

Si falla, detener captura nueva y retirar la ruta nueva con precondición UID;
restaurar únicamente el Ingress legacy guardado, con metadata de creación limpia
y UID nuevo registrado. Legacy permanece a cero: restaurar su ruta no equivale a
restaurar servicio sano. Resolver la API v2 o volver a su digest previo comprobado;
no reactivar el binario legacy ni ejecutar migraciones inversas automáticamente.

## Captura separada, sin inferencia automática ni envío

La API vacía se valida antes de tocar sesiones. Después de verificar identidad,
provisionar **una copia** de la sesión preservada; no autenticar/login ni modificar
la sesión original, membresías, joins o leaves. Registrar generación/auth-key de
la copia sin registrar su contenido. Parar cualquier cliente que use esa misma
generación antes del inventario o de habilitar captura; exclusión real requerida.

Crear el Secret temporal `noctis-v2-session-provision` desde un archivo de sesión
privado, mediante `kubectl create secret generic … --from-file=collector.session=…
--dry-run=client -o json` redirigido a un archivo `0600`. Verificar de nuevo identidad,
aplicarlo y aplicar/desuspender `06-session-provision.json`. El Job se niega a
sobrescribir una sesión; crea `session/` `0700` y `collector.session` `0600`, ambos
UID `65532`, sobre el **PVC nuevo**. Telegram monta ese subdirectorio mediante
`subPath`, de forma que los checks de propietario no dependen del propietario del
punto de montaje del volumen. Comprobar permisos/hash de copia sin mostrar bytes.
Retirar el Secret temporal solo por UID conocido tras completar y cerrar el Job.

Provisionar credenciales Telegram y capture-policy en los Secrets exactos del
template, mediante archivos privados. Usar los comandos de onboarding/consent
de 007: inventario sin mensajes/history, importación PAUSED, selección humana,
activación y consentimiento de producción explícito ligados a cuenta/generación,
épocas y cuotas. No arrancar Telegram hasta comprobar la nueva política de
producción; el template anterior de presupuesto piloto no autoriza producción.

Después de revisar esos recibos, escalar worker mecánico, RSS y Telegram por
separado a una réplica donde corresponda. El worker lleva
`--automatic-inference=false`: ni `Once` de IA ni `PlanEligible` se ejecutan,
incluso si después se configura un proveedor. El envío no se activa mientras
`--delivery-endpoint` esté ausente. Habilitar IA automática y envío requiere
cambios explícitos independientes, con revisión humana de calidad; no hacerlo
como parte de este arranque conservador. No crear fuentes RSS por defecto.

Guardar comprobaciones de operaciones/consentimiento, progreso/checkpoints,
una captura representativa autorizada y su caso/evidencia mecánica, cierre de
cliente ante cuota/expiración/revocación y ausencia de intentos AI/envíos. Comprobar
un reinicio controlado solo del runtime nuevo: mismos cursores/contadores,
sin reset de presupuesto ni doble publicación. Si no llega actividad viva,
registrar esa limitación y distinguir inventario/captura histórica de captura viva.

## Backup y recibos

`ops/rebuild/production/backup.py --namespace-uid … --pod-uid … --image …
--destination … --key …` reutiliza snapshot compartido, manifiesto por catálogo,
serialización determinista y cifrado age de `operations/backup.py`. Comprueba
un destino nuevo dentro de `/home/zyrak/.local/share/noctis-rebuild/`, con padre
privado existente y clave age privada externa. Comprueba también
identidad y pod PG exacto; usa el password dentro del entorno PG, nunca en argv.
El catálogo incluye automáticamente las tablas nuevas de 007, migraciones,
checksums, constraints y conteos; no hay lista cerrada de tablas para el dump.
Antes de confiar en ese backup ejecutar una restauración aislada real con
`python ops/rebuild/operations/backup.py restore --archive … --key …
--destination …`, que compara manifiesto/consultas y elimina solo su contenedor
propio. El adapter Kubernetes se verificó contra la base nueva el 20 de octubre
de 2026: snapshot compartido de 74 tablas y restauración aislada con migraciones,
esquema, conteos, digests y consultas exactos. También se restauraron los 11
archivos de configuración y se validó offline el consentimiento sin renovarlo.
Los recibos privados están en `~/.local/share/noctis-rebuild/production-20261020/`.
Esta prueba no acredita copia fuera del host, recuperación de actividad posterior
al snapshot ni funcionamiento de la ruta pública.

Completar aparte un directorio privado compatible con `backup-config`:
`ai-master.json`, `admin.secret`, cuatro `database-MODE.secret`, `tls.crt`,
`tls.key`, y, al habilitar Telegram, `collector.session`,
`telegram-credentials.json`, `capture-policy.json`. Respaldar todos los modos
seleccionados y probar `restore-config`; no guardar la clave age con el archivo
cifrado. Los backups preservados previos no se modifican.

El recibo final debe separar preparación offline, apply, migración, grants,
rollout/digests/UID, TLS/cutover, DB sin DDL runtime, producto vacío, onboarding,
captura/progreso/reinicio, no-AI/no-envíos y backup/restore real. Un render o una
UI sana no cierra por sí solo las puertas G4/G6/G7/G8 ni demuestra captura viva.
