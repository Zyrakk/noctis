# Recibo P0 — 18-10-2026

**Preservación física, dump lógico y restore independiente verificados.**
La copia física se recuperó en ARM64 nativo; los dumps reales se restauraron
en PostgreSQL16 AMD64 y sus manifests y consultas coincidieron exactamente.
Los originales permanecen detenidos y no se activaron fuentes.

## Origen y protección

Se verificaron cuenta, servidor, contexto `zcloud-cluster`, namespace `noctis`,
UID exactos y cero réplicas de los workloads originales. No había pods ni
consumidores de ambos PVC. Se inspeccionaron otros controladores y PV: sin
alias NFS solapados. Los provisioners NFS conservan sus montajes administrativos
de raíz; no son consumidores de Noctis. Un PV histórico retenido con referencia
al antiguo claim no se modificó ni se incluyó como si fuese el PVC actual.

El auxiliar temporal montó los dos PVC completos en RO, comprobado tanto en la
especificación como en `/proc/mounts`; sin labels de Services, token de Service
Account, privilegios ni fsGroup. PostgreSQL es versión mayor 16 y el control
indica parada limpia. No hay symlinks/tablespaces externos. Se conservaron
PGDATA, WAL, sesión y metadatos completos.

| Copia | Archivos | Bytes | Resultado |
|---|---:|---:|---|
| PostgreSQL | 1.523 | 1.714.928.599 | SHA-256 por archivo idéntico en origen antes/después y extracción |
| Sesión | 1 | 4.197 | SHA-256 por archivo idéntico en origen antes/después y extracción |

Los encabezados tar coinciden con el inventario original de permisos, UID/GID,
tamaños, timestamps y membresía. La extracción local conserva el usuario local;
la propiedad original sigue disponible en el tar. No hubo errores de lectura.

Destino: `$HOME/.local/share/noctis-rebuild/recovery-20261018/`, directorio 0700
en volumen local LUKS, con unos 895 GiB libres al inicio. La clave age queda en
el directorio hermano `recovery-20261018-keys/`, 0700, archivo 0600 separado.
No se almacenaron artefactos privados en el repositorio ni en `/tmp`.

`preserved.age`: 1.716.530.520 bytes, age 1.2.1 instalado mediante Go modules
con verificación de checksums. Descifrado completo en streaming y comparación
SHA-256 satisfactorios. SHA-256 del cifrado:
`59fd0aa881390410c018f53dc63a202198c9e200757c497f6b578e40306ed4fc`.
Archivo y clave aún están en el mismo equipo; no se ejecutó transferencia a
otro dominio de fallo. Las copias locales están en un dominio distinto del NFS.

## Inventario y herramientas

Cinco semillas de configuración se exportaron sin consultar Telegram. El
inventario completo desde la restauración contiene 1.781 filas de `sources`
con todas sus columnas, 1.823 identidades históricas por procedencia y cinco
semillas de configuración: 3.609 registros, todos sin resolver, con cuatro
conflictos conservados. Los IDs completos son cadenas; identidades nativas y
account scope desconocidos quedan null. `sources-manifest-v1` conserva estados
restrictivos, provenance y aliases sin política ni activación. Las restricciones
y auditoría de triage/blacklist se exportaron aparte y completas. No se
inventaron canales, autorizaciones ni diálogos.

El guard físico ARM64/AMD64 se conserva. Se utilizó un auxiliar nativo ARM64
en `oracle1`, sólo con emptyDir, usuario no root, raíz RO, sin capacidades,
escalada, token, Secret, PVC ni namespaces host. La política deny-all exclusiva
se creó antes del pod; controles sintéticos bidireccionales positivos y
negativos acreditaron enforcement antes de transferir datos. Se verificaron
UID del nodo y namespace, readiness, ausencia de presión y unos 116 GiB reales
libres. Kubernetes/K3s conserva excepciones relativas a nodos; este ensayo no
acredita aislamiento absoluto. No se consultaron Internet ni servicios reales
desde los auxiliares de prueba.

Sólo `database.tar` se transfirió por stdin binario sin TTY. Se revalidaron
membresía, tamaños y SHA256 de los 1.523 archivos antes del arranque; nunca se
transfirieron sesión ni clave age. PG16.15 ARM64 arrancó sobre esa copia con
auto.conf apartado y configuración mínima: socket Unix, sin TCP PostgreSQL,
replicación, recuperación, archive, preloads, workers ni autovacuum. Los settings
efectivos y la ausencia de listener TCP se comprobaron. El valor mostrado
`archive_command=(disabled)` sólo se acepta junto con `archive_mode=off`.

Se inventariaron todas las bases no template: `noctis` y `postgres`, ambas
UTF8, locale `en_US.utf8`, proveedor libc. Cada dump, manifest y consultas
representativas compartieron snapshot con transacción abierta hasta completar
todos los consumidores. El dump parcial pasó a definitivo sólo tras éxito.
La restauración local AMD64 usó un destino nuevo sin red y
`--exit-on-error --single-transaction --no-owner --no-privileges`.

| Base | Tablas | Filas | Comparación |
|---|---:|---:|---|
| noctis | 19 | 478.398 | Manifest y consultas exactos |
| postgres | 0 | 0 | Manifest y consultas exactos |

Se compararon locale/encoding, esquema normalizado, extensiones, conteos,
digests de todas las filas, secuencias (`last_value`/`is_called`), large objects
y consultas de fuentes/histórico/migraciones/relaciones. Los roles/ACL originales
sin contraseñas se guardaron aparte; ownership y privilegios no se aplicaron
al destino. Las bases reales no tienen secuencias ni large objects; ambos se
ejercitaron con datos sintéticos, incluyendo secuencia sin llamar e IDs >2^53.

Evidencia privada completa:
`$HOME/.local/share/noctis-rebuild/recovery-20261018/arm-logical-d0a1f080d8/`.
Incluye los dos dumps, manifests origen/restaurado, hashes de consultas,
inventario completo, versiones servidor/tools, reportes de transferencia,
settings, NetworkPolicy, UID y ausencia tras limpieza.

Los 33 artefactos nuevos se cifraron reutilizando la clave age separada, sin
sobrescribir la preservación original. `logical-recovery.age` ocupa 143.518.104
bytes; se verificó descifrado completo en streaming y hash del tar plaintext.
SHA256 del cifrado:
`592815f56f296322854efedf599543559037781280aa1aedba12e1ea620f7387`.
Una comprobación final confirmó inalterado el SHA256 original de `preserved.age`.
La copia Docker detenida permanece privada en `restore-data`; el cifrado
incluye su representación portable completa (los dumps), no otra copia física.
Archivo y clave siguen en este equipo; no se transfirieron externamente.

Los tres auxiliares se eliminaron con precondición de sus UID exactos, se
confirmó su ausencia y sólo entonces se retiró la política con su UID. Se
repitió preflight: originales a cero réplicas y sin consumidores de sus PVC.
El contenedor de restauración quedó detenido, exit 0, network none, conservando
datos privados. No quedan procesos ni contenedores en ejecución de esta tarea.
No se realizó inferencia, tráfico Telegram, cambios de acceso, commits ni publicación.

Comprobaciones ejecutadas:

```sh
python3 -m unittest discover -s ops/rebuild/recovery -p 'test_*.py'
python3 ops/rebuild/recovery/preserve.py PRIVATE_DESTINATION
python3 ops/rebuild/recovery/protect.py PRIVATE_DESTINATION
python3 ops/rebuild/recovery/integration.py PRIVATE_DESTINATION
python3 ops/rebuild/recovery/recover.py --arm-kube PRIVATE_DESTINATION
```

Quince tests unitarios pasaron, incluyendo arquitectura, UID, PVC/config
inseguros, transferencia corrupta/ausente/extra/tamaño, fallo de snapshot,
propagación de fallos y diferencias de secuencia. La integración sintética
PostgreSQL16 comprobó dump/restore reales, full sources/histórico/restricciones,
FK/large object y rechazo real de un dump corrupto por pg_restore. Dos intentos
previos abortaron de forma segura (sentinel archive y stdin del comprobador
redundante); sus auxiliares se eliminaron y no se trataron como éxitos.

No se instaló QEMU/binfmt ni se cambió configuración global. No se realizó
inferencia, tráfico Telegram, paid calls, cambios de acceso, commits ni
publicación. Esta evidencia acredita recuperación de datos; no acredita una
migración funcional de la aplicación ni autoriza activar fuentes.
