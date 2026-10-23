# Preservación del archivo, infraestructura y canales

Estado: **procedimiento de implementación pendiente de ejecutar**, con inventario de infraestructura comprobado en modo lectura el 16-10-2026. No se ha creado un backup, montado un PVC, arrancado PostgreSQL ni conectado a Telegram durante esta planificación.

## Lo comprobado en la infraestructura

| Recurso | Estado observado | Implicación |
|---|---|---|
| Contexto Kubernetes | `zcloud-cluster`, namespace `noctis` | Existe acceso de lectura; verificar de nuevo antes de cualquier operación. |
| Deployment `noctis` | Réplicas deseadas/listas: 0/0; imagen `ghcr.io/zyrakk/noctis:latest` | Aplicación detenida; no arrancarla con el pipeline legado por accidente. |
| StatefulSet `noctis-postgres` | Réplicas deseadas/listas: 0/0; imagen `postgres:16-alpine` | No hay servidor disponible para hacer dump lógico hoy. |
| PVC `noctis-data` | Bound, 1 GiB, `nfs-shared` | Puede contener sesión y otros artefactos; contenido e integridad sin verificar. |
| PVC `noctis-postgres-data` | Bound, 50 GiB, `nfs-shared` | Archivo potencialmente recuperable; Bound no prueba recuperación. |
| StorageClass `nfs-shared` | NFS subdir external provisioner, reclaim `Retain` | No asumir snapshots/clones CSI ni que Retain sustituye un backup. |
| Servicio PostgreSQL | `ClusterIP` | Conservar red interna y aislar restauraciones. |
| IngressRoute | `noctis-dashboard` presente | No mover tráfico hasta aceptar el nuevo sistema. |
| ConfigMap Telegram | Habilitado; 5 entradas con username, ninguna con ID numérico/invite; catchup 100; sesión `/data/telegram.session` | Son semillas configuradas, no el inventario completo de DB o cuenta. |
| Herramientas locales | `kubectl` y `docker` disponibles; `pg_dump`, `pg_restore`, `psql` no encontrados en PATH | Usar herramientas PostgreSQL 16 de imagen fijada en la fase de recuperación. |

No se han leído Secrets, datos de sesión, mensajes ni credenciales. No hay IDs numéricos de canales recuperados todavía. Los nombres de canales pueden obtenerse de la configuración existente; los inventarios privados no deben publicarse en Git.

## Decisión: conservar legado y crear runtime limpio

Conservar la base anterior y su copia verificada. Crear una **base `noctis_v2` independiente en la instancia PostgreSQL reutilizada**, cuando capacidad y recuperación estén comprobadas. Es una base distinta, no ejecutar migraciones nuevas sobre tablas legacy ni cambiar su `_migrations`. Roles y conexiones distintos impiden que el runtime v2 escriba en el legado.

La recuperación puede necesitar una instancia temporal aislada sobre copia del almacenamiento. No implica desplegar una segunda plataforma PostgreSQL permanente. Si la capacidad o el almacenamiento no permiten coexistencia segura, documentar otra ubicación antes de escribir; no resolverlo eliminando el original.

«Empezar de cero» significa esquema, procesamiento, políticas y captura nuevos. No significa borrar datos, canales o sesiones. Importar fuentes autorizadas al inicio; conservar historial aparte y hacer su importación/reanálisis selectivo sin bloquear el inicio de captura fresca.

## Artefactos privados a producir en P0

Directorio privado fuera del repositorio, permisos restrictivos y cifrado para copias exportadas. Un manifiesto público de estado solo contiene hashes, conteos y resultados saneados.

| Artefacto | Contenido | Verificación |
|---|---|---|
| `inventory.json` | Contexto, namespace, objetos/UID, imagen/digest conocido, PVC/PV, rutas/PGDATA y capacidad libre | Identifica inequívocamente el origen y no incluye secretos. |
| Copia física protegida | Árbol PostgreSQL completo, WAL/tablespaces necesarios y metadatos de permisos | Copia realizada sin escritores; inventario/hash de archivos, errores de lectura visibles. |
| `legacy.dump` | Dump custom PostgreSQL consistente, todas las tablas de la base legacy | Hash y restauración completa en destino aislado. |
| `legacy-manifest.json` | Versión servidor/herramienta, encoding, extensiones, migraciones, conteos y digest ordenado por tabla | Comparar con restauración del mismo snapshot. |
| `sources.jsonl` | Fuentes completas exportadas por herramienta específica con campos privados separados | Recuento por tipo/estado, UUID completos e identidad sin truncar. |
| `channel-inventory.jsonl` | Semillas config/DB, IDs encontrados, aliases, autorización y discrepancias | Ninguna entrada se habilita solo por existir en dialogs. |
| Sesión Telegram protegida | Copia del archivo y otros artefactos necesarios, nunca su contenido en informe | Copia offline; dueño, permisos y hash comprobados. |
| `recovery-report.json` | Resultado restore, hashes/conteos, incidencias y decisión de recuperación | Estado `verified` solo tras restauración y consultas representativas. |

El dump incluye datos sensibles. No ponerlo en Git, un artefacto CI público, una carpeta servida por web ni un contexto Docker que se envíe al builder. Los exports de configuración deben redactar DSN, API keys, teléfonos, invites, access hashes y sesiones.

## Recuperación cuando PostgreSQL está apagado

1. **Preflight:** comprobar contexto/namespace/UID, cero pods/escritores, ubicación real de PGDATA/subPath/tablespaces, versión mayor, espacio libre y destino protegido. Confirmar que NFS tiene garantías necesarias; no dar por supuesto soporte de snapshot.
2. **Proteger el original:** obtener snapshot soportado o copia offline completa a otro destino. Mantener cero escritores durante toda la copia. Copia fallida/incompleta no habilita el siguiente paso. Copiar sesión por separado mientras la aplicación permanece parada.
3. **Recuperar una copia:** iniciar PostgreSQL de versión compatible sobre una copia de trabajo, con red aislada y sin runtime Noctis. La recuperación puede escribir WAL: nunca ensayarla sobre la única copia ni montar el mismo PGDATA con dos servidores. Capturar incidencias sin volcar datos privados.
4. **Dump lógico y manifiesto:** desde servidor recuperado, usar herramientas de versión compatible y autenticación por fichero/secret mount, sin contraseña en argumentos. Calcular conteos/digest dentro de una vista consistente; no comparar export de un momento con conteos de otro.
5. **Restauración de prueba:** restaurar el dump en una base temporal aislada; fallar ante cualquier error; comprobar esquema, extensiones, filas, hashes y búsquedas representativas. Listar el dump no demuestra que restaure.
6. **Preparar reutilización:** solo con recuperación verificada se prepara PostgreSQL estable, roles separados y `noctis_v2`. Mantener dump y copia del legado en dominio de fallo separado. Guardar recibo saneado de cada paso.

Si el original estaba detenido abruptamente, la copia física puede necesitar recuperación crash-consistent con todos los archivos requeridos. Copiar algunas tablas/directorios no es un backup válido. No ejecutar `initdb`, `pg_resetwal` ni borrado de PVC como reparación rutinaria.

## Inventario y resolución de canales

Fuentes del inventario: ConfigMap/configuración, tabla `sources`, pares `source_type/source_id` y metadatos históricos, más dialogs/peers que la cuenta autorizada pueda consultar durante una fase explícita. Se conservan discrepancias, no se elige un ganador por parecido de nombre.

```json
{
  "inventory_version": 1,
  "legacy_source_id": "legacy-uuid-or-null",
  "peer_type": "channel",
  "native_peer_id": "numeric-id-as-string-or-null",
  "aliases": ["public_username"],
  "origins": ["config", "legacy_sources"],
  "authorization": "previously_configured",
  "resolution_status": "pending",
  "desired_collection": "enabled",
  "session_ref": "private-secret-reference",
  "start_policy": "bounded_bootstrap_then_live"
}
```

Es contrato propuesto, no export real. IDs numéricos se serializan como cadenas para evitar errores de precisión JavaScript. UUID Noctis, username, ID nativo MTProto y representación Bot API son identidades distintas. `access_hash` y datos de sesión se conservan protegidos y asociados a la cuenta **y sesión de autenticación** que los resolvió; no son una identidad pública estable ni garantizan acceso con otra cuenta/login. Resolver nuevamente tras una autenticación nueva; ver [peers Telegram](https://core.telegram.org/api/peers).

Resolver por tipo+ID nativo usando la sesión autorizada; username es alias mutable y puede reasignarse. Migración de grupo a supergrupo y cambio de username requieren alias/relación explícitos. Entradas privadas, baneadas o inaccesibles permanecen registradas con causa; no hacer autojoin/import de invites para «arreglarlas».

El estado previo guía la política: activas/aprobadas/configuradas se proponen para reactivación; pausadas, rechazadas/baneadas o descubiertas sin aprobar conservan restricción hasta resolver conflicto. Un canal visto en mensajes o dialogs no recibe autorización automática. Todos se inventarían y se da una resolución a cada uno, pero solo se captura lo autorizado.

Importar en transacción por identidad de exportación y peer canónico, con dry-run y recibo `created/matched/conflict/skipped`. Repetir la misma importación no duplica, no alerta ni sobrescribe políticas o pausas decididas posteriormente. `desired_collection=enabled` expresa intención; no activa sin resolución y política válidas. Dialogs se paginan completos, incluidos archivados, bajo el cliente autorizado, sin autojoin: [getDialogs](https://core.telegram.org/method/messages.getDialogs). La representación [Bot API](https://core.telegram.org/api/bots/ids) no sustituye la identidad MTProto.

## Defectos del legado que impiden copiar cursores

En `internal/collector/telegram.go`, `telegramMessage` no conserva `msg.ID` ni revisión; catchup usa `ch.ID` de configuración en vez del peer resuelto, y el handler de updates no filtra los peers autorizados antes de `processMessage`. `last_collected` se actualiza por ticker y no representa el último mensaje confirmado.

Por ello: `source_id=0`, nombres y timestamps no se convierten en checkpoint confiable. Un dato ambiguo se importa como `legacy_unresolved`; no se atribuye a un canal por conjetura. Los IDs y cursores nuevos se resuelven y adquieren explícitamente, y se registra cualquier hueco de cobertura entre última evidencia legacy y nueva captura.

La allowlist nueva es `(account_scope, peer_type, native_peer_id)` y se aplica antes de persistir contenido. No reutilizar directamente el handler legacy para inventariar o iniciar scraping: puede recolectar otros canales de la cuenta y ejecutar autojoin en la resolución.

Si el protocolo requiere avanzar estado de updates sobre eventos excluidos, persistir solo una disposición mínima `excluded_policy` y el cambio de cursor, sin payload ajeno ni inferencia. Probar lotes mixtos autorizados/excluidos para no bloquear diferencias ni recolectar fuera de política.

## Época nueva, historial y propiedad de sesión

Crear `collection_epoch` y frontera por fuente con estado nativo y hora. `bootstrap_history`, `legacy_import` y `live` tienen cursores, cuotas y políticas de entrega distintos. Backfill nunca adelanta live ni genera avisos por defecto. Historial paginado con solapamiento y diferencias del protocolo explican cobertura; `MAX(message_id)` no demuestra ausencia de huecos, ediciones o eliminaciones. Ver [updates Telegram](https://core.telegram.org/api/updates) y [gotd updates](https://pkg.go.dev/github.com/gotd/td/telegram/updates); integrar un manager no prueba atomicidad con la DB de Noctis.

Un solo dueño por cuenta/sesión. `ReadWriteOnce`, `Recreate` y lease SQL no prueban exclusividad de un cliente en NFS. Perder lease cancela RPC y cierra cliente; transferir propiedad exige terminación confirmada del anterior. Si no se puede demostrar, `ownership_uncertain` y no arrancar segundo consumer. SQL fencing protege commits, no impide llamadas de red de un proceso obsoleto.

Comparación shadow desde corpus/export/inbox ya capturado, nunca dos collectors compartiendo sesión. Persistir `retry_at` de FloodWait y respetar espera con jitter; no fijar una cuota Telegram universal. Revocación de permisos pausa la fuente/cuenta afectada con causa, sin retry indefinido.

Rollback posterior a captura conserva inbox, jobs, ledger, outbox y cursores y vuelve a una versión v2 compatible o pausa. Retirar legacy en P8 es retirar su ejecución/escritura, nunca borrar sus datos/volúmenes.

## Referencias de recuperación

Procedimiento contrastado con [backup físico PostgreSQL 16](https://www.postgresql.org/docs/16/backup-file.html), [pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html), [pg_restore](https://www.postgresql.org/docs/16/app-pgrestore.html) y [snapshots consistentes](https://www.postgresql.org/docs/16/functions-admin.html). Confirmar versión real antes de ejecutar; estos enlaces no certifican el contenido del volumen.

## Herramientas por implementar, no disponibles aún

Comandos nuevos propuestos: `noctis legacy inspect`, `legacy export`, `sources import --dry-run`, `sources reconcile`, `telegram peers --read-only`, `telegram bootstrap` y `readiness report`. Especificaciones en los paquetes de trabajo; no invocarlos como si existieran. El actual `source list` trunca UUID/identificador y no es un export completo para reconstrucción.

La primera implementación debe hacer inventario/export restaurable y prueba de importación antes de desplegar colectores nuevos. Recuperar contenido no obliga a confiar en sus antiguas clasificaciones o atribuciones.
