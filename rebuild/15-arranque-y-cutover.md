# Arranque limpio, reinyección de canales y cutover

Runbook propuesto para P0/P4/P6/P8. **No ejecutado.** Los pasos de escritura se aplican cuando exista código v2 probado y recursos concretos verificados. No escalar ahora la imagen legacy para «ver si arranca»: `serve` ejecuta migraciones y componentes antiguos.

## Estado inicial conocido

Aplicación y PostgreSQL detenidos; PVC conservados. Configuración tiene cinco usernames, pero la tabla `sources` y la cuenta Telegram pueden contener más. No se han recuperado IDs, dump ni sesión. «Todos los canales» significa inventario reconciliado completo y disposición explícita; no activar fuentes rechazadas, no autorizadas o inaccesibles.

## Secuencia y condiciones de parada

| Paso | Acción preparada | Resultado comprobable | Detener si |
|---|---|---|---|
| **R0 Inventariar** | Identificar contexto/namespace/UID, PVC/PGDATA, versión real/capacidad y configuración saneada | Recibo de origen y destino sin secretos | Contexto dudoso, escritores inesperados o capacidad insuficiente. |
| **R1 Preservar** | Copia física completa y sesión offline, una copia protegida y otra de trabajo | Archivos/hash/permisos e inventario de WAL/tablespaces | Lecturas fallidas, copia incompleta o único original expuesto a recuperación. |
| **R2 Recuperar y exportar** | PG compatible aislado sobre copia de trabajo; dump+manifest y restore en DB vacía | G0 verificado y copia fuera del dominio de fallo | Recuperación/restore/hash/conteos discrepantes sin explicar. |
| **R3 Preparar v2** | Reutilizar PG estable, crear DB/roles `noctis_v2`, migraciones explícitas y config nueva | G1–G3 locales/aislados; runtime vacío funcional sin IA | Runtime accede legacy con permisos de escritura o inicia componentes viejos. |
| **R4 Importar inventario** | Dry-run y commit de fuentes; resolver peers con sesión protegida y política | Cada registro con resultado y correspondencia; replay sin cambios indebidos | Username reasignado, IDs ambiguos, nuevas autorizaciones implícitas. |
| **R5 Preparar sesión** | Comprobar dueño anterior terminado; transferir sesión/cache protegido al collector v2 | Un propietario efectivo, auth scope y allowlist por peer | `ownership_uncertain`, sesión inválida o cliente anterior posiblemente activo. |
| **R6 Captura piloto sin entrega** | Una fuente existente autorizada, epoch/frontera/cursor nuevos; bootstrap acotado | ID/revisión/procedencia correctos, restart/replay/gaps demostrados | Cursor avanza sin datos/disposición, contenido ajeno persistido, FloodWait ignorado. |
| **R7 Expandir captura** | Activar fuentes autorizadas por oleadas según límites; histórico en cola distinta | Progreso por canal, estado/errores/disposición completa y no duplicados | Backlog/latencia/esperas/capacidad exceden política; pausar expansión. |
| **R8 Integrar inteligencia** | G5/G6, presupuestos/reservas y modelo/ruta evaluados | Tres historias y pipeline degradado funcional, límites visibles | Coste incierto ilimitado, citas inventadas o confirmación IA sin política. |
| **R9 Habilitar producto/entrega** | Configurar destinatario y política, probar receipt; abrir UI privada candidata | Entregas solo de epoch/cambios elegibles, acceso/cobertura comprobados | Doble sender, alerta de bootstrap, destinatario incorrecto o pérdida de privacidad. |
| **R10 Cutover estable** | Release por digest, un dueño captura/entrega, tráfico privado al candidato | Gates afectados sobre artefacto release y operación representativa | No existe rollback compatible o respaldo de v2 comprobado. |
| **R11 Cerrar rebuild** | Desconectar runtime legacy y reconciliar docs/config; mantener archivo | G8 y trazabilidad completa, fuente a fuente y capacidad a capacidad | Algún requisito core sin verificar o exclusión no justificada. |

R3 puede desarrollarse y probarse en local mientras R0–R2 esperan recuperación privada. R4/R5 no deben tener acceso de escritura al archivo legacy. R9 puede habilitarse durante piloto controlado, antes del corte estable R10, manteniendo políticas/epoch/destino explícitos.

## Qué reinjectar y qué no

| Material | Tratamiento |
|---|---|
| Canales configurados/activos/aprobados | Proponer resolución/activación según permiso vigente; registrar conflictos. |
| Pausados/baneados/rechazados/solo descubiertos | Importar inventario con restricción, sin activar automáticamente. |
| Dialogs de la cuenta no presentes en fuentes | Candidatos pendientes; nunca permiso por pertenecer a la cuenta. |
| IDs nativos demostrables y aliases | Importar identidad con origen; username mutable no es clave definitiva. |
| `source_id=0`, nombre o último timestamp legacy | Preservar como dato ambiguo; no inventar peer ni cursor. |
| Sesión y peer access hashes | Material privado por cuenta y auth session; nunca en manifest público o frontend. |
| Contenido antiguo | Archivo read-only y/o import opcional idempotente sin alertas. |
| Clasificaciones, scores, correlaciones y entidades derivadas | Resultados históricos con método/versión; no cargar como hechos confirmados. |
| Alertas pendientes y presupuesto legacy | No trasladar a entrega nueva; conservar auditoría histórica separada. |

No hace falta recargar todo el texto histórico para volver a captar. Sí hace falta conservarlo y poder consultarlo/restaurarlo. El reanálisis posterior usa cuota y política propias.

## Frontera de captura y recuperación del periodo apagado

Por fuente guardar `collection_epoch`, instante de activación, estado updates/differences necesario, referencia del límite conocido y límites de backfill. El algoritmo y versión del adaptador forman parte del recibo.

Primero establecer cómo se reconciliarán updates e historial para no perder eventos durante bootstrap; persistir estado de recepción/disposición atómicamente. El backfill puede cubrir una ventana acordada o un número máximo de mensajes, con paginación/cursor y prioridad bajos. No usar simplemente los últimos 100 mensajes como prueba de recuperación completa.

La alerta se decide por epoch, modalidad de captura, event time y novedad/política; nunca solo por `collected_at`. Mensajes anteriores recolectados hoy no se convierten en novedades de hoy. Las actualizaciones materiales de un episodio antiguo pueden generar una nueva revisión elegible conforme a regla explícita.

Si Telegram no conserva historia, falta acceso o existe discontinuidad, registrar `coverage_gap` con intervalo/alcance y causa conocida o desconocida. No afirmar cero pérdidas. Ediciones y borrados necesitan revisión/tombstone, no se resuelven únicamente con máximo ID.

## Comandos futuros y herramientas actuales

Implementar y probar antes de usar: `legacy inspect/export/verify`, `sources export/import/reconcile`, `telegram peers --read-only`, `bootstrap`, `runtime readiness`, `deliveries enable/disable` o comandos equivalentes. La sintaxis definitiva se fija con sus tests/help en P0–P4. No se da un comando de despliegue con namespace/DSN inventados.

Patrón PostgreSQL de la herramienta de recuperación, con servicios y archivos privados ya preparados, versión compatible y destino vacío:

```sh
pg_dump --dbname=service=legacy_recovery --format=custom --file=legacy.dump
pg_restore --list legacy.dump
pg_restore --dbname=service=restore_check --exit-on-error --single-transaction --no-owner --no-privileges legacy.dump
```

No son comandos ejecutados. `PGSERVICEFILE`/`PGPASSFILE` montados y permisos adecuados contienen conexión/credenciales. Roles/ACL/extensiones se inventarían y recrean deliberadamente; no copiar roles con contraseñas a un informe. En un archivo grande, ajustar estrategia de restore sin perder fail-fast ni verificación completa.

## Rollback y pausa

**Antes de captura/entrega:** detener candidato y mantener origen preservado, sin modificarlo para satisfacer el esquema nuevo.

**Después de captura v2:** deshabilitar dispatcher, detener collector y confirmar cierre del cliente; preservar inbox/observaciones/jobs/checkpoints/outbox/ledger. Revertir a release v2 compatible con esquema o mantener pausa. No ejecutar reverse migrations destructivas ni reactivar collector legacy. Restaurar un backup es recuperación con pérdida potencial dentro del RPO, no equivalente a revertir imagen.

**Entrega incierta:** no reenviar sin revisar identificador estable y contrato del destinatario. Si el receptor soporta idempotencia, reutilizar clave; si no, conservar estado incierto y seguir política documentada.

**Sesión incierta:** no iniciar segundo dueño hasta confirmar que el anterior terminó. Fencing protege DB, no RPC. Mantener estado visible y fuente pausada si no se puede demostrar exclusividad.

## Recibo de arranque final

Debe incluir: release/digest, contrato/esquema/política; origen del backup y restore verificado; fuentes totales con activas/pausadas/conflictos/inaccesibles; epoch/frontera/gaps; propietario de sesión; progreso y atraso por fuente; destinatario/estado de entrega; ruta/modelo/caps y coste; consultas privadas representativas; restore/rollback probados y limitaciones. No incluir mensajes, secrets, access hashes o invites.

El arranque se considera funcional cuando una observación nueva autorizada llega a un expediente citado, aparece como cambio correcto y produce aviso/brief conforme a política, manteniendo recuperación y privacidad. No se acredita contando pods Running.
