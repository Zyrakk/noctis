# Segundo piloto live G4 — ejecutado (2026-10-18)

El usuario autorizó un nuevo ensayo local independiente: misma cuenta, AuthKey/generación y único peer aprobado; dos procesos `collect` como máximo, 300 s por proceso con SIGTERM a 290 s, dentro de una ventana de 600 s. Se mantienen las cuotas anteriores: 256 admisiones aplicación/control, 1.000 observaciones, 64 MiB de payload y 4 MiB de metadatos persistidos, además de los mismos límites por fase. Sin backfill, resolve, login, joins, workers, IA, alertas ni producción.

Se preparó una base local nueva con esquema006, un nuevo `budget_id`, copias privadas de configuración y credenciales completas. Se conserva el binario congelado `2cbf233e5d8348ed4f17933716a95437a624518061aaee530f2a500e0fcc8a60`. El piloto anterior, su base detenida y presupuesto revocado permanecen intactos; no hay reset ni cursores injertados. El software no permite renovar el presupuesto en la misma base; este ensayo no demuestra continuidad entre pilotos.

El primer preflight se detuvo por credenciales del clúster caducadas, antes de cualquier cliente Telegram o presupuesto persistido. Tras comunicar el usuario su renovación, se repitió correctamente el preflight completo de contexto/servidor/usuario, UID originales, réplicas0, ausencia de pods, exclusividad, hashes y custodias. No hubo login ni renovación automática.

Se ejecutaron exactamente dos `collect`, de 292,17 s y 292,37 s, ambos con SIGTERM del supervisor a 290 s, exit0, sin SIGKILL y cierre demostrado por cuenta/owner/lease/flock. La segunda sesión sólo arrancó después de comprobar el cierre anterior y el mismo binding, contadores y vencimiento. Las dos sesiones ocuparon 586,37 s desde T0 dentro de la ventana original de 600 s. Presupuesto/epochs intactos durante el reinicio y contadores/cursores nativos monótonos. No hubo tercer cliente, backfill, resolve ni ampliación/reset de cuotas.

Resultado: **0 observaciones live, 0 bootstrap y 0 contenido fresco tras reinicio**. Tres entradas inbox de protocolo y 43 commits; cero payload excluido, duplicados, jobs, intentos IA y outbox. Las 47 admisiones acumuladas y los bytes persistidos finales fueron:

| Fase | Admisiones | Observaciones | Payload bytes | Metadata bytes |
|---|---:|---:|---:|---:|
| Control | 6 | 0 | 0 | 0 |
| Bootstrap | 1 | 0 | 0 | 0 |
| Live | 40 | 0 | 0 | 333 |

Estas unidades son admisiones de aplicación/control y bytes persistidos; no miden paquetes MTProto, RPC internos del SDK ni tráfico de ingreso. Una admisión de inicialización bootstrap no demuestra historial capturado.

Backup lógico de la nueva DB y configuración Telegram cifrados con age, claves separadas y descifrado íntegro verificado. Restore aislado de68 tablas/69 filas en30,62s, exacto en manifiesto/filas y hashes de cuentas, binding, presupuesto, contadores, fuentes, checkpoints, epochs y cursores; configuración byte a byte y permisos0600 verificados. El contenedor auxiliar de restore se eliminó. Los datos privados permanecen recuperables sobre LUKS en el mismo host, sin copia offsite.

Cierre final verificado: fuentes y peer propios deshabilitados, presupuesto nuevo revocado, cuenta cerrada sin owner ni lease y PostgreSQL propio detenido por identidad/label. Hashes de originales y artefactos del piloto anterior sin cambios; su DB nunca se arrancó. Se conservaron los recibos previos y no se modificó el producto ni se repitió QA global.

G4/T26 sigue pendiente: no llegó contenido live publicado desde T0 y capturado tras arrancar la segunda sesión. Las dos sesiones reales de esta autorización se han consumido; cualquier otro ensayo requiere autorización expresa. G6/G7/G8 siguen abiertos.
