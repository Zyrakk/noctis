# Horizonte de reintentos y pausa de fuentes

Los trabajos tienen un vencimiento persistente `retry_deadline_at`, inicialmente
`created_at + 24 horas`. Una pausa aparca los trabajos `parse` vigentes de esa
fuente, tanto `queued` como `retry_wait`, y registra `source_paused_at`. Al
reanudar, el vencimiento aumenta exactamente la duración documentada de ese
aparcado; se limpia el inicio una sola vez. No se cambia `created_at`, no se
concede un día nuevo y se conserva un `retry_at` futuro. El código de error
`source_resumed` ya no concede excepciones.

La congelación comienza cuando se aparca durablemente. No descuenta tiempo
anterior en ejecución, pausa global ni indisponibilidad del worker. `Finish`
devuelve el intento interrumpido por pausa antes de publicar. Un fallo real y
un lease vencido conservan el intento consumido; `Fail` y la recuperación del
lease aparcan si la fuente sigue pausada y conserva presupuesto. Se mantienen
el máximo de cinco intentos y los fallos permanentes. Un horizonte agotado
antes del aparcado no se rehabilita. `Claim`, `Fail`, pausa y reanudación se
ordenan mediante el guard de proyección; los barridos bajo ese guard usan
`SKIP LOCKED` para no esperar a un `Finish` o `Fail` que ya posee la fila.

La reanudación conserva autorización, política, revisión, época y caducidad de
evidencia. No despierta cancelados, cuarentenados ni claves ya analizadas; las
claves ausentes se crean mediante la restricción única existente. El replay
explícito sigue siendo el reinicio autorizado: limpia el aparcado e intentos,
y fija `created_at` y un vencimiento de 24 horas nuevos. No es un replay masivo.

## Antes de aplicar la migración 012

Con los procesos antiguos detenidos, ejecutar esta consulta de solo lectura en
la base objetivo ya identificada y conservar los conteos en el recibo del
despliegue. No registrar contenidos ni secretos:

```sql
SELECT
 count(*) FILTER (WHERE state='dependency_blocked'
   AND last_error_code='source_paused'
   AND created_at+interval '24 hours'>statement_timestamp()) AS paused_positive,
 count(*) FILTER (WHERE state IN ('queued','retry_wait','leased','dependency_blocked')
   AND last_error_code='source_paused'
   AND created_at+interval '24 hours'<=statement_timestamp()) AS paused_unknown,
 count(*) FILTER (WHERE state IN ('queued','retry_wait','leased','dependency_blocked')
   AND last_error_code='source_resumed'
   AND created_at+interval '24 hours'<=statement_timestamp()) AS resumed_unknown
FROM noctis_v2.jobs;
```

No existe evidencia suficiente para reconstruir el comienzo de una pausa
antigua. La migración inicializa el vencimiento desde `created_at` en todas las
filas. Para `source_paused` con saldo positivo congela solo desde la migración.
Las filas activas antiguas `source_paused` o `source_resumed` cuyo vencimiento ya
pasó quedan `dependency_blocked` con `retry_horizon_unknown`, sin fecha de
aparcado inventada. No cambia intentos ni rehabilita estados terminales.

Después, comprobar el conteo `WHERE last_error_code='retry_horizon_unknown'`
y evaluar cada caso con el flujo de replay autorizado existente. La reanudación
normal no desbloquea esos casos; un diagnóstico no constituye autorización para
reiniciarlos. Las comprobaciones PostgreSQL/race viven en
`internal/runtimev2/source_retry_horizon_test.go`; las regresiones Core005
comprueban publicación única y ausencia de resurrección de evidencia caducada.
