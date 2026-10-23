# Piloto G4 autorizado — 2026-10-18

Binario congelado `2cbf233e5d8348ed4f17933716a95437a624518061aaee530f2a500e0fcc8a60`; esquema 006. Un peer aprobado y cuatro excluidos. 2 sesiones reales; un intento previo falló en validación local por faltar `account` en la copia de credenciales, sin cliente, presupuesto ni RPC. La copia se corrigió con la identidad ya aprobada.

Sesión 1: `collect`, 291 s, cierre limpio tras SIGTERM del supervisor a 290 s. Sesión 2: `backfill`, 3 s, una página y 100 observaciones bootstrap. Observaciones live frescas: 0. Payload excluido, duplicados, jobs procesados, intentos IA y outbox: 0; 100 jobs permanecieron en cola. Reinicio y continuidad del presupuesto y vencimiento verificados. Límites originales sin ampliación ni reset.

Las dos sesiones reales transcurrieron dentro de 303 s desde T0, con 29 admisiones de aplicación/control de las 256 permitidas. Se alcanzó el límite de 100 observaciones bootstrap de la página autorizada; no se abrió otro cliente ni se repitió la página. La validación local fallida anterior no inició transporte ni ventana y se registra por separado.

Backup lógico y configuración Telegram cifrados con age, claves separadas y descifrado íntegro verificado. Restauración aislada con manifiesto, filas, binding, contadores, epochs y cursores exactos. Sesión original intacta; fuentes y peer propios deshabilitados, presupuesto cerrado y PostgreSQL propio detenido. Datos privados recuperables retenidos sobre LUKS; copia en el mismo host, sin offsite.

El snapshot real contiene 68 tablas y 570 filas; la restauración tardó 27,91 s y su contenedor aislado fue eliminado. Configuración restaurada idéntica con permisos 0600. La copia activa conservó AuthKey/generación; sus cambios se limitaron a campos SDK de salt/configuración DC.

G4/T26 permanece pendiente: no hubo contenido live fresco y no se demostró su captura tras reinicio. G6 revisión humana, G7 utilidad y G8 producción siguen abiertos. No workers, IA, alertas, joins ni cambios de producción.

Admisiones y bytes persistidos finales (no paquetes MTProto ni bytes de ingreso):

```json
{
  "live": {
    "api": 21,
    "observations": 0,
    "payload_bytes": 0,
    "metadata_bytes": 1858
  },
  "control": {
    "api": 6,
    "observations": 0,
    "payload_bytes": 0,
    "metadata_bytes": 0
  },
  "bootstrap": {
    "api": 2,
    "observations": 100,
    "payload_bytes": 139645,
    "metadata_bytes": 39804
  }
}
```

Ventana original: 600 s; procesos de hasta 300 s con SIGTERM del supervisor a 290 s. Contadores monótonos: True; epochs iguales: True; cursor nativo monótono: True. Backfill: 1 comando, máximo una página de 100 mensajes con los límites bootstrap ya aprobados. No se afirma historial completo; GetState/inicialización y Difference no prueban backfill.

Los artefactos privados y claves separadas están fuera del repositorio. No se cambió código del producto, ni se repitió QA global. Verificaciones ejecutadas: preflight de exclusividad/contexto/UIDs/replicas, cierre por sesión/owner/lease/flock, binding y límites persistidos, invariantes de captura y restauración real.
