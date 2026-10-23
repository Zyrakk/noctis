# Recuperación P0

Herramientas operativas privadas; no se ejecutan desde tests generales ni CI.
Requieren Python 3.12+, PyYAML, kubectl, Docker y age. Los tests unitarios usan
fixtures sintéticas y no conectan al clúster:

```sh
python3 -m unittest discover -s ops/rebuild/recovery -p 'test_*.py'
```

`preflight.py` verifica cuenta, servidor, contexto, namespace, UID, workloads
detenidos y ausencia de otros montajes/controladores de los PVC conocidos.
`preserve.py DESTINO` requiere el helper temporal conocido, PVC completos
montados con `readOnly` tanto en volumen como montaje, y destino privado
fuera del repositorio. Rechaza enlaces y miembros especiales que necesiten
preservación adicional. Guarda tar con metadatos originales, inventario de
permisos/propiedad/fechas y hashes por archivo; compara dos lecturas del origen
y la copia extraída. Las extracciones locales conservan el usuario local;
la propiedad original permanece en los encabezados tar verificados.

`protect.py DESTINO` cifra los artefactos de primer nivel con age, guarda una
clave 0600 en directorio hermano 0700 y comprueba el archivo completo mediante
descifrado en streaming y SHA-256. No copia automáticamente clave ni archivo
a almacenamiento externo. Conservar ambos en otro dominio de fallo según la
política privada; no enviar ninguno a Git/CI/contexto de build.

`recover.py DESTINO` exige las copias verificadas y `architecture.json`.
Rechaza una arquitectura distinta antes de crear datos de trabajo o contenedor.
El destino de restauración debe ser nuevo. Usa PostgreSQL 16 Alpine por digest,
socket local sin red Docker, copia de trabajo separada y overrides que anulan
configuración de recuperación/red/archive y librerías preloaded. El dump y el
manifest comparten snapshot exportado con transacción abierta. La restauración
es fail-fast y transaccional; compara esquema, encoding, extensiones, tablas,
conteos/digests deterministas, secuencias y large objects. Inventaría roles/ACL
sin contraseñas por separado y exporta identidades de fuentes desde la copia
restaurada, sin contactar Telegram ni activar políticas. El `finally` detiene
los contenedores conservando sus datos privados.

`inventory.py` produce también el contrato `sources-manifest-v1`, con IDs
completos como cadenas, identidades desconocidas null y disposición explícita.
La configuración exportada queda pendiente; la exportación completa desde DB
requiere primero una restauración verificada. Ningún identificador numérico
legacy se convierte por su formato en peer nativo.

Para recuperar un origen ARM64 sin alterar el guard físico, `recover.py
--arm-kube DESTINO` utiliza un auxiliar nativo en `oracle1` y restaura el dump
lógico en Docker AMD64 con `--network none`. El auxiliar sólo monta emptyDir,
sin PVC, Secret ni token de cuenta; su spec exige usuario no root, capabilities
vacías, seccomp RuntimeDefault y raíz RO. Verifica nodo/namespace/UIDs,
readiness, ausencia de presión, originales detenidos y disco real disponible.

`kube_guard.py` crea primero una NetworkPolicy exclusiva deny-all. Tres pods
sin datos prueban controles positivos entre pods y bloqueos de ingreso/egreso
del auxiliar; cualquier fallo impide transferir datos privados. Kubernetes/K3s
mantiene excepciones de tráfico relacionado con nodos: este ensayo no promete
aislamiento absoluto. Los listeners sintéticos se detienen antes de la copia.
Sólo se transfiere `database.tar` por stdin binario sin TTY; nunca la sesión ni
la clave age. Se revalidan hashes/membresía antes y después de transferir, mayor
PG16 y ARM. Configuración, PID, auto.conf y propiedad sólo cambian en la copia.
Se comprueban overrides efectivos y ausencia de listeners TCP PostgreSQL.

Cada base no template se exporta con snapshot mantenido abierto para dump,
manifest y consultas representativas. Se comparan exactamente encoding,
locale, esquema normalizado, extensiones, filas/conteos/digests, secuencias
incluido `is_called`, large objects y consultas de fuentes/histórico/migraciones/
relaciones. Roles/ACL sin contraseñas quedan aparte porque restore usa
`--no-owner --no-privileges`. Errores y timeouts invalidan el resultado; un dump
parcial sólo cambia a nombre definitivo después de cerrar snapshot con éxito.

`integration.py DESTINO_PRIVADO` ejecuta una recuperación PostgreSQL16 sintética
completa y un fallo real de pg_restore en Docker aislado. Incluye IDs >2^53,
secuencia aún no llamada, nulls, columnas adicionales e identidades/restricciones
históricas; sus datos no acreditan G0. El recibo distingue la evidencia real.

Los resultados de cada intento quedan en un subdirectorio `arm-logical-*` nuevo.
`protect.py RESULTADO --reuse-key CLAVE_EXISTENTE` crea `logical-recovery.age`
sin sobrescribir preservación/clave, verifica descifrado completo y hash e
incluye dumps y evidencia. La copia restaurada detenida queda privada en
`restore-data`; su representación portable es el dump lógico verificado.
Los pods se eliminan con UID antes de retirar su política; se prueba ausencia
y se repite preflight. Los contenedores Docker se detienen conservando datos.

El helper se crea y elimina bajo preflight y UID conocidos. Antes de eliminarlo
debe comprobarse también su UID exacto; nunca usar una eliminación por selector.
No escalar workloads originales ni iniciar la aplicación legacy. Una copia,
un tar legible o `pg_restore --list` no acreditan un restore.
