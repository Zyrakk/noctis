# Preparación offline de G4/G6/G7/G8

Estas herramientas producen propuestas privadas revisables. No conceden permisos,
activan fuentes, ejecutan modelos ni aplican infraestructura. Todos los identificadores,
hashes, contenido y hojas de revisión quedan fuera del repositorio, en 0700/0600.

`prepare.py --inventory DIRECTORIO_PRIVADO --output DIRECTORIO_PRIVADO_EXISTENTE`
usa el inventario y reconciliación ya preservados; crea propuestas nuevas sin
sobrescribirlas. Propone el primer peer sin conflictos en el orden estable de los
cinco resultados, deja cuatro sin seleccionar y conserva los cuatro conflictos y
todas las restricciones. Alias actuales no acreditan identidad histórica.

El presupuesto durable006 y el arranque SDK guardado están implementados. El
piloto sigue bloqueado hasta verificar freeze/hash y QA del binario concreto,
aprobación explícita y preflight del operador, incluida custodia y cierre del
dueño anterior. Las revisiones humanas G6 y el corpus adjudicado siguen pendientes.
Los límites propuestos son
10 minutos, dos ejecuciones de cinco, un bootstrap de 100 mensajes como máximo,
256 admisiones de aplicación/control, 1000 observaciones y 64 MiB entre ambas
ejecuciones y bootstrap. Una admisión de control cubre el establecimiento y su
inicialización/retries internos del SDK; las operaciones API públicas consumen
admisiones adicionales. No cuenta cada RPC interno, paquete o retransmisión
MTProto, ni mide bytes ingress. Un timeout
por sí solo no acredita estos límites. FLOOD/revocación o cierre incierto detienen
el piloto sin reintento automático. G4 continúa pendiente si no llega contenido.

Para G6/G7, `extract_candidates.py --dump DUMP_LOGICO_VERIFICADO --output NUEVO`
restaura exclusivamente una copia en un contenedor PG16 propio sin red. Requiere
Docker y la imagen ya local; no arranca restauraciones P0 conservadas. Selecciona
400 filas con orden determinista por hash, sin usar etiquetas legacy, guarda
contenido sólo en un fichero privado separado y elimina su contenedor/volumen al
terminar. La selección no promete representatividad. El idioma queda desconocido
si el archivo no tiene una etiqueta fiable; episodio y partición requieren revisión.
No proporcionar el contenido al modelo durante esta preparación.

Dos revisores humanos deben etiquetar independientemente sin acceso a etiquetas
legacy ni predicciones. El adjudicador documenta desacuerdos y decide episodios,
idiomas y particiones temporales sin dividir episodios. Marcar abstención y causa
cuando falta evidencia. Verificar exhaustividad, citas, roles, negación, actualidad,
duplicados y aplicabilidad; registrar cada omisión y falsa alarma por separado.
Las hojas no adjudicadas quedan fuera del evaluador. Las etiquetas históricas no
son gold. `tools/eval` conserva `quality_measured=false` y no autoriza promociones.

Para utilidad, registrar tarea y criterio de éxito antes de ver la salida; comparar
baseline manual y candidato en orden ciego alternado, con tiempos, atención,
omisiones, falsas alarmas y resultado verificable. Una preferencia aislada no cierra
G7. No ejecutar inferencia hasta aprobar por separado ruta, clases de datos,
presupuesto monetario absoluto y concurrencia. Campos pendientes no autorizan gasto.

G8 incluye una propuesta de cuatro roles y plantillas pausadas para contexto
`zcloud-cluster`, namespace `noctis`; image digest/origen/Secret siguen pendientes.
No son manifiestos desplegables. El rollback de software conserva schema006 y
datos v2; no ejecutar un binario legacy contra schema v2 ni mutar/copiar los PVC P0.
Registrar UIDs, réplicas previas, digest anterior compatible y prueba de backup/restore
antes de proponer una orden de rollback. Piloto, inferencia pagada y cutover requieren
aprobaciones independientes, con dueño, alcance, límites y evidencia concretos.
