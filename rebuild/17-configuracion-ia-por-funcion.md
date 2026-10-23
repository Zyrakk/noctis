# Configuración interactiva de IA por función

Requisito explícito del usuario, 18-10-2026. Diseño revisado por Astra xhigh; implementación y pruebas pendientes. Complementa `04`, `05`, `06` y `08` y forma parte del core, no de las extensiones.

## Comportamiento

Sistema → IA ofrece un selector por cada función de IA realmente implementada. Permite introducir proveedor/adaptador compatible, URL, API key e ID de modelo, guardar, desactivar y comprobar estructura sin ejecutar inferencia. Cada función muestra su configuración efectiva y estado; ninguna conserva clientes globales ocultos del runtime anterior. Una conexión puede compartirse de forma explícita entre funciones.

El registro de funciones ejecutables incluye las capacidades semánticas, análisis y síntesis de expedientes, brief, consulta tipada, traducción y triage que implemente el runtime. Las funciones todavía no disponibles se identifican como tales y no ofrecen selectores que aparenten efecto. OCR y embeddings siguen condicionados por sus contratos propios.

La selección individual no impone varias llamadas por observación: subtareas semánticas pueden agruparse en una pasada cuando coincidan ruta, modelo, límites, privacidad y esquema. Configuraciones distintas requieren trabajos y reservas separados con coste visible. Severidad mecánica, permisos, publicación y presupuesto no se delegan al modelo.

## Persistencia y seguridad

- Conexiones y bindings por función tienen revisiones inmutables, control optimista de concurrencia y auditoría saneada. Cada intento conserva el snapshot de configuración usado; desactivación, revocación y privacidad se comprueban antes de salir a la red.
- API keys de escritura exclusiva: conservar, sustituir y eliminar son operaciones distintas. Las lecturas solo devuelven `secret_present`; nunca la clave, tampoco en errores, logs, auditoría o almacenamiento del navegador. El formulario borra la clave de su estado tras guardar.
- Credenciales cifradas mediante AEAD con identificador/revisión autenticados, `key_id` y clave maestra montada fuera de PostgreSQL; fallo de descifrado bloquea la función. La recuperación incluye copia protegida y versión de la clave maestra.
- Configuración privada con permiso administrativo, sesión HttpOnly/Secure/SameSite, protección CSRF y Origin. La demo no consulta estos endpoints.
- URL HTTPS sin credenciales, query ni fragmento. Transporte sin proxy ambiental ni redirects; DNS e IP se validan y la conexión se fija a una dirección permitida conservando TLS. Proveedores locales solo mediante allowlist de host/IP/puerto administrada en el servidor; el panel no puede conceder esa excepción.
- Guardar y validar no llaman a proveedores ni gastan. Habilitar una ruta exige límites, capacidades y política de datos compatibles. El ledger reserva antes de cada intento; timeout o consumo ausente conservan exposición incierta. Cambios de ruta/modelo invalidan la evaluación afectada.

## Paquete y aceptación

**P6.5**, coordinado con P6.1–P6.3 y P7.1: backend de conexiones/bindings/secretos/router, API privada, formulario de Sistema e integración real de todos los consumidores por `FunctionID`. Un único responsable coordina las migraciones.

| Prueba | Evidencia requerida |
|---|---|
| **T45** Configuración durable | Dos funciones con URL/modelo distintos; lectura saneada, CAS con conflicto, desactivación y persistencia tras reiniciar API/worker. |
| **T46** Credenciales y fronteras | Conservar/sustituir/eliminar, fallo AEAD, permisos/CSRF, ausencia de secretos, SSRF/DNS/redirects y excepción local exclusivamente administrada. |
| **T47** Consumo efectivo | Gateways falsos reciben rutas/modelos correctos; coalescencia compatible, snapshots/revocación, bloqueo privacidad/capacidad/caps y timeout incierto. Ninguna inferencia real pagada. |
| **T48** Panel integrado | Playwright contra frontend compilado y PostgreSQL real: editar/guardar/reiniciar/usar, errores y conflicto visibles, claves ausentes tras guardar y demo aislada. |

T45–T47 forman parte de G6 y T48 de G7. La existencia del formulario o de mocks sin consumidor real no verifica el requisito.
