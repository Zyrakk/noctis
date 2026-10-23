# Operación, seguridad y autonomía sostenible

Diseño propuesto. La revisión inicial no accedió al clúster; la planificación posterior comprobó metadatos de recursos/PVC y configuración filtrada en modo lectura: [inventario](12-preservacion-infra-y-canales.md). No se accedió a secretos, contenido de DB, cuentas Telegram ni inferencia remota. Completar el inventario y verificar recuperación antes de implementar sobre esa infraestructura o desplegar.

## Perfiles de despliegue

| Perfil | Componentes | Cuándo usarlo |
|---|---|---|
| Desarrollo/aceptación | PostgreSQL y binario Go con frontend compilado; gateway falso y fixtures | Integración reproducible sin credenciales reales. |
| Personal estable | PostgreSQL, core/worker, colectores autorizados aislados y proxy TLS/autenticación disponible | Opción principal para un operador. Reutilizar servicios existentes. |
| Kubernetes existente | Mismos componentes y contratos con PVC, probes, recursos, secretos y políticas de red | Si la infraestructura del operador ya lo justifica; no crear clúster solo para Noctis. |

Hipótesis inicial de ensayo: 2–4 vCPU, 4–8 GiB RAM y SSD con espacio para datos, índices y WAL; **no dimensionamiento certificado**. Medir carga, latencia, memoria por adaptador y tamaño real del archivo antes de fijar límites. No hace falta GPU en el diseño inicial.

PostgreSQL necesita almacenamiento con garantías adecuadas de fsync/locking y recuperación. El `nfs-shared` actual exige comprobar esas garantías; no asumirlas por el nombre de la StorageClass. Backups en dominio de fallo separado, no solo snapshots en el mismo volumen.

## Salud y objetivos de servicio

- Liveness indica proceso capaz de responder; no debe reiniciar por una caída transitoria de un proveedor.
- Readiness de API comprueba dependencias necesarias para servir; disponibilidad de inferencia se informa por separado.
- Cobertura operacional muestra última captura por fuente frente a su intervalo, backlog y edad del job más antiguo, porcentaje de procesamiento bloqueado y última entrega de brief.
- El estado global distingue operativo, degradado y detenido con causa. No mostrar cero amenazas cuando el sistema no tiene datos o vigilancia.

Objetivos iniciales para validar, no garantías actuales: RPO de metadatos ≤24 h con backup diario y RTO ≤4 h; posteriormente RPO ≤1 h si se habilita archivado WAL y el valor lo justifica. El ensayo de restauración debe demostrar los objetivos elegidos. La cadencia de cada fuente define su retraso aceptable; usar un umbral único para RSS, Telegram y feeds diarios produce alarmas falsas.

## Recuperación y mantenimiento

| Fallo | Comportamiento automático | Intervención excepcional |
|---|---|---|
| PostgreSQL no disponible | No confirmar ingest/cursor; backoff acotado y replay seguro | Reparar servicio/capacidad si persiste. |
| Worker cae | Lease expira; otro intento recupera; resultado viejo no puede sobrescribir | Cuarentena por fallo repetible de datos/código. |
| Proveedor IA cae/429 | Reintento limitado según error; captura mecánica continúa | Revisar contrato/cupo si persiste. |
| Presupuesto agotado | `budget_blocked`; priorizar trabajo pendiente, sin clasificar como ruido | Cambiar presupuesto solo por decisión explícita. |
| Timeout con consumo incierto | Reserva y estado incierto; no duplicar ciegamente | Reconciliar proveedor o limitar exposición residual por política. |
| Fuente revoca acceso | Pausar credencial y mostrar pérdida de cobertura | Renovar autorización/sesión. |
| Disco al umbral | Reducir trabajo opcional y aplicar retención autorizada; preservar evidencia comprometida | Ampliar capacidad o ajustar retención. No borrar expedientes silenciosamente. |
| Entrega de alerta incierta | Identificador estable y retry según contrato del destino | Mostrar incertidumbre si no hay recibo/idempotencia externa. |
| Migración falla | Detener avance, preservar versión anterior compatible | Reparación ensayada; nunca borrar PVC como solución. |

Backups cifrados y comprobación automatizada de completitud; restauración periódica a entorno separado con conteos, hashes y consulta de expediente. Alertar una sola excepción útil por condición, con recordatorio limitado y resolución automática cuando se recupere.

## Fronteras de seguridad concretas

**Fetch y descubrimiento.** Validar URL y destino en todas las rutas, incluidos configuración y redirect; solo esquemas permitidos, bloqueo de loopback/privadas/link-local/metadatos y validación DNS al conectar para evitar rebinding. Separar perfiles públicos/Tor y excepciones privadas explícitas. Límite de redirects, cuerpo, tiempo, descompresión y concurrencia. `tor_required` falla cerrado. Las allowlists de discovery no sustituyen controles del fetcher.

**Autenticación.** Reutilizar un proveedor de identidad existente si lo hay; en perfil personal, sesión segura de navegador con cookie HttpOnly/Secure/SameSite, caducidad y revocación. Proteger CSRF en mutaciones y aplicar roles de lectura/operación/publicación si existen varios usuarios. Tokens de servicio acotados y rotables; secretos nunca en parámetros URL, logs o frontend. QR Telegram en flujo administrativo autenticado separado de probes públicos.

**Contenido hostil.** Renderizar como texto saneado; sin ejecución HTML/JS, imágenes remotas automáticas ni descarga/ejecución de adjuntos por defecto. Build frontend con dependencias empaquetadas y CSP compatible, sin Tailwind/React runtime CDN. Limitar tamaños y formato; MIME y extensión no garantizan seguridad.

**Inferencia.** Clase de privacidad y permiso de envío antes de la llamada. Redactar secretos/datos de acceso cuando no sean necesarios; modelos sin shell, red libre ni acceso a administración. Fallback no cambia la jurisdicción/proveedor permitido implícitamente. Un prompt hostil no obtiene capacidades porque el modelo no las tiene.

**Efectos externos.** Inteligencia y remediación son contratos distintos. No activar bloqueos, NetworkPolicies o respuestas destructivas por una etiqueta IA. Empezar por alertas privadas y exportaciones limitadas; cualquier automatización de respuesta futura requiere política, pruebas y autorización propias.

**Datos.** Retención por clase y fuente, trazabilidad de purga, cifrado de backups y sesiones Telegram, minimización de credenciales filtradas y permisos independientes de DB. No enviar datos privados a un servicio de enriquecimiento solo porque acepta el formato.

## Descubrimiento sin crecimiento descontrolado

Estados de fuente: propuesta → prueba acotada → habilitada → degradada/pausada → retirada. El operador autoriza familias y límites, no cada mensaje. RSS público de dominios aprobados puede probarse automáticamente dentro de cuota; entrar en grupos privados, autenticarse en foros o usar nuevos privilegios exige decisión explícita.

Cada prueba tiene máximo de solicitudes/día, profundidad cero o acotada, TTL y criterio de utilidad. Un LLM propone tema/interés, pero no habilita accesos. Un bloqueo aprendido por ruido caduca y es reversible; no penaliza permanentemente un dominio completo por unos pocos ejemplos. La salud y el valor se miden por separado.

## CI y release

Construir frontend desde lockfile, compilar Go e incluir únicamente sus artefactos resultantes. Checks de lógica focalizada, contrato, migración y build antes de publicar imagen. Versionar imagen por digest/release, prompts, schemas, políticas y migraciones con checksum. Configuración validada y ejemplos probados reemplazan copias contradictorias de YAML.

Estrategia de actualización aditiva compatible: backup verificado, migración bajo exclusión, canary privado, health/progreso y operación representativa, rollback de aplicación si el esquema sigue compatible. No asumir que revertir imagen revierte datos.
