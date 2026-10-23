# Producto, experiencia e identidad visual

La unidad central es el **expediente**, no una clasificación ni un nodo de grafo. El expediente puede crearse automáticamente mientras sus afirmaciones siguen sin verificar. El operador recibe una explicación de cambios, relevancia y evidencia, sin ensamblar manualmente doce pantallas.

## Navegación propuesta

| Área | Pregunta | Elementos principales |
|---|---|---|
| **Hoy** | ¿Qué cambió y merece atención? | Novedades materiales, brief, excepciones concretas, cobertura y degradación. |
| **Expedientes** | ¿Qué sabemos de este episodio? | Resumen citado, revisiones, cronología, contradicciones, acciones y seguimiento. |
| **Explorar** | ¿Qué encuentro y cómo se relaciona? | Búsqueda tipada, observaciones, entidades, observables, CVEs y grafo contextual. |
| **Fuentes** | ¿Qué vigilo y qué falta? | Salud, permisos, dependencia/originalidad, política y pruebas de nuevas fuentes. |
| **Sistema** | ¿Puede seguir funcionando? | Backlog/edad, presupuesto, integración, recuperación y configuración. |

Estas áreas sustituyen una navegación centrada en módulos. Findings, IOCs, notas y correlaciones continúan accesibles como vistas/filtros/contexto, sin exigir que el usuario recuerde qué subsistema produjo cada objeto.

## Hoy: cambios antes que contadores

Cabecera propuesta: «Tres cambios materiales desde tu última visita. Telegram actualizado hace cuatro minutos. Una fuente retrasada». Debe salir de datos reales y conservar fecha de actualización; una fuente caída no puede convertirse en «sin amenazas».

Fila de novedad: título, interés/PIR relacionado, **qué cambió**, por qué importa, prioridad, estado evidencial y referencia. Ejemplo: «El aviso del fabricante añade la versión que vigilas; cuatro publicaciones posteriores reproducen ese aviso». No presentar cinco publicaciones como cinco corroboraciones.

El brief integra cambios y límites de cobertura. Si no hay novedades: «No se observaron cambios materiales en las fuentes disponibles», acompañado de periodo y salud. Los contadores de volumen se relegan a operación y exploración.

## Expediente y evidencia

Composición: cabecera estable, resumen breve, bloque de cambio frente a revisión anterior, timeline y lector lateral de evidencia. En portátil, el lector puede abrirse como panel; en móvil pasa a vista completa manteniendo regreso al punto de lectura.

Cada afirmación abre su cita exacta con contexto, fuente, autor si existe, fecha publicada, fecha recolectada, revisión y rol de origen/repost. Distinguir original, traducción y resumen. Texto retenido parcialmente o expirado se indica; tombstone no se representa como original verificable.

Timeline agrupa original, copias, correcciones, contradicciones y retractaciones. El grafo se abre desde expediente/entidad con límites de nodos, saltos y periodo; cada arista indica relación, evidencia y vigencia. No usar una red global de miles de nodos como portada.

```text
┌ Navegación ─┬ Hoy / Expediente ───────────────────┬ Evidencia ───────────┐
│ Hoy         │ Qué cambió · por qué importa       │ Fuente y revisión   │
│ Expedientes │ Resumen [1] [2]                    │ Texto exacto        │
│ Explorar    │ Timeline: original → copias       │ Contexto            │
│ Fuentes     │ Contradicciones / incógnitas      │ Fechas y origen     │
│ Sistema     │ Acción concreta si procede        │ Estado verificable  │
└─────────────┴────────────────────────────────────┴─────────────────────┘
```

## Estados: tres ejes, una experiencia

| Eje | Estados orientativos | No implica |
|---|---|---|
| Expediente | Nuevo, seguimiento, resuelto, archivado | Incidente confirmado. |
| Afirmación | Reportada, sustentada, contradicha, retirada, desconocida | Que todas las afirmaciones del expediente compartan certeza. |
| Atención | Automática, silenciada hasta cambio, excepción | Que visto/archivado confirme una hipótesis. |

Revisión excepcional requiere motivo, decisión concreta, evidencia necesaria y plazo. Si nadie responde, mantiene provisionalidad o espera; no confirma por silencio. Las hipótesis ordinarias no llenan una cola humana. Un silencio puede romperse ante evidencia independiente, retractación o cambio de impacto según política configurada.

Medir presupuesto de atención: minutos de revisión semanal, excepciones abiertas y decisiones resolutivas. Si crece sin aportar valor, reducir fuentes/ruido o mejorar política; no trasladar la clasificación masiva al operador.

## Tres historias de aceptación

### A. Vulnerabilidad vigilada

Un aviso coincide con una tecnología. La versión del activo es desconocida: el expediente muestra aplicabilidad pendiente, no «seguro» ni «afectado confirmado». Actualización posterior añade un rango afectado que coincide con versión inventariada. El radar explica por qué subió prioridad; KEV indica explotación conocida global, no compromiso local.

### B. Oferta de acceso y republicaciones

Un canal afirma vender acceso a una organización vigilada; cuatro canales copian el anuncio. Conservar cinco observaciones, un contenido reutilizable y un origen conocido. Alertar «oferta reportada» con cita, nunca «brecha confirmada». Una negativa de la organización entra como contradicción; el expediente conserva ambas y actualiza el brief. Esta historia underground es parte de la aceptación del relanzamiento.

### C. Handle e infraestructura compartida

Aparece un handle conocido junto a un dominio nuevo. Coincidencia abre hipótesis, no fusiona identidades. Un hosting compartido reduce especificidad del vínculo. Dossier muestra el camino factual y la incógnita. Nuevas evidencias pueden reforzar o retirar la hipótesis conservando historia.

## Dirección visual

Identidad de observatorio y archivo de investigación: azul tinta, superficies discretas, tipografía clara y violeta de Noctis para selección/referencias. Ámbar para incertidumbre/degradación y rojo reservado a urgencia. Color siempre acompañado de texto/icono; prioridad y certeza no comparten un badge ambiguo.

Mantener Fira Sans y Fira Code empaquetadas localmente. Cuerpo 14–16 px; metadatos normalmente ≥12 px; monoespaciada para identificadores. Preferir tablas/filas comparables y lector de evidencia a tarjetas repetitivas. Validar contraste, foco visible, teclado, zoom y reducción de movimiento. Estas son especificaciones propuestas, no resultados de una auditoría visual ejecutada.

Tres elementos reconocibles: banda de cambios entre revisiones, recorrido de procedencia y citas consistentes en todo el producto. Movimiento breve para cambios/selección, nunca animaciones que dificulten lectura. Soportar portátil sin depender de 1920×1080.

## Vitrina pública

Landing y demo autónomas con un conjunto sintético versionado. Mostrar un recorrido completo: señal → afirmación → copias → nueva evidencia → cambio de prioridad. Badge persistente de datos sintéticos; sin requests a endpoints privados ni resúmenes extraídos del archivo real.

La promesa pública debe explicar producto self-hosted, evidencia y ahorro operativo; distinguir inferencia externa opcional de ejecución local de aplicación/datos. Publicar métricas de calidad solo con método, muestra, periodo y limitaciones. Capturas, arquitectura y quickstart reproducible aportan credibilidad; «99 % preciso», «cubre la dark web» o «cero mantenimiento» no están demostrados.

No se crea una web nueva durante esta tarea: se especifica el rediseño de la aplicación existente. La demo actual de `docs/presentation/` sirve de precedente sin reescribir sus anécdotas como benchmarks.

## Estados y navegación verificables

Hallazgos estáticos adicionales: `Intelligence.jsx` descarta el error de `useApi` y usa valores vacíos/cero; `App.jsx` busca rutas exactas mientras recibe enlaces con query; `Graph.jsx` no consume la selección de URL. Deben validarse al implementar, no se han reproducido en navegador en esta revisión.

Exigir estados diferenciados de carga, vacío real, fallo y datos antiguos. Enlaces profundos, filtros y selección recuperables con URL; atrás/adelante y apertura directa funcionan. Cada operación ofrece respuesta y conserva contexto ante error.

Hipótesis de usabilidad para piloto: comprender qué cambió en ~30 segundos, acceder a evidencia en una o dos acciones y revisar rutina en pocos minutos. Medirlas con las tres historias anteriores; no certificar usabilidad por screenshots.
