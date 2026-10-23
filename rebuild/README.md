# Noctis: plan de rebuild

**Diseño consensuado por tres GPT-6 Astra en xhigh, 16 de octubre de 2026.** Revisión de los 16 Markdown originales y contraste con código, UI, despliegue y fuentes oficiales de modelos. Este directorio es la propuesta para el siguiente Noctis; el runtime actual todavía no implementa estas garantías.

## Decisión central

Construir una plataforma personal de threat intelligence basada en **expedientes, cambios materiales y evidencias**, con autonomía gobernada por reglas. Conservar Go, PostgreSQL y React. Rehacer procedencia, ejecución durable y modelo de afirmaciones antes de apilar más IA.

No entrenar un clasificador propio como requisito. Extraer observables y ejecutar políticas mecánicamente; usar una pasada semántica económica solo cuando hace falta, y escalar casos relevantes. Modelos candidatos: Luna, GPT-OSS 20B y GPT-OSS 120B; la precisión queda pendiente de evaluación con datos de Noctis.

Zrelay es una integración futura mediante adaptador, **pendiente de su rebuild**. El núcleo y sus pruebas de contrato no deben esperar a esa migración. Su catálogo local y las tarifas oficiales se analizan por separado.

## Roadmap ejecutable añadido

Una segunda ronda de **tres Astra xhigh** convirtió el diseño en nueve etapas P0–P8 y paquetes de código/pruebas. Se comprobó infraestructura en modo lectura: aplicación y PostgreSQL detenidos, PVC conservados y cinco usernames en configuración, todavía sin IDs ni archivo recuperados.

Empezar por [11 — Roadmap ejecutable](11-roadmap-ejecutable.md). Desarrolla las tres fases de `09` sin sustituir la visión del resto:

| Documento | Para ejecutar |
|---|---|
| [12 — Preservación e inventario](12-preservacion-infra-y-canales.md) | Conservar base/sesión, verificar restore y recuperar inventario de canales. |
| [13 — Pruebas y gates](13-pruebas-y-gates.md) | PostgreSQL real, crash/replay, Telegram, UI, seguridad y evaluación. |
| [14 — Paquetes de implementación](14-paquetes-de-implementacion.md) | Encargos por fase, archivos, dependencias y aceptación. |
| [15 — Arranque y cutover](15-arranque-y-cutover.md) | DB nueva sobre PG reutilizado, reinyección, epoch, piloto, entrega y rollback. |
| [16 — Trazabilidad y control](16-trazabilidad-y-control.md) | Requisitos, capacidades anteriores y definición de rebuild terminado. |

## Leer en este orden

Requisito añadido el 18-10-2026: [17 — Configuración de IA por función](17-configuracion-ia-por-funcion.md). El panel debe permitir proveedor, URL, API key e ID de modelo por cada función IA, con persistencia segura y efecto real en el runtime (P6.5/T45–T48).

El [contrato de captura nativa](native-capture-contract.md) describe la política protegida, cuotas persistentes por fase, admisión de establecimiento/API y cierre de sesión. Los resultados comprobados siguen en [18 — Ejecución y recibos](18-ejecucion-y-recibos.md).

| Documento | Contenido |
|---|---|
| [01 — Auditoría](01-auditoria.md) | Cobertura de los 16 Markdown, problemas comprobados, reutilización y límites. |
| [02 — Visión y alcance](02-vision-y-alcance.md) | Propuesta de valor, recorridos, autonomía y ambición por etapas. |
| [03 — Arquitectura y datos](03-arquitectura-y-datos.md) | Observaciones, afirmaciones, expedientes, jobs, idempotencia y almacenamiento. |
| [04 — Reglas, IA y calidad](04-reglas-ia-y-calidad.md) | Qué es mecánico, qué necesita IA, evaluación y criterios de precisión. |
| [05 — Modelos y presupuesto](05-modelos-y-presupuesto.md) | Fuentes oficiales, alternativas actuales, escenarios y sensibilidad de coste. |
| [06 — Producto y experiencia](06-producto-y-experiencia.md) | Cinco áreas, lector de evidencia, identidad visual, demo y historias completas. |
| [07 — Operación y seguridad](07-operacion-y-seguridad.md) | Despliegue personal/Kubernetes, recuperación, red, privacidad, CI y salud. |
| [08 — Contrato Zrelay](08-contrato-zrelay.md) | Puerto de inferencia, capacidades, errores, uso, fallback y pruebas simuladas. |
| [09 — Roadmap y aceptación](09-roadmap-y-aceptacion.md) | Tres fases, encargos por área, gates y migración del archivo histórico. |
| [10 — Decisiones y consenso](10-decisiones-y-consenso.md) | Debate, objeciones resueltas y decisiones compartidas por los tres Astra. |

## Qué cambia respecto al planteamiento anterior

- Contenido deduplicado **con todas sus observaciones**, sin perder dónde apareció.
- Observable, afirmación, indicador malicioso y atribución son conceptos separados.
- Errores de proveedor no se convierten en contenido irrelevante; reintentos y gasto son durables.
- Copias aumentan difusión, no corroboración independiente.
- Expedientes y novedades sustituyen el recorrido manual entre módulos; grafo como herramienta contextual.
- Alertas factuales/provisionales automáticas; mayor autonomía inferida solo tras evaluación.
- Vitrina sintética separada del archivo privado; operación degradada visible.

## Primer resultado ejecutable posterior

RSS autorizado → objetivo/watchlist → observación durable → expediente citado → novedad → alerta deduplicada y brief. Después, piloto Telegram autorizado para el relanzamiento funcional, con interpretación estructurada evaluada. El roadmap detalla aceptación y dependencias.

Como orientación, el escenario de 100.000 observaciones/mes y 30 % de unidades interpretadas da **$13,82/mes de IA directa con margen** bajo los supuestos publicados; no incluye infraestructura ni constituye presupuesto medido. Más volumen, contexto o escalado cambian mucho el resultado.

## Estado de la entrega

La ejecución iniciada el 18-10-2026 se registra en [18 — Ejecución y recibos](18-ejecucion-y-recibos.md). El párrafo siguiente describe el estado de la entrega documental original, previo a esa implementación.

Documentación en `rebuild/` y lecturas filtradas de metadatos de infraestructura; sin cambios de runtime, commits, despliegues ni llamadas de inferencia pagadas. No se han creado backups, extraído IDs de DB/Telegram ni probado recuperación. Se revisan enlaces locales, coherencia documental, cálculos y diff. Calidad real, capacidad, gasto desplegado y carga humana requieren piloto. La documentación anterior permanece como descripción histórica hasta implementar y reconciliar las guías.
