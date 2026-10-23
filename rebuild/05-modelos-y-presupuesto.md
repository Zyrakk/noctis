# Modelos candidatos y presupuesto

Consulta de fuentes oficiales: **16 de octubre de 2026**. USD por millón de tokens; entrada sin caché y salida. Tarifas y catálogos cambian: comprobarlos al implementar. No se ha ejecutado un benchmark CTI ni una inferencia pagada en esta revisión.

## Qué modelos evaluar

| Modelo / servicio | Entrada | Salida | Contexto anunciado | Función candidata |
|---|---:|---:|---:|---|
| GPT-6 Luna / OpenAI | $0,10 | $0,50 | 1.050.000 | Interpretación económica estructurada. |
| GPT-OSS 20B / Groq | $0,075 | $0,30 | 131.072 | Competidor de bajo coste para primera pasada. |
| GPT-OSS 120B / Groq | $0,15 | $0,60 | 131.072 | Competidor de mayor tamaño para contexto semántico. |
| Gemini 3.1 Flash-Lite / Google | $0,25 | $1,50 | 1.048.576 entrada | Alternativa de proveedor/multimodal, si se necesita. |
| DeepSeek Flash V4.1 | $0,15 fuera de pico / $0,30 pico | $0,60 / $1,20 | 1 M | Alternativa; contabilizar razonamiento y cambios de alias. |
| GLM-5.3-Flash / Z.AI | $0,15 | $0,50 | 1 M | Alternativa; thinking no desactivable según documentación consultada. |
| GPT-6.1 Sol / OpenAI | $2 | $10 | 1.050.000 | Escalado selectivo, síntesis de expedientes y brief. |

Fuentes: [precios OpenAI](https://developers.openai.com/api/docs/pricing), [Luna](https://developers.openai.com/api/docs/models/gpt-6-luna), [Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol), [modelos Groq](https://console.groq.com/docs/models), [precios Gemini](https://ai.google.dev/gemini-api/docs/pricing), [Flash-Lite](https://ai.google.dev/gemini-api/docs/models/gemini-3.1-flash-lite), [DeepSeek](https://api-docs.deepseek.com/quick_start/pricing/), [precios Z.AI](https://docs.z.ai/guides/overview/pricing), [GLM](https://docs.z.ai/guides/vlm/glm-5.3-flash).

El contexto anunciado no equivale a admisión de una cuenta, gateway o pool. OpenAI tiene tarifas distintas por encima de 272.000 tokens de entrada; los escenarios siguientes quedan por debajo. GPT-OSS 20B/120B en Groq admiten [JSON Schema estricto](https://console.groq.com/docs/structured-outputs); estructura válida no demuestra verdad factual.

**Recomendación provisional:** enfrentar Luna, GPT-OSS 20B y GPT-OSS 120B con el mismo corpus y presupuesto. Elegir por calidad CTI medida, coste facturado, latencia, privacidad y estabilidad. Mantener un proveedor habitual y un fallback evaluado. Sol es candidato para escalado; no requisito fijo ni árbitro de verdad. No integrar siete proveedores para arrancar.

Llama 4 Scout, configurado en el proyecto, fue retirado de Groq free/developer el 17/07/2026, con excepción de compromisos enterprise: [retiradas oficiales](https://console.groq.com/docs/deprecations). Tampoco asumir que una suscripción Coding Plan de Z.AI cubre un daemon CTI: revisar [FAQ del plan](https://docs.z.ai/devpack/faq) y modalidad API apropiada.

## Presupuesto de inferencia directa

Supuestos ilustrativos, pendientes de medir:

- `N`: observaciones al mes; `U = 0,30 × N`: unidades elegibles tras dedupe y reglas.
- Primera pasada Luna: 1.000 tokens entrada y 350 salida por unidad.
- Escalado Sol: 0,5 % de U, con 4.000 entrada y 600 salida.
- Treinta briefs Sol: 12.000 entrada y 1.500 salida cada uno.
- Todos los tokens facturados de salida, incluido razonamiento si aplica, deben caber en el supuesto. Sin herramientas, OCR, caché, batch ni consultas interactivas.

```text
primera_pasada = U × (1000 × 0.10 + 350 × 0.50) / 1_000_000
escalado      = U × 0.005 × (4000 × 2 + 600 × 10) / 1_000_000
briefs        = 30 × (12000 × 2 + 1500 × 10) / 1_000_000
C             = U × 0.000275 + U × 0.005 × 0.014 + 1.17
```

| N / mes | U | Primera pasada | Escalado | Briefs | Total base | Margen 20 % |
|---:|---:|---:|---:|---:|---:|---:|
| 100.000 | 30.000 | $8,25 | $2,10 | $1,17 | **$11,52** | **$13,82** |
| 1.000.000 | 300.000 | $82,50 | $21,00 | $1,17 | **$104,67** | **$125,60** |
| 10.000.000 | 3.000.000 | $825,00 | $210,00 | $1,17 | **$1.036,17** | **$1.243,40** |

Sensibilidad: con 1 M de observaciones y escalado del **5 %**, el total es $293,67 base / $352,40 con margen. Cada 1.000 consultas Sol de 4.000/600 tokens añade $14. El porcentaje que pasa reglas y el tamaño del contexto pueden dominar el coste. El margen no es un cap técnico.

No incluye servidor, disco, copias, electricidad, tráfico, licencias ni tiempo humano. No se recomienda comprar GPU: comparar coste total y calidad del despliegue local únicamente si existe requisito de datos o volumen que lo justifique.

## Zrelay: escenario separado y pendiente

Inspección **solo lectura** de `../zrelay/docs/wallet-catalog.md`, `worker/README.md`, documentación de fallback y registros de `backend/wallet_catalog.json`. Catálogo local `wallet-20261012-v2`; no se comprobó servicio remoto, saldo, credenciales ni facturación. El usuario indica que su rebuild aún no está migrado.

El catálogo local anuncia Luna/Sol en Chat Completions y Responses, límites predeterminados 128.000 entrada / 4.096 salida y multiplicador cliente GPT Flex 0,20. **Luna nominal local es $0,20/$1,20**, distinto de la tarifa oficial anterior. Por tanto, en ese catálogo Luna Flex sería $0,04/$0,24 y Sol $0,40/$2.

No aplicar un «80 % de descuento» sobre la tabla oficial: la base es diferente. Usando exclusivamente esas tarifas locales, los mismos escenarios producirían:

| N / mes | Total catálogo local | Con margen 20 % |
|---:|---:|---:|
| 100.000 | $4,374 | $5,25 |
| 1.000.000 | $41,634 | $49,96 |
| 10.000.000 | $414,234 | $497,08 |

Son cálculos documentales, no una oferta ni disponibilidad garantizada. El adaptador futuro debe resolver catálogo, pool, modelo, precio y capacidades realmente admitidos. La decisión de calidad requiere evaluar la ruta efectiva, no solo el nombre comercial.

## Control de gasto exigido

Ledger persistente por periodo UTC, función, proveedor y modelo. Antes de una llamada, reservar transaccionalmente coste máximo autorizado usando límite de entrada/salida y tarifa vigente, no consumo histórico aproximado. Reconciliar uso real; si hay timeout con posible ejecución, conservar reserva incierta hasta reconciliación o política de exposición acotada. Un retry puede costar de nuevo si el upstream no garantiza idempotencia.

Caps duros por día/mes y tarea, concurrencia, máximo por caso y cola priorizada. Agotar IA bloquea esa tarea, conserva captura y extracción mecánica y muestra estado visible. No pasar a otro proveedor sin autorización de datos, capacidades evaluadas y reserva compatible. Tarifas, moneda y redondeo forman parte de la versión del cálculo.

## Fuentes CTI que condicionan decisiones

- [FIRST EPSS](https://www.first.org/epss/faq): probabilidad de explotación en los próximos 30 días, no riesgo específico de un activo.
- [FIRST evaluación de fuentes](https://www.first.org/global/sigs/cti/curriculum/source-evaluation): separar fuente e información.
- [FIRST PIR](https://www.first.org/global/sigs/cti/curriculum/pir): necesidades explícitas para evitar recolección sin objetivo.
- [VirusTotal Public/Premium](https://docs.virustotal.com/reference/public-vs-premium-api): límites y restricciones de uso; no asumir enriquecimiento gratuito ilimitado.
- [URLhaus API](https://urlhaus.abuse.ch/api/): Auth-Key, cadencia y posibles requisitos comerciales. Incorporarlo solo si cubre una necesidad concreta.

Registrar por conector permisos de acceso, redistribución, retención, envío a terceros y fecha de comprobación. Estos requisitos afectan también a qué se puede mostrar en la vitrina y enviar a inferencia externa.
