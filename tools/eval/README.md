# Replay de evaluación

`python3 -m unittest discover -s tools/eval` verifica intervalos exactos, denominadores,
integridad temporal y separación por episodio. `evaluate.py --dataset DATASET.json
--predictions OUTPUT.jsonl --output REPORT.json` calcula segmentos y coste entero;
las predicciones necesitan identidad de ruta/modelo/prompt/política/schema/tarifa.

`synthetic-v1.json` es una matriz adversarial de contratos, **SYNTHETIC, no gold**.
Sus expectativas y predicciones de prueba no miden calidad de un modelo. El informe
no autoriza promociones. Requiere sustituirla por ejemplos reales saneados,
adjudicados independientemente por personas y con límites/periodos documentados.
Cualquier cambio de configuración invalida promociones guardadas por el runtime.

## Exportación GOLD v1

El CLI existente acepta un dataset con `metadata.gold` opcional. Sin GOLD calcula
regresión descriptiva y devuelve `not_evaluated`; escribir «human» en
`label_provenance` no habilita ningún criterio. No genera etiquetas, revisiones,
llamadas de modelos ni documentos humanos. Los tests usan exclusivamente registros
**SIMULATED** inventados para probar el software.

La raíz conserva `metadata` y `examples`. Cada ejemplo necesita `id`, `episode`,
`partition` (`development`, `selection`, `test`), `at` ISO-8601, `language`, `source`,
`task` y `relevant` booleano. `metadata` necesita `version`, `synthetic` booleano,
`label_provenance` e `input_fixture`: fichero JSON que mapea todos los IDs a texto
saneado no vacío. Las fechas sin zona usan UTC. No se admite compartir episodios
entre particiones ni solapar tiempos, tampoco al omitir la partición intermedia.
La familia de copias debe tener el mismo `episode` en el exportador.

Con GOLD cada ejemplo incluye además `input` no vacío y `context` textual explícito
(puede ser vacío cuando no hay contexto). Su esquema es estricto: los campos
anteriores más `semantic` y `adversarial` opcionales; no admite metadatos arbitrarios.
`gold.example_commitment(row)` calcula `example_sha256` sobre exactamente `id`,
`input`, `context`, `episode`, `partition`, `at`, `language`, `source` y `task`.
Excluye las etiquetas GOLD (`relevant`, `semantic`), preservando revisión ciega.
Cambiar ID, texto, contexto o segmentación invalida los compromisos existentes,
incluso si se recalcula el digest global del dataset. Un cambio legítimo requiere
nueva exportación y revisiones del material congelado correspondiente.

`gold` es un objeto de campos estrictos:

| Campo | Contrato |
| --- | --- |
| `contract` | Literal `noctis-human-gold-v1`. |
| `origin` | `human_adjudicated` con `synthetic:false`; `simulated_fixture` con `synthetic:true` exclusivamente para pruebas. |
| `dataset_sha256` | Digest de `examples` **después** de incorporar `input` desde el fixture. |
| `guideline_sha256` | Compromiso con la guía humana versionada y taxonomía. |
| `sampling_sha256` | Compromiso con el plan de muestreo, población y cobertura. |
| `independence_sha256` | Compromiso con la revisión de independencia y familias de copias. |
| `frozen_at` | Fecha del corpus congelado, posterior o igual al periodo observado. |
| `reviews` | Mapa exacto de IDs a `{reviews:[REVIEW, REVIEW], adjudication:REVIEW}`. |
| `prediction_audits` | Opcional: mapa exacto de IDs a auditorías de predicciones descritas abajo. |

Cada `REVIEW` tiene exactamente `reviewer` (identificador humano seudonimizado no
vacío), `at`, `blind:true`, `judgment`, `example_sha256` y `record_sha256`.
Cada compromiso debe coincidir con el ejemplo revisado; copiar los tres registros
de otro ID no es válido. Las dos personas revisoras
y la adjudicadora deben ser distintas. Las revisiones ocurren tras la congelación;
la adjudicación, tras ambas revisiones. El protocolo de exportación debe garantizar
que las personas no ven las salidas candidatas al etiquetar y que las primeras
revisiones son independientes. `judgment` contiene exactamente `relevant` booleano y
`semantic` (objeto tipado o `null`). La adjudicación debe coincidir con el ejemplo.
Se reportan acuerdo inicial, desacuerdos y correcciones respecto de adjudicación.

`semantic` contiene exactamente `labels` (lista de strings únicos), `intent`
(string no vacío) y `observable_roles` (lista sin duplicados de objetos exactos
`{observable_id: string, role: string}`). GOLD y predicción usan el mismo contrato.
El informe calcula TP/FP/FN, precisión/recall/F1 por etiqueta y macro-F1 de
etiquetas, intención y pares observable/rol. Si falta cualquier anotación o salida
semántica en un corte, ese corte queda `not_measured`; no se imputa acierto ni cero.
Estas métricas no verifican por sí solas spans, extracción ni soporte de claims.

Las predicciones GOLD tienen exactamente `id`, las seis claves de identidad,
`relevant` (booleano/null), `schema_valid`, `citations_valid`, `cost_units`,
`example_sha256`, `high_priority_inferred_alert` (booleano), `alert_text` y
`semantic` opcional. El booleano representa una alerta de alta prioridad inferida efectivamente
emitida por esa salida; no se infiere de relevancia ni de intención semántica.
`alert_text` contiene el texto completo efectivamente emitido, no vacío; es `null`
cuando no hubo emisión. La auditoría debe juzgar ese contenido concreto y su
soporte; su digest cubre texto, semántica, emisión, identidad y compromiso.
El compromiso debe coincidir con el ejemplo congelado. El formato descriptivo
sintético sin GOLD conserva compatibilidad y no exige estos nuevos campos.

La auditoría humana opcional de predicciones contiene exactamente
`prediction_sha256`, `execution_sha256`, `example_sha256`, `reviewer`, `at`, `record_sha256`,
`schema_error` y `citation_error` booleanos, `unsupported_claims` y `omitted_claims`
enteros no negativos; admite únicamente el campo adicional `alert_correct`
(booleano/null). Este juicio humano evalúa la corrección de la alerta emitida
completa, incluidos sus claims y prioridad, según la guía comprometida; omitido o
null significa que esa corrección no se ha medido. Debe realizarla la persona
adjudicadora después de etiquetar.
El digest de ejecución cubre las seis claves de identidad; el de predicción cubre
la predicción JSON completa. Esto impide reutilizar una auditoría con otra salida
o configuración. También cubre el compromiso del ejemplo: no permite trasplantar
salidas ni auditorías entre textos/contextos. Sin esta auditoría los errores
humanos son `not_measured`.
`schema_errors` y `citation_errors` descriptivos proceden de flags de la predicción:
**no constituyen verificación humana ni prueba de soporte**.

Los digests usan SHA-256 del JSON UTF-8 canónico con claves ordenadas,
`ensure_ascii=False` y separadores `(',', ':')`, sin salto final: función `gold.digest`.
Los hashes de registros excluyen únicamente su propio `record_sha256`. Los tres
documentos comprometidos deben conservarse fuera del informe para auditoría.
El software comprueba estructura, enlaces y consistencia; **no autentica personas,
firmas, documentos, representatividad ni independencia real**. No se debe convertir
un fixture en evidencia cambiando sus metadatos. Verificar su autenticidad y
procedencia sigue siendo un requisito humano externo.

## Criterio y límites

`executions` separa `(route, model, prompt, policy, schema, price_version)`. El
criterio usa solamente `test`, tanto para cada identidad como para cada combinación
observada `(language, source, task)` dentro de ella. No suma rutas ni versiones para
alcanzar tamaños de muestra. Los cortes sin suficientes muestras fallan; cortes
no presentes en el corpus no quedan validados ni cubiertos por el informe.

La precisión de relevancia es **descriptiva**, nunca el criterio de precisión de
alertas. En esa métrica un episodio con alguna predicción relevante es correcto
solo si todas esas predicciones son relevantes. Para recall de gate, un episodio
accionable se recupera si alguna fila realmente relevante recibe emisión positiva.
El criterio de gate usa exclusivamente filas con `task:gate`: recall puntual
≥0,98 y su intervalo exacto publicado. No exige un umbral de precisión de relevancia.
Por ello precisión y recall tienen sus propios denominadores; las cuentas de
episodio no son una matriz binaria de filas. La independencia declarada requiere
auditoría externa; el programa solo puede agrupar los episodios exportados.

El criterio de **alertas inferidas de alta prioridad** exige ≥100 episodios
independientes con alertas efectivamente emitidas y adjudicadas y límite inferior
Clopper–Pearson unilateral 95 % de precisión ≥0,95. Cada episodio falla si alguna
alerta emitida tiene `alert_correct:false`, relevancia incorrecta, etiquetas,
intención o roles discordantes, error humano de esquema/citas o claims sin soporte.
Si no hay emisiones o falta juicio humano de corrección o semántica de alguna
emisión, queda `not_measured`. La ausencia de auditoría nunca acredita precisión,
aunque la relevancia sea perfecta. El contrato actual representa como máximo una
alerta inferida de alta prioridad por fila; un exportador con varias debe crear
filas distintas y conservar el mismo episodio para evitar inflar independencia.
Otros productos factuales deterministas requieren su política separada.

En cortes exclusivamente `gate` aplica su recall; en los demás se necesita el
criterio de alertas. Un corte mixto debe superar ambos. Un pase requiere métricas
semánticas disponibles; no inventa umbrales de F1. Los flags del modelo no
sustituyen auditoría humana de citas o claims.
Las métricas `overall`, marginales e `independent_episode_metrics` globales son
descriptivas; la elegibilidad solo procede de los cortes separados de `executions`.

`promotion_criterion.statistically_eligible` puede ser cierto para un contrato
válido que supera esos criterios. Un fixture simulado puede probar esa rama del
software sin acreditar calidad. `real_corpus_statistical_candidate` exige además
`synthetic:false`, pero tampoco autentica el corpus. `quality_validated` y
`promotion_authorized` permanecen siempre `false`: hacen falta revisión humana
externa de procedencia/cobertura, métricas de producto aplicables y aprobación de
política. Este evaluador no cierra G6 humano, G7 de utilidad ni G8.

Verificación local obligatoria para este componente:
`python3 -m unittest discover -s tools/eval`. Requiere solo Python 3 y su biblioteca
estándar. Ninguna prueba ejecuta inferencia ni consume etiquetas privadas reales.
