# Reglas, IA y calidad de inteligencia

## Reparto de responsabilidades

| Trabajo | Implementación preferida | Papel de IA |
|---|---|---|
| Identidad de fuente/documento, hash, cursor, edición y repost | Adaptadores, claves estables y transacciones | Ninguno. |
| IPv4/IPv6, URL, dominio, correo, hash, CVE | Parsers y validadores con normalización reversible | Interpretar rol cuando el texto lo exige. No inventar valores. |
| Wallets y otros identificadores | Decodificación/checksum según cadena; tipos no soportados explícitos | Ayudar a interpretar contexto, sin sustituir validación. |
| Defanging (`hxxp`, `[.]`) | Transformación acotada que conserva original y spans | Ninguno para casos conocidos. |
| Ruido obvio, copias y boilerplate | Reglas versionadas conservadoras | Clasificar lo ambiguo; muestrear descartes para detectar falsos negativos. |
| CVE/KEV/EPSS y producto afectado | Feed estructurado, versiones y reglas de aplicabilidad | Interpretar avisos no estructurados; nunca fabricar rangos afectados. |
| Watchlists de dominio/hash/CVE | Matching exacto y reglas de límites | Alias ambiguos y referencias indirectas a organización/producto. |
| Categoría semántica e intención | Una inferencia estructurada selectiva | Distinguir oferta, noticia, rumor, negación, investigación y evidencia directa. |
| Entidades y relaciones | Diccionarios/aliases existentes primero | Proponer nuevas menciones y relaciones con spans; fusión por política. |
| Ranking de urgencia e impacto | Política explicable con factores separados | Aportar contexto, sin decidir permisos ni hechos. |
| Correlación | Joins, ventanas, rareza y dependencia de origen | Formular hipótesis y alternativas cuando hay evidencia suficiente. |
| Resumen y brief | Plantilla mecánica base | Redactar síntesis por expediente con referencias verificables. |
| Descubrimiento de fuentes | Allowlist, reglas URL, reputación operativa y prueba acotada | Proponer interés temático; no autorizar acceso por sí sola. |
| Consultas del operador | Plan tipado, filtros y consultas parametrizadas | Traducir lenguaje a ese plan y explicar resultados permitidos. |
| Alertas, presupuestos, reintentos y publicación | Política determinista, outbox y ledger | Ninguno como autoridad de ejecución. |

La presencia de una IP no es malicia. Un CVE es un identificador de vulnerabilidad, no un IOC de compromiso. Un dominio oficial puede ser referencia útil y debe conservarse como tal. Una lista de excepciones puede reducir ruido, pero no borrar evidencia original ni hacer irrecuperables los resultados.

## Pipeline propuesto

1. Persistir observación completa y procedencia; extraer texto y metadatos en representación identificada.
2. Extraer y normalizar observables mecánicos sobre todo el texto permitido, no solo los primeros 4 KB. Conservar spans y bandera de contenido incompleto.
3. Reutilizar análisis del mismo blob cuando política, idioma y contexto sean compatibles; conservar análisis específicos de autor/fuente aparte.
4. Ejecutar reglas de relevancia y watchlists. Las reglas de descarte son conservadoras, reversibles y auditadas. Un hallazgo urgente puede emitir alerta factual provisional antes del resumen IA.
5. Enviar contenido elegible a **una** pasada semántica barata: categorías multietiqueta, intención, afirmaciones, entidades propuestas, roles de observables y evidencia. No dividir por defecto en clasificador, resumen, extractor y librarian independientes.
6. Validar esquema, enums, longitudes, IDs y citas. Cada evidencia debe existir en entrada y versión indicadas. Un span válido prueba que la fuente lo dijo, no que sea verdad.
7. Agrupar en expedientes con reglas. Escalar a modelo más fuerte solo por relevancia/ambigüedad material o tarea evaluada; no porque un LLM diga estar seguro o inseguro.
8. Recalcular política de prioridad, estado evidencial y entrega. Resumir solo novedad material; generar brief con referencias y cobertura explícita.

Documentos largos se segmentan con límites de tokens y solapamiento acotado. Debe conservarse un mapa de segmentos y cobertura; extraer al final del documento es un caso obligatorio de aceptación. Resumir primero y extraer después puede perder evidencia y no debe ser la única ruta.

## Salida semántica mínima

```json
{
  "schema_version": "1",
  "labels": ["access_offer"],
  "intent": "seller_claim",
  "language": "es",
  "claims": [{
    "predicate": "offers_access_to",
    "subject_mention_id": "m1",
    "object_mention_id": "m2",
    "evidence_ids": ["span-17"],
    "epistemic_status": "source_claim"
  }],
  "observable_roles": [{
    "observable_id": "o1",
    "role": "claimed_target",
    "evidence_ids": ["span-18"]
  }],
  "limitations": []
}
```

Ejemplo de contrato, no taxonomía ya implementada. La severidad y la política de entrega se calculan después. `schema_version`, taxonomía, prompts, modelo, reglas y conjunto evaluado se versionan por separado.

## Confianza sin falsa precisión

Mantener dimensiones distintas: fiabilidad histórica de fuente, credibilidad de afirmación, independencia de soporte, actualidad, relevancia local y fuerza del enlace de identidad. Los puntajes de ranking no son probabilidades. La autoconfianza del modelo no es calibración ni autoriza confirmación.

Estados propuestos de afirmación: `source_claim`, `supported`, `contradicted`, `unresolved`, `retracted`, con explicación. La política debe especificar qué significa `supported` para cada tipo: una observación técnica puede verificarse mecánicamente; una atribución de actor requiere evidencia más fuerte y normalmente queda como hipótesis. «Verificado» se reserva a hechos verificables y alcance explícito.

Una fuente que replica tres noticias no aporta tres confirmaciones. Diferentes proveedores IA opinando igual tampoco constituyen evidencia externa independiente. Revisión y contraprueba por otro modelo pueden mejorar análisis, pero deben evaluarse por errores detectados, no venderse como consenso probatorio.

La valoración de una fuente no puede depender únicamente de cuántos mensajes el mismo clasificador llamó útiles. Usar disponibilidad, originalidad, retraso, correcciones, soporte comprobable y utilidad auditada. Cambios de puntuación son reversibles y se registra incertidumbre con pocos datos.

## Evaluación antes de escoger modelo

Reutilizar muestreo y validación existentes, sin requerir entrenamiento. Desde el primer corte, disponer de un corpus pequeño de aceptación y regresión adversarial. Para seleccionar IA, preparar una primera muestra humana de 300–500 ejemplos reales saneados, estratificados por fuente, idioma, intención, relevancia y periodo; ampliar hacia 600–1.000 o más cuando la cobertura e intervalos lo requieran. Es un presupuesto de validación, no un prerrequisito para comenzar el corte mecánico ni garantía de significancia.

Separar conjuntos de desarrollo, selección y prueba final por tiempo y por familias de copias/episodios para evitar filtración. Etiquetas humanas con guía; discrepancias documentadas. Un modelo caro puede sugerir etiquetas, pero no se considera verdad automática. Las etiquetas históricas necesitan revalidación.

| Nivel | Qué medir |
|---|---|
| Reglas | Precisión/recall de extracción por tipo, normalización, spans y observables al final del documento. |
| Gate | Recall de material accionable, falsos descartes, abstención y ahorro; cortes por idioma/fuente/categoría. |
| Semántica | Macro-F1, precisión/recall por etiqueta, negación/intención, roles, extracción sustentada y fallo de esquema. |
| Expedientes | Dedupe correcto, agrupación indebida, independencia de origen, contradicciones y novedades omitidas. |
| Alertas | Precisión, cobertura estimada por auditoría, duplicados y latencia respecto a evidencia disponible. |
| Resúmenes | Afirmaciones sin soporte, citas incorrectas, omisiones importantes y coherencia tras retractación. |
| Operación | Coste total por 1.000 observaciones y expediente útil, p95, tasa de timeout/retry y atención humana. |

Objetivos iniciales de promoción, **pendientes de medir**: gate con recall puntual ≥98 % de accionables e intervalo reportado; alertas automáticas inferidas de alta prioridad con límite inferior del intervalo unilateral de confianza del 95 % de precisión ≥95 %, sobre al menos 100 eventos independientes adjudicados; cero atribuciones confirmadas únicamente por salida LLM. Para precisión binaria usar Clopper–Pearson unilateral al 95 % y publicar denominador, periodo y segmentos. La muestra mínima no sustituye el criterio del intervalo. Si no hay suficiente evidencia, mantener feed/brief y avisos factuales provisionales de política explícita en piloto, sin anunciar calidad validada ni ampliar privilegios. Un aviso estructurado como «CISA añadió este CVE a KEV» tiene una política factual separada y no afirma exposición local ni compromiso.

El 100 % de afirmaciones mostradas debe tener referencias resolubles al soporte o a un tombstone con motivo de indisponibilidad. Un tombstone preserva trazabilidad de existencia, pero no permite verificar el texto: mostrar esa limitación y revalidar productos dependientes. Para habilitar una nueva alerta de alta prioridad se exige evidencia accesible y suficiente en ese momento. Los segmentos con poca muestra se muestran «no validados».

## Corpus adversarial obligatorio

Instrucciones hostiles dentro de mensajes, JSON truncado, texto multilingüe, venta legítima vs acceso ilícito, ironía/negación, rumores y retractaciones, URLs defanged, IPv6, hashes benignos, CVEs citados en documentación, mismo handle de personas distintas, CDN/cloud compartida, cuatro canales que copian una noticia, IOC en último segmento, muestra sin texto y caídas del proveedor.

La IA no tiene herramientas con red libre ni acceso a secretos. La defensa no depende solo del prompt: permisos inexistentes, salida validada y política posterior. Un input ambiguo puede quedar pendiente o desconocido; nunca se obliga a inventar una conclusión.

## Evaluación continua barata

Canary por tareas y segmentos, comparación ciega entre candidato y versión vigente, pequeño muestreo semanal de descartes y alertas, y alarma ante deriva de idioma/fuentes/coste. Conservar rollback de prompts/modelos/políticas. Cuando cambia el catálogo del proveedor, volver a comprobar capacidades y calidad antes de promover el alias nuevo.
