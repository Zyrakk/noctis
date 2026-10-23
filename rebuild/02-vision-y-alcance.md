# Visión: inteligencia verificable para un operador

## Producto propuesto

Noctis convierte señales dispersas en expedientes de inteligencia relevantes para objetivos explícitos: infraestructura, organizaciones, actores, campañas, sectores o preguntas de inteligencia. Conserva la evidencia y explica qué cambió, qué se sabe y qué sigue siendo una hipótesis. La IA interpreta lenguaje y redacta; las reglas gobiernan ejecución, identidad de observables, prioridades operativas y publicación.

El producto necesita responder cinco preguntas antes de añadir más colectores:

1. ¿Qué ha cambiado desde la última visita y por qué me afecta?
2. ¿Qué evidencia original sostiene cada conclusión?
3. ¿Son observaciones independientes o copias del mismo rumor?
4. ¿Qué puedo hacer, con qué urgencia y qué incertidumbre queda?
5. ¿Está funcionando la vigilancia o faltan fuentes/procesamiento?

La ventaja defendible es combinar investigación contextual de Telegram y fuentes seleccionadas con relevancia local, procedencia y operación barata. El objetivo no es ganar por número de IOCs ni ofrecer cobertura universal del underground.

## Tres recorridos prioritarios

### Riesgo de vulnerabilidades para mi infraestructura

Una watchlist de tecnologías, versiones conocidas y exposición se cruza con avisos oficiales, KEV, EPSS y menciones contextualizadas. El expediente distingue «producto posiblemente afectado», «versión afectada comprobada» y «explotación reportada». Una ausencia de inventario nunca se interpreta como ausencia de exposición.

Resultado: cambio de prioridad explicado, evidencias y recomendación concreta. Noctis no ejecuta el parche ni bloquea red por una inferencia de IA.

### Señales de acceso inicial o filtración que afectan a mis intereses

Vigilar dominios, organizaciones y marcas expresamente configuradas. Agrupar oferta original, copias, negativas y actualizaciones en un expediente. Distinguir «el vendedor afirma tener acceso» de «se ha verificado el compromiso». No descargar dumps, credenciales completas o muestras peligrosas por defecto.

Resultado: notificación concisa ante novedad relevante; las republicaciones enriquecen la propagación, no multiplican la corroboración.

### Seguimiento de actores, campañas e infraestructura

Construir dossiers con línea temporal y relaciones sustentadas. Un handle compartido propone una coincidencia; no fusiona identidades automáticamente. Las infraestructuras compartidas de hosting y servicios públicos no prueban autoría común.

Resultado: investigación por caminos de evidencia, cambios de dossier y un brief periódico sin repetir todos los mensajes.

## Capas de ambición

| Horizonte | Capacidades | Condición para avanzar |
|---|---|---|
| Relanzamiento útil | Watchlists/PIR, política básica de fuentes, ingest durable RSS/Telegram autorizado, observables mecánicos, expedientes, radar mínimo de cambios materiales, dependencia de orígenes, buscador, alertas y brief trazables | Calidad y operación verificadas con datos representativos. |
| Plataforma profesional personal | Fuentes con política de confianza, dossiers, investigación por grafo limitado, feedback mínimo, evaluación continua, exportaciones seleccionadas | Beneficio medido y presupuesto sostenible. |
| Diferenciación ambiciosa | Radar avanzado, cobertura de preguntas de inteligencia, análisis de propagación, revalidación de hipótesis, integración SIEM mediante contratos | Ninguna capacidad degrada procedencia ni multiplica falsas alertas. |
| Expansión condicionada | STIX/TAXII, OCR acotado, búsqueda semántica, compartición multiusuario, conectores adicionales | Demanda concreta y licencia, coste y seguridad resueltos. |

No forman parte del primer relanzamiento: entrenamiento/fine-tuning propio, enjambre de agentes permanentes, crawler indiscriminado, sandbox de malware, atribución autónoma, remediación automática, múltiples bases especializadas ni multi-tenancy comercial.

El primer corte técnico valida RSS → objetivo → expediente → alerta → brief. El relanzamiento funcional incluye también un piloto Telegram autorizado y sostenible, porque ese contexto es parte de la diferenciación de Noctis. Las cinco áreas de navegación propuestas no obligan a terminar cinco módulos completos antes de ese primer corte.

## Autonomía con límites explícitos

- **Automático:** ingest de fuentes habilitadas, parseo, dedupe de contenido, registro de observaciones, jobs, feeds, caché, correlaciones mecánicas, actualización de expediente y recuperación de fallos transitorios.
- **Automático con política y presupuesto:** interpretación IA, enriquecimiento de observables públicos autorizados, alertas privadas y revalidación de evidencias.
- **Excepciones de baja frecuencia:** activar una nueva fuente de riesgo, resolver evidencia contradictoria de impacto alto, aprobar publicación real y cambiar permisos/presupuesto.

La cola humana recibe excepciones ordenadas por impacto y caducidad, no cada mensaje ni cada desacuerdo entre modelos. Una hipótesis puede permanecer abierta sin detener el sistema. La calidad se audita con muestreo pequeño y periódico; «mínima interacción» no significa cero mantenimiento o cero verificación.

## Resultados medibles

Medir por recorrido y ventana temporal: precisión de alertas, señales útiles omitidas en muestra auditada, tiempo desde evidencia disponible hasta expediente actualizado, duplicados notificados, coste por expediente útil, cobertura de watchlists, edad del backlog y minutos semanales de atención humana.

No usar volumen bruto de mensajes, número de nodos, autoconfianza del modelo ni porcentaje clasificado como prueba de inteligencia de calidad.

## Supuestos abiertos

La ronda posterior comprobó parte de la infraestructura existente en modo lectura: [inventario](12-preservacion-infra-y-canales.md). Volumen efectivo, presupuesto, tecnologías vigiladas, espacio libre e integridad del archivo siguen pendientes. El diseño adopta un operador y despliegue único, sin GPU obligatoria. La implementación completará inventario, recuperación y objetivos; cambiar esas cifras no debe exigir cambiar el núcleo conceptual.
