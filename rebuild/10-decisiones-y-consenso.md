# Decisiones y contraste entre tres Astra

Fecha: 2026-10-16. Tres agentes **GPT-6 Astra, esfuerzo xhigh**: arquitectura/operación, inteligencia/IA y producto/UX. Por el límite de concurrencia (principal incluido), se escalonaron y se abrieron rondas de réplica con mensajes directos entre revisores. Los informes y réplicas los integra el principal en estos documentos; los Astra no implementaron código ni ejecutaron acciones externas.

Las síntesis de trabajo quedan fuera del repositorio en `/tmp/noctis-rebuild-RLnGLl/`. Son temporales; las decisiones necesarias para implementar se conservan aquí.

## Qué se discutió y cómo se resolvió

| Pregunta | Contraste | Resolución común |
|---|---|---|
| ¿Reescribir todo con otra plataforma? | Arquitectura pidió corregir garantías; producto pidió valor temprano | Conservar stack, rehacer datos/ejecución y entregar corte vertical antes de ampliar. |
| ¿Deduplicar para ahorrar IA o guardar cada aparición? | Ahorro frente a procedencia/corroboración | Blob y caché compartidos, observaciones separadas y dependencia de origen explícita. |
| ¿Cuándo una alerta puede ser automática? | CTI exige no confirmar rumores; producto necesita utilidad sin revisión constante | Avisos factuales/provisionales según predicado real; inferencias de alta prioridad requieren validación por segmento. No confirmar atribuciones por confidence. |
| ¿El radar de cambios es una mejora futura? | Primer borrador lo situaba en expansión; producto lo consideró promesa esencial | Radar mínimo, novedades y dependencia de fuentes desde el primer corte; análisis avanzado después. |
| ¿RSS basta para relanzar Noctis? | Arquitectura prioriza aceptación sencilla; producto defiende diferenciación underground | RSS para primer corte técnico; relanzamiento funcional incluye piloto Telegram autorizado. |
| ¿Todo debe basarse en activos propios? | Prioridad local es útil; CTI también sigue actores/campañas/sectores | PIR amplios y exposición local opcional por recorrido. |
| ¿Grafo como centro visual? | Existe grafo; producto observa que obliga a ensamblar conclusiones | Expediente, timeline, diff y evidencia primero; grafo secundario de investigación. |
| ¿Cada incertidumbre requiere revisión humana? | Rigor frente a mínima interacción | Hipótesis puede permanecer abierta. Atención excepcional requiere decisión concreta, motivo, plazo y presupuesto. Visto no confirma. |
| ¿600–1.000 etiquetas bloquean el primer corte? | Evaluación representativa frente a coste inicial | Corpus adversarial funcional desde día 1; 300–500 orientativo para primera selección, ampliación según cobertura. No bloquear recorrido mecánico. |
| ¿Cita resoluble equivale a texto verificable? | Retención puede borrar originales | Tombstone conserva procedencia histórica, UI marca texto no verificable; nueva inferencia urgente necesita soporte accesible. |
| ¿Modelos y descuento Zrelay definitivos? | Precios oficiales difieren de catálogo local | Separar tarifas directas y escenario documental Zrelay; decidir por evaluación de ruta real después. |

## Registro de decisiones

| ID | Decisión | Alternativa descartada y razón | Revisar cuando |
|---|---|---|---|
| D01 | Monolito modular Go/Postgres/React | Microservicios y varias bases aumentan carga de un operador sin necesidad medida | Límites medidos de carga/aislamiento. |
| D02 | Observaciones, contenido y afirmaciones separados | Fila única por hash destruye procedencia | Invariante del dominio; no depende de escala. |
| D03 | Jobs durables + outbox + idempotencia | Polling por booleanos duplica trabajo y mezcla fallos | Si cola externa aporta beneficio probado. |
| D04 | Reglas primero, IA semántica selectiva | Entrenamiento propio y múltiples llamadas por mensaje no son necesarios | Evaluación demuestre necesidad concreta. |
| D05 | Política decide publicación/entrega | LLM como autoridad introduce certeza y permisos no sustentados | Nunca por autoconfianza; solo nuevas políticas evaluadas. |
| D06 | Consulta natural mediante plan tipado | SQL libre con blacklist no impone frontera real | Requisito avanzado con privilegios separados. |
| D07 | Ledger/reserva persistente | Memoria y margen presupuestario no limitan consumo concurrente | Contrato de facturación cambie, conservando límite. |
| D08 | Fuente autorizada y fetch aislado | Discovery irrestricto/Tor fallback exponen red y credenciales | Nuevos perfiles explícitos de acceso. |
| D09 | Demo pública separada | Truncar resúmenes privados no anonimiza | Publicación curada con permiso y revisión. |
| D10 | Zrelay por puerto/adaptador futuro | Acoplar a catálogo actual bloquea o invalida rebuild | Su contrato migrado esté disponible y comprobado. |

## Límites compartidos

Este registro corresponde a la revisión inicial, anterior al inventario remoto. La ronda posterior de implementación comprobó estado de cargas, PVC y configuración, descritos en [12](12-preservacion-infra-y-canales.md); no comprobó contenido, integridad o recuperación. Volumen histórico, presupuesto aceptable y calidad sobre datos propios siguen pendientes. No hay benchmark, despliegue o migración ejecutados. Las cifras de coste son cálculos de supuestos; precisión y capacidad son objetivos de piloto. La ambición se conserva con fronteras técnicas que permiten operar sin una plantilla de analistas.

No quedaron discrepancias sustantivas abiertas tras la ronda de contraste. Eso es acuerdo de diseño, no demostración empírica. Las decisiones se revisan con evidencia de aceptación, no por preferencia del modelo.
