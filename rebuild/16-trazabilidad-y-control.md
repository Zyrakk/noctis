# Trazabilidad, decisiones de implementación y control de entrega

Registro inicial del roadmap, 16-10-2026. En esa fecha todos los requisitos de implementación estaban pendientes. El estado comprobado durante la ejecución se recoge en [18-ejecucion-y-recibos.md](18-ejecucion-y-recibos.md); esta matriz conserva la correspondencia de requisitos, paquetes y pruebas. Inventario de metadatos infra verificado en modo lectura no equivale a backup ni captura funcional. No marcar verificado por terminar su documentación.

## Requisitos core y pruebas

| ID | Origen | Comportamiento/entrega | Paquetes | Pruebas / gate |
|---|---|---|---|---|
| **R01** | `01`, `07`, `09` | Preservar archivo/sesión y restaurar copia antes de tocar origen | P0.1–P0.2 | T00–T02 / G0 |
| **R02** | `02`, `09`, `12` | Inventario completo config/DB/histórico/dialogs con disposición por canal | P0.3, P4.1 | T03–T04 / G4 |
| **R03** | `03`, D01 | Stack único modular; modos API/worker/collector con aislamiento por privilegios | P1.1–P1.4 | T05/T08/T09 / G1 |
| **R04** | `03`, D02 | Blobs dedup y observaciones/revisiones separados, original conservado | P2.1 | T10–T11 / G2 |
| **R05** | `03` | Fuente/ID estable, tiempos publicación/captura/proceso y checkpoint coherente | P2.1, P4.2 | T10–T11/T24 / G2/G4 |
| **R06** | `03`, D03 | Jobs durables, leases/fencing, estados/retry/quarantine y replay | P2.2 | T12–T13 / G2 |
| **R07** | `01`, `03` | Rol runtime sin DDL/escritura legacy; migración checksum/lock y DB nueva | P1.2–P1.3 | T06–T08 / G1 |
| **R08** | `04`, D04 | Extracción sintáctica completa con validación/normalización reversible/spans | P3.1 | T15 / G3 |
| **R09** | `02`, `04` | PIR/watchlists para org/actor/campaña/sector/tecnología; gate conservador | P3.1 | T16/T35 / G3/G6 |
| **R10** | `03`, `04` | Observable≠indicator; sightings únicos, contexto y datos benignos conservados | P3.1, P5.3 | T15/T29 / G5 |
| **R11** | `02`, `06` | Expediente automático, revisión, radar mínimo y cambios materiales | P3.2–P3.3 | T17/T20/T21 / G3 |
| **R12** | `04`, D05 | Claims con evidencia/contradicción, independencia y cero atribución por confidence | P5.1 | T27/T30 / G5 |
| **R13** | `03`, `06` | Identidad/aliases reversibles, dossiers y grafo acotado con soporte | P5.1, P7.1 | T27/T36 / G7 |
| **R14** | `04`, `06` | Retractación invalida derivados y actualiza radar/brief/historia | P5.1, P7.3 | T27/T38/T40 / G7 |
| **R15** | `03`, `07` | Outbox transaccional, DeliveryKey estable y estado incierto | P3.2 | T18 / G3 |
| **R16** | `02`, `06` | Brief mecánico temprano y semántico citado por novedad/cobertura | P3.2, P6.2, P7.3 | T17/T21/T34/T38 / G6/G7 |
| **R17** | `07`, D08 | Fetch SSRF/redirect/DNS/límites y Tor cerrado | P2.3 | T14 / G2 |
| **R18** | `06`, `07` | Auth/sesión/CSRF, QR administrativo y contenido hostil saneado | P3.3, P4.3 | T19/T25 / G3/G4 |
| **R19** | `06` | Build local assets; errores/vacío/stale y URLs profundas estables | P1.4, P3.3, P7.1 | T09/T20/T36/T39 / G7 |
| **R20** | `07`, `12` | Telegram allowlist antes de payload; peers+IDs/revisiones y estado nativo | P4.1–P4.2 | T22–T24 / G4 |
| **R21** | `07`, `12` | Sesión exclusiva, FloodWait durable y takeover cerrado | P4.3 | T25–T26 / G4 |
| **R22** | `09`, `12` | Epoch/live/bootstrap separados, gaps y cero alertas históricas | P4.2, P8.2 | T23–T24/T42 / G4/G8 |
| **R23** | `02`, `04` | CVE/KEV/EPSS con snapshot, aplicabilidad/versiones/exposición desconocida | P5.2 | T28/T30 / G5 |
| **R24** | `04`, `05` | Enrichment con permisos/privacidad/cuotas/caché TTL y juicio revocable | P5.3 | T29/T33 / G5/G6 |
| **R25** | `03`, `04` | Indicadores con vigencia/revocación; replay no rejuvenece ni infla | P5.3 | T29 / G5 |
| **R26** | `04`, `08` | Pasada IA selectiva, schema/citas, chunks y cache contextual | P6.1–P6.2 | T31/T33–T34 / G6 |
| **R27** | `05`, D07 | Ledger/reservas persistentes, caps concurrentes y exposición incierta | P6.1 | T32 / G6 |
| **R28** | `04`, `05` | Calidad por segmento/modelo/ruta, corpus sin filtración y promoción medida | P6.3–P6.4 | T35 / G6 |
| **R29** | `08`, D10 | Gateway y errores/capacidades/fallback evaluados sin depender de Zrelay | P6.1 | T31–T35 / G6 |
| **R30** | `04`, D06 | Consulta natural→QueryPlan tipado y SQL parametrizado limitado | P7.1 | T36 / G7 |
| **R31** | `06` | Cinco áreas, tres historias A/B/C y lector de evidencia | P3.3, P5.4, P7.1 | T20/T30/T36/T39 / G7 |
| **R32** | `02`, `06` | Atención excepcional, silencios/reapertura y visto≠confirmado | P7.3 | T38 / G7 |
| **R33** | `07` | Discovery limitado/TTL y score no circular; cobertura/caída por PIR | P7.2 | T37 / G7 |
| **R34** | `06`, D09 | Vitrina sintética autónoma sin requests privados ni métricas inventadas | P7.4 | T39 / G7 |
| **R35** | `03`, `07` | Retención por clase, tombstones/auditoría y purga trazable | P8.1 | T40 / G8 |
| **R36** | `07` | Backup/restore v2, RPO/RTO y capacidad/progreso/degradación medidos | P1/P3 básicos, P8.1 | T02/T13/T41 / G8 |
| **R37** | `07`, `09` | Release reproducible, rollback compatible, cutover sin doble cliente/entrega | P1.4, P8.2 | T09/T42 / G8 |
| **R38** | `01`, `09`, `10` | Retirada runtime legacy y docs/config canónicas, sin borrar archivo | P8.3–P8.4 | T43 / G8 |
| **R39** | `01`, `02`, `07` | Adaptadores web/paste/forum conservados con captura/fetch seguros | P7.5 | T44 / G7 |
| **R40** | `09`, `12` | Import histórico opcional idempotente, read-only y sin elevar certeza | P0.2–P0.3, P4.5 | T03–T04/T23/T27 / G4 |
| **R41** | Usuario 18-10-2026, `17` | Panel proveedor/URL/API key/modelo por función IA, configuración segura durable y consumo efectivo | P6.5, P7.1 | T45–T48 / G6/G7 |

R40 exige conservación/consulta y un contrato de import probado; ejecutar la importación completa de todo el archivo no es obligatorio para empezar ni para G8. Si no se hace, informar archivo disponible aparte y volumen sin reanalizar.

## Destino de cada capacidad del sistema anterior

| Capacidad legacy | Destino en v2 | Condición |
|---|---|---|
| RSS/Atom | Adaptado en P2/P3 | Primer recorrido completo. |
| Telegram | Rehecho en P4 | No reutilizar dedupe/handler/cursor actual como contrato. |
| Web HTML, paste, foros | Adaptadores al contrato seguro en P7.5 | Desactivados hasta fuente autorizada; prueba sintética obligatoria. |
| Matcher y alert path síncrono | Políticas y outbox P3 | Matcher útil se reutiliza; IA inline/entrega síncrona se retiran. |
| Classifier/summarizer/IOC/librarian | Parsers P3 y pasada selectiva P6 | No mantener cinco llamadas obligatorias por mensaje. |
| Entidades/graph bridge/correlator/analyst | Claims y proyecciones P5/P7 | Sin promoción por conteo/confianza. |
| IOC lifecycle | Indicadores/TTL/revocación P5 | Separar tiempo de observación de procesamiento. |
| NVD/EPSS/KEV | Feeds/snapshots/contexto P5 | Mantener origen y aplicabilidad desconocida. |
| Enrichment externo | Adaptadores con cuotas/permiso/cache P5 | No depender de API gratuita ilimitada. |
| Briefs y notas | Expedientes/revisiones/briefs citados P3/P6/P7 | Notas IA no se reciclan como evidencia externa. |
| SQL natural libre | QueryPlan P7 | Ruta libre excluida del runtime nuevo. |
| Source discovery/triage/source value | Discovery acotado P7 | No autojoin ni bloqueo permanente por opiniones LLM. |
| Dashboard/auth/metrics/health | Cinco áreas y salud real P1/P3/P7/P8 | Frontend compilado local, privacidad por diseño. |
| Public stats/recent | Demo sintética P7 | No exponer consultas del archivo privado. |
| Sesiones y administración | Credenciales separadas y control de propiedad P4/P8 | Un dueño y flujos autenticados. |
| Canary/NetworkPolicy/remediación automática | Fuera del core: respuesta requiere proyecto/política específicos | No activación por inferencia; no se pierde silenciosamente, se excluye por alcance `02/07`. |
| Entrenamiento F1 | Fuera de runtime; reutilizar muestreo/validación útiles | Usuario descarta entrenamiento propio como enfoque. |
| Presentación antigua | Conservar como relato histórico; nueva demo aislada | No reescribir anécdotas como benchmark. |

## Capacidad ambiciosa condicionada

X1 Zrelay real espera su rebuild y prueba de ruta. X2 STIX/TAXII, OCR, embeddings, SIEM/nuevos conectores y multiusuario necesitan un caso de uso y aceptación propios. Estado inicial `condicionado`, no `verificado` ni «eliminado». No usarlos como excusa para dejar incompletos presupuesto, contratos, búsqueda segura o expediente core.

## Estados y recibo por paquete

```text
package_id:
status: pendiente | implementado_sin_verificar | verificado | bloqueado | condicionado
commit_or_workspace_revision:
contracts_and_policy_versions:
requirements:
commands_and_environment:
test_results_and_artifacts:
private_artifacts_receipt_only:
limitations_and_open_failures:
gate:
```

Un bloqueo en recuperación no convierte en bloqueado todo el proyecto: especificar la dependencia y continuar paquetes locales independientes. No marcar gate aprobado si solo hay mocks, skips, screenshots o archivos de configuración.

## Definition of Done del rebuild

G0–G8 con sus evidencias, requisitos R01–R41 verificados según alcance, cinco áreas funcionales y tres historias completas. Todas las fuentes inventariadas tienen disposición; activas, resolución/acceso/progreso comprobados. Producto opera con IA selectiva configurable por función y degrada útilmente sin ella, datos y gasto son recuperables y el runtime antiguo ya no captura, interpreta ni entrega.

Acompañar release con límites reales: segmentos no validados, fuentes inaccesibles, gaps históricos, import pendiente, capacidades condicionadas y costes/recursos medidos. No hace falta cubrir todo el underground ni habilitar toda extensión para cumplir el core; sí hace falta decir exactamente qué se entregó.

## Registro del contraste Astra

Los tres revisores acuerdan P0–P8 y X1/X2. Operación y arquitectura fijaron DB nueva en PG reutilizado, archivo protegido, epoch fresco y sesión exclusiva. Validación añadió gates PG real/build offline, cobertura de todas capacidades core y rollback v2 compatible. Se resolvió:

- CI, auth y restore/pausa mínimos desde P1/P3, repetidos sobre release en P8.
- Cierre G8 exige producto/operación y retirada efectiva legacy; no basta un RSS demo o pods Running.
- Inventario total no implica activación total; import repetido no cambia políticas posteriores.
- Allowlist rechaza payload ajeno, pero protocolo puede avanzar con disposición mínima sin contenido.
- Lease/fencing SQL no demuestra cierre RPC; takeover requiere terminación confirmada.
- Shadow usa corpus/export/inbox, nunca dos clientes de la misma sesión.
- Infra comprobada solo en metadatos: siguen sin verificar integridad del volumen, datos, IDs y sesión.

Las síntesis privadas de trabajo de esta ronda quedan en `/tmp/noctis-implementation-cTCDYr/`; este registro conserva las decisiones durables. Sin disensos sustantivos abiertos; las garantías técnicas siguen pendientes de implementación y prueba.
