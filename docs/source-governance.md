# Pregunta gobernante de una fuente

`question_sources` representa la relación vigente: cero preguntas para una política
independiente o una pregunta gobernante. Una pregunta puede gobernar varias fuentes.
La procedencia de `discovery_proposals`, las políticas inmutables, productos y recibos
conservan sus referencias históricas al cambiar la gobernante.

`POST /api/v2/sources/{id}/policy` sustituye política y relación en una transacción,
bajo el bloqueo de proyección, `expected_revision` y `request_id` existentes. El
servidor resuelve la identidad y revisión de una política `question:…`; un
`question_id` distinto produce `400 question_policy_mismatch`, y asignar una revisión
antigua produce `409 stale_question_policy` con la revisión actual de la pregunta.
El CAS de la fuente continúa devolviendo `409 stale_revision` y su revisión actual.

Omitir `policy_version` conserva la asignación. Una política independiente explícita
elimina la relación; no admite `question_id`. Repetir la misma asignación conserva
`independence`; sustituir la pregunta inicia ese metadato en `unknown`.
Discovery mantiene su pregunta de procedencia y selecciona su política actual al
activar, aunque el cliente tenga una revisión anterior de esa misma pregunta.

La reasignación no concede permisos discovery ni renueva consentimiento Telegram
de una fuente ya activada. La pausa propia de la fuente y la de su gobernante
siguen siendo independientes. Editar una pregunta abandonada no cambia la fuente;
los trabajos antiguos conservan su identidad y su barrera de publicación rechaza
una política que ya no sea la vigente.

La migración `011_source_governance.sql` conserva la asociación que coincide con la
política canónica actual y sus metadatos, y añade unicidad por fuente. Aborta de
forma transaccional y enumera las fuentes cuando no encuentra esa asociación,
la política es incoherente o eliminaría una pregunta pausada mientras la nueva
gobernante está habilitada. Esta última comprobación incluye fuentes pausadas o
con permisos separados revocados: no se elimina tampoco una barrera latente.
Esos datos requieren conciliación explícita previa, sin activación automática.
