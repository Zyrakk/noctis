# Despliegue premium en inglés — 13 de noviembre de 2026

Publicado y comprobado en <https://noctis.zyrak.cloud/>.
Versión: `premium-20261113-b04335e1edfb`.
Los cambios se detallan en [el informe de interfaz](premium-english-2026-11-13.md).

- Imagen instalada:
  `ghcr.io/zyrakk/noctis@sha256:ba3c0909471c9858220ec3b62cef6d71be1c7b35acea00d494c1d28af7bd8a9d`.
- Manifest ARM64:
  `sha256:d71191e0ed40c4773b3f2f9dffedb48929e2904ea70f0015f192f940eb343a56`.
- Contexto `zcloud-cluster`, cuenta `system:admin`, namespace `noctis-v2`
  UID `c4e880f8-db41-4823-9582-aaae2810d4b0`, nodo ARM64 `oracle1`.
- Deployment API UID `407f74f0-1c6b-492a-9ed4-9862dc0da0fd`.
  Pod nuevo UID `6fe8cf98-6300-449c-b1b0-3e870bb4632a`, disponible y sin reinicios.

## Verificación

Preflight correcto antes de preparar y de actualizar. Los siete checksums de
migración coinciden con producción. Un JSONPatch con pruebas de UID,
resourceVersion, nombre del contenedor e imagen anterior cambió exclusivamente
la imagen API. Las demás specs de Deployment permanecen idénticas: worker con
una réplica y collectors a cero. No hubo migraciones, cambios de secretos,
activación de captura ni inferencia pagada.

- 40 pruebas de interfaz correctas; build final correcto y 17 pruebas del build
  correctas. El spec HTTPS omitido deliberadamente en esa fase se ejecutó después
  en el harness real con datos sintéticos.
- 41 pruebas Python y suite Go con detector de carreras correctas; 96 casos
  obligatorios comprobados, cero omisiones inesperadas.
- Imagen AMD64: smoke offline y E2E del binario extraído correctos: HTTPS 1/1,
  producto 7/7 e IA con gateways sintéticos 1/1. ARM64: ELF y manifest comprobados;
  arquitectura y versión comprobadas en ejecución después del rollout.
- Producción: rollout completo, generación observada y réplica disponible;
  `/livez` y `/readyz` HTTP200; base, esquema y funcionalidades sanos;
  `ai_enabled=false`.
- Navegador real: landing inglesa, fuentes, captura incrustada, vídeo y relevo,
  pausa/reanudación, scroll, menú móvil y movimiento reducido correctos.
  Demo con documento y cita correspondientes correcta. Login real, lecturas de
  sesión, Today, Sources y System HTTP200 y logout correctos.
- Cero errores JavaScript y cero bloqueos CSP propios o no identificados.
  Persiste el inline de JavaScript Detections inyectado por Cloudflare, identificado
  mediante su hash en cada documento, descrito en el
  [despliegue anterior](deployment-glass-2026-11-13.md#aviso-conocido-de-cloudflare).
  No se relajó la CSP ni se cambió Cloudflare.

La primera integración detectó dos expectativas todavía en español, que se
corrigieron. Una segunda ejecución encontró `Failed to fetch` en tres lecturas
secundarias del expediente. Se consultó Astra y se añadió diagnóstico de fallos
de transporte. La ejecución completa de imagen pasó sin cambios de runtime,
reintentos automáticos ni ampliación de timeouts. No se ha demostrado la causa
del fallo previo ni se presenta como corregido por una modificación de producto.

Los checks iniciales del rollout asumían incorrectamente el formato de `image`
del estado Kubernetes y el envelope de `/livez`; se corrigió la comprobación:
`imageID` identifica el índice, el manifest ARM64 se comprueba separadamente,
`/livez` expone `data.live` y `/readyz` devuelve el estado detallado.

## Evidencia y recuperación

Recibos privados en `/home/zyrak/.cache/noctis-premium-production-20261113/`:
fuentes, enmienda exclusivamente de test, preflights, specs, builds, pruebas,
publicación, patch, rollout y navegador. Las capturas de producción son públicas;
no contienen el panel autenticado. DB, secretos y contenedor locales sintéticos
se retiraron tras revisar sus logs.

Rollback exclusivo de imagen, comprobando de nuevo identidad y resourceVersion:
`ghcr.io/zyrakk/noctis@sha256:249e82f9075aa8e90397a43433b362d3d3ee53d8604422f8cf4d270406baa57a`.
No requiere migración inversa. El worker conserva su imagen anterior; las fuentes
originales y los textos históricos mantienen su idioma.
