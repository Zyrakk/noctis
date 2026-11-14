# Despliegue de la variante glass — 13 de noviembre de 2026

**Desplegada en <https://noctis.zyrak.cloud/>**, sustituyendo la landing anterior.
Versión ejecutada: `glass-20261113-fb5e4dfc0691`.

## Cambio y artefacto

Se promovió `web/noctis-glass.html` a `web/index.html`, cambiando sus dos enlaces
de marca a `/`. El preview separado sigue siendo local y no se añade al build.
La captura y el poster están incrustados; vídeo y fuentes usan sus orígenes
remotos. Se actualizaron los checks de menú, composición y scroll al nuevo diseño.
No cambió el código backend respecto a la release anterior.

- Imagen instalada por digest:
  `ghcr.io/zyrakk/noctis@sha256:249e82f9075aa8e90397a43433b362d3d3ee53d8604422f8cf4d270406baa57a`.
- Manifest ARM64 comprobado:
  `sha256:4a188592f8fe5f665859e38c122f129ad241909477097e0ebf8f9e332f4e57ac`.
- Contexto `zcloud-cluster`, cuenta `system:admin`, namespace `noctis-v2`
  UID `c4e880f8-db41-4823-9582-aaae2810d4b0`, nodo ARM64 `oracle1`.
- Deployment API UID `407f74f0-1c6b-492a-9ed4-9862dc0da0fd`.
- Pod nuevo UID `4ac43ca8-4272-4ddc-a685-9cdc1a3a1462`, listo y sin reinicios.

Preflight correcto antes de preparar y justo antes de actualizar. Se conservó
la identidad de los recursos legacy. Los siete checksums de migración coinciden
con producción. El JSONPatch solo cambió la imagen de la API y probó previamente
UID, resourceVersion, nombre del contenedor e imagen anterior.

Se mantuvieron estrategia `Recreate`, una réplica API, una worker y cero en ambos
collectors. La comparación de specs demuestra que no hubo otros cambios de
Deployments. No se aplicaron migraciones, secretos, políticas, volúmenes ni Ingress.

## Validación

- Build frontend correcto; 12 pruebas del build correctas. La única omisión fue
  el spec que requiere harness; después se ejecutó mediante el E2E de imagen.
- Suite frontend completa final: **35 pruebas correctas**. Incluye anchuras de
  320–1920 px, título de dos líneas sin recortes, menú/Escape/foco, imagen,
  scroll, movimiento reducido, demo y panel privado.
- Regresión Go de documento público/privado, CSP y HEAD con `-race`: correcta.
- Imagen AMD64: smoke offline y E2E del binario extraído con API HTTPS real,
  navegador, producto y gateways IA **sintéticos** correctos. Imagen ARM64:
  ELF/manifest comprobados antes de publicar; arquitectura y versión verificadas
  en ejecución real tras el rollout.
- Rollout completo, generación observada y una réplica disponible. `imageID`
  informa del índice; se comprobaron separadamente su entrada ARM64 única y la
  versión ejecutada, sin confundirlo con el digest del manifest.
- GET/HEAD raíz, `/livez` y `/readyz`: HTTP200. Esquema/base/funcionalidad sanos,
  `ai_enabled=false`.
- Navegador público real: variante glass, Poppins/Source Serif 4, enlaces de marca,
  captura incrustada, reproducción y relevo de vídeo, pausa/reanudación, scroll,
  menú móvil y movimiento reducido correctos. Inspección visual de la captura
  pública de producción realizada.
- Autenticación real, lecturas de sesión, Hoy, Fuentes y Sistema: HTTP200 y
  envelopes válidos. Logout correcto. Ninguna captura contiene datos privados
  del panel autenticado.

Durante la integración un primer check de demo coincidió con una recarga de Vite.
Un check posterior del panel móvil encontró el documento sin lector dentro de su
espera. Se conservan los logs: el caso móvil pasó aislado con traza **sin cambiar
su implementación**, y la repetición completa final pasó 35/35. No se atribuye una
causa definitiva al fallo móvil ni se ampliaron timeouts para obtener el resultado.

## Aviso conocido de Cloudflare

Persiste un bloqueo CSP identificado del inline de JavaScript Detections por
ruta (`/` y `/v2/login`). El check compara el hash indicado por cada mensaje con
el script inyectado presente en ese documento. **Cero errores JavaScript y cero
bloqueos CSP propios o no identificados**; los avisos conocidos se conservan en
el recibo. La CSP y Cloudflare no se relajaron. Se mantiene la limitación sobre
escenarios de challenge no probados descrita en el
[despliegue anterior](deployment-2026-11-13.md#aviso-csp-identificado).

## Recibos y recuperación

Evidencia privada: `/home/zyrak/.cache/noctis-glass-production-20261113/`.
Incluye hashes de fuente, preflights, snapshots, checksums, build, pruebas,
publicación, patch, `rollout-receipt.json`, `production-browser-receipt.json`
y capturas públicas. El PostgreSQL local desechable de pruebas se retiró después
del E2E.

Rollback exclusivo de imagen, con identidad/resourceVersion nuevamente comprobados:
`ghcr.io/zyrakk/noctis@sha256:ea42e1ca7c65d9054bfab776fd4547bf021f38aef7eac6d31620a0c91abec2b5`.
Recupera la primera landing publicada, sin migraciones inversas.

Captura e IA conservan su estado previo. No se ejecutó inferencia pagada ni se
resolvieron los bloqueos operativos de la [revisión](review-2026-11-13.md).
