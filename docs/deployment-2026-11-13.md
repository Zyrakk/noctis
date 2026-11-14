# Despliegue de la landing — 13 de noviembre de 2026

Esta primera landing fue sustituida después por la
[variante glass aprobada](deployment-glass-2026-11-13.md). Este recibo conserva
la evidencia y el alcance de la publicación anterior.

Resultado: **desplegado y funcionalmente verificado, con aviso CSP de Cloudflare**.

Origen: <https://noctis.zyrak.cloud>.
Versión ejecutada: `landing-20261113-1f85c764e9c1`.

## Artefacto e identidad

- Índice publicado e instalado:
  `ghcr.io/zyrakk/noctis@sha256:ea42e1ca7c65d9054bfab776fd4547bf021f38aef7eac6d31620a0c91abec2b5`.
- Manifest ejecutable ARM64 del índice:
  `sha256:d2d0eb02acc47b95101a9948279a3f0b6f002a44e0dd5684bd415f85dbc1f298`.
- Contexto `zcloud-cluster`, cuenta `system:admin`, namespace `noctis-v2`
  UID `c4e880f8-db41-4823-9582-aaae2810d4b0`, nodo ARM64 `oracle1`.
- Deployment API UID `407f74f0-1c6b-492a-9ed4-9862dc0da0fd`.
- Pod nuevo UID `be6ba00b-edf1-4ba3-be1e-0030fd35ff1e`, disponible y sin reinicios.

El preflight verificó además identidades legacy preservadas, réplicas legacy
cero y salud del nodo. Se repitió inmediatamente antes del cambio. Los siete
checksums de migración de producción coinciden con el candidato.

La publicación reutilizó exactamente los archivos de imagen comprobados por
`ops/rebuild/operations/image_checks.py`. AMD64 pasó smoke offline; ARM64 pasó
verificación ELF y manifest. El binario AMD64 extraído de la imagen pasó el E2E
canónico con navegador, producto y gateways IA HTTPS sintéticos. En producción
se comprobó ejecución nativa ARM64 y la versión esperada.

El runtime informa `imageID` con el digest del **índice**, no con el del manifest
ARM64. Se verificaron por separado el índice remoto, su única entrada ARM64, la
arquitectura del nodo y la versión ejecutada; no se presenta `imageID` como prueba
directa del digest del manifest ARM64.

## Cambio realizado

Se modificó únicamente `spec.template.spec.containers[0].image` de la API,
mediante JSONPatch con precondiciones de UID, resourceVersion, nombre del
contenedor e imagen anterior. Se conservó `Recreate` y una réplica. El rollout
terminó correctamente.

La comparación de specs anterior/posterior acredita que los otros Deployments
permanecen iguales. Worker sigue con una réplica, ambos collectors con cero.
No se ejecutaron migraciones, cambios de secretos, configuración IA, políticas,
volúmenes ni rutas Ingress. Las pruebas de login/logout solo ejercitaron el
ciclo normal de sesión.

## Comprobaciones reales

- `/`: antes 404; después GET y HEAD 200, HTML de Noctis y `Cache-Control: no-cache`.
- `/livez` y `/readyz`: 200; base/esquema/funcionalidad correctos, IA deshabilitada.
- Navegador HTTPS con validación normal de certificado: captura incrustada,
  vídeo reproduciéndose, transición de scroll, menú móvil y movimiento reducido.
- `/v2/login`: formulario separado, autenticación real, lecturas de sesión,
  Hoy, Fuentes y Sistema con HTTP200 y envelope válido; logout correcto.
- Los tres scripts propios de la landing ejecutan con sus hashes CSP. Cero
  errores JavaScript y cero bloqueos CSP de scripts propios o no identificados
  en la comprobación complementaria.

## Aviso CSP identificado

La comprobación inicial de «cero mensajes CSP» **falló**. No se descarta su
resultado: Cloudflare añade un inline dinámico con `window.__CF$cv$params` y
`/cdn-cgi/challenge-platform/`, bloqueado tanto en raíz como en login. La
comprobación complementaria comparó el hash indicado por cada error con el
contenido del script inyectado presente en ese mismo documento: un bloqueo
Cloudflare por ruta, ningún bloqueo propio/no identificado. Los flujos anteriores
sí funcionaron.

Cloudflare documenta esta incompatibilidad de JavaScript Detections con CSP sin
nonce en su [documentación oficial](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/).
El panel previo ya utilizaba `script-src 'self'`, que tampoco autorizaba ese
inline. Se conservó la CSP y la configuración de Cloudflare, sin añadir
`unsafe-inline`, hashes dinámicos ni desactivar controles. No se hizo rollback
por este aviso identificado. No queda acreditado el comportamiento de todos los
posibles challenges o visitantes; resolver esa integración es un pendiente aparte.

## Evidencia y rollback

Recibos privados, sin copiar credenciales al repositorio:
`/home/zyrak/.cache/noctis-landing-production-20261113/`.
Incluye manifiesto de hashes de fuente, snapshots de Deployments, preflights,
build/publicación, E2E de imagen, patch, `rollout-receipt.json`,
`production-browser-receipt.json` (fallo del criterio global CSP conservado),
`edge-csp-receipt.json` (diagnóstico complementario) y capturas públicas.

Imagen previa preservada para rollback exclusivo del campo imagen, tras
revalidar identidad y resourceVersion:
`ghcr.io/zyrakk/noctis@sha256:2a0b14affded42be68260f7e691ab694d8cf4761047e067568e1220ef41050bc`.
Ese rollback recuperaría también el comportamiento anterior de raíz 404.

Los bloqueos operativos de Telegram, IA real, captura/aplicabilidad y recuperación
recogidos en la [revisión](review-2026-11-13.md) no se corrigen con este despliegue.
No se ejecutó inferencia pagada ni se reanudó captura.
