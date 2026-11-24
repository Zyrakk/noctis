# Despliegue de las veinte mejoras — 14 de noviembre de 2026

Las veinte propuestas aceptadas están implementadas, integradas secuencialmente en `dev`, publicadas y desplegadas en `https://noctis.zyrak.cloud`. El inventario funcional está en [finished-implementations.md](../finished-implementations.md) y las decisiones en [propuesta-avance.md](../propuesta-avance.md).

## Artefacto e identidad

- Fuente: `f7b45739088f134ee22bf59e266705022af26fa0`.
- Versión: `avance-20261114-f7b45739088f`.
- Imagen: `ghcr.io/zyrakk/noctis@sha256:9f17fc5ee7ba3420bf432823cdde229d925ef0088267e169fba4fe0501f568f9`.
- Manifest ejecutable ARM64 del índice: `sha256:415178765fafe49063bc11b2f4d3faef7dbad675142c9cdc22c592fcec662457`.
- Contexto `zcloud-cluster`, namespace `noctis-v2`, nodo `oracle1` ARM64; identidades comprobadas antes de cada fase. Se preservaron los recursos legacy.

El preflight de publicación volvió a cargar los archivos probados, extrajo sus ejecutables y contrastó hashes y recibos. Los manifests remotos coinciden con los artefactos probados; no hubo reconstrucción para publicar. Containerd informa el digest del índice multiarch como `imageID`; la versión se ejecutó y contrastó en ambos pods del nodo ARM64.

## Verificación

- `make ci-check`: suite Go/race aprobada, **105 pruebas obligatorias**, cero omisiones inesperadas; 63 pruebas Python aprobadas y trece checksums correctos. Build de frontend: 17 pruebas aprobadas y una omisión prevista del escenario HTTPS, ejecutado después por el harness real.
- UI conjunta: **56/56**, sin omisiones, fallos ni pruebas inestables.
- Harness del binario extraído de la imagen final: **10/10** — HTTPS, ocho escenarios de producto y uno de IA con gateways sintéticos. Incluye paginación 50→51, CAS entre dos sesiones, resumen, traducción y reinicio.
- Ajustes finales del harness: permiso DELETE limitado a `question_sources` para sus LOGIN sintéticos, con revocación/recuperación probadas; selección explícita del caso basal de IA para que una fuente pausada por otra prueba no determine el caso elegido. No se relajaron autorizaciones del producto.
- PostgreSQL productivo: **13 migraciones y checksums exactos**, PK de transiciones UUID, cero secuencias.
- Cuatro LOGIN reales: conexión autenticada, CRUD y EXECUTE requeridos, DDL denegado, transacciones de prueba revertidas.
- API y worker: rollout aprobado, versión correcta, disponibles y cero reinicios en la comprobación. API: `/livez` y `/readyz` 200 mediante HTTPS directo, certificado y hostname verificados.
- Navegador público: TLS válido, login, seis lecturas autenticadas con HTTP200, logout y sesión revocada; cero errores JavaScript. Las lecturas incluyen Hoy, fuentes, sistema, casos e historial de IA.

Los recibos locales están en `/home/zyrak/.cache/noctis-avance-evidence-20261114`: `final-ci-2.log`, `final-go-2.jsonl`, `final-ui.json`, `final-images-2.log`, `images-2/publication-receipt.json`, `production-ledger-after.json`, `production-login-check3.log`, `production-origin-health.json`, `production-browser-receipt.json`, `production-api-arm64.json`, `production-worker-arm64.json` y `production-deployments-final.json`.

## Respaldo y ejecución

Antes del DDL se comprobaron gobernanza, horizontes de reintento, conexiones y locks: cero bloqueos; 1.175 trabajos `parse` terminados, cero trabajos IA y ninguna relación de gobernanza que eliminar. La base ocupaba aproximadamente 19 MB, con espacio suficiente en su volumen.

La configuración actual y la sesión se respaldaron cifradas con age: **once archivos**, cuatro modos de ejecución, restauración a destino nuevo y comparación exacta de bytes y permisos. La sesión se copió con un helper de solo lectura, propietario/modo y hash estable; el helper fue eliminado con precondición UID y su desaparición se verificó.

Tras detener API y worker y comprobar ausencia de escritores, se tomó un snapshot compartido de PostgreSQL: **74 tablas, 14.416 filas**. El archivo cifrado se restauró en un contenedor nuevo sin red; esquema, migraciones, conteos, digests y consultas representativas coincidieron exactamente. El contenedor de restauración se eliminó. Respaldos cifrados y recibos privados: `/home/zyrak/.local/share/noctis-rebuild/production-avance-20261114`; la clave age permanece separada.

Se ejecutaron una vez las migraciones y el Job de grants. Dos intentos de comprobación de LOGIN fallaron antes de completar SQL: el primero por rechazo TCP inicial; el segundo por transformación de `$$` en el comando de Kubernetes. Se conservaron ambos Jobs. El intento final incorpora una barrera acotada `SELECT 1` y delimitadores SQL etiquetados; los cuatro LOGIN pasaron. La hipótesis de propagación inicial de red no se presenta como causa demostrada del primer rechazo.

Las cuatro imágenes se cambiaron con réplicas cero mediante patches con precondiciones de UID, resourceVersion, contenedor e imagen anterior. Se abrió primero API, se comprobó la sesión pública y después se abrió worker.

La comprobación final de specs confirma que sólo cambió la imagen y se recuperaron las réplicas previas; los tres Jobs requeridos están Complete y los pods API/worker siguen Ready sin reinicios. Los veinte worktrees temporales, el PostgreSQL sintético, los archivos locales de ambos candidatos y las copias temporales descifradas se retiraron. Se conservaron las ramas, los recibos, los respaldos cifrados y la clave separada; la evidencia local ocupa aproximadamente 9 MB. Los dos Jobs de diagnóstico fallidos se preservaron para auditoría.

## Estado y límites

API y worker conservan una réplica cada uno. RSS y Telegram conservan cero. Inferencia automática y manual permanecen desactivadas; no se configuró envío externo. La comprobación final conserva los 1.175 trabajos `parse` terminados y cero trabajos IA; no había cola nueva con la que acreditar procesamiento productivo adicional.

La petición de sondas públicas realizada con Python recibió HTTP403; la navegación pública autenticada pasó y las sondas directas al origen devolvieron HTTP200. No se modificaron reglas de red o acceso para esta comprobación.

Este despliegue no acredita calidad de inferencia pagada ni captura Telegram real. No se iniciaron esos servicios para probarlo. Los respaldos permanecen en este host; no se afirma copia externa. Tras migrar, una recuperación debe respetar el esquema exacto: no basta volver a la imagen antigua.
