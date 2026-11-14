# Noctis v2

Producto privado de inteligencia con evidencia verificable, captura durable y
expedientes revisables. Backend Go y PostgreSQL16; frontend React compilado e
incluido en el binario. La inferencia es opcional: las rutas, modelo, credencial,
privacidad y límites se configuran por función en Sistema. Un resultado IA no
confirma una atribución por sí solo.

La interfaz reúne Hoy, Casos, Entidades, Fuentes y Sistema. El lector distingue
original, traducción generada, revisión y evidencia caducada/no disponible. Las
demos públicas de A/B/C son sintéticas y no consultan el backend privado.
El diseño y los criterios de aceptación están en [rebuild/](rebuild/README.md).

La raíz pública presenta el proyecto en `web/index.html`, con CSS, scripts y
captura del panel incrustados; vídeo y fuentes son remotos. El acceso privado
permanece en `/v2/login`, separado de la landing. Con Vite activo se puede
regenerar la captura sintética mediante `cd web && node scripts/capture-dashboard.mjs`;
`npm run test:landing` verifica presentación y regresiones del panel desde `web/`.
La [revisión del 13 de noviembre](docs/review-2026-11-13.md) recoge los bloqueos
operativos y los hallazgos de la revisión de veinte ámbitos.

## Desarrollo y comprobaciones

Requiere Go según `go.mod`, Node22, Docker y PostgreSQL16 local de pruebas.
No reutilizar la base legacy ni secretos productivos.

```sh
make build
python3 -m unittest discover -s ops/rebuild/operations -p 'test_*.py'
```

`make ci` exige las variables `NOCTIS_V2_TEST_DATABASE_URL` (base sintética
loopback cuyo nombre contiene `v2_test`) y `NOCTIS_V2_FAULT_DOCKER_IMAGE`
(imagen PostgreSQL16 ya disponible localmente). Ejecuta Go/race sin skips de
integración, frontend compilado y el runner canónico de aceptación con navegador,
producto y gateways IA HTTPS falsos. No realiza inferencia pagada ni Telegram real.
Los recibos de CI se conservan como artefactos. Véase
[operación y validación](ops/rebuild/operations/README.md).

```sh
bin/noctis v2 --help
bin/noctis v2 --database-secret-file /ruta/privada/database migrate
```

La migración es explícita y usa credenciales separadas del runtime. Un proceso
v2 existente valida versión y checksum exactos; no migra al iniciar. API,
worker y collector son modos separados de `v2 serve`. La API necesita archivos
admin/TLS y un Origin canónico; el master key IA queda fuera de PostgreSQL y debe
respaldarse por separado. No pasar DSN, claves ni contraseñas en argumentos.

## Imagen y despliegue

`Dockerfile` compila Node/Go sobre BUILDPLATFORM y cruza Go a TARGETOS/TARGETARCH
con CGO desactivado. La imagen final distroless no root incluye assets locales,
migraciones y prompts, y su comando predeterminado selecciona v2 con archivos de
secretos. Sin esos archivos falla cerrado. No necesita QEMU para construir ARM64.

[deploy/v2/](deploy/v2/README.md) contiene plantillas por digest, réplicas cero
y migración suspendida; no se han aplicado. La configuración de `deploy/`
superior es histórica. No iniciar el runtime legacy; el archivo y sus
herramientas de inspección/importación se conservan para recuperación autorizada.

## Recuperación y límites de aceptación

El [recibo P0](ops/rebuild/recovery/receipt.md) documenta la recuperación del
archivo preservado. La herramienta [backup v2](ops/rebuild/operations/backup.py)
comparte snapshot entre dump/manifest, cifra con age y restaura a un contenedor
nuevo aislado, comparando esquema, migraciones, conteos, digests y consultas.
El runbook incluye pausa y rollback únicamente a binario de esquema exactamente
compatible. Nunca borrar inbox, cursores, jobs, outbox o ledger para recuperar.

Las pruebas sintéticas locales no acreditan piloto Telegram, calidad humana de
una ruta/modelo, capacidad productiva, copia fuera del host ni cutover. Esos gates
requieren sus propios recibos y autorizaciones. El estado operativo medido y las
limitaciones están en [operations/receipt.md](ops/rebuild/operations/receipt.md).
Persisten avisos npm de dependencias del build; no se afirma auditoría sin hallazgos.

Licencia [MIT](LICENSE).
