# Operación local v2

V2 usa DB independiente cuyo nombre contiene `v2`, sin tablas legacy. Las migraciones
son explícitas, con checksum, lock y transacción por archivo. No ejecuta Telegram ni
inferencia. Esta entrega no acredita G0.

El archivo `--database-secret-file` contiene el DSN, permisos 0600 y montaje separado
para migración/runtime. Crear rol runtime LOGIN sin ownership, CREATEDB, CREATEROLE
ni CREATE sobre schemas; conceder CONNECT, USAGE sobre noctis_v2,
SELECT/INSERT/UPDATE de sus tablas y **solo SELECT** sobre
public.noctis_v2_migrations para verificar compatibilidad. Revocar CREATE público.
No conceder acceso legacy. El arranque no ejecuta DDL.

```sh
noctis v2 migrate --database-secret-file /mounted/migration.secret
noctis v2 policy p1 /mounted/watchlist.json --database-secret-file /mounted/runtime.secret
noctis v2 source rss https://example.org/feed 'Fuente autorizada' p1 --database-secret-file /mounted/runtime.secret
```

Una watchlist es una lista JSON de `{ "type":"cve", "value":"CVE-2026-12345" }`;
tipos: cve/hash/url/domain/email/ip y keyword. Versiones inmutables; sin coincidencia
el gate conserva unknown. No descarta ni declara malicia. Registrar fuente crea epoch
y activación nuevos. RSS conserva identidad GUID/Atom ID/enlace, revisiones por hash y
coverage feed_window_only; no promete recuperar entradas desaparecidas del feed.

```sh
noctis v2 serve --mode collector --database-secret-file /mounted/runtime.secret
noctis v2 serve --mode worker --database-secret-file /mounted/runtime.secret
noctis v2 serve --mode api --database-secret-file /mounted/runtime.secret \
  --admin-secret-file /mounted/admin.json --origin https://noctis.example.org \
  --tls-cert-file /mounted/tls.crt --tls-key-file /mounted/tls.key
```

admin.json contiene username/password (mínimo 16 bytes). API requiere Origin canónico,
cookies Secure/HttpOnly/SameSite Strict, sesiones aleatorias almacenadas como hash,
expiry/revocación y CSRF en logout. Con TLS terminado en proxy confiable pueden omitirse
archivos TLS conservando Origin HTTPS. Secure nunca se desactiva. Sirve frontend
compilado local/rutas profundas; la API privada existe solo bajo /api/v2.

`poll SOURCE_ID`, `capture BATCH_JSON_FILE`, `run-once` permiten operación acotada.
BatchID estable permite replay postcommit preACK; cambiar su contenido o el de una
revisión existente es conflicto. Checkpoint/blob/observaciones/jobs/receipt son atómicos.
`replay JOB_ID` permite solo bloqueados/cuarentena/cancelado; cinco intentos pasan a
cuarentena con código visible. SIGTERM cancela loops y apaga HTTP. Fallo DB detiene el
proceso; fallo fuente registra gap_unknown y continúa otras fuentes.

Worker extrae documento UTF8 completo, crea expedientes factuales para watchlists,
con citas por bytes y revisiones inmutables. Agrupa copia exacta o edición de misma
identidad nativa; PIR compartida no basta. Independencia desconocida; copias no aportan
corroboración ni nuevas entregas.

`brief YYYY-MM-DD POLICY` genera snapshot mecánico citado idempotente por periodo/policy.
Worker genera el día UTC cerrado; el operador decide el instante del snapshot actual.
`dispatch-once ENDPOINT` entrega un evento a un destino administrado explícitamente.
Antes de salir guarda uncertain; solo ACK 2xx pasa delivered. Crash/timeout/ACK perdido
conserva uncertain sin reintento automático. Dispatcher producción deshabilitado por defecto.

Fetch no usa proxy ambiental, valida DNS/IP/redirect y fija IP de conexión. Rechaza
redes especiales/credenciales/onion sin Tor aislado. Tor cerrado, sin fallback directo.
Excepción local administrada con `--fixture-authority HOST:PORT` en collector/poll solo
para fixtures. Límites: 2 MiB comprimido, 8 MiB decodificado, 20 s, cinco redirects.

## Validación sintética

NOCTIS_V2_TEST_DATABASE_URL apunta a PG local sintético con CREATE DATABASE; cada test
crea/borra DB independiente. El harness solo acepta loopback y origen con nombre v2_test.

```sh
go test -race -count=1 ./internal/capture ./internal/jobs ./internal/intelligence ./internal/runtimev2 ./internal/database/v2
go build -o /tmp/noctis-v2 ./cmd/noctis
go run ./ops/rebuild/e2e --binary /tmp/noctis-v2 --browser --keep
```

Runner crea DB, feed/receptor local, TLS autofirmado; usa CLI binario y Playwright real
sin mocks. Detiene API/fixtures al salir. --keep conserva DB y directorio 0700
/tmp/noctis-v2-e2e-* con secrets 0600/log/receipt; sin --keep elimina ambos.
Excepción TLS solo en clientes harness. No acredita producción ni G0/G2/G3 sin recibo
detallado de pruebas y limitaciones.
