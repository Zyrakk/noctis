# Inferencia v2: operación explícita

El modo `worker` ejecuta trabajos IA durables; `api` sólo autoriza y encola.
Sin binding habilitado, credencial válida, clase de datos compatible y reserva
disponible no sale contenido. Guardar y validar configuración no contacta proveedores.

Montar fuera de PostgreSQL un archivo privado 0600 con JSON
`{"key_id":"identificador-estable","key":"<64 caracteres hexadecimales aleatorios>"}`.
Seleccionarlo con `serve --ai-master-key-file PATH` tanto en API como en worker.
Custodiar una copia protegida separada del backup PG y registrar su `key_id`;
sin esa versión de clave las credenciales cifradas no son recuperables. Una clave
incorrecta bloquea el descifrado. No sustituir la clave montada como método de
rotación: restaurar primero la versión que cifra las revisiones y crear revisiones
con el procedimiento de rotación que se implemente y verifique explícitamente.

Las conexiones aceptan el endpoint HTTPS completo de Chat Completions compatible.
No existen redirects, proxy ambiental, fallback o privilegios implícitos. Las
excepciones locales usan exclusivamente `--ai-local-authority IP:puerto` montado
por el servidor; el panel no concede excepciones. `--ai-ca-file PATH` añade una
raíz TLS administrada sin desactivar la verificación de certificado/hostname.

Las tarifas son configuradas y versionadas en nanodólares USD por token, con caps
diarios/mensuales UTC y concurrencia. No representan tarifas actuales verificadas.
Cada llamada reserva su máximo; varias funciones semánticas compatibles comparten
una llamada y exposición global, con atribución conservadora a cada función.
Un timeout, SIGKILL o respuesta sin usage conserva exposición incierta; no hay
reintento automático de una ejecución potencialmente facturada. Una nueva petición
requiere nueva reserva. El coste conocido se liquida aunque se cancele el trabajo
o se pierda el fence. No se asume idempotencia del proveedor.

GET/PUT `/api/v2/ai/config` usa ETag/If-Match y 412 para conflictos. API keys son
write-only (`unchanged`, `set`, `clear`); las lecturas sólo exponen secret_present.
POST `/api/v2/ai/jobs` devuelve 202/Location; el consumidor consulta estado y puede
cancelarlo. `/api/v2/query` ejecuta QueryPlan v1 parametrizado sin IA. Productos
históricos conservan dependencias; las lecturas detectan cambios y exigen revalidación.

Validación local sin gasto: ejecutar tests `TestAI*` con PostgreSQL sintético y
`go run ./ops/rebuild/e2e --binary BINARIO_COMPILADO --ai`. Este runner levanta
gateways HTTPS falsos y reinicia realmente la API; cierra sus procesos y DB al salir.
`tools/eval` sólo aporta tooling/corpus sintético y CP exacto. Calidad representativa,
promociones humanas, ruta pagada real y piloto autorizado siguen pendientes.
