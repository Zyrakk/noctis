# Adaptador Responses y preparación de pruebas reales — 2026-10-18

Adaptador explícito `openai-responses` integrado en backend, panel y harness; conserva `openai-chat`. Configura URL literal, modelo y JSON Schema estricto; no cambia de endpoint/modelo ante errores. Las respuestas incompletas, rechazos y usos inválidos se detienen conservando el uso disponible para el ledger. El esquema comunica las restricciones de los validadores existentes, que no se han debilitado.

Campaña de prueba opt-in: máximo acumulado de 5 USD y 20 reservas, bloqueo concurrente y estado durable entre reinicios, sin devolución de reservas ni reintentos automáticos. Los recibos registran también costes superiores al límite. El cálculo local no certifica cargos internos añadidos por un proveedor: la ejecución real requiere confirmar un límite duro restante de la key de como máximo 5 USD.

Verificación ejecutada por Sol: pruebas focalizadas Go con `-race` de inferencia/harness y regresiones PostgreSQL de Chat legacy correctas; build frontend y binario correctos. Panel HTTPS/PG con credencial sintética: cero intentos. Responses HTTPS simulado: 14 consumidores, 10 intentos liquidados, cinco funciones semánticas agrupadas y citas/hash/rangos UTF-8 comprobados. La exposición conservadora del fixture fue 3,15392 USD; no es gasto real. PostgreSQL propio eliminado.

Candidato de estas pruebas: SHA256 `ea86220d3e074ca7b7eb48bf43471f72d592ff6293e19d752afa85d76163c984`. El binario congelado de captura anterior permanece intacto. Astra revisó código y recibos y no encontró bloqueos técnicos adicionales; no repitió las pruebas.

Proveedor real autorizado: `https://api.zrelay.net/v1/responses`, modelo `gpt-6.1-sol`, sin fallback. Configuración prevista de reserva conservadora: 4.500 nanodólares por token de entrada y 10.000 por token de salida. Distingue estimación, exposición y factura del proveedor. La key permanece fuera del repositorio y no se ha leído ni utilizado durante estas verificaciones.

**Pendiente:** confirmación del límite duro restante de la key y ejecución real con una única campaña durable. Cero llamadas al proveedor real y cero gasto hasta este recibo. Los fixtures no acreditan compatibilidad real, GOLD, calidad humana ni cierre de G6/G7/G8. No hubo commits, publicación ni despliegue.
