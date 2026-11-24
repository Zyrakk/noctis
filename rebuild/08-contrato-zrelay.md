# Puerto de inferencia y futura integración Zrelay

La migración/rebuild de Zrelay sigue pendiente. Este documento define lo que Noctis necesita, sin convertir la implementación actual del repositorio vecino en un contrato futuro garantizado. No modifica Zrelay ni requiere desplegarlo para validar el núcleo.

## Frontera

Noctis controla trabajo, evidencias, privacidad, selección de tarea, evaluación y presupuesto de aplicación. El gateway controla su routing y liquidación conforme al contrato que finalmente publique. No compartir base de datos, importar internals de `../zrelay` ni vincular expedientes a detalles de un pool concreto.

Crear un puerto interno `InferenceGateway` con adaptador HTTP configurable y servidor falso para aceptación. Se puede usar una ruta directa autorizada durante el piloto; Zrelay entra cuando su ruta real supere las mismas pruebas.

## Solicitud lógica

```json
{
  "request_id": "stable-logical-id",
  "attempt_id": "attempt-uuid",
  "task": "interpret_observation",
  "task_version": "1",
  "model_policy": "semantic-economy-v1",
  "schema_version": "claims-v1",
  "data_class": "public-approved",
  "max_input_tokens": 8000,
  "max_output_tokens": 1000,
  "deadline_ms": 30000,
  "evidence_ids": ["e1"],
  "budget_reservation_id": "reservation-uuid"
}
```

Es un contrato interno propuesto. No se presupone que Zrelay acepte literalmente estos campos. El adaptador traduce a Chat Completions/Responses y registra qué garantías externas existen realmente. El contenido y JSON Schema viajan en campos de transporte específicos con tamaño acotado; no incluir secretos de Noctis ni credenciales de fuentes.

`request_id` identifica trabajo lógico; `attempt_id` separa intentos y consumo. No asumir idempotencia remota porque exista un header. Un timeout puede corresponder a inferencia facturada; conservar consumo/reserva inciertos.

## Respuesta normalizada

Resultado estructurado validado, finish reason, modelo solicitado y modelo declarado/resuelto si el gateway lo expone, endpoint/ruta/pool cuando estén disponibles, uso entrada/salida/caché/razonamiento, moneda/unidad, tarifa/version, receipt/request ID remoto, latencia y estado de liquidación.

Una propiedad no expuesta se registra `unknown`, sin fingir verificación del upstream. La ejecución solo se considera apta para tareas cuya política permita ese grado de observabilidad. `usage` ausente no equivale a coste cero. No sumar snapshots acumulados de streaming como consumo incremental.

Los adaptadores síncronos Chat y Responses solo admiten HTTP 200. Cualquier estado 201–299 produce `response_status_invalid`, permanente e incierto, sin resultado ni uso aceptados: conserva la exposición máxima y bloquea el trabajo sin reintento automático. Un éxito HTTP sin respuesta admitida no demuestra ausencia de ejecución. Un cuerpo aparentemente válido, `Location` o `Retry-After` no autorizan publicación, sondeo ni reenvío; no hay soporte asíncrono implícito. Se mantienen los límites de cuerpo y tiempo y la incertidumbre ante fallos de lectura.

## Capacidades a comprobar

| Capacidad | Validación requerida |
|---|---|
| Endpoint/modelo y alias | Ruta real disponible y estable; rechazo explícito de alias desconocido. |
| JSON Schema | Schema admitido, enums/límites, rechazo/truncamiento; validación local siempre. |
| Tokenización y límites | Entrada efectiva, salida, reasoning y parámetros aceptados. |
| Privacidad y fallback | Proveedores permitidos, restricciones de datos, persistencia y ruta alternativa. |
| Uso y coste | Unidad de facturación, límites, redondeo, caché y razón de discrepancia. |
| Retry/cancelación | Qué se ejecuta/factura al timeout y qué idempotencia se garantiza. |
| Identidad del modelo | Modelo solicitado frente al declarado; cambio de catálogo invalida evaluación si afecta tarea. |

Errores estables internos: autenticación/configuración, modelo/capacidad no admitidos, rate limit con retry-after, presupuesto/cupo, timeout, respuesta inválida/truncada, rechazo de contenido y fallo upstream. Clasificar transitorio vs permanente; un 400 no merece repetir cinco veces idéntica solicitud.

## Fallback y reconciliación

Fallback solo a una ruta previamente evaluada con esquema, clase de datos y coste compatibles. Registrar la elección y volver a reservar si cambia el máximo. Un brief puede esperar; una alerta factual no necesita IA para informar de un evento estructurado. No degradar a un modelo desconocido silenciosamente.

Comparar coste estimado, uso declarado y receipt del gateway. Diferencias materiales generan excepción de contabilidad, no se ocultan ajustando el contador local. Noctis y Zrelay pueden llevar libros distintos: la correspondencia debe estar documentada por ejecución y unidad monetaria.

## Aceptación sin Zrelay desplegado

Servidor falso con respuesta válida, campos ausentes, JSON incorrecto, timeout tras posible consumo, 429, 401, alias sustituido, output truncado y cancelación. Verificar que captura continúa, claims inválidos no se publican, no se duplica entrega y reservas sobreviven a reinicio. La prueba de ruta real requiere después cuenta/endpoint/catálogo concretos y una autorización de gasto; no se ha realizado en esta tarea.
