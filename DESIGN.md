# Noctis: mesa de investigación nocturna

La interfaz privada acompaña sesiones de lectura e investigación en ambientes de poca luz. Recupera el violeta de Noctis con planos oscuros diferenciados y una navegación estable. Su gesto propio es la relación entre observación, síntesis y documento: Hoy distribuye los cambios en una columna amplia y el brief en un plano lateral; una cita abre un lector de evidencia con procedencia y revisión.

## Tokens

| Uso | Valor |
| --- | --- |
| Fondo | `#0A0A0F` |
| Superficie | `#12121A` |
| Plano lateral | `#1A1726` |
| División | `#302A42` |
| Acento | `#A78BFA` |
| Texto | `#E8E5F0` |
| Texto secundario | `#B4AEC6` |
| Error | `#FFB8B1` sobre `#2F1C24` |
| Foco | `#C4B5FD`, 3 px, separación 4 px |

Fira Sans local para lectura y controles. Fira Code local para código y referencias. Escala fija de 12, 13, 14, 15, 18, 21 y 32 px; títulos de peso medio. Párrafos de hasta 75 caracteres. La fecha de actualización se muestra en español y conserva el valor ISO en el elemento `time`.

## Composición y comportamiento

Barra lateral de 220 px; cabecera de 78 px. El botón Salir es el primer control de teclado. A menos de 760 px, la navegación pasa a cinco accesos horizontales y el contenido a una columna. Hoy usa una relación aproximada 2:1; expedientes y fuentes conservan filas de lectura. La evidencia usa un `dialog` lateral con foco contenido, Escape y devolución del foco al invocador.

Sistema ofrece límites globales, conexiones, índice de funciones y editores visibles agrupados por ejecución, versiones y presupuesto. El índice usa las funciones recibidas del servidor. No inventa actividad, recuentos ni credenciales. Las acciones de guardar y validar tienen significados distintos; validar no contacta proveedores.

En móvil, las acciones de configuración se mantienen al pie en dos filas. El desplazamiento reserva espacio para esta barra y conserva visibles los campos al enfocarlos. La demo pública conserva texto de citas y foco violeta oscuro sobre sus superficies claras.

El acento marca selección, foco y acciones. Las divisiones organizan información; los iconos Lucide acompañan la navegación y la procedencia. No hay animaciones de entrada ni nuevos recursos remotos. Los estados de carga, fallo, cobertura degradada y vacío permanecen explícitos.
