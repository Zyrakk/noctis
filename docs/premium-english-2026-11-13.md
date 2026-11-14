# Noctis en inglés y pulido visual — 13 de noviembre de 2026

## Cambios

Se conserva la composición glass de dos paneles, el planeta violeta y la entrada
del dashboard al hacer scroll. La landing, la demo, el login y los controles del
panel están en inglés, incluyendo metadatos, accesibilidad y formatos de fecha.
La captura incrustada del dashboard se regeneró con datos sintéticos en inglés.

Se consultaron seis agentes Astra sobre landing, demo, evidencia, login,
traducción y validación. Sus encargos fueron de análisis; la implementación y
las comprobaciones se integraron por separado.

- Landing: mejor contraste sobre el planeta, tipografía y estados interactivos
  más discretos, sin cambiar la distribución aprobada.
- Demo: tres escenarios con tres revisiones y documentos distintos; cada revisión
  muestra únicamente las fuentes disponibles en ese momento. El lector resalta
  la cita correspondiente, conserva su URL y devuelve el foco al cerrar.
  Navegación, recarga e historial preservan escenario, revisión y vista.
  Los registros se identifican explícitamente como sintéticos. No usa API privada,
  almacenamiento de sesión, recolección real ni inferencia.
- Login: composición editorial violeta, formulario glass, mostrar/ocultar clave,
  errores seguros en inglés y bloqueo inmediato de envíos duplicados. Conserva
  la ruta de destino completa, incluido su fragmento, sin persistir credenciales.
- Panel: traducción de interfaz y nuevos textos descriptivos del sistema. Se
  conservan contratos, estados, claves y desplazamientos UTF-8 de las evidencias.

## Límites

Los documentos originales y los textos históricos guardados conservan su idioma:
no se reescribieron evidencias ni se migraron datos. La demo no acredita capacidades
de modelos activos. Este cambio no activa captura ni IA ni resuelve los pendientes
operativos recogidos en [la revisión completa](review-2026-11-13.md).

## Verificación local

- Suite de interfaz: 40 pruebas correctas, incluyendo móvil, contraste, foco,
  movimiento reducido, navegación de demo y protección del formulario.
- Revisión visual de landing, demo de escritorio/móvil y login realizada.
- Los siete checksums de migraciones y 41 pruebas Python pasan.
- Suite Go con detector de carreras: 96 pruebas obligatorias comprobadas y cero
  omisiones inesperadas.

Los resultados finales de integración, imagen y producción se documentan en el
[recibo de despliegue](deployment-premium-2026-11-13.md).
