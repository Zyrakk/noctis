# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Operador único autorizado que investiga amenazas en privado, de forma recurrente. Su trabajo: seguir vulnerabilidades, ransomware y filtraciones, organizar expedientes y volver al texto que sustenta cada afirmación. La landing pública es una superficie aparte, separada del acceso privado (`/v2/login`).

## Product Purpose

Noctis es un observatorio privado de inteligencia sobre amenazas. Reúne fuentes de Telegram y otras fuentes de ciberinteligencia para investigar, organizar expedientes y verificar evidencia. Éxito: el operador llega de cualquier afirmación al texto original que la respalda.

## Positioning

Evidencia verificable y trazable: cada afirmación se identifica por observación, revisión, representación, hash y rango, y el lector distingue original, derivados, retención y revisiones sustituidas. La IA es opcional y nunca confirma por sí sola un incidente, atribución o exposición local.

## Operating Context

Experiencia principal (interfaz en inglés): Today, Case files, Explore, Sources y System. Los datos privados proceden de la API; las demostraciones públicas y las pruebas usan datos sintéticos explícitos. Backend Go y PostgreSQL 16; frontend React compilado e incluido en el binario. La landing pública vive en `web/index.html`.

## Capabilities and Constraints

- Una pantalla vacía no significa ausencia global de amenazas: el producto declara cobertura y degradación.
- La IA es opcional y se configura por 14 funciones: clasificación, relevancia, afirmaciones, entidades y relaciones, roles de observables, desambiguación, contexto de vulnerabilidades, análisis y síntesis de expedientes, brief, planificación y explicación de consultas, traducción de evidencia y evaluación de fuentes. Cada una tiene conexión, modelo, versiones, presupuesto, límites y tarifa propios. No hay fallback implícito. Búsqueda y lectura no requieren inferencia.
- Conexiones y secretos se administran en System; las credenciales se retiran del formulario tras guardar.
- Importar una identidad no autoriza captura: políticas, permisos y activación son explícitos.

## Evidence on Hand

Solo demos sintéticas y la captura sintética del panel. No existen clientes, testimonios, benchmarks ni precios: futuras superficies no deben fabricarlos.

## Product Principles

1. La evidencia primero: toda afirmación enlaza a su texto original.
2. Declarar cobertura y degradación; vacío no es ausencia de amenaza.
3. La IA es opcional, explícita por función y nunca confirma por sí sola.
4. Lo privado permanece privado; lo público usa datos sintéticos.
