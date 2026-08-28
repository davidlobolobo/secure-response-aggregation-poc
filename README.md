# Cifrado extremo a extremo para agregación segura entre microservicios

Propuesta de arquitectura y prueba de concepto (PoC) para que un servicio intermediario/agregador pueda enrutar y agrupar respuestas de varios microservicios **sin poder leer su contenido**.

- **[propuesta_cifrado_extremo_a_extremo_java21.md](./propuesta_cifrado_extremo_a_extremo_java21.md)** — el documento de diseño completo: modelo de confianza, protocolo criptográfico (X25519 + HKDF-SHA256 + AES-256-GCM vía HPKE / RFC 9180), estimaciones de capacidad, y el plan de pruebas.
- **[secure-demo/](./secure-demo)** — PoC funcional en Java 21 que implementa el protocolo con HPKE real (Bouncy Castle) y demuestra las propiedades de seguridad del diseño.

## Alcance

La arquitectura descrita es agnóstica de la plataforma de implementación (ver la sección "Alcance de esta fase" del documento). Java 21 se usa aquí como plataforma de referencia para el PoC y la validación del concepto; una implementación en otra plataforma queda fuera del alcance de este repositorio por ahora.

## Idea central

> Cada petición genera una clave pública temporal (X25519). Los servicios destino cifran sus respuestas con esa clave pública; únicamente el servicio que originó la petición conserva la clave privada para descifrarlas. El intermediario transporta y agrega ciphertext, pero nunca puede leerlo.

## Estado

Prueba de concepto. Antes de llevar esto a producción, ver la sección "Recomendación final" y "Próximos pasos recomendados" del documento de diseño (TLS 1.3/mTLS, firma de la metadata de la petición, anti-replay, pruebas de carga).

## Licencia

[MIT](./LICENSE)
