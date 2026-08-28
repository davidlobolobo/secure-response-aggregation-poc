# Cifrado extremo a extremo para agregación segura entre microservicios

Prueba de concepto (PoC) de una arquitectura de cifrado extremo a extremo para que un servicio intermediario/agregador pueda enrutar y agrupar respuestas de varios microservicios **sin poder leer su contenido**.

- **[secure-demo/](./secure-demo)** — PoC funcional en Java 21 que implementa el protocolo con HPKE real (RFC 9180, vía Bouncy Castle) y demuestra las propiedades de seguridad del diseño.

## Idea central

> Cada petición genera una clave pública temporal (X25519). Los servicios destino cifran sus respuestas con esa clave pública; únicamente el servicio que originó la petición conserva la clave privada para descifrarlas. El intermediario transporta y agrega ciphertext, pero nunca puede leerlo.

## Protocolo

- X25519 para el intercambio/encapsulación de claves.
- HKDF-SHA256 para la derivación de claves.
- AES-256-GCM para el cifrado autenticado del contenido.
- HPKE (RFC 9180) como envoltura estándar de los tres puntos anteriores.
- Claves efímeras por petición; la clave privada nunca sale del servicio que originó la petición.

## Alcance

La arquitectura es agnóstica de la plataforma de implementación. Java 21 se usa aquí como plataforma de referencia para el PoC y la validación del concepto; una implementación en otra plataforma queda fuera del alcance de este repositorio por ahora.

## Estado

Prueba de concepto — no apto para producción tal cual. Ver el checklist de producción en [`secure-demo/README.md`](./secure-demo/README.md#qué-falta-para-producción) (TLS 1.3/mTLS, firma de la metadata de la petición, anti-replay, pruebas de carga).

## Licencia

[MIT](./LICENSE)
