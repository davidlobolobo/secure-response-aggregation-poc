# secure-demo

Prueba de concepto en Java 21 de un protocolo de cifrado extremo a extremo para agregación segura de respuestas entre microservicios: un intermediario hace fan-out y agrega respuestas cifradas sin poder leer su contenido.

Simula, en un solo proceso, el flujo completo:

1. `service-a` (requester) genera un par de claves X25519 efímero. La clave privada nunca sale de su memoria.
2. Un `AggregatorService` recibe solo la clave pública y hace fan-out en paralelo (Virtual Threads) hacia cuatro `ResponderService` (`service-b`, `service-c`, `service-d`, `service-e`).
3. Cada responder cifra su JSON con **HPKE real (RFC 9180)** usando esa clave pública — vía Bouncy Castle, suite `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM`.
4. El aggregator agrega los cuatro envelopes cifrados **sin poder descifrarlos** (nunca recibe ni retiene una clave privada).
5. `service-a` descifra las cuatro respuestas.
6. Se ejecutan tres pruebas negativas: ciphertext manipulado, `requestId` sustituido (falla la verificación del AAD), e intento de descifrado con una clave equivocada (simulando al propio aggregator).

## Requisitos

- Java 21
- Maven 3.9+

## Compilar y ejecutar

```bash
mvn compile exec:java
```

o generar el jar y ejecutarlo manualmente:

```bash
mvn package
java -cp target/classes:$(find ~/.m2 -name 'bcprov-jdk18on-*.jar' -o -name 'jackson-*.jar' | tr '\n' ':') com.example.secure.Demo
```

## Salida esperada

```
=== Fase 1: peticion original ===
[requester] requestId=... -- publicKey generada, privateKey solo en memoria local
[aggregator] requestId=... -- reenviando publicKey a 4 responders (sin retener clave privada)
[service-b] JSON original: {"customerId":12567,"status":"ACTIVE","balance":15234.22}
...
[aggregator] requestId=... src=service-b ciphertext(hex, primeros 16 bytes)=... -- NO puede descifrar

=== Fase 2: requester descifra ===
[requester] decrypted from service-b: {"customerId":12567,"status":"ACTIVE","balance":15234.22}
...

=== Prueba negativa 1: manipulacion de ciphertext ===
[OK] descifrado rechazado como se esperaba: InvalidCipherTextException

=== Prueba negativa 2: sustitucion de requestId via AAD ===
[OK] respuesta no trasladable a otro requestId: InvalidCipherTextException

=== Prueba negativa 3: intento de descifrado del aggregator ===
[OK] aggregator no puede descifrar: InvalidCipherTextException
```

## Estructura

| Clase | Rol |
|---|---|
| `CryptoUtils` | Generación y (de)codificación de claves X25519 (API lightweight de Bouncy Castle) |
| `HpkeCodec` | Wrapper de `org.bouncycastle.crypto.hpke.HPKE` para la suite fija del protocolo |
| `AadCodec` | Construye el AAD (`requestId\|src\|dst\|ts\|schema_version`) que liga cada respuesta a su petición |
| `RequestContext` | Estado efímero del requester (incluida la clave privada) |
| `EncryptedEnvelope` | Formato del envelope que cruza el aggregator |
| `ResponderService` | Simula un servicio downstream que cifra su respuesta |
| `AggregatorService` | Simula el intermediario: fan-out y agregación, sin acceso a ninguna clave privada |
| `Demo` | Orquesta el flujo completo y las pruebas negativas |

## Nota importante sobre la API de Bouncy Castle

`HPKEContext.seal` / `.open` reciben los argumentos como **`(aad, data)`**, no `(data, aad)` — es fácil equivocarse porque no coincide con el orden habitual de otras APIs AEAD de Java. Si el orden se invierte, el AAD termina cifrado como si fuera el plaintext y el descifrado falla con `InvalidCipherTextException` ("data too short" o "mac check failed" según el tamaño). Verificado contra el bytecode real de `bcprov-jdk18on` 1.79 y 1.85.2.

## Qué falta para producción

Este PoC valida el mecanismo criptográfico central, pero **no es apto para producción tal cual**. Antes de llevarlo a un entorno real:

- TLS 1.3 / mTLS en el transporte real (aquí todo corre en un solo proceso, sin red).
- Firma (Ed25519) de la metadata de la petición, para que el aggregator no pueda sustituir la clave pública del requester.
- Anti-replay real: rechazo de `request_id` duplicados, ventana de expiración, nonces.
- Servicios como procesos/contenedores independientes comunicándose por HTTP/2, no llamadas en memoria.
- Pruebas de carga (1k/5k/10k RPS) y medición de p95/p99, CPU y GC.
