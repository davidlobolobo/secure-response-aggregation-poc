# Propuesta de cifrado extremo a extremo para agregación segura de respuestas entre microservicios

## 1. Introducción

El objetivo de esta propuesta es proteger la información intercambiada entre un conjunto de servicios que operan a través de un servicio intermediario o agregador.

El flujo funcional es el siguiente:

1. Un servicio origen realiza una petición al intermediario.
2. El intermediario replica la petición hacia otros cuatro servicios.
3. Cada servicio procesa su información y genera una respuesta en formato JSON.
4. Cada respuesta es devuelta al intermediario.
5. El intermediario agrega las respuestas.
6. El intermediario entrega el resultado al servicio que originó la petición.

El requisito principal es que **el intermediario pueda transportar y agrupar las respuestas, pero no pueda conocer su contenido**.

La solución propuesta implementa **cifrado extremo a extremo por petición**, utilizando criptografía moderna, eficiente y adecuada para miles de solicitudes concurrentes.

La propuesta base es:

- TLS 1.3 / mTLS para proteger y autenticar las conexiones.
- HPKE como mecanismo de cifrado de mensajes.
- X25519 para intercambio/encapsulación de claves.
- HKDF-SHA256 para derivación de claves.
- AES-256-GCM para cifrado autenticado del contenido.
- Claves efímeras por petición.
- AAD para ligar cada respuesta con su contexto.
- Identidad criptográfica por servicio cuando sea necesario.
- Java 21 como plataforma de implementación.

## Alcance de esta fase

La arquitectura descrita es agnóstica de la plataforma de implementación: se basa en primitivas y protocolos estándar (X25519, HKDF-SHA256, AES-256-GCM, HPKE RFC 9180, TLS 1.3/mTLS), no en características propias de un lenguaje.

Java 21 se utiliza en este documento como **plataforma de referencia para el prototipo (PoC) y la validación del concepto**. Los mismos principios podrían implementarse en cualquier otra plataforma con soporte criptográfico adecuado; esa decisión queda fuera del alcance de este documento y se evaluará en una fase posterior.

---

# 2. Explicación de alto nivel

## 2.1 Idea central

El principio fundamental es sencillo:

> Cada petición genera una clave pública temporal que puede ser utilizada por los servicios destino para cifrar sus respuestas, pero únicamente el servicio que inició la petición conserva la clave privada necesaria para descifrarlas.

El intermediario nunca recibe esa clave privada.

Por lo tanto, aunque vea todas las respuestas, únicamente observa bloques cifrados.

## 2.2 Quién conoce qué claves

Supongamos que el Servicio A inicia una petición.

El Servicio A genera un par de claves efímeras:

```text
PrivateKey_A_Request_123
PublicKey_A_Request_123
```

La clave privada:

```text
PrivateKey_A_Request_123
```

permanece exclusivamente dentro del Servicio A.

La clave pública:

```text
PublicKey_A_Request_123
```

puede viajar a través del intermediario y llegar a los Servicios B, C, D y E.

Los servicios B, C, D y E utilizan esta clave pública para cifrar sus respuestas.

El intermediario solamente observa:

```text
Ciphertext_B
Ciphertext_C
Ciphertext_D
Ciphertext_E
```

pero no posee la clave privada necesaria para descifrarlos.

## 2.3 Qué conoce el intermediario

El intermediario puede conocer información operativa mínima:

- identificador de la petición;
- servicio origen;
- servicio que respondió;
- estado HTTP;
- tiempo de respuesta;
- tamaño de la respuesta;
- timeout;
- error de transporte.

Sin embargo, no conoce:

- contenido del JSON;
- campos de negocio;
- valores sensibles;
- datos personales;
- información financiera;
- tokens incluidos dentro del payload;
- resultados procesados por los servicios.

## 2.4 Beneficio de seguridad

Incluso si el intermediario es comprometido, el atacante no obtiene automáticamente acceso al contenido de las respuestas.

Esto reduce considerablemente la superficie de exposición.

La arquitectura transforma al intermediario en un componente de transporte y agregación, no en un punto de confianza criptográfica.

---

# 3. Diagrama general

```text
                         ┌─────────────────┐
                         │   Servicio A    │
                         │   Requester     │
                         └────────┬────────┘
                                  │
                         genera clave X25519
                             efímera
                                  │
                    PublicKey(request-123)
                                  │
                                  ▼
                         ┌────────────────┐
                         │ Intermediario  │
                         │ / Aggregator   │
                         │                │
                         │ NO posee la    │
                         │ clave privada  │
                         └───────┬────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
                 ▼               ▼               ▼
            Servicio B      Servicio C      Servicio D      Servicio E
                 │               │               │               │
                 │ JSON          │ JSON          │ JSON          │ JSON
                 ▼               ▼               ▼               ▼
             HPKE encrypt    HPKE encrypt    HPKE encrypt    HPKE encrypt
                 │               │               │               │
                 └───────────────┴───────┬───────┴───────────────┘
                                         │
                                  respuestas cifradas
                                         │
                                         ▼
                                ┌─────────────────┐
                                │ Intermediario   │
                                │ agrega blobs    │
                                │ sin descifrar   │
                                └────────┬────────┘
                                         │
                                         ▼
                                    Servicio A
                                         │
                           PrivateKey(request-123)
                                         │
                                 descifra B/C/D/E
```

---

# 4. Modelo de confianza

## 4.1 Componentes confiables

Cada servicio protege:

- sus claves privadas permanentes de identidad;
- sus claves privadas efímeras;
- su memoria de proceso;
- su keystore o secreto de Kubernetes;
- sus credenciales mTLS.

## 4.2 Componente no confiable para confidencialidad

El intermediario se considera confiable para:

- enrutamiento;
- disponibilidad;
- correlación;
- agregación;
- control de errores.

Pero **no necesita ser confiable para confidencialidad**.

Esto es una característica importante de la propuesta.

## 4.3 Principio criptográfico

```text
La clave pública puede ser distribuida.

La clave privada no se distribuye.

Los servicios destino cifran con la clave pública.

Únicamente el requester descifra con la clave privada.
```

---

# 5. Protocolos y algoritmos recomendados

## 5.1 Transporte

### TLS 1.3

TLS protege la comunicación en tránsito.

### mTLS

Mutual TLS permite que ambos extremos autentiquen la identidad del otro.

Ejemplo:

```text
Servicio A
    │
    │ TLS 1.3 + mTLS
    ▼
Intermediario
    │
    │ TLS 1.3 + mTLS
    ▼
Servicio B
```

mTLS no sustituye el cifrado extremo a extremo.

El intermediario podría leer el contenido si solamente existiera TLS.

Por eso se agrega HPKE.

---

## 5.2 Cifrado de mensajes

La suite recomendada es:

```text
HPKE
DHKEM(X25519, HKDF-SHA256)
HKDF-SHA256
AES-256-GCM
```

### X25519

Se utiliza para establecer o encapsular material criptográfico de forma eficiente mediante curvas elípticas modernas.

Ventajas:

- claves pequeñas;
- excelente rendimiento;
- ampliamente soportado;
- adecuado para alto volumen.

### HKDF-SHA256

Se utiliza para derivar claves criptográficas independientes a partir del secreto obtenido mediante X25519.

### AES-256-GCM

Se utiliza para cifrar el JSON.

Proporciona:

- confidencialidad;
- integridad;
- autenticación del ciphertext;
- excelente rendimiento en hardware moderno.

## Nota sobre disponibilidad de HPKE en Java

El JDK no incluye una implementación nativa de HPKE (RFC 9180) en su JCE estándar. `KeyPairGenerator.getInstance("X25519")` y `Cipher.getInstance("AES/GCM/NoPadding")` sí están disponibles nativamente, pero HPKE como protocolo completo (encapsulación, binding de `info`, modos base/auth/psk) requiere una librería adicional.

La opción recomendada es **Bouncy Castle** (`org.bouncycastle.crypto.hpke.HPKE`, artefacto `bcprov-jdk18on` ≥1.77), que implementa RFC 9180 completo para la suite `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM` mediante los métodos `seal(pkR, info, aad, pt)` / `open(enc, skR, info, aad, ct)`. Ver sección 44.1 para el ejemplo de uso.

---

# 6. Por qué no cifrar directamente con RSA

No se recomienda cifrar directamente grandes JSON utilizando RSA.

La criptografía asimétrica debe utilizarse para proteger o derivar una clave simétrica.

La arquitectura correcta es híbrida:

```text
X25519
   │
   ▼
Shared Secret
   │
   ▼
HKDF
   │
   ▼
AES Key
   │
   ▼
AES-GCM(JSON)
```

AES realiza el cifrado del contenido porque es mucho más eficiente.

---

# 7. Flujo criptográfico detallado

## 7.1 Paso 1: generación de petición

Servicio A genera:

```text
request_id

X25519:
    private_key_A
    public_key_A
```

La clave privada permanece en memoria de A.

La clave pública viaja en la petición.

Ejemplo conceptual:

```json
{
  "request_id": "f729f500-02f1-4cb1-8956-2bb97ce1a7ce",
  "requester": "service-a",
  "timestamp": 1787630000,
  "expires": 1787630060,
  "response_public_key": "<x25519-public-key>"
}
```

---

## 7.2 Paso 2: propagación

El intermediario recibe:

```text
request_id
public_key_A
```

y realiza el fan-out:

```text
             ┌──> B
             │
A -> AGG ----├──> C
             │
             ├──> D
             │
             └──> E
```

---

## 7.3 Paso 3: cifrado de respuesta

Supongamos que Servicio B genera:

```json
{
  "customerId": 12567,
  "status": "ACTIVE",
  "balance": 15234.22
}
```

B utiliza la clave pública de A.

Conceptualmente:

```text
public_key_A
      │
      │ X25519 / HPKE
      ▼
shared secret
      │
      ▼
HKDF-SHA256
      │
      ▼
AES-256 key
      │
      ▼
AES-GCM(JSON)
      │
      ▼
ciphertext
```

B devuelve un envelope:

```json
{
  "rid": "f729f500-02f1-4cb1-8956-2bb97ce1a7ce",
  "src": "service-b",
  "enc": "<hpke-encapsulation>",
  "ct": "<ciphertext>"
}
```

---

# 8. AAD

AES-GCM permite asociar información adicional autenticada sin cifrarla.

Se recomienda utilizar como AAD:

```text
request_id
source_service
destination_service
timestamp
schema_version
```

Ejemplo:

```text
AAD =
requestId |
service-b |
service-a |
timestamp |
v1
```

Esto evita ataques de sustitución.

Por ejemplo, un atacante no podría tomar:

```text
respuesta de request-123
```

y presentarla como:

```text
respuesta de request-999
```

porque la verificación del tag GCM fallaría.

---

# 9. Anti-replay

Cada petición debe contener:

```text
request_id
timestamp
expires
nonce
```

Los servicios deberán rechazar:

- peticiones expiradas;
- request_id duplicados;
- nonces reutilizados;
- timestamps fuera de ventana.

Ejemplo de ventana:

```text
TTL = 30-60 segundos
```

según las necesidades operativas.

---

# 10. Autenticación de la clave pública del requester

Un aspecto crítico es impedir que el intermediario reemplace la clave pública.

Ataque hipotético:

```text
A envía:
PublicKey_A

Intermediario sustituye:
PublicKey_Attacker

B cifra para PublicKey_Attacker
```

Para evitarlo, la información de petición puede estar firmada por A.

Ejemplo:

```text
request_id
requester
response_public_key
timestamp
expires
nonce
```

Firma recomendada:

```text
Ed25519
```

Los demás servicios conocen previamente la clave pública de identidad de A.

---

# 11. Firma por mensaje: opción de seguridad

Existen dos niveles posibles.

## Nivel 1 — recomendado para alto throughput

```text
mTLS
+
HPKE
+
AES-GCM
+
AAD
```

Ventajas:

- máxima eficiencia;
- identidad fuerte de transporte;
- confidencialidad extremo a extremo;
- integridad de ciphertext.

## Nivel 2 — auditoría criptográfica

Agregar:

```text
Ed25519 signature
```

a cada respuesta.

Esto permite demostrar criptográficamente qué servicio generó cada ciphertext.

Sin embargo, aumenta el número de firmas/verificaciones.

Para sistemas de miles de RPS debe evaluarse si este requisito es realmente necesario.

---

# 12. Envelope agregado

El intermediario puede devolver:

```json
{
  "rid": "f729f500-02f1-4cb1-8956-2bb97ce1a7ce",
  "responses": [
    {
      "src": "service-b",
      "enc": "<...>",
      "ct": "<...>"
    },
    {
      "src": "service-c",
      "enc": "<...>",
      "ct": "<...>"
    },
    {
      "src": "service-d",
      "enc": "<...>",
      "ct": "<...>"
    },
    {
      "src": "service-e",
      "enc": "<...>",
      "ct": "<...>"
    }
  ]
}
```

El intermediario puede agregar estas estructuras sin conocer su contenido.

---

# 13. Diagrama detallado del ciclo de una petición

```text
┌───────────────┐
│  SERVICE A    │
└───────┬───────┘
        │
        │ generate X25519 ephemeral keypair
        │
        ├──── privateKey_A   [LOCAL ONLY]
        │
        └──── publicKey_A
                 │
                 ▼
        signed request metadata
                 │
                 ▼
┌──────────────────────────────┐
│         AGGREGATOR           │
│                              │
│ request_id                   │
│ publicKey_A                  │
│ ciphertext only on response  │
└─────────────┬────────────────┘
              │
     ┌────────┼────────┬────────┐
     │        │        │        │
     ▼        ▼        ▼        ▼
    B        C        D        E
     │        │        │        │
     │ produce application JSON│
     │        │        │        │
     ▼        ▼        ▼        ▼
   HPKE     HPKE     HPKE     HPKE
     │        │        │        │
     ▼        ▼        ▼        ▼
 CipherB  CipherC  CipherD  CipherE
     │        │        │        │
     └────────┴────┬───┴────────┘
                   │
                   ▼
             AGGREGATOR
                   │
        assemble ciphertexts
                   │
                   ▼
              SERVICE A
                   │
       privateKey_A + HPKE
                   │
          decrypt in parallel
                   │
                   ▼
       JSON B + C + D + E
```

---

# 14. Implementación recomendada en Java 21

## 14.1 Stack

```text
Java 21
Spring Boot 3.x
TLS 1.3
mTLS
HTTP/2
Virtual Threads
HPKE
X25519
HKDF-SHA256
AES-256-GCM
Jackson
```

---

# 15. APIs criptográficas disponibles en Java 21

Java 21 proporciona las primitives necesarias mediante JCA/JCE.

Ejemplos:

```java
KeyPairGenerator keyPairGenerator =
    KeyPairGenerator.getInstance("X25519");
```

```java
KeyAgreement keyAgreement =
    KeyAgreement.getInstance("X25519");
```

```java
Cipher cipher =
    Cipher.getInstance("AES/GCM/NoPadding");
```

---

# 16. Generación de clave X25519

Ejemplo conceptual:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");

KeyPair keyPair = kpg.generateKeyPair();

PrivateKey privateKey = keyPair.getPrivate();
PublicKey publicKey = keyPair.getPublic();
```

La clave privada debe mantenerse únicamente durante la vida de la petición.

Ejemplo:

```text
requestId -> PrivateKey
```

Al finalizar:

```text
remove(requestId)
```

---

# 17. AES-256-GCM

Ejemplo conceptual:

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

GCMParameterSpec gcmSpec =
    new GCMParameterSpec(128, iv);

SecretKey key =
    new SecretKeySpec(aesKeyBytes, "AES");

cipher.init(
    Cipher.ENCRYPT_MODE,
    key,
    gcmSpec
);

cipher.updateAAD(aadBytes);

byte[] ciphertext =
    cipher.doFinal(jsonBytes);
```

Importante:

```text
NUNCA reutilizar la misma combinación:

AES key + IV
```

---

# 18. Procesamiento binario

Para alto throughput se recomienda evitar conversiones innecesarias.

No recomendado:

```text
Object
 -> JSON String
 -> byte[]
 -> AES
 -> Base64
 -> String
 -> JSON wrapper
 -> byte[]
```

Preferible:

```text
Object
 -> Jackson
 -> byte[]
 -> AES-GCM
 -> byte[]
 -> HTTP
```

---

# 19. Base64

Base64 incrementa el tamaño aproximadamente 33%.

Ejemplo:

```text
10 KB ciphertext
```

puede convertirse aproximadamente en:

```text
13.3 KB Base64
```

Para alto volumen se recomienda evaluar:

```text
application/octet-stream
```

o formatos binarios como:

```text
CBOR
Protocol Buffers
```

si la interoperabilidad lo permite.

---

# 20. Intermediario con Java 21

El intermediario realiza un patrón de fan-out.

```text
request
   │
   ├──> Service B
   ├──> Service C
   ├──> Service D
   └──> Service E
```

Las cuatro peticiones deben ejecutarse en paralelo.

---

# 21. Virtual Threads

Java 21 permite utilizar Virtual Threads para manejar grandes cantidades de I/O concurrente.

Ejemplo:

```java
try (var executor =
         Executors.newVirtualThreadPerTaskExecutor()) {

    Future<Response> b =
        executor.submit(() -> callServiceB());

    Future<Response> c =
        executor.submit(() -> callServiceC());

    Future<Response> d =
        executor.submit(() -> callServiceD());

    Future<Response> e =
        executor.submit(() -> callServiceE());

    // aggregate results
}
```

Este enfoque simplifica la programación concurrente frente a arquitecturas reactivas cuando el caso principal es I/O bloqueante.

---

# 22. HTTP

Recomendaciones:

```text
HTTP/2
persistent connections
keep-alive
connection pooling
TLS session reuse
```

Debe evitarse abrir una nueva conexión TCP/TLS por cada petición.

---

# 23. Protección operativa

El agregador debe incorporar:

```text
timeouts
circuit breakers
bulkheads
connection limits
backpressure
rate limiting
```

Ejemplo:

```text
10,000 RPS
x
30 second timeout
```

podría generar cientos de miles de operaciones pendientes si un servicio downstream queda bloqueado.

---

# 24. Estimación de capacidad

## Supuestos

Se utilizarán los siguientes valores:

```text
4 servicios downstream

10 KB JSON promedio por servicio

1,000 / 5,000 / 10,000
requests originales por segundo
```

---

# 25. Operaciones por petición

Por cada request original:

| Operación | Cantidad |
|---|---:|
| Clave X25519 requester | 1 |
| HPKE encrypt | 4 |
| HPKE decrypt | 4 |
| AES-GCM encrypt | 4 |
| AES-GCM decrypt | 4 |
| HKDF | 8 |
| Respuestas cifradas | 4 |

---

# 26. Operaciones por segundo

| RPS originales | Downstream calls/s | Encryptions/s | Decryptions/s |
|---:|---:|---:|---:|
| 1,000 | 4,000 | 4,000 | 4,000 |
| 5,000 | 20,000 | 20,000 | 20,000 |
| 10,000 | 40,000 | 40,000 | 40,000 |

Por lo tanto:

```text
10,000 requests/s originales

≈ 40,000 llamadas downstream/s

≈ 40,000 cifrados/s

≈ 40,000 descifrados/s
```

---

# 27. Ancho de banda

Con respuestas promedio de:

```text
10 KB
```

cada petición produce:

```text
4 x 10 KB
=
40 KB
```

El tráfico ocurre:

```text
services -> aggregator
+
aggregator -> requester
```

aproximadamente:

```text
80 KB por request
```

---

# 28. Ancho de banda estimado

| RPS | Payload aproximado | Red aproximada |
|---:|---:|---:|
| 1,000 | ~82 MB/s | ~0.66 Gbps |
| 5,000 | ~410 MB/s | ~3.3 Gbps |
| 10,000 | ~819 MB/s | ~6.6 Gbps |

Estos valores no incluyen completamente:

- headers;
- framing HTTP;
- TLS;
- metadatos;
- observabilidad;
- retransmisiones;
- sidecars;
- overhead Kubernetes.

Para 10,000 RPS sostenidos podría ser razonable diseñar para:

```text
7-8+ Gbps
```

dependiendo de la arquitectura.

---

# 29. Impacto del tamaño del JSON

| JSON por servicio | 1k RPS | 5k RPS | 10k RPS |
|---:|---:|---:|---:|
| 2 KB | 0.13 Gbps | 0.66 Gbps | 1.31 Gbps |
| 10 KB | 0.66 Gbps | 3.28 Gbps | 6.55 Gbps |
| 50 KB | 3.28 Gbps | 16.4 Gbps | 32.8 Gbps |

Por tanto, el tamaño medio y p95 del JSON son parámetros críticos.

---

# 30. Costo de AES-GCM

AES-GCM es muy eficiente en CPUs modernas con aceleración criptográfica.

Con:

```text
10 KB x 4 respuestas
```

cada petición procesa aproximadamente:

```text
40 KB cifrado
+
40 KB descifrado
=
80 KB
```

A:

```text
10,000 RPS
```

son aproximadamente:

```text
800 MB/s
```

de datos procesados por AES, distribuidos entre los servicios.

Esto normalmente no será el principal cuello de botella.

---

# 31. CPU criptográfica estimada

Para planeación inicial puede utilizarse un rango conservador agregado de:

```text
0.5 - 1.0 ms CPU
por request original
```

considerando principalmente:

```text
X25519
HKDF
AES-GCM
HPKE overhead
```

Resultado aproximado:

| RPS | CPU agregado crypto |
|---:|---:|
| 1,000 | 0.5-1 core |
| 5,000 | 2.5-5 cores |
| 10,000 | 5-10 cores |

Estos valores deben validarse con benchmarks sobre el hardware real.

---

# 32. Firmas Ed25519 y throughput

Si se firma cada request y cada respuesta:

Por petición original:

```text
5 firmas
8 verificaciones
```

A 10,000 RPS:

```text
50,000 firmas/s
80,000 verificaciones/s
```

Esto puede convertirse en un consumo apreciable de CPU.

Por ello se recomienda distinguir:

## Perfil de máximo throughput

```text
mTLS
+
HPKE
+
AES-GCM
+
AAD
```

## Perfil de máxima auditabilidad

```text
mTLS
+
HPKE
+
AES-GCM
+
AAD
+
Ed25519 por mensaje
```

---

# 33. Cuello de botella probable

El orden probable de impacto es:

1. tamaño de JSON;
2. fan-out 4x;
3. ancho de banda del agregador;
4. connection pooling;
5. copias de memoria;
6. serialización JSON;
7. latencia de downstreams;
8. X25519 / HPKE;
9. AES-GCM.

---

# 34. Escalamiento del agregador

Para:

```text
10,000 incoming RPS
```

el agregador puede generar:

```text
40,000 downstream RPS
```

además de recibir otras:

```text
40,000 responses/s
```

y devolver:

```text
10,000 aggregate responses/s
```

Por ello debe escalar horizontalmente.

Ejemplo:

```text
               Load Balancer
                    │
                    ▼
            ┌───────────────┐
            │ Aggregator x N│
            └───────┬───────┘
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    Service B    Service C    Service D    Service E
      x N          x N          x N          x N
```

---

# 35. Dimensionamiento inicial de pods

Ejemplo conservador:

```text
Aggregator pod:

4 vCPU
8 GB RAM
```

Pruebas iniciales:

```text
1 pod  -> 1,000 RPS
2 pods -> 2,000 RPS
5 pods -> 5,000 RPS
10 pods -> 10,000 RPS
```

Estos valores son puntos iniciales de prueba, no límites esperados.

El objetivo es medir el throughput real.

Se recomienda operar aproximadamente a:

```text
50-60% CPU promedio
```

para conservar margen ante picos.

---

# 36. Latencia y fan-out paralelo

Ejemplo:

```text
B = 20 ms
C = 35 ms
D = 18 ms
E = 50 ms
```

Secuencial:

```text
20 + 35 + 18 + 50
=
123 ms
```

Paralelo:

```text
~50 ms
+
crypto
+
aggregator overhead
```

Por ello, ejecutar los downstreams en paralelo tiene mucho más impacto que micro-optimizar AES.

---

# 37. Métricas que deben medirse

Durante una prueba de carga:

```text
RPS
p50
p95
p99
CPU
heap
allocation rate
GC pauses
network throughput
connection pool usage
pending requests
timeouts
HPKE time
AES time
JSON serialization time
downstream latency
```

---

# 38. Pruebas recomendadas

Escenarios:

```text
1,000 RPS
5,000 RPS
10,000 RPS
20,000 RPS
```

Tamaños:

```text
2 KB
10 KB
50 KB
```

Combinar:

```text
RPS x payload size
```

para identificar:

- saturación de CPU;
- saturación de red;
- memoria;
- GC;
- límites HTTP;
- límites downstream.

---

# 39. Mockup de prueba

El siguiente mockup permite probar el concepto antes de implementar HPKE completo.

Se puede construir con tres componentes:

```text
requester
aggregator
responder
```

El objetivo es demostrar:

1. requester genera X25519;
2. aggregator recibe la clave pública;
3. responder cifra el JSON;
4. aggregator observa solamente ciphertext;
5. requester descifra.

---

# 40. Mockup — estructura de paquetes

```text
secure-demo/

src/main/java/com/example/secure/

    CryptoUtils.java
    RequestContext.java
    EncryptedResponse.java
    RequesterDemo.java
    ResponderDemo.java
    AggregatorDemo.java
```

---

# 41. Mockup — generación X25519

```java
package com.example.secure;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class CryptoUtils {

    private CryptoUtils() {}

    public static KeyPair generateX25519KeyPair()
            throws Exception {

        KeyPairGenerator generator =
            KeyPairGenerator.getInstance("X25519");

        return generator.generateKeyPair();
    }
}
```

---

# 42. Mockup — shared secret

```java
package com.example.secure;

import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class X25519Utils {

    private X25519Utils() {}

    public static byte[] sharedSecret(
            PrivateKey privateKey,
            PublicKey publicKey)
            throws Exception {

        KeyAgreement agreement =
            KeyAgreement.getInstance("X25519");

        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        return agreement.generateSecret();
    }
}
```

---

# 43. Mockup — derivación simplificada

Para el mockup puede utilizarse HKDF-SHA256.

Conceptualmente:

```text
sharedSecret
    │
    ▼
HKDF-SHA256
    │
    ▼
32 bytes
    │
    ▼
AES-256 key
```

En producción se recomienda utilizar una librería HPKE madura o una implementación estandarizada.

---

# 44. Mockup — AES-GCM

```java
package com.example.secure;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmUtils {

    private AesGcmUtils() {}

    public static byte[] encrypt(
            byte[] keyBytes,
            byte[] iv,
            byte[] aad,
            byte[] plaintext)
            throws Exception {

        SecretKey key =
            new SecretKeySpec(keyBytes, "AES");

        Cipher cipher =
            Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            new GCMParameterSpec(128, iv)
        );

        cipher.updateAAD(aad);

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(
            byte[] keyBytes,
            byte[] iv,
            byte[] aad,
            byte[] ciphertext)
            throws Exception {

        SecretKey key =
            new SecretKeySpec(keyBytes, "AES");

        Cipher cipher =
            Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            new GCMParameterSpec(128, iv)
        );

        cipher.updateAAD(aad);

        return cipher.doFinal(ciphertext);
    }
}
```

---

## 44.1 HPKE real con Bouncy Castle (recomendado para producción)

Las secciones 41–44 muestran una construcción manual (X25519 + HKDF + AES-GCM) útil para entender el mecanismo interno paso a paso. Para la implementación real se recomienda sustituir esa construcción manual por HPKE estándar (RFC 9180) usando Bouncy Castle, que ya implementa correctamente el binding de `info`, la codificación de `enc` y los modos definidos por el RFC.

Dependencia:

```text
org.bouncycastle:bcprov-jdk18on:1.79 (o superior)
```

Lado responder (sender):

```java
HPKE hpke = new HPKE(
    HPKE.mode_base,
    HPKE.kem_X25519_SHA256,
    HPKE.kdf_HKDF_SHA256,
    HPKE.aead_AES_GCM256
);

HPKEContextWithEncapsulation ctx =
    hpke.setupBaseS(requesterPublicKey, info);

byte[] ciphertext =
    ctx.seal(aad, jsonBytes);

byte[] enc =
    ctx.getEncapsulation();
```

Lado requester (recipient):

```java
HPKE hpke = new HPKE(
    HPKE.mode_base,
    HPKE.kem_X25519_SHA256,
    HPKE.kdf_HKDF_SHA256,
    HPKE.aead_AES_GCM256
);

HPKEContext ctx =
    hpke.setupBaseR(enc, requesterPrivateKey, info);

byte[] plaintext =
    ctx.open(aad, ciphertext);
```

El envelope de respuesta (secciones 7.3 y 12) debe incluir `enc` (la encapsulación devuelta por el sender) junto con el ciphertext, ya que el receptor lo necesita para reconstruir el mismo contexto HPKE.

---

# 45. Mockup — flujo esperado

## Requester

```text
1. generate requestId
2. generate X25519 keypair
3. store privateKey locally
4. send publicKey + requestId
```

## Aggregator

```text
1. receive request
2. forward publicKey
3. receive encrypted response
4. DO NOT decrypt
5. return ciphertext
```

## Responder

```text
1. receive publicKey
2. generate ephemeral X25519 keypair
3. derive shared secret
4. derive AES key
5. encrypt JSON
6. return ciphertext + responder public key + IV
```

## Requester

```text
1. receive envelope
2. derive shared secret
3. derive AES key
4. decrypt ciphertext
5. parse JSON
6. destroy request private key
```

---

# 46. Mockup — evidencia esperada

Log del responder:

```text
JSON original:

{
  "customerId": 12567,
  "status": "ACTIVE"
}
```

Log del aggregator:

```text
requestId=f729f500...

ciphertext:

9D 2A 44 3F A7 91 C2 ...
```

El agregador no puede reconstruir el JSON.

Log del requester:

```text
decrypted:

{
  "customerId": 12567,
  "status": "ACTIVE"
}
```

---

# 47. Mockup de prueba de ataque

También debe incluirse una prueba negativa.

Modificar un byte del ciphertext:

```text
ciphertext[10] ^= 0x01;
```

El resultado esperado es:

```text
AEADBadTagException
```

Esto demuestra que AES-GCM detecta manipulación.

---

# 48. Mockup de sustitución de request

Usar un AAD distinto:

```text
requestId_original = request-123

requestId_attack = request-999
```

El descifrado debe fallar.

Esto demuestra que una respuesta no puede trasladarse de una petición a otra.

---

# 49. Mockup de intento de descifrado del intermediario

El intermediario puede intentar descifrar utilizando cualquier clave distinta.

Resultado esperado:

```text
decrypt failed
```

Esto valida la propiedad principal del diseño:

> El intermediario puede transportar la información, pero no puede conocer su contenido.

---

# 50. Resultado esperado de la prueba de concepto

La prueba debe demostrar:

```text
✓ requester genera la clave privada
✓ la clave privada nunca abandona requester
✓ responders reciben únicamente la clave pública
✓ responders cifran el contenido
✓ aggregator recibe ciphertext
✓ aggregator no puede descifrar
✓ requester sí puede descifrar
✓ manipulación del ciphertext es detectada
✓ cambio de requestId es detectado mediante AAD
```

---

# 51. Recomendación final

La arquitectura recomendada para producción es:

```text
Java 21

TLS 1.3
+
mTLS

HPKE
+
X25519
+
HKDF-SHA256
+
AES-256-GCM

AAD
+
request_id
+
timestamp
+
expiration
+
nonce

HTTP/2
+
persistent connections
+
Virtual Threads

fan-out paralelo

payload binario
cuando sea posible
```

En Java 21, la capa HPKE se implementa mediante Bouncy Castle (`org.bouncycastle.crypto.hpke.HPKE`, ver sección 44.1).

El intermediario conserva la capacidad de:

```text
enrutar
agregar
correlacionar
manejar timeouts
manejar errores
medir latencia
```

sin obtener acceso al contenido protegido.

La principal propiedad de seguridad es:

```text
Requester:
    conoce la PrivateKey efímera

Responders:
    conocen la PublicKey del requester

Aggregator:
    conoce solamente ciphertext
```

Esto permite mantener confidencialidad extremo a extremo incluso a través de una arquitectura centralizada de agregación.

---

# 52. Próximos pasos recomendados

1. Crear un PoC Java 21 con requester, aggregator y responder.
2. Validar X25519 + HKDF + AES-GCM.
3. Sustituir el mockup criptográfico manual (secciones 41–44) por HPKE estándar (RFC 9180) usando Bouncy Castle (sección 44.1).
4. Habilitar TLS 1.3/mTLS.
5. Implementar fan-out paralelo.
6. Ejecutar pruebas de 1k/5k/10k RPS.
7. Medir p95/p99, CPU, red y GC.
8. Ajustar tamaño de pods y número de réplicas.
9. Evaluar si se requieren firmas Ed25519 por mensaje.
10. Realizar revisión de seguridad antes de producción.
