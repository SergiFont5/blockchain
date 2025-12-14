# Documentación del Sistema Blockchain con Firmas Digitales

## Índice
1. [Introducción](#introducción)
2. [Arquitectura del Sistema](#arquitectura-del-sistema)
3. [Componentes Principales](#componentes-principales)
4. [Funcionamiento Detallado](#funcionamiento-detallado)
5. [Seguridad y Criptografía](#seguridad-y-criptografía)
6. [Guía de Uso](#guía-de-uso)
7. [Casos de Prueba](#casos-de-prueba)

---

## Introducción

Este proyecto implementa un sistema de blockchain con firmas digitales utilizando Java. El sistema permite crear una cadena de bloques donde cada bloque está firmado digitalmente usando certificados X.509 y claves RSA.

### Características Principales
- **Blockchain con integridad garantizada**: Cada bloque está vinculado al anterior mediante hash SHA-256
- **Firmas digitales**: Cada bloque está firmado con SHA256withRSA
- **Verificación de certificados**: Sistema de registro y validación de certificados X.509
- **Interfaz de consola interactiva**: Menú simple para gestionar la blockchain

---

## Arquitectura del Sistema

El sistema está compuesto por 5 clases principales:

```
com.example
├── BlockSigned.java          # Representa un bloque individual
├── BlockChainSigned.java     # Gestiona la cadena de bloques
├── CryptoUtils.java          # Utilidades criptográficas
├── CertificateRegistry.java  # Registro de certificados
└── Main.java                 # Interfaz de usuario
```

### Diagrama de Flujo

```
Usuario → Main → CryptoUtils → KeyStore (.p12)
                     ↓
                CertificateRegistry
                     ↓
              BlockChainSigned
                     ↓
                 BlockSigned
```

---

## Componentes Principales

### 1. BlockSigned.java

Representa un bloque individual en la cadena.

#### Atributos:
- `index`: Posición del bloque en la cadena
- `timestamp`: Momento de creación (milisegundos desde epoch)
- `previousHash`: Hash del bloque anterior
- `data`: Datos almacenados en el bloque
- `hash`: Hash SHA-256 del bloque actual
- `signature`: Firma digital de los datos (Base64)
- `signerSubject`: Subject DN del certificado que firma

#### Métodos Principales:

**Constructor:**
```java
public BlockSigned(int index, String previousHash, String data)
```
- Inicializa todos los campos del bloque
- Calcula automáticamente el hash SHA-256 del bloque
- El timestamp se genera automáticamente

**Cálculo de Hash:**
```java
public static String calculateHash(int index, String previousHash, long timestamp, String data)
```
- Concatena: index + previousHash + timestamp + data
- Aplica SHA-256
- Retorna el hash en formato hexadecimal

**Getters y Setters:**
- Métodos para acceder y modificar la firma y el firmante
- Métodos de solo lectura para los demás campos

---

### 2. BlockChainSigned.java

Gestiona la cadena completa de bloques.

#### Atributos:
- `chain`: Lista de bloques (`List<BlockSigned>`)

#### Métodos Principales:

**Constructor:**
```java
public BlockChainSigned()
```
- Crea automáticamente el **bloque génesis**
- El bloque génesis tiene:
  - index = 0
  - previousHash = "0"
  - data = "Genesis Block"
  - Sin firma (es el bloque inicial)

**Añadir Bloque Firmado:**
```java
public void addSignedBlock(String data, String signatureB64, String signerSubject)
```
1. Obtiene el hash del último bloque de la cadena
2. Crea un nuevo bloque con los datos proporcionados
3. Asigna la firma digital y el subject del firmante
4. Añade el bloque a la cadena

**Verificar Cadena:**
```java
public boolean verifyChain(CertificateRegistry reg)
```
Para cada bloque (excepto el génesis), verifica:
1. **Encadenamiento**: El previousHash coincide con el hash del bloque anterior
2. **Integridad del hash**: Recalcula el hash y verifica que coincida
3. **Existencia de firma**: El bloque tiene firma y firmante
4. **Certificado registrado**: El certificado del firmante existe en el registry
5. **Validez de firma**: La firma digital es válida usando el certificado

Si alguna verificación falla, retorna `false` y muestra un mensaje de error.

**Imprimir Cadena:**
```java
public void printChain()
```
Muestra todos los bloques con sus detalles:
- Índice, timestamp, hash anterior
- Datos, hash actual
- Firma (primeros 50 caracteres) y firmante

---

### 3. CryptoUtils.java

Proporciona funciones criptográficas esenciales.

#### Métodos Principales:

**Cargar KeyStore:**
```java
public static KeyStore loadKeyStore(String path, String password)
```
1. Crea una instancia de KeyStore tipo PKCS12
2. Abre el archivo .p12 especificado
3. Carga el keystore con la contraseña
4. Retorna el KeyStore cargado

**Obtener Clave Privada:**
```java
public static PrivateKey getPrivateKey(KeyStore ks, String alias, String keyPassword)
```
- Extrae la clave privada del keystore usando el alias y contraseña
- Retorna un objeto PrivateKey

**Obtener Certificado:**
```java
public static X509Certificate getCertificate(KeyStore ks, String alias)
```
- Extrae el certificado X.509 del keystore usando el alias
- Retorna un objeto X509Certificate

**Firmar Datos:**
```java
public static String sign(PrivateKey pk, String data)
```
1. Crea un objeto Signature con algoritmo SHA256withRSA
2. Inicializa con la clave privada (modo firma)
3. Actualiza con los bytes de los datos
4. Genera la firma
5. Codifica en Base64 y retorna

**Verificar Firma:**
```java
public static boolean verify(X509Certificate cert, String data, String signatureB64)
```
1. Crea un objeto Signature con algoritmo SHA256withRSA
2. Inicializa con la clave pública del certificado (modo verificación)
3. Actualiza con los bytes de los datos
4. Decodifica la firma de Base64
5. Verifica y retorna true/false

---

### 4. CertificateRegistry.java

Registro simple para almacenar y buscar certificados.

#### Atributos:
- `map`: HashMap que relaciona Subject DN con certificados

#### Métodos:

**Registrar Certificado:**
```java
public void register(X509Certificate cert)
```
- Extrae el Subject DN del certificado
- Almacena el certificado en el mapa usando el DN como clave

**Buscar Certificado:**
```java
public X509Certificate getBySubject(String subjectDn)
```
- Busca y retorna el certificado asociado al Subject DN
- Retorna null si no existe

---

### 5. Main.java

Interfaz de usuario por consola.

#### Flujo de Ejecución:

**1. Inicialización:**
```
1. Solicitar ruta del keystore .p12
2. Solicitar contraseña del keystore
3. Solicitar alias de la clave
4. Solicitar contraseña de la clave privada
5. Cargar keystore
6. Extraer clave privada y certificado
7. Registrar certificado en el registry
8. Crear blockchain con bloque génesis
```

**2. Menú Interactivo:**
El sistema acepta los siguientes comandos:

- `add <datos>`: Firma y añade un nuevo bloque con los datos especificados
- `verify`: Verifica la integridad completa de la cadena
- `print`: Muestra todos los bloques de la cadena
- `exit`: Sale del programa

**3. Proceso de Añadir Bloque:**
```
1. Usuario escribe: add Primera transacción
2. Sistema extrae los datos: "Primera transacción"
3. Firma los datos con la clave privada
4. Crea un nuevo bloque con:
   - Datos: "Primera transacción"
   - Firma: [signatura en Base64]
   - Firmante: [Subject DN del certificado]
5. Añade el bloque a la cadena
6. Confirma al usuario
```

---

## Funcionamiento Detallado

### Proceso de Creación de un Bloque

1. **Obtención de datos del usuario**
   - Usuario introduce: `add Transacción de ejemplo`

2. **Firma digital**
   ```
   Datos → Clave Privada → SHA256withRSA → Firma (Base64)
   ```

3. **Creación del bloque**
   ```java
   BlockSigned newBlock = new BlockSigned(
       chain.size(),                    // índice
       previousBlock.getHash(),         // hash anterior
       "Transacción de ejemplo"         // datos
   );
   ```

4. **Cálculo del hash**
   ```
   Input = índice + hash_anterior + timestamp + datos
   Hash = SHA256(Input) → hexadecimal
   ```

5. **Asignación de firma y firmante**
   ```java
   newBlock.setSignature(signatureB64);
   newBlock.setSignerSubject(subjectDN);
   ```

6. **Adición a la cadena**
   ```java
   chain.add(newBlock);
   ```

### Proceso de Verificación de la Cadena

Para cada bloque (i > 0):

**Paso 1: Verificar Encadenamiento**
```java
if (!current.getPreviousHash().equals(previous.getHash())) {
    return false; // Cadena rota
}
```

**Paso 2: Verificar Integridad del Hash**
```java
String calculatedHash = BlockSigned.calculateHash(
    current.getIndex(),
    current.getPreviousHash(),
    current.getTimestamp(),
    current.getData()
);
if (!calculatedHash.equals(current.getHash())) {
    return false; // Hash manipulado
}
```

**Paso 3: Verificar Existencia de Firma**
```java
if (current.getSignature() == null || current.getSignerSubject() == null) {
    return false; // Bloque sin firmar
}
```

**Paso 4: Verificar Certificado Registrado**
```java
X509Certificate cert = registry.getBySubject(current.getSignerSubject());
if (cert == null) {
    return false; // Certificado no autorizado
}
```

**Paso 5: Verificar Firma Digital**
```java
if (!CryptoUtils.verify(cert, current.getData(), current.getSignature())) {
    return false; // Firma inválida
}
```

Si todos los bloques pasan todas las verificaciones → **Cadena válida**

---

## Seguridad y Criptografía

### Algoritmos Utilizados

**SHA-256 (Hash):**
- Función hash criptográfica
- Produce un hash de 256 bits (64 caracteres hex)
- Resistente a colisiones
- Usado para: hash de bloques

**SHA256withRSA (Firma Digital):**
- Combina SHA-256 para hash + RSA para cifrado
- La firma se genera: RSA(SHA256(datos), clavePrivada)
- La verificación: comparar SHA256(datos) con RSA(firma, clavePublica)
- Tamaño de clave: 2048 bits (recomendado)

**PKCS#12 (KeyStore):**
- Formato estándar para almacenar claves y certificados
- Protegido con contraseña
- Extensión: .p12 o .pfx

### Propiedades de Seguridad

**Inmutabilidad:**
- Cada bloque contiene el hash del anterior
- Modificar un bloque invalida todos los siguientes
- Detectable mediante verificación de hashes

**Autenticidad:**
- Firmas digitales garantizan quién creó el bloque
- Solo quien tiene la clave privada puede firmar
- El certificado identifica al firmante

**Integridad:**
- Hashes garantizan que los datos no han sido modificados
- Firmas garantizan que los datos son del autor declarado
- Verificación completa detecta cualquier manipulación

**No repudio:**
- Una vez firmado, el firmante no puede negar haber creado el bloque
- La firma está vinculada criptográficamente a su clave privada

---

## Guía de Uso

### Requisitos Previos

1. **Java Development Kit (JDK) 17 o superior**
2. **Maven** (para compilación)
3. **Certificado PKCS#12** (.p12 file)

### Generar un Certificado de Prueba

```bash
keytool -genkeypair \
  -alias testkey \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore test.p12 \
  -validity 365 \
  -storepass password123 \
  -keypass password123 \
  -dname "CN=Test User, OU=Test Department, O=Test Organization, L=Test City, ST=Test State, C=ES"
```

### Compilar el Proyecto

```bash
mvn clean compile
```

### Ejecutar el Programa

```bash
mvn exec:java -Dexec.mainClass="com.example.Main"
```

### Ejemplo de Sesión Interactiva

```
=== Sistema Blockchain amb Signatures Digitals ===

Introdueix la ruta del keystore .p12: test.p12
Introdueix la contrasenya del keystore: password123
Introdueix l'alias de la clau: testkey
Introdueix la contrasenya de la clau privada: password123

Carregant keystore...
Obtenint clau privada i certificat...
Certificat carregat: CN=Test User,OU=Test Department,O=Test Organization,L=Test City,ST=Test State,C=ES
Certificat registrat al registry.

Blockchain inicialitzat amb bloc Genesis.

=== Menú d'Opcions ===
add <data>  - Afegir un bloc signat amb les dades especificades
verify      - Verificar la integritat de la cadena
print       - Mostrar tots els blocs de la cadena
exit        - Sortir del programa

> add Primera transacción
Signant dades...
Afegint bloc a la cadena...
✓ Bloc afegit correctament!

> add Segunda transacción
Signant dades...
Afegint bloc a la cadena...
✓ Bloc afegit correctament!

> print
--- Bloc 0 ---
  Timestamp: 1765710036494
  Previous Hash: 0
  Data: Genesis Block
  Hash: 384a549791818bdfac8b3f9c5433572b66f5909ee4976e76beef92b718cda097
  Signature: N/A
  Signer: N/A

--- Bloc 1 ---
  Timestamp: 1765710036551
  Previous Hash: 384a549791818bdfac8b3f9c5433572b66f5909ee4976e76beef92b718cda097
  Data: Primera transacción
  Hash: 3e70909b018867c0ce2246c220747a842cf14bf8f2f7b1d5b9f9799ce3828717
  Signature: cqQ2BzmE6RFDrdOya3OjEZHKXcD2uNmUA5gYTpNU7NDzVEutcw...
  Signer: CN=Test User,OU=Test Department,O=Test Organization,L=Test City,ST=Test State,C=ES

--- Bloc 2 ---
  Timestamp: 1765710036566
  Previous Hash: 3e70909b018867c0ce2246c220747a842cf14bf8f2f7b1d5b9f9799ce3828717
  Data: Segunda transacción
  Hash: b5203d18701a4d840b6b66b6df19c552b4027585952dbe9fa5bb6b18c8a8fa7f
  Signature: kZj5iXxGrq0HcdUux3yrEr27KqHgKdMoUHgpTdOW+0r1qc7yWT...
  Signer: CN=Test User,OU=Test Department,O=Test Organization,L=Test City,ST=Test State,C=ES

> verify
Verificant la cadena...
✓ La cadena és vàlida!

> exit
Sortint del programa...
```

---

## Casos de Prueba

### Caso 1: Añadir Bloques y Verificar

**Objetivo:** Verificar que se pueden añadir bloques y la cadena es válida

**Pasos:**
1. Iniciar el programa
2. Cargar certificado
3. Ejecutar: `add Bloque 1`
4. Ejecutar: `add Bloque 2`
5. Ejecutar: `add Bloque 3`
6. Ejecutar: `verify`

**Resultado Esperado:** "La cadena és vàlida!"

---

### Caso 2: Bloque Génesis

**Objetivo:** Verificar que el bloque génesis se crea correctamente

**Pasos:**
1. Iniciar el programa
2. Cargar certificado
3. Ejecutar: `print`

**Resultado Esperado:**
- Debe mostrar un bloque con índice 0
- Previous Hash: "0"
- Data: "Genesis Block"
- Sin firma

---

### Caso 3: Integridad de Hashes

**Objetivo:** Verificar que cada bloque contiene el hash del anterior

**Pasos:**
1. Añadir 3 bloques
2. Ejecutar: `print`
3. Verificar manualmente que:
   - Bloque 1: previousHash = hash del bloque 0
   - Bloque 2: previousHash = hash del bloque 1
   - Bloque 3: previousHash = hash del bloque 2

**Resultado Esperado:** Los hashes están correctamente encadenados

---

### Caso 4: Verificación de Firmas

**Objetivo:** Verificar que las firmas son válidas

**Pasos:**
1. Añadir varios bloques
2. Ejecutar: `verify`

**Resultado Esperado:**
- Todas las verificaciones pasan
- "La cadena és vàlida!"

---

### Caso 5: Múltiples Transacciones

**Objetivo:** Probar el sistema con muchos bloques

**Pasos:**
1. Añadir 10 bloques con diferentes datos
2. Ejecutar: `print` para revisar todos
3. Ejecutar: `verify`

**Resultado Esperado:**
- Todos los bloques se muestran correctamente
- La verificación es exitosa
- Los hashes están correctamente encadenados

---

## Posibles Mejoras Futuras

1. **Persistencia:** Guardar la blockchain en disco (serialización, base de datos)
2. **Minería:** Implementar Proof of Work con dificultad ajustable
3. **Red distribuida:** Múltiples nodos comunicándose
4. **Smart Contracts:** Ejecutar código en la blockchain
5. **Gestión de múltiples certificados:** Permitir diferentes usuarios
6. **Revocación de certificados:** Lista de certificados revocados
7. **Interfaz gráfica:** GUI en lugar de consola
8. **API REST:** Exponer funcionalidades vía HTTP

---

## Conclusión

Este sistema implementa los conceptos fundamentales de blockchain:
- **Encadenamiento criptográfico** mediante hashes
- **Firmas digitales** para autenticación
- **Verificación de integridad** completa
- **Gestión de certificados** para autorización

Es una implementación educativa que demuestra los principios básicos de tecnología blockchain aplicada con criptografía de clave pública (PKI).
