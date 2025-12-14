# Sistema Blockchain con Firmas Digitales

Sistema de blockchain implementado en Java con firmas digitales usando certificados X.509 y algoritmo SHA256withRSA.

## Características

- Blockchain con hash SHA-256
- Firmas digitales con certificados X.509
- Verificación completa de integridad
- Interfaz de consola interactiva
- Registro de certificados

## Inicio Rápido

### 1. Generar certificado de prueba

```bash
keytool -genkeypair -alias testkey -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore test.p12 -validity 365 -storepass password123 -keypass password123 -dname "CN=Test User, OU=Test Department, O=Test Organization, L=Test City, ST=Test State, C=ES"
```

### 2. Compilar

```bash
mvn clean compile
```

### 3. Ejecutar

```bash
mvn exec:java -Dexec.mainClass="com.example.Main"
```

## Comandos del Menú

- `add <datos>` - Añade un bloque firmado con los datos especificados
- `verify` - Verifica la integridad de toda la cadena
- `print` - Muestra todos los bloques
- `exit` - Sale del programa

## Ejemplo de Uso

```
> add Primera transacción
✓ Bloc afegit correctament!

> add Segunda transacción
✓ Bloc afegit correctament!

> verify
✓ La cadena és vàlida!

> print
--- Bloc 0 ---
  Data: Genesis Block
  ...

--- Bloc 1 ---
  Data: Primera transacción
  ...
```

## Estructura del Proyecto

```
src/main/java/com/example/
├── BlockSigned.java          # Bloque individual
├── BlockChainSigned.java     # Cadena de bloques
├── CryptoUtils.java          # Utilidades criptográficas
├── CertificateRegistry.java  # Registro de certificados
└── Main.java                 # Interfaz de usuario
```

## Tecnologías

- Java 17
- Maven
- SHA-256 (hashing)
- SHA256withRSA (firmas digitales)
- X.509 (certificados)
- PKCS#12 (keystore)

## Documentación Completa

Ver [DOCUMENTACION.md](DOCUMENTACION.md) para información detallada sobre:
- Arquitectura del sistema
- Funcionamiento interno
- Seguridad y criptografía
- Casos de prueba
- Guías de uso

## Autor

Sergi Font - Grado Superior de Desarrollo de Aplicaciones Multiplataforma
Proyecto: RA1-PR2-Part2
Asignatura: Servicios y Procesos
