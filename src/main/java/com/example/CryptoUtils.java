package com.example;

import java.security.*;
import java.security.cert.X509Certificate;

/**
 * Classe utilitària per a:
 * a) Carregar un KeyStore (.p12)
 * b) Obtenir clau privada i certificat
 * c) Signar dades
 * d) Verificar signatura amb el certificat
 */

public class CryptoUtils {
    /**
     * Carrega un KeyStore PKCS12.
     * Implementar:
     * - Obrir fitxer .p12
     * - Carregar-lo amb password
     */
    public static KeyStore loadKeyStore(String path, String password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            java.io.FileInputStream fis = new java.io.FileInputStream(path);
            ks.load(fis, password.toCharArray());
            fis.close();
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Error carregant keystore: " + e.getMessage(), e);
        }
    }

    /**
     * Obtén clau privada del keystore.
     */
    public static PrivateKey getPrivateKey(KeyStore ks, String alias, String keyPassword) {
        try {
            return (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException("Error obtenint clau privada: " + e.getMessage(), e);
        }
    }

    /**
     * Obtén el certificat X.509 del keystore.
     */
    public static X509Certificate getCertificate(KeyStore ks, String alias) {
        try {
            return (X509Certificate) ks.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException("Error obtenint certificat: " + e.getMessage(), e);
        }
    }

    /**
     * Signa dades:
     * a) Crear objecte Signature SHA256withRSA.
     * b) Inicialitzar-lo amb clau privada.
     * c) Firmar bytes.
     */
    public static String sign(PrivateKey pk, String data) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(pk);
            sig.update(data.getBytes());
            byte[] signatureBytes = sig.sign();
            return java.util.Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error signant dades: " + e.getMessage(), e);
        }
    }

    /**
     * Verifica signatura amb el certificat.
     * a) Inicialitzar Signature en mode verify.
     * b) Usar la clau pública del certificat.
     * c) Comparar signatura.
     */
    public static boolean verify(X509Certificate cert, String data, String signatureB64) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(cert.getPublicKey());
            sig.update(data.getBytes());
            byte[] signatureBytes = java.util.Base64.getDecoder().decode(signatureB64);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error verificant signatura: " + e.getMessage(), e);
        }
    }
}
