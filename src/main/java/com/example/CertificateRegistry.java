package com.example;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Registre simple per guardar certificats X.509.
 * Implementar:
 * - Afegir certificat
 * - Buscar certificat per Subject DN
 */
public class CertificateRegistry {

    private Map<String, X509Certificate> map = new HashMap<>();

    public void register(X509Certificate cert) {
        String subjectDN = cert.getSubjectX500Principal().getName();
        map.put(subjectDN, cert);
    }

    public X509Certificate getBySubject(String subjectDn) {
        return map.get(subjectDn);
    }
}
