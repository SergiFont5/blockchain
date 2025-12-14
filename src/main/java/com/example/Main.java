package com.example;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Consola:
 * - Carregar certificats i claus.
 * - Afegir blocs signats.
 * - Validar la cadena.
 */
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.println("=== Sistema Blockchain amb Signatures Digitals ===\n");

            System.out.print("Introdueix la ruta del keystore .p12: ");
            String keystorePath = scanner.nextLine();

            System.out.print("Introdueix la contrasenya del keystore: ");
            String keystorePassword = scanner.nextLine();

            System.out.print("Introdueix l'alias de la clau: ");
            String alias = scanner.nextLine();

            System.out.print("Introdueix la contrasenya de la clau privada: ");
            String keyPassword = scanner.nextLine();

            System.out.println("\nCarregant keystore...");
            KeyStore keyStore = CryptoUtils.loadKeyStore(keystorePath, keystorePassword);

            System.out.println("Obtenint clau privada i certificat...");
            PrivateKey privateKey = CryptoUtils.getPrivateKey(keyStore, alias, keyPassword);
            X509Certificate certificate = CryptoUtils.getCertificate(keyStore, alias);

            String subjectDN = certificate.getSubjectX500Principal().getName();
            System.out.println("Certificat carregat: " + subjectDN);

            CertificateRegistry registry = new CertificateRegistry();
            registry.register(certificate);
            System.out.println("Certificat registrat al registry.\n");

            BlockChainSigned blockchain = new BlockChainSigned();
            System.out.println("Blockchain inicialitzat amb bloc Genesis.\n");

            System.out.println("=== Menú d'Opcions ===");
            System.out.println("add <data>  - Afegir un bloc signat amb les dades especificades");
            System.out.println("verify      - Verificar la integritat de la cadena");
            System.out.println("print       - Mostrar tots els blocs de la cadena");
            System.out.println("exit        - Sortir del programa\n");

            while (true) {
                System.out.print("> ");
                String input = scanner.nextLine().trim();

                if (input.isEmpty()) {
                    continue;
                }

                if (input.equalsIgnoreCase("exit")) {
                    System.out.println("Sortint del programa...");
                    break;
                }

                if (input.equalsIgnoreCase("verify")) {
                    System.out.println("Verificant la cadena...");
                    boolean isValid = blockchain.verifyChain(registry);
                    if (isValid) {
                        System.out.println("La cadena és vàlida!");
                    } else {
                        System.out.println("La cadena NO és vàlida!");
                    }
                    continue;
                }

                if (input.equalsIgnoreCase("print")) {
                    blockchain.printChain();
                    continue;
                }

                if (input.startsWith("add ")) {
                    String data = input.substring(4).trim();
                    if (data.isEmpty()) {
                        System.out.println("Error: Has de proporcionar dades per al bloc.");
                        continue;
                    }

                    System.out.println("Signant dades...");
                    String signature = CryptoUtils.sign(privateKey, data);

                    System.out.println("Afegint bloc a la cadena...");
                    blockchain.addSignedBlock(data, signature, subjectDN);

                    System.out.println("Bloc afegit correctament!");
                    continue;
                }

                System.out.println("Comanda no reconeguda. Utilitza: add <data>, verify, print o exit");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}