package com.example;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Blockchain amb:
 * a) Blocs signats digitalment
 * b) Validació del hash
 * c) Validació de la signatura
 * d) Validació del certificat
 */
public class BlockChainSigned {

    private List<BlockSigned> chain = new ArrayList<>();

    public BlockChainSigned() {
        BlockSigned genesis = new BlockSigned(0, "0", "Genesis Block");
        chain.add(genesis);
    }

    /**
     * Afegeix un bloc signat:
     * 1) Crear bloc nou.
     * 2) Calcular hash.
     * 3) Signar les dades.
     * 4) Assignar subject del certificat.
     * 5) Afegir a la cadena.
     */
    public void addSignedBlock(String data, String signatureB64, String signerSubject) {
        BlockSigned previousBlock = chain.get(chain.size() - 1);
        BlockSigned newBlock = new BlockSigned(chain.size(), previousBlock.getHash(), data);
        newBlock.setSignature(signatureB64);
        newBlock.setSignerSubject(signerSubject);
        chain.add(newBlock);
    }

    /**
     * Comprova:
     * a) Que previousHash coincideix amb hash de l'anterior.
     * b) Que el hash del bloc és correcte.
     * c) Que la signatura és vàlida.
     * d) Que el certificat del remitent es troba registrat.
     */
    public boolean verifyChain(CertificateRegistry reg) {
        for (int i = 1; i < chain.size(); i++) {
            BlockSigned current = chain.get(i);
            BlockSigned previous = chain.get(i - 1);

            if (!current.getPreviousHash().equals(previous.getHash())) {
                System.out.println("ERROR: previousHash no coincideix al bloc " + i);
                return false;
            }

            String calculatedHash = BlockSigned.calculateHash(current.getIndex(), current.getPreviousHash(),
                                                             current.getTimestamp(), current.getData());
            if (!calculatedHash.equals(current.getHash())) {
                System.out.println("ERROR: Hash incorrecte al bloc " + i);
                return false;
            }

            if (current.getSignature() == null || current.getSignerSubject() == null) {
                System.out.println("ERROR: Bloc " + i + " sense signatura o subject");
                return false;
            }

            X509Certificate cert = reg.getBySubject(current.getSignerSubject());
            if (cert == null) {
                System.out.println("ERROR: Certificat no registrat per " + current.getSignerSubject());
                return false;
            }

            if (!CryptoUtils.verify(cert, current.getData(), current.getSignature())) {
                System.out.println("ERROR: Signatura invàlida al bloc " + i);
                return false;
            }
        }
        return true;
    }

    public String getLastHash() {
        return chain.get(chain.size() - 1).getHash();
    }

    public void printChain() {
        for (BlockSigned block : chain) {
            System.out.println("--- Bloc " + block.getIndex() + " ---");
            System.out.println("  Timestamp: " + block.getTimestamp());
            System.out.println("  Previous Hash: " + block.getPreviousHash());
            System.out.println("  Data: " + block.getData());
            System.out.println("  Hash: " + block.getHash());
            System.out.println("  Signature: " + (block.getSignature() != null ? block.getSignature().substring(0, Math.min(50, block.getSignature().length())) + "..." : "N/A"));
            System.out.println("  Signer: " + (block.getSignerSubject() != null ? block.getSignerSubject() : "N/A"));
            System.out.println();
        }
    }
}