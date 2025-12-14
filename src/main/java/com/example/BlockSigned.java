package com.example;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Bloc amb signatura digital.
 * Ha de contenir:
 * a) Hash del bloc.
 * b) Signatura digital de les dades.
 * c) Subject del certificat de qui signa.
 */
public class BlockSigned {
    private int index;
    private long timestamp;
    private String previousHash;
    private String data;
    private String hash;
    private String signature;
    private String signerSubject;

    public BlockSigned(int index, String previousHash, String data) {
        this.index = index;
        this.previousHash = previousHash;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
        this.hash = calculateHash();
    }

    private String calculateHash() {
        return calculateHash(index, previousHash, timestamp, data);
    }

    public static String calculateHash(int index, String previousHash, long timestamp, String data) {
        try {
            String input = index + previousHash + timestamp + data;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error calculant hash: " + e.getMessage(), e);
        }
    }

    public int getIndex() {
        return index;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getData() {
        return data;
    }

    public String getHash() {
        return hash;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignerSubject() {
        return signerSubject;
    }

    public void setSignerSubject(String signerSubject) {
        this.signerSubject = signerSubject;
    }
}
