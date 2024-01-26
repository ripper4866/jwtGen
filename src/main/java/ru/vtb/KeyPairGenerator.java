package ru.vtb;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyPairGenerator {

    public static void main( String[] args ) throws IOException {
        if (args.length != 1) {
            System.out.printf("Got %d arguments, expected 1.\n" +
                    "Usage: pass signature algorithm as first argument\n", args.length);
            return;
        }
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.forName(args[0]));
        PrivateKey privateKey = keyPair.getPrivate();
        writeToFile("private_key.pem", formatAsPEM(privateKey,
                "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
        );
        PublicKey publicKey = keyPair.getPublic();
        writeToFile("public_key.pem", formatAsPEM(publicKey,
                "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----")
        );
        System.out.printf("Key pair generated using algorithm %s\n", args[0]);
    }

    public static String formatAsPEM(Key key, String prefix, String postfix) {
        String content = Base64.getEncoder().encodeToString(key.getEncoded());
        StringBuilder split = new StringBuilder().append(prefix).append('\n');
        for (int i = 0; i <= content.length() / 64; i++) {
            split.append(content.substring(i * 64, Math.min((i + 1) * 64, content.length()))).append('\n');
        }
        return split.append(postfix).toString();
    }

    public static void writeToFile(String fileName, String content) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write(content);
        writer.close();
    }
}
