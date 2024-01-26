package ru.vtb;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;


public class JWTGenerator {
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.out.printf("Got %d arguments, expected 1.\n" +
                            "Usage:\n" +
                            "Pass signature algorithm as first argument\n" +
                            "Only \"EC\" algorithm is working currently!!!\n" +
                            "Files \"data.json\", \"private_key.pem\" should be placed in current working directory\n",
                    args.length
            );
            return;
        }
        String jsonString = readFile("data.json");
        JSONArray jwtData = new JSONArray(jsonString);
        for (int i = 0; i < jwtData.length(); i++) {
            JSONObject jwtDetails = jwtData.getJSONObject(i);
            Iterator<String> keys = jwtDetails.keys();

            JwtBuilder jwtBuilder = Jwts.builder().setHeaderParam("typ", "JWT");
            while (keys.hasNext()) {
                String key = keys.next();
                if (!(jwtDetails.get(key) instanceof JSONObject || jwtDetails.get(key) instanceof JSONArray)) {
                    // do something with jsonObject here
                    jwtBuilder = jwtBuilder.claim(key, jwtDetails.get(key));
                }
            }
            String jwt = jwtBuilder
                    .signWith(getPrivateKey(restoreFromPEM("private_key.pem"), args[0]))
                    .compact();
            jwtDetails.put("jwt", jwt);
        }
        writeToFile("output.json", jwtData.toString(4));
    }

    public static ECPrivateKey getPrivateKey(String key, String signingAlgorithm) {
        try {
            KeyFactory kf = KeyFactory.getInstance(signingAlgorithm);
            return (ECPrivateKey) kf.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String readFile(String filename) throws IOException {
        FileInputStream inputStream = new FileInputStream(new File(filename));
        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append('\n');
            }
        }
        return resultStringBuilder.toString();
    }

    public static String restoreFromPEM(String filename) throws IOException {
        FileInputStream inputStream = new FileInputStream(new File(filename));
        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line);
            }
        }
        return resultStringBuilder.toString().split("-----")[2];
    }

    public static void writeToFile(String fileName, String content) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write(content);
        writer.close();
    }
}

