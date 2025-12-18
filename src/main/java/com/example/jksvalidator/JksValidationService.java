package com.example.jksvalidator;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate; // Standard Certificate
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Service
public class JksValidationService {

    public String testConnection(MultipartFile jksFile,
                                 String keystorePassword,
                                 String keyPassword,
                                 String alias,
                                 String targetUrl,
                                 String httpMethod,
                                 String headers,
                                 String requestBody) throws Exception {

        System.out.println("\n>>> --- DIAGNOSTIC START ---");

        // 1. Load Keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream storeStream = jksFile.getInputStream()) {
            keyStore.load(storeStream, keystorePassword.toCharArray());
        }
        System.out.println(">>> Keystore loaded successfully.");

        // 2. Determine Alias
        String targetAlias = alias;
        if (targetAlias == null || targetAlias.trim().isEmpty()) {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (keyStore.isKeyEntry(a)) {
                    targetAlias = a;
                    break;
                }
            }
        }
        System.out.println(">>> Selected Alias: " + targetAlias);

        if (targetAlias == null) {
            throw new Exception("No PrivateKey found in JKS.");
        }

        // 3. Determine Password
        char[] effectiveKeyPass = (keyPassword != null && !keyPassword.trim().isEmpty())
                ? keyPassword.toCharArray()
                : keystorePassword.toCharArray();

        // 4. *** CRITICAL DIAGNOSTIC STEP (Fixed Casting) ***
        try {
            System.out.println(">>> Attempting to retrieve Private Key...");
            Key key = keyStore.getKey(targetAlias, effectiveKeyPass);
            if (key == null) {
                throw new Exception("CRITICAL: Key retrieval returned null. Is the password correct?");
            }
            System.out.println(">>> Private Key retrieved! Algorithm: " + key.getAlgorithm());

            Certificate[] rawChain = keyStore.getCertificateChain(targetAlias);
            System.out.println(">>> Certificate Chain Length: " + (rawChain != null ? rawChain.length : "null"));

            if (rawChain != null && rawChain.length > 0) {
                if (rawChain[0] instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) rawChain[0];
                    System.out.println("    Leaf Subject: " + x509.getSubjectDN());
                    System.out.println("    Leaf Issuer:  " + x509.getIssuerDN());
                }
            }

        } catch (UnrecoverableKeyException e) {
            throw new Exception("PASSWORD ERROR: The 'Key Password' is incorrect. " + e.getMessage());
        } catch (Exception e) {
            throw new Exception("KEY ERROR: Could not read key [" + targetAlias + "]. " + e.getMessage());
        }

        // 5. Setup Custom KeyManager
        final String finalAlias = targetAlias;
        final KeyStore finalKeyStore = keyStore;
        final char[] finalPass = effectiveKeyPass;

        X509KeyManager customKeyManager = new X509ExtendedKeyManager() {
            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                System.out.println(">>> SSL Handshake asked for alias. Returning: " + finalAlias);
                return finalAlias;
            }

            @Override public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) { return finalAlias; }
            @Override public String[] getClientAliases(String keyType, Principal[] issuers) { return new String[]{finalAlias}; }
            @Override public String[] getServerAliases(String keyType, Principal[] issuers) { return new String[]{finalAlias}; }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                try {
                    // SAFE CASTING LOGIC
                    Certificate[] cChain = finalKeyStore.getCertificateChain(alias);
                    if (cChain == null) return null;
                    X509Certificate[] xChain = new X509Certificate[cChain.length];
                    for (int i = 0; i < cChain.length; i++) {
                        xChain[i] = (X509Certificate) cChain[i];
                    }
                    return xChain;
                } catch (Exception e) { e.printStackTrace(); return null; }
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                try { return (PrivateKey) finalKeyStore.getKey(alias, finalPass); }
                catch (Exception e) { e.printStackTrace(); return null; }
            }
        };

        // 6. Connect
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(new KeyManager[]{customKeyManager}, tmf.getTrustManagers(), new SecureRandom());

        System.out.println(">>> Connecting to: " + targetUrl);
        URL url = new URL(targetUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setConnectTimeout(10000);
        connection.setRequestMethod(httpMethod);

        // Headers
        if (headers != null && !headers.isEmpty()) {
            BufferedReader reader = new BufferedReader(new StringReader(headers));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    connection.setRequestProperty(parts[0].trim(), parts[1].trim());
                }
            }
        }

        // Body
        if (requestBody != null && !requestBody.trim().isEmpty()) {
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(requestBody.getBytes("UTF-8"));
            }
        }

        connection.connect();
        int responseCode = connection.getResponseCode();

        System.out.println(">>> SUCCESS! Response Code: " + responseCode);
        return "Connected! HTTP " + responseCode + "\nCipher: " + connection.getCipherSuite();
    }
}