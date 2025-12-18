package io.extio.learn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JksValidatorApplication {
    public static void main(String[] args) {
        java.security.Security.setProperty("crypto.policy", "unlimited");

        // 2. Force TLS 1.2 specifically (System property override)
        System.setProperty("https.protocols", "TLSv1.2");
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
        SpringApplication.run(JksValidatorApplication.class, args);
    }
}