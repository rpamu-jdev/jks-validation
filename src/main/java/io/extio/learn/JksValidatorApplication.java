package io.extio.learn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JksValidatorApplication {
    public static void main(String[] args) {

        System.out.println("==================================================================================");
        System.out.println(" APPLICATION  : JksValidatorApplication v1.0");
        System.out.println(" AUTHOR       : Rajkumar Pamu");
        System.out.println(" DESCRIPTION  : Facilitates validation of JKS files by attempting connections");
        System.out.println("                to URLs. Enforces TLS 1.2 and Unlimited Crypto policy.");
        System.out.println(" START TIME   : " + java.time.LocalDateTime.now());
        System.out.println("==================================================================================");

        java.security.Security.setProperty("crypto.policy", "unlimited");

        // 2. Force TLS 1.2 specifically (System property override)
        System.setProperty("https.protocols", "TLSv1.2");
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
        SpringApplication.run(JksValidatorApplication.class, args);
    }
}