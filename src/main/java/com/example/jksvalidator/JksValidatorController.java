package com.example.jksvalidator;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class JksValidatorController {

    private final JksValidationService service;

    public JksValidatorController(JksValidationService service) {
        this.service = service;
    }

    @GetMapping("/")
    public String index(Model model) {
        // Set default values for first load
        model.addAttribute("method", "GET");
        return "index";
    }

    @PostMapping("/validate")
    public String validate(@RequestParam("file") MultipartFile file,
                           @RequestParam("keystorePassword") String keystorePassword,
                           @RequestParam(value = "keyPassword", required = false) String keyPassword,
                           @RequestParam(value = "alias", required = false) String alias,
                           @RequestParam("url") String url,
                           @RequestParam("method") String method,
                           @RequestParam("headers") String headers,
                           @RequestParam("body") String body,
                           Model model) {

        // Retain user inputs in the form
        model.addAttribute("url", url);
        model.addAttribute("method", method);
        model.addAttribute("headers", headers);
        model.addAttribute("body", body);
        model.addAttribute("keystorePassword", keystorePassword);
        model.addAttribute("keyPassword", keyPassword);
        model.addAttribute("alias", alias);

        try {
            if (url == null || url.trim().isEmpty()) throw new IllegalArgumentException("URL is required");
            if (file.isEmpty()) throw new IllegalArgumentException("JKS File is required");

            String result = service.testConnection(
                    file, keystorePassword, keyPassword, alias, url, method, headers, body
            );

            model.addAttribute("response", result);
            model.addAttribute("success", true);

        } catch (Exception e) {
            Throwable cause = e;
            while (cause.getCause() != null && cause.getCause() != cause) {
                cause = cause.getCause();
            }
            model.addAttribute("response", "Error: " + cause.getMessage());
            model.addAttribute("success", false);
        }
        return "index";
    }
}