package io.extio.learn;

public class ValidationResult {
    private final int statusCode;
    private final String statusMessage;
    private final String cipherSuite;
    private final String body;

    public ValidationResult(int statusCode, String statusMessage, String cipherSuite, String body) {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
        this.cipherSuite = cipherSuite;
        this.body = body;
    }

    public int getStatusCode() { return statusCode; }
    public String getStatusMessage() { return statusMessage; }
    public String getCipherSuite() { return cipherSuite; }
    public String getBody() { return body; }
}