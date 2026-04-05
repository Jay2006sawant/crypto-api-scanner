package com.cryptoscanner.policy;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

public class OpaClient {
    private final HttpClient client;
    private final ObjectMapper mapper;
    private final String baseUrl;

    public OpaClient() {
        this("http://localhost:8181");
    }

    public OpaClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        this.mapper = new ObjectMapper();
    }

    public String evaluate(String policy, Object input) {
        try {
            String requestBody = mapper.writeValueAsString(Map.of("input", input));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/data/crypto/" + policy))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return "WARNING: OPA unavailable, using fallback policy checks";
        }
    }
}
