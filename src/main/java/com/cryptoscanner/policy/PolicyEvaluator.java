package com.cryptoscanner.policy;

import com.cryptoscanner.model.Finding;
import com.cryptoscanner.model.ScanReport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public class PolicyEvaluator {
    private final OpaClient opaClient;
    private final ObjectMapper objectMapper;

    public PolicyEvaluator() {
        this(new OpaClient());
    }

    public PolicyEvaluator(OpaClient opaClient) {
        this.opaClient = opaClient;
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    public ScanReport evaluateReport(Path reportPath) throws IOException {
        ScanReport report = objectMapper.readValue(reportPath.toFile(), ScanReport.class);
        evaluateReportInMemory(report);
        objectMapper.writeValue(reportPath.toFile(), report);
        printSummary(report);
        return report;
    }

    public void evaluateReportInMemory(ScanReport report) {
        for (Finding finding : report.getFindings()) {
            String response = opaClient.evaluate("crypto_policy", finding);
            if (response.startsWith("WARNING:")) {
                applyFallbackPolicy(finding);
            } else {
                applyFromOpaResponse(finding, response);
            }
        }
    }

    public void applyFallbackPolicy(Finding finding) {
        if ("MD5_Init".equals(finding.getFunctionName())) {
            finding.setFlaggedByPolicy(true);
            finding.setPolicyReason("deny: weak algorithm MD5");
            return;
        }
        if ("SHA256_Init".equals(finding.getFunctionName()) && finding.getExtractedKeySize() == null) {
            finding.setFlaggedByPolicy(false);
            finding.setPolicyReason("warn: SHA256 without explicit key size");
            return;
        }
        if ("hashing".equals(finding.getCategory())) {
            finding.setFlaggedByPolicy(false);
            finding.setPolicyReason("allow: hashing accepted");
            return;
        }
        if ("encryption".equals(finding.getCategory())
                && finding.getExtractedKeySize() != null
                && finding.getExtractedKeySize() < 128) {
            finding.setFlaggedByPolicy(true);
            finding.setPolicyReason("deny: encryption key size below 128");
            return;
        }
        finding.setFlaggedByPolicy(false);
        finding.setPolicyReason("allow: policy checks passed");
    }

    private void applyFromOpaResponse(Finding finding, String responseBody) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode result = root.path("result");
            if (result.isMissingNode() || result.isNull()) {
                applyFallbackPolicy(finding);
                return;
            }
            String decision = result.path("result").asText("allow");
            String reason = result.path("reason").asText("policy decision");
            finding.setFlaggedByPolicy("deny".equalsIgnoreCase(decision));
            finding.setPolicyReason(decision + ": " + reason);
        } catch (Exception e) {
            applyFallbackPolicy(finding);
        }
    }

    private void printSummary(ScanReport report) {
        Map<String, int[]> perFileStats = new LinkedHashMap<>();
        for (Finding finding : report.getFindings()) {
            int[] stats = perFileStats.computeIfAbsent(finding.getFilePath(), key -> new int[]{0, 0});
            stats[0]++;
            if (finding.isFlaggedByPolicy()) {
                stats[1]++;
            }
        }

        System.out.println("Policy evaluation summary");
        System.out.println("file | total | flagged | status");
        for (Map.Entry<String, int[]> entry : perFileStats.entrySet()) {
            int total = entry.getValue()[0];
            int flagged = entry.getValue()[1];
            String status = flagged > 0 ? "FAIL" : "PASS";
            System.out.println(entry.getKey() + " | " + total + " | " + flagged + " | " + status);
        }
    }
}
