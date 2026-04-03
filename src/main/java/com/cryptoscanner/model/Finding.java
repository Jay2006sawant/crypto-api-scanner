package com.cryptoscanner.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Finding {
    private String filePath;
    private int lineNumber;
    private String functionName;
    private String category;
    private String rawArguments;
    @JsonProperty("keySize")
    private Integer extractedKeySize;
    private boolean flaggedByPolicy;
    private String policyReason;

    public Finding() {
    }

    public Finding(String filePath, int lineNumber, String functionName, String category, String rawArguments, Integer extractedKeySize) {
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.functionName = functionName;
        this.category = category;
        this.rawArguments = rawArguments;
        this.extractedKeySize = extractedKeySize;
        this.flaggedByPolicy = false;
        this.policyReason = "not evaluated";
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(int lineNumber) {
        this.lineNumber = lineNumber;
    }

    public String getFunctionName() {
        return functionName;
    }

    public void setFunctionName(String functionName) {
        this.functionName = functionName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getRawArguments() {
        return rawArguments;
    }

    public void setRawArguments(String rawArguments) {
        this.rawArguments = rawArguments;
    }

    public Integer getExtractedKeySize() {
        return extractedKeySize;
    }

    public void setExtractedKeySize(Integer extractedKeySize) {
        this.extractedKeySize = extractedKeySize;
    }

    public boolean isFlaggedByPolicy() {
        return flaggedByPolicy;
    }

    public void setFlaggedByPolicy(boolean flaggedByPolicy) {
        this.flaggedByPolicy = flaggedByPolicy;
    }

    public String getPolicyReason() {
        return policyReason;
    }

    public void setPolicyReason(String policyReason) {
        this.policyReason = policyReason;
    }
}
