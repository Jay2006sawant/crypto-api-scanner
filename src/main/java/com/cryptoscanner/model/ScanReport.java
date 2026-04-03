package com.cryptoscanner.model;

import java.util.ArrayList;
import java.util.List;

public class ScanReport {
    private String scanTimestamp;
    private int totalFilesScanned;
    private int totalFindings;
    private List<Finding> findings = new ArrayList<>();

    public String getScanTimestamp() {
        return scanTimestamp;
    }

    public void setScanTimestamp(String scanTimestamp) {
        this.scanTimestamp = scanTimestamp;
    }

    public int getTotalFilesScanned() {
        return totalFilesScanned;
    }

    public void setTotalFilesScanned(int totalFilesScanned) {
        this.totalFilesScanned = totalFilesScanned;
    }

    public int getTotalFindings() {
        return totalFindings;
    }

    public void setTotalFindings(int totalFindings) {
        this.totalFindings = totalFindings;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }
}
