package com.cryptoscanner;

import com.cryptoscanner.model.Finding;
import com.cryptoscanner.model.ScanReport;
import com.cryptoscanner.policy.PolicyEvaluator;
import com.cryptoscanner.report.JsonReporter;
import com.cryptoscanner.scanner.CFileScanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java -jar target/crypto-api-scanner.jar <source-directory>");
            System.exit(1);
        }

        Path root = Path.of(args[0]);
        if (!Files.exists(root) || !Files.isDirectory(root)) {
            System.err.println("Input path must be an existing directory: " + root);
            System.exit(1);
        }

        CFileScanner scanner = new CFileScanner();
        List<Finding> findings = new ArrayList<>();
        int totalFiles = 0;

        try (Stream<Path> files = Files.walk(root)) {
            List<Path> sourceFiles = files
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".c") || path.toString().endsWith(".cpp"))
                    .toList();
            totalFiles = sourceFiles.size();
            for (Path sourceFile : sourceFiles) {
                findings.addAll(scanner.scan(sourceFile));
            }
        } catch (IOException e) {
            System.err.println("Failed to scan source directory: " + e.getMessage());
            System.exit(1);
        }

        ScanReport report = new ScanReport();
        report.setScanTimestamp(Instant.now().toString());
        report.setTotalFilesScanned(totalFiles);
        report.setFindings(findings);
        report.setTotalFindings(findings.size());

        JsonReporter jsonReporter = new JsonReporter();
        try {
            Path reportPath = jsonReporter.write(report);
            System.out.println("Raw scan report written to: " + reportPath);
            new PolicyEvaluator().evaluateReport(reportPath);
            System.out.println("Pipeline complete. Findings: " + findings.size());
        } catch (IOException e) {
            System.err.println("Failed to write/evaluate report: " + e.getMessage());
            System.exit(1);
        }
    }
}
