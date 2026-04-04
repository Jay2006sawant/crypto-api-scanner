package com.cryptoscanner.report;

import com.cryptoscanner.model.ScanReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class JsonReporter {
    private final ObjectMapper objectMapper;

    public JsonReporter() {
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    public Path write(ScanReport report) throws IOException {
        Path outputPath = Path.of("test_output", "scan_report.json");
        Files.createDirectories(outputPath.getParent());
        objectMapper.writeValue(outputPath.toFile(), report);
        return outputPath;
    }
}
