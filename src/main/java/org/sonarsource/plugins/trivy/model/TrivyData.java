package org.sonarsource.plugins.trivy.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Trivy data model for storing vulnerability results from Trivy SARIF format
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrivyData {
    private String ruleId;
    private String ruleName;
    private String severity;
    private String message;
    private String helpUri;
    private String filePath;
    private int startLine;
    private int startColumn;
    private int endLine;
    private int endColumn;
    private String packageName;
    private String installedVersion;
    private String fixedVersion;
    private String description;
    private List<String> links;
} 