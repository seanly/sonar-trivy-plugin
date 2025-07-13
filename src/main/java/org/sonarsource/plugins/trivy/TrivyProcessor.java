package org.sonarsource.plugins.trivy;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.sonarsource.plugins.trivy.model.TrivyData;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Trivy processor for parsing Trivy vulnerability reports in SARIF format
 */
public class TrivyProcessor {
    
    private static final Logger LOGGER = Loggers.get(TrivyProcessor.class);
    private static final Pattern SEMVER_PATTERN = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)(?:-(.+))?(?:\\+(.+))?$");
    
    /**
     * Parse Trivy SARIF file and extract vulnerability data
     * @param trivySarifFile The Trivy SARIF file to parse
     * @return List of TrivyData objects
     */
    public List<TrivyData> parseTrivySarifFile(File trivySarifFile) {
        List<TrivyData> trivyDataList = new ArrayList<>();
        
        if (!trivySarifFile.exists()) {
            LOGGER.warn("Trivy SARIF file does not exist: {}", trivySarifFile.getAbsolutePath());
            return trivyDataList;
        }
        
        try (Reader reader = new FileReader(trivySarifFile)) {
            JsonObject trivySarifJson = new JsonParser().parse(reader).getAsJsonObject();
            trivyDataList = parseTrivySarifJson(trivySarifJson);
            LOGGER.info("Parsed {} vulnerabilities from Trivy SARIF file", trivyDataList.size());
        } catch (IOException e) {
            LOGGER.error("Error reading Trivy SARIF file: {}", e.getMessage(), e);
        } catch (Exception e) {
            LOGGER.error("Error parsing Trivy SARIF file: {}", e.getMessage(), e);
        }
        
        return trivyDataList;
    }
    
    /**
     * Parse Trivy SARIF JSON content
     * @param trivySarifJson The Trivy SARIF JSON object
     * @return List of TrivyData objects
     */
    public List<TrivyData> parseTrivySarifJson(JsonObject trivySarifJson) {
        List<TrivyData> trivyDataList = new ArrayList<>();
        
        try {
            JsonArray runs = trivySarifJson.getAsJsonArray("runs");
            if (runs == null) {
                LOGGER.warn("No 'runs' array found in Trivy SARIF file");
                return trivyDataList;
            }
            
            for (JsonElement runElement : runs) {
                JsonObject run = runElement.getAsJsonObject();
                parseRun(run, trivyDataList);
            }
            
            // Apply deduplication and version optimization
            trivyDataList = deduplicateAndOptimizeVersions(trivyDataList);
            LOGGER.info("After deduplication and optimization: {} vulnerabilities", trivyDataList.size());
            
        } catch (Exception e) {
            LOGGER.error("Error parsing Trivy SARIF JSON: {}", e.getMessage(), e);
        }
        
        return trivyDataList;
    }
    
    private void parseRun(JsonObject run, List<TrivyData> trivyDataList) {
        // Parse tool information
        JsonObject tool = run.getAsJsonObject("tool");
        if (tool == null) {
            return;
        }
        
        JsonObject driver = tool.getAsJsonObject("driver");
        if (driver == null) {
            return;
        }
        
        // Parse rules first - this creates the rule definitions
        Map<String, JsonObject> rulesMap = parseRules(driver);
        
        // Parse results - each result references a rule by ruleId
        JsonArray results = run.getAsJsonArray("results");
        if (results == null) {
            return;
        }
        
        for (JsonElement resultElement : results) {
            JsonObject result = resultElement.getAsJsonObject();
            parseResult(result, rulesMap, trivyDataList);
        }
    }
    
    private Map<String, JsonObject> parseRules(JsonObject driver) {
        Map<String, JsonObject> rulesMap = new HashMap<>();
        
        JsonArray rules = driver.getAsJsonArray("rules");
        if (rules != null) {
            for (JsonElement ruleElement : rules) {
                JsonObject rule = ruleElement.getAsJsonObject();
                String ruleId = getStringValue(rule, "id");
                if (ruleId != null) {
                    rulesMap.put(ruleId, rule);
                }
            }
        }
        
        return rulesMap;
    }
    
    private void parseResult(JsonObject result, Map<String, JsonObject> rulesMap, List<TrivyData> trivyDataList) {
        try {
            String ruleId = getStringValue(result, "ruleId");
            String level = getStringValue(result, "level");
            String message = getMessageText(result);
            
            // Get the referenced rule
            JsonObject rule = rulesMap.get(ruleId);
            if (rule == null) {
                LOGGER.warn("Rule not found for ruleId: {}", ruleId);
                return;
            }
            
            // Extract information from the rule
            String ruleName = getStringValue(rule, "name");
            String helpUri = getStringValue(rule, "helpUri");
            String description = getRuleDescription(rule);
            String severity = getSeverityFromRule(rule);
            
            // Parse locations
            JsonArray locations = result.getAsJsonArray("locations");
            if (locations != null && locations.size() > 0) {
                for (JsonElement locationElement : locations) {
                    JsonObject location = locationElement.getAsJsonObject();
                    parseLocation(location, ruleId, level, message, helpUri, ruleName, description, severity, trivyDataList);
                }
            } else {
                // Create entry without location information
                TrivyData trivyData = createTrivyData(ruleId, level, message, helpUri, ruleName, description, severity, null, null);
                if (trivyData != null) {
                    trivyDataList.add(trivyData);
                }
            }
            
        } catch (Exception e) {
            LOGGER.error("Error parsing result: {}", e.getMessage(), e);
        }
    }
    
    private void parseLocation(JsonObject location, String ruleId, String level, String message, 
                             String helpUri, String ruleName, String description, String severity,
                             List<TrivyData> trivyDataList) {
        JsonObject physicalLocation = location.getAsJsonObject("physicalLocation");
        if (physicalLocation == null) {
            return;
        }
        
        JsonObject artifactLocation = physicalLocation.getAsJsonObject("artifactLocation");
        JsonObject region = physicalLocation.getAsJsonObject("region");
        
        String filePath = null;
        if (artifactLocation != null) {
            filePath = getStringValue(artifactLocation, "uri");
        }
        
        TrivyData trivyData = createTrivyData(ruleId, level, message, helpUri, ruleName, description, severity, filePath, region);
        if (trivyData != null) {
            trivyDataList.add(trivyData);
        }
    }
    
    private TrivyData createTrivyData(String ruleId, String level, String message, String helpUri,
                                    String ruleName, String description, String severity,
                                    String filePath, JsonObject region) {
        try {
            // Extract package information from message
            String packageName = extractPackageName(message);
            String installedVersion = extractInstalledVersion(message);
            String fixedVersion = extractFixedVersion(message);
            
            // Extract link from message text and create list
            List<String> links = new ArrayList<>();
            String link = extractLinkFromMessage(message);
            if (link != null && !link.isEmpty()) {
                links.add(link);
            }
            
            // Parse location information
            int startLine = 1;
            int startColumn = 1;
            int endLine = 1;
            int endColumn = 1;
            
            if (region != null) {
                startLine = getIntValue(region, "startLine", 1);
                startColumn = getIntValue(region, "startColumn", 1);
                endLine = getIntValue(region, "endLine", startLine);
                endColumn = getIntValue(region, "endColumn", startColumn);
            }
            
            return new TrivyData(ruleId, ruleName, severity, message, helpUri, filePath,
                               startLine, startColumn, endLine, endColumn,
                               packageName, installedVersion, fixedVersion, description, links);
                               
        } catch (Exception e) {
            LOGGER.error("Error creating TrivyData: {}", e.getMessage(), e);
            return null;
        }
    }
    
    private String getStringValue(JsonObject obj, String key) {
        JsonElement element = obj.get(key);
        return element != null && !element.isJsonNull() ? element.getAsString() : null;
    }
    
    private int getIntValue(JsonObject obj, String key, int defaultValue) {
        JsonElement element = obj.get(key);
        return element != null && !element.isJsonNull() ? element.getAsInt() : defaultValue;
    }
    
    private String getMessageText(JsonObject result) {
        JsonObject messageObj = result.getAsJsonObject("message");
        if (messageObj != null) {
            return getStringValue(messageObj, "text");
        }
        return "";
    }
    
    private String getRuleDescription(JsonObject rule) {
        JsonObject fullDescription = rule.getAsJsonObject("fullDescription");
        if (fullDescription != null) {
            return getStringValue(fullDescription, "text");
        }
        
        JsonObject shortDescription = rule.getAsJsonObject("shortDescription");
        if (shortDescription != null) {
            return getStringValue(shortDescription, "text");
        }
        
        return "";
    }
    
    private String getSeverityFromRule(JsonObject rule) {
        // Try to get severity from properties.security-severity
        JsonObject properties = rule.getAsJsonObject("properties");
        if (properties != null) {
            JsonElement securitySeverity = properties.get("security-severity");
            if (securitySeverity != null && !securitySeverity.isJsonNull()) {
                double severityValue = securitySeverity.getAsDouble();
                if (severityValue >= 9.0) {
                    return "critical";
                } else if (severityValue >= 7.0) {
                    return "high";
                } else if (severityValue >= 4.0) {
                    return "medium";
                } else {
                    return "low";
                }
            }
        }
        
        // Try to get severity from tags
        JsonArray tags = rule.getAsJsonArray("tags");
        if (tags != null) {
            for (JsonElement tag : tags) {
                String tagValue = tag.getAsString();
                if (tagValue.equals("CRITICAL")) {
                    return "critical";
                } else if (tagValue.equals("HIGH")) {
                    return "high";
                } else if (tagValue.equals("MEDIUM")) {
                    return "medium";
                } else if (tagValue.equals("LOW")) {
                    return "low";
                }
            }
        }
        
        // Default to high if no severity found
        return "high";
    }
    
    private String extractPackageName(String message) {
        // Extract package name from Trivy message format
        // Example: "Package: com.fasterxml.jackson.core:jackson-core"
        if (message != null && message.contains("Package:")) {
            int start = message.indexOf("Package:") + 8;
            int end = message.indexOf("\n", start);
            if (end == -1) {
                end = message.length();
            }
            return message.substring(start, end).trim();
        }
        return "";
    }
    
    private String extractInstalledVersion(String message) {
        // Extract installed version from Trivy message format
        // Example: "Installed Version: 2.12.3"
        if (message != null && message.contains("Installed Version:")) {
            int start = message.indexOf("Installed Version:") + 18;
            int end = message.indexOf("\n", start);
            if (end == -1) {
                end = message.length();
            }
            return message.substring(start, end).trim();
        }
        return "";
    }
    
    private String extractFixedVersion(String message) {
        // Extract fixed version from Trivy message format
        // Example: "Fixed Version: 2.15.0"
        if (message != null && message.contains("Fixed Version:")) {
            int start = message.indexOf("Fixed Version:") + 14;
            int end = message.indexOf("\n", start);
            if (end == -1) {
                end = message.length();
            }
            return message.substring(start, end).trim();
        }
        return "";
    }
    
    private String extractLinkFromMessage(String message) {
        // Extract link from Trivy message format
        // Example: "Link: [CVE-2022-25647](https://avd.aquasec.com/nvd/cve-2022-25647)"
        if (message != null && message.contains("Link:")) {
            int start = message.indexOf("Link:") + 5;
            int end = message.indexOf("\n", start);
            if (end == -1) {
                end = message.length();
            }
            String linkText = message.substring(start, end).trim();
            
            // Extract URL from markdown format [text](url)
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[([^\\]]+)\\]\\(([^)]+)\\)");
            java.util.regex.Matcher matcher = pattern.matcher(linkText);
            
            if (matcher.find()) {
                return matcher.group(2); // Return the URL part
            }
        }
        return null;
    }

    private List<TrivyData> deduplicateAndOptimizeVersions(List<TrivyData> trivyDataList) {
        Map<String, TrivyData> uniqueResults = new HashMap<>();
        
        for (TrivyData data : trivyDataList) {
            // Create a key based on packageName and installedVersion only
            String key = createDeduplicationKey(data);
            
            if (!uniqueResults.containsKey(key)) {
                uniqueResults.put(key, data);
            } else {
                // If we have a duplicate, merge links and keep the one with the highest fixed version
                TrivyData existing = uniqueResults.get(key);
                
                // Merge links from both entries
                List<String> mergedLinks = new ArrayList<>(existing.getLinks());
                if (data.getLinks() != null) {
                    for (String link : data.getLinks()) {
                        if (!mergedLinks.contains(link)) {
                            mergedLinks.add(link);
                        }
                    }
                }
                existing.setLinks(mergedLinks);
                
                int comparison = compareVersions(data.getFixedVersion(), existing.getFixedVersion());
                if (comparison > 0) {
                    LOGGER.debug("Replacing entry for key {} with higher fixed version: {} -> {}", 
                                key, existing.getFixedVersion(), data.getFixedVersion());
                    // Update the existing entry with new data but keep merged links
                    data.setLinks(mergedLinks);
                    uniqueResults.put(key, data);
                } else if (comparison == 0) {
                    // If fixed versions are equal, prefer the one with higher severity
                    if (compareSeverity(data.getSeverity(), existing.getSeverity()) > 0) {
                        LOGGER.debug("Replacing entry for key {} with higher severity: {} -> {}", 
                                    key, existing.getSeverity(), data.getSeverity());
                        // Update the existing entry with new data but keep merged links
                        data.setLinks(mergedLinks);
                        uniqueResults.put(key, data);
                    }
                }
            }
        }
        
        LOGGER.info("Deduplication reduced {} entries to {} unique entries", 
                   trivyDataList.size(), uniqueResults.size());
        
        return new ArrayList<>(uniqueResults.values());
    }
    
    private String createDeduplicationKey(TrivyData data) {
        // Create a unique key based on packageName and installedVersion only
        // This ensures we deduplicate entries with the same package and version
        // If both packageName and installedVersion are empty, include ruleId to avoid deduplication
        String packageName = data.getPackageName() != null ? data.getPackageName() : "";
        String installedVersion = data.getInstalledVersion() != null ? data.getInstalledVersion() : "";
        
        if (packageName.isEmpty() && installedVersion.isEmpty()) {
            // If no package information, include ruleId to avoid deduplication
            return data.getRuleId() != null ? data.getRuleId() : "";
        }
        
        StringBuilder key = new StringBuilder();
        key.append(packageName);
        key.append("|");
        key.append(installedVersion);
        return key.toString();
    }

    private int compareVersions(String version1, String version2) {
        if (version1 == null && version2 == null) {
            return 0;
        }
        if (version1 == null) {
            return -1;
        }
        if (version2 == null) {
            return 1;
        }
        
        // Check if both versions are valid semver
        boolean isSemver1 = isValidSemver(version1);
        boolean isSemver2 = isValidSemver(version2);
        
        if (isSemver1 && isSemver2) {
            // Both are valid semver, use semver comparison
            try {
                return compareSemver(version1, version2);
            } catch (Exception e) {
                LOGGER.debug("Error in semver comparison, falling back to string comparison: {}", e.getMessage());
                return version1.compareTo(version2);
            }
        } else if (isSemver1) {
            // Only version1 is semver, prefer it
            return 1;
        } else if (isSemver2) {
            // Only version2 is semver, prefer it
            return -1;
        } else {
            // Neither is semver, use string comparison
            return version1.compareTo(version2);
        }
    }
    
    private boolean isValidSemver(String version) {
        if (version == null || version.trim().isEmpty()) {
            return false;
        }
        return SEMVER_PATTERN.matcher(version.trim()).matches();
    }
    
    private int compareSemver(String version1, String version2) {
        if (version1.equals(version2)) {
            return 0;
        }
        
        // Extract major.minor.patch parts
        String[] parts1 = version1.split("[-+]")[0].split("\\.");
        String[] parts2 = version2.split("[-+]")[0].split("\\.");
        
        int maxLength = Math.max(parts1.length, parts2.length);
        
        // Compare major.minor.patch numerically
        for (int i = 0; i < maxLength; i++) {
            int num1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
            int num2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;
            
            if (num1 != num2) {
                return Integer.compare(num1, num2);
            }
        }
        
        // If major.minor.patch are equal, compare pre-release versions
        String preRelease1 = extractPreRelease(version1);
        String preRelease2 = extractPreRelease(version2);
        
        // According to semver spec: pre-release versions have lower precedence than release versions
        if (preRelease1.isEmpty() && !preRelease2.isEmpty()) {
            return 1; // version1 is release, version2 is pre-release
        }
        if (!preRelease1.isEmpty() && preRelease2.isEmpty()) {
            return -1; // version1 is pre-release, version2 is release
        }
        if (preRelease1.isEmpty() && preRelease2.isEmpty()) {
            return 0; // Both are release versions with same major.minor.patch
        }
        
        // Both have pre-release, compare them
        return comparePreRelease(preRelease1, preRelease2);
    }
    
    private int comparePreRelease(String preRelease1, String preRelease2) {
        if (preRelease1.equals(preRelease2)) {
            return 0;
        }
        
        String[] parts1 = preRelease1.split("\\.");
        String[] parts2 = preRelease2.split("\\.");
        
        int maxLength = Math.max(parts1.length, parts2.length);
        
        for (int i = 0; i < maxLength; i++) {
            String part1 = i < parts1.length ? parts1[i] : "";
            String part2 = i < parts2.length ? parts2[i] : "";
            
            // Try to compare as numbers first
            try {
                int num1 = Integer.parseInt(part1);
                int num2 = Integer.parseInt(part2);
                if (num1 != num2) {
                    return Integer.compare(num1, num2);
                }
            } catch (NumberFormatException e) {
                // If not numbers, compare as strings
                int comparison = part1.compareTo(part2);
                if (comparison != 0) {
                    return comparison;
                }
            }
        }
        
        return 0;
    }
    
    private String extractPreRelease(String version) {
        int dashIndex = version.indexOf('-');
        if (dashIndex != -1) {
            int plusIndex = version.indexOf('+');
            if (plusIndex != -1 && plusIndex > dashIndex) {
                return version.substring(dashIndex + 1, plusIndex);
            } else {
                return version.substring(dashIndex + 1);
            }
        }
        return "";
    }
    
    /**
     * Compare severity levels and return positive if severity1 is higher than severity2
     * @param severity1 First severity level
     * @param severity2 Second severity level
     * @return Positive if severity1 > severity2, 0 if equal, negative if severity1 < severity2
     */
    private int compareSeverity(String severity1, String severity2) {
        if (severity1 == null && severity2 == null) {
            return 0;
        }
        if (severity1 == null) {
            return -1;
        }
        if (severity2 == null) {
            return 1;
        }
        
        // Define severity hierarchy (higher index = higher severity)
        String[] severityLevels = {"low", "medium", "high", "critical"};
        
        int index1 = -1;
        int index2 = -1;
        
        for (int i = 0; i < severityLevels.length; i++) {
            if (severity1.toLowerCase().equals(severityLevels[i])) {
                index1 = i;
            }
            if (severity2.toLowerCase().equals(severityLevels[i])) {
                index2 = i;
            }
        }
        
        // If both severities are recognized, compare by index
        if (index1 >= 0 && index2 >= 0) {
            return Integer.compare(index1, index2);
        }
        
        // If only one is recognized, prefer the recognized one
        if (index1 >= 0) {
            return 1;
        }
        if (index2 >= 0) {
            return -1;
        }
        
        // If neither is recognized, use string comparison
        return severity1.compareToIgnoreCase(severity2);
    }
} 