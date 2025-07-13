package org.sonarsource.plugins.trivy;

import com.google.gson.JsonObject;
import org.junit.Test;
import org.sonarsource.plugins.trivy.model.TrivyData;

import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * Simple test for Trivy SARIF processing
 */
public class SimpleTrivyTest {

    @Test
    public void testParseTrivySarifJson() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Create a minimal Trivy SARIF JSON for testing with proper rule-result relationship
        String minimalTrivySarifJson = "{\n" +
                "  \"version\": \"2.1.0\",\n" +
                "  \"runs\": [\n" +
                "    {\n" +
                "      \"tool\": {\n" +
                "        \"driver\": {\n" +
                "          \"name\": \"Trivy\",\n" +
                "          \"rules\": [\n" +
                "            {\n" +
                "              \"id\": \"CVE-2021-44228\",\n" +
                "              \"name\": \"Log4j Vulnerability\",\n" +
                "              \"helpUri\": \"https://avd.aquasec.com/nvd/cve-2021-44228\",\n" +
                "              \"shortDescription\": {\n" +
                "                \"text\": \"Log4j vulnerability\"\n" +
                "              },\n" +
                "              \"fullDescription\": {\n" +
                "                \"text\": \"Apache Log4j2 vulnerability\"\n" +
                "              },\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 10.0\n" +
                "              },\n" +
                "              \"tags\": [\n" +
                "                \"vulnerability\",\n" +
                "                \"security\",\n" +
                "                \"CRITICAL\"\n" +
                "              ]\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      },\n" +
                "      \"results\": [\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-2021-44228\",\n" +
                "          \"ruleIndex\": 0,\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: org.apache.logging.log4j:log4j-core\\nInstalled Version: 2.14.1\\nFixed Version: 2.15.0\"\n" +
                "          },\n" +
                "          \"locations\": [\n" +
                "            {\n" +
                "              \"physicalLocation\": {\n" +
                "                \"artifactLocation\": {\n" +
                "                  \"uri\": \"pom.xml\"\n" +
                "                },\n" +
                "                \"region\": {\n" +
                "                  \"startLine\": 1,\n" +
                "                  \"startColumn\": 1,\n" +
                "                  \"endLine\": 1,\n" +
                "                  \"endColumn\": 1\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        
        com.google.gson.JsonParser parser = new com.google.gson.JsonParser();
        JsonObject trivySarifJson = parser.parse(minimalTrivySarifJson).getAsJsonObject();
        
        List<TrivyData> trivyDataList = processor.parseTrivySarifJson(trivySarifJson);
        
        assertNotNull("Trivy data list should not be null", trivyDataList);
        assertEquals("Should have exactly one vulnerability", 1, trivyDataList.size());
        
        TrivyData vuln = trivyDataList.get(0);
        assertEquals("Rule ID should match", "CVE-2021-44228", vuln.getRuleId());
        assertEquals("Rule name should match", "Log4j Vulnerability", vuln.getRuleName());
        assertEquals("Severity should be critical based on security-severity", "critical", vuln.getSeverity());
        assertEquals("Package name should be extracted", "org.apache.logging.log4j:log4j-core", vuln.getPackageName());
        assertEquals("Installed version should be extracted", "2.14.1", vuln.getInstalledVersion());
        assertEquals("Fixed version should be extracted", "2.15.0", vuln.getFixedVersion());
        assertEquals("Help URI should match", "https://avd.aquasec.com/nvd/cve-2021-44228", vuln.getHelpUri());
        assertEquals("Description should match", "Apache Log4j2 vulnerability", vuln.getDescription());
        assertEquals("File path should match", "pom.xml", vuln.getFilePath());
        assertEquals("Start line should match", 1, vuln.getStartLine());
        
        System.out.println("Test passed! Successfully parsed Trivy SARIF data:");
        System.out.println("Rule ID: " + vuln.getRuleId());
        System.out.println("Rule Name: " + vuln.getRuleName());
        System.out.println("Severity: " + vuln.getSeverity());
        System.out.println("Package: " + vuln.getPackageName() + "@" + vuln.getInstalledVersion());
        System.out.println("Fixed Version: " + vuln.getFixedVersion());
        System.out.println("Help URI: " + vuln.getHelpUri());
    }
    
    @Test
    public void testTrivyDataStore() {
        TrivyDataStore store = TrivyDataStore.instance();
        assertNotNull("TrivyDataStore instance should not be null", store);
        
        List<String> testLinks = new ArrayList<>();
        testLinks.add("https://test.com");
        
        TrivyData testData = new TrivyData("TEST-CVE", "Test Vulnerability", "high", 
                                          "Test message", "https://test.com", "test.java", 
                                          1, 1, 1, 1, "test-package", "1.0.0", "2.0.0", "Test description", testLinks);
        
        store.addTrivyData(testData);
        
        List<TrivyData> dataList = store.getTrivyData();
        assertNotNull("Data list should not be null", dataList);
        assertFalse("Data list should not be empty", dataList.isEmpty());
        assertEquals("Should have one test data", 1, dataList.size());
        assertEquals("Test data should match", "TEST-CVE", dataList.get(0).getRuleId());
    }
} 