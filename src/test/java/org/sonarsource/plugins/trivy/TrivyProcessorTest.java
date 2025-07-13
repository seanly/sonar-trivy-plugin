package org.sonarsource.plugins.trivy;

import com.google.gson.JsonObject;
import org.junit.Test;
import org.sonarsource.plugins.trivy.model.TrivyData;

import java.io.File;
import java.util.List;
import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * Test class for TrivyProcessor
 */
public class TrivyProcessorTest {

    @Test
    public void testParseTrivySarifFile() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Test with the provided Trivy SARIF file
        File trivySarifFile = new File("trivy-report.sarif");
        
        if (trivySarifFile.exists()) {
            List<TrivyData> trivyDataList = processor.parseTrivySarifFile(trivySarifFile);
            
            assertNotNull("Trivy data list should not be null", trivyDataList);
            assertFalse("Trivy data list should not be empty", trivyDataList.isEmpty());
            
            // Check first vulnerability
            TrivyData firstVuln = trivyDataList.get(0);
            assertNotNull("Rule ID should not be null", firstVuln.getRuleId());
            assertNotNull("Rule name should not be null", firstVuln.getRuleName());
            assertNotNull("Severity should not be null", firstVuln.getSeverity());
            assertNotNull("Message should not be null", firstVuln.getMessage());
            
            // Check that we have helpUri for vulnerability details
            assertNotNull("Help URI should not be null", firstVuln.getHelpUri());
            assertTrue("Help URI should be a valid URL", 
                      firstVuln.getHelpUri().startsWith("https://avd.aquasec.com/nvd/"));
            
            // Check that package information is extracted
            assertNotNull("Package name should be extracted", firstVuln.getPackageName());
            assertNotNull("Installed version should be extracted", firstVuln.getInstalledVersion());
            
            System.out.println("Found " + trivyDataList.size() + " vulnerabilities");
            System.out.println("First vulnerability: " + firstVuln.getRuleId() + " - " + firstVuln.getSeverity());
            System.out.println("Package: " + firstVuln.getPackageName() + "@" + firstVuln.getInstalledVersion());
        } else {
            System.out.println("Trivy SARIF file not found, skipping test");
        }
    }
    
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
    }
    
    @Test
    public void testSeverityMapping() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Test severity mapping from security-severity values
        String trivySarifJsonWithSeverities = "{\n" +
                "  \"version\": \"2.1.0\",\n" +
                "  \"runs\": [\n" +
                "    {\n" +
                "      \"tool\": {\n" +
                "        \"driver\": {\n" +
                "          \"name\": \"Trivy\",\n" +
                "          \"rules\": [\n" +
                "            {\n" +
                "              \"id\": \"CVE-CRITICAL\",\n" +
                "              \"name\": \"Critical Vulnerability\",\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 9.8\n" +
                "              }\n" +
                "            },\n" +
                "            {\n" +
                "              \"id\": \"CVE-HIGH\",\n" +
                "              \"name\": \"High Vulnerability\",\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 7.5\n" +
                "              }\n" +
                "            },\n" +
                "            {\n" +
                "              \"id\": \"CVE-MEDIUM\",\n" +
                "              \"name\": \"Medium Vulnerability\",\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 5.0\n" +
                "              }\n" +
                "            },\n" +
                "            {\n" +
                "              \"id\": \"CVE-LOW\",\n" +
                "              \"name\": \"Low Vulnerability\",\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 2.0\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      },\n" +
                "      \"results\": [\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-CRITICAL\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Critical vulnerability found\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-HIGH\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"High vulnerability found\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-MEDIUM\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Medium vulnerability found\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-LOW\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Low vulnerability found\"\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        
        com.google.gson.JsonParser parser = new com.google.gson.JsonParser();
        JsonObject trivySarifJson = parser.parse(trivySarifJsonWithSeverities).getAsJsonObject();
        
        List<TrivyData> trivyDataList = processor.parseTrivySarifJson(trivySarifJson);
        
        assertEquals("Should have exactly 4 vulnerabilities", 4, trivyDataList.size());
        
        // Check severity mapping
        assertEquals("Critical severity should be mapped correctly", "critical", 
                    trivyDataList.stream().filter(v -> v.getRuleId().equals("CVE-CRITICAL")).findFirst().get().getSeverity());
        assertEquals("High severity should be mapped correctly", "high", 
                    trivyDataList.stream().filter(v -> v.getRuleId().equals("CVE-HIGH")).findFirst().get().getSeverity());
        assertEquals("Medium severity should be mapped correctly", "medium", 
                    trivyDataList.stream().filter(v -> v.getRuleId().equals("CVE-MEDIUM")).findFirst().get().getSeverity());
        assertEquals("Low severity should be mapped correctly", "low", 
                    trivyDataList.stream().filter(v -> v.getRuleId().equals("CVE-LOW")).findFirst().get().getSeverity());
    }
    
    @Test
    public void testDeduplicationAndVersionOptimization() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Create test data with duplicates and different fixed versions
        String trivySarifJsonWithDuplicates = "{\n" +
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
                "              \"properties\": {\n" +
                "                \"security-severity\": 9.8\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      },\n" +
                "      \"results\": [\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-2021-44228\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: org.apache.logging.log4j:log4j-core\\nInstalled Version: 2.14.1\\nFixed Version: 2.15.0\"\n" +
                "          },\n" +
                "          \"locations\": [\n" +
                "            {\n" +
                "              \"physicalLocation\": {\n" +
                "                \"artifactLocation\": {\n" +
                "                  \"uri\": \"pom.xml\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-2021-44228\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: org.apache.logging.log4j:log4j-core\\nInstalled Version: 2.14.1\\nFixed Version: 2.16.0\"\n" +
                "          },\n" +
                "          \"locations\": [\n" +
                "            {\n" +
                "              \"physicalLocation\": {\n" +
                "                \"artifactLocation\": {\n" +
                "                  \"uri\": \"pom.xml\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-2021-44228\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: org.apache.logging.log4j:log4j-core\\nInstalled Version: 2.14.1\\nFixed Version: 2.15.0\"\n" +
                "          },\n" +
                "          \"locations\": [\n" +
                "            {\n" +
                "              \"physicalLocation\": {\n" +
                "                \"artifactLocation\": {\n" +
                "                  \"uri\": \"build.gradle\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-2021-44228\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: com.fasterxml.jackson.core:jackson-core\\nInstalled Version: 2.12.3\\nFixed Version: 2.15.0\"\n" +
                "          },\n" +
                "          \"locations\": [\n" +
                "            {\n" +
                "              \"physicalLocation\": {\n" +
                "                \"artifactLocation\": {\n" +
                "                  \"uri\": \"pom.xml\"\n" +
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
        JsonObject trivySarifJson = parser.parse(trivySarifJsonWithDuplicates).getAsJsonObject();
        
        List<TrivyData> trivyDataList = processor.parseTrivySarifJson(trivySarifJson);
        
        // Should be deduplicated to 2 unique entries (same ruleId + packageName + installedVersion)
        assertEquals("Should have exactly 2 unique vulnerabilities after deduplication", 2, trivyDataList.size());
        
        // Find the log4j vulnerability (should have the highest fixed version 2.16.0)
        TrivyData log4jVuln = trivyDataList.stream()
                .filter(v -> v.getPackageName().equals("org.apache.logging.log4j:log4j-core"))
                .findFirst()
                .orElse(null);
        
        assertNotNull("Log4j vulnerability should be found", log4jVuln);
        assertEquals("Should have the highest fixed version", "2.16.0", log4jVuln.getFixedVersion());
        
        // Find the jackson vulnerability
        TrivyData jacksonVuln = trivyDataList.stream()
                .filter(v -> v.getPackageName().equals("com.fasterxml.jackson.core:jackson-core"))
                .findFirst()
                .orElse(null);
        
        assertNotNull("Jackson vulnerability should be found", jacksonVuln);
        assertEquals("Should have the correct fixed version", "2.15.0", jacksonVuln.getFixedVersion());
    }
    
    @Test
    public void testDeduplicationWithPackageAndVersion() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Create test data with same packageName and installedVersion but different fixed versions
        List<TrivyData> testData = new ArrayList<>();
        
        // Test case 1: Same package and installed version, different fixed versions
        List<String> links1 = new ArrayList<>();
        links1.add("http://example.com/cve1");
        TrivyData data1 = new TrivyData("CVE-2021-1234", "Test Vuln 1", "high", "Test message 1", 
                                       "http://example.com", "test.java", 1, 1, 1, 1,
                                       "com.example:test-package", "1.0.0", "1.0.1", "Description 1", links1);
        
        List<String> links2 = new ArrayList<>();
        links2.add("http://example.com/cve2");
        TrivyData data2 = new TrivyData("CVE-2021-1234", "Test Vuln 1", "high", "Test message 2", 
                                       "http://example.com", "test.java", 1, 1, 1, 1,
                                       "com.example:test-package", "1.0.0", "1.0.2", "Description 2", links2);
        
        List<String> links3 = new ArrayList<>();
        links3.add("http://example.com/cve3");
        TrivyData data3 = new TrivyData("CVE-2021-1234", "Test Vuln 1", "high", "Test message 3", 
                                       "http://example.com", "test.java", 1, 1, 1, 1,
                                       "com.example:test-package", "1.0.0", "1.0.0", "Description 3", links3);
        
        // Test case 2: Different package, should not be deduplicated
        List<String> links4 = new ArrayList<>();
        links4.add("http://example.com/cve4");
        TrivyData data4 = new TrivyData("CVE-2021-5678", "Test Vuln 2", "medium", "Test message 4", 
                                       "http://example.com", "test2.java", 1, 1, 1, 1,
                                       "com.example:other-package", "1.0.0", "1.0.1", "Description 4", links4);
        
        // Test case 3: Same package but different installed version, should not be deduplicated
        List<String> links5 = new ArrayList<>();
        links5.add("http://example.com/cve5");
        TrivyData data5 = new TrivyData("CVE-2021-1234", "Test Vuln 1", "high", "Test message 5", 
                                       "http://example.com", "test.java", 1, 1, 1, 1,
                                       "com.example:test-package", "1.0.1", "1.0.2", "Description 5", links5);
        
        testData.add(data1);
        testData.add(data2);
        testData.add(data3);
        testData.add(data4);
        testData.add(data5);
        
        // Use reflection to call the private method
        try {
            java.lang.reflect.Method deduplicateMethod = TrivyProcessor.class.getDeclaredMethod("deduplicateAndOptimizeVersions", List.class);
            deduplicateMethod.setAccessible(true);
            
            @SuppressWarnings("unchecked")
            List<TrivyData> result = (List<TrivyData>) deduplicateMethod.invoke(processor, testData);
            
            // Should have 3 unique entries (data2 with highest fixed version, data4, data5)
            assertEquals("Should have 3 unique entries after deduplication", 3, result.size());
            
            // Find the entry for com.example:test-package with installed version 1.0.0
            TrivyData deduplicatedEntry = null;
            for (TrivyData data : result) {
                if ("com.example:test-package".equals(data.getPackageName()) && 
                    "1.0.0".equals(data.getInstalledVersion())) {
                    deduplicatedEntry = data;
                    break;
                }
            }
            
            assertNotNull("Should find deduplicated entry", deduplicatedEntry);
            assertEquals("Should keep the entry with highest fixed version", "1.0.2", deduplicatedEntry.getFixedVersion());
            
        } catch (Exception e) {
            fail("Test failed with exception: " + e.getMessage());
        }
    }
    
    @Test
    public void testSemverVersionComparison() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Test semver comparison using reflection
        try {
            java.lang.reflect.Method compareVersionsMethod = TrivyProcessor.class.getDeclaredMethod("compareVersions", String.class, String.class);
            compareVersionsMethod.setAccessible(true);
            
            // Test cases for semver comparison
            assertEquals("1.0.2 should be greater than 1.0.1", 1, compareVersionsMethod.invoke(processor, "1.0.2", "1.0.1"));
            assertEquals("1.0.1 should be less than 1.0.2", -1, compareVersionsMethod.invoke(processor, "1.0.1", "1.0.2"));
            assertEquals("1.0.1 should equal 1.0.1", 0, compareVersionsMethod.invoke(processor, "1.0.1", "1.0.1"));
            
            // Test pre-release versions
            assertEquals("1.0.0 should be greater than 1.0.0-alpha", 1, compareVersionsMethod.invoke(processor, "1.0.0", "1.0.0-alpha"));
            assertEquals("1.0.0-alpha should be less than 1.0.0", -1, compareVersionsMethod.invoke(processor, "1.0.0-alpha", "1.0.0"));
            
            // Test build metadata (should be ignored in comparison)
            assertEquals("1.0.0+build should equal 1.0.0", 0, compareVersionsMethod.invoke(processor, "1.0.0+build", "1.0.0"));
            
        } catch (Exception e) {
            fail("Test failed with exception: " + e.getMessage());
        }
    }
    
    @Test
    public void testSemverComparison() {
        TrivyProcessor processor = new TrivyProcessor();
        
        // Test semver comparison with different version formats
        String trivySarifJsonWithVersions = "{\n" +
                "  \"version\": \"2.1.0\",\n" +
                "  \"runs\": [\n" +
                "    {\n" +
                "      \"tool\": {\n" +
                "        \"driver\": {\n" +
                "          \"name\": \"Trivy\",\n" +
                "          \"rules\": [\n" +
                "            {\n" +
                "              \"id\": \"CVE-TEST\",\n" +
                "              \"name\": \"Test Vulnerability\",\n" +
                "              \"properties\": {\n" +
                "                \"security-severity\": 7.0\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      },\n" +
                "      \"results\": [\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-TEST\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: test:package\\nInstalled Version: 1.0.0\\nFixed Version: 1.0.0-alpha\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-TEST\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: test:package\\nInstalled Version: 1.0.0\\nFixed Version: 1.0.0\"\n" +
                "          }\n" +
                "        },\n" +
                "        {\n" +
                "          \"ruleId\": \"CVE-TEST\",\n" +
                "          \"level\": \"error\",\n" +
                "          \"message\": {\n" +
                "            \"text\": \"Package: test:package\\nInstalled Version: 1.0.0\\nFixed Version: 1.0.0-beta\"\n" +
                "          }\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        
        com.google.gson.JsonParser parser = new com.google.gson.JsonParser();
        JsonObject trivySarifJson = parser.parse(trivySarifJsonWithVersions).getAsJsonObject();
        
        List<TrivyData> trivyDataList = processor.parseTrivySarifJson(trivySarifJson);
        
        // Should be deduplicated to 1 unique entry with the highest version (1.0.0)
        assertEquals("Should have exactly 1 unique vulnerability after deduplication", 1, trivyDataList.size());
        
        TrivyData vuln = trivyDataList.get(0);
        assertEquals("Should select the release version over pre-release versions", "1.0.0", vuln.getFixedVersion());
    }
} 