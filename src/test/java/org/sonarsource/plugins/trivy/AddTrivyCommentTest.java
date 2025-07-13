package org.sonarsource.plugins.trivy;

import org.junit.Test;
import org.sonarsource.plugins.trivy.AddTrivyComment;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Test class for AddTrivyComment
 */
public class AddTrivyCommentTest {

    @Test
    public void testCreateCommentTextWithSeverity() throws Exception {
        // Use reflection to access private method for testing
        AddTrivyComment addTrivyComment = new AddTrivyComment();
        Method createCommentTextMethod = AddTrivyComment.class.getDeclaredMethod("createCommentText", List.class, String.class);
        createCommentTextMethod.setAccessible(true);
        
        // Test case 1: Single link with HIGH severity
        List<String> links1 = Arrays.asList("https://avd.aquasec.com/nvd/cve-2021-44228");
        String severity1 = "high";
        String result1 = (String) createCommentTextMethod.invoke(addTrivyComment, links1, severity1);
        
        assertNotNull("Comment text should not be null", result1);
        assertTrue("Comment should contain CVE ID", result1.contains("CVE-2021-44228"));
        assertTrue("Comment should contain the link", result1.contains("https://avd.aquasec.com/nvd/cve-2021-44228"));
        assertTrue("Comment should contain severity information", result1.contains("| Severity: HIGH"));
        
        // Test case 2: Multiple links with CRITICAL severity
        List<String> links2 = Arrays.asList(
            "https://avd.aquasec.com/nvd/cve-2021-44228",
            "https://avd.aquasec.com/nvd/cve-2020-13956"
        );
        String severity2 = "critical";
        String result2 = (String) createCommentTextMethod.invoke(addTrivyComment, links2, severity2);
        
        System.out.println("Result2: '" + result2 + "'");
        System.out.println("Result2 length: " + result2.length());
        System.out.println("Split result: " + Arrays.toString(result2.split("\\| Severity: CRITICAL")));
        
        assertNotNull("Comment text should not be null", result2);
        assertTrue("Comment should contain first CVE ID", result2.contains("CVE-2021-44228"));
        assertTrue("Comment should contain second CVE ID", result2.contains("CVE-2020-13956"));
        // 修正：每一行都应包含 | Severity: CRITICAL
        String[] lines = result2.split("\\n");
        for (String line : lines) {
            assertTrue("Each line should contain severity information", line.contains("| Severity: CRITICAL"));
        }
        
        // Test case 3: Link without CVE ID with MEDIUM severity
        List<String> links3 = Arrays.asList("https://example.com/vulnerability");
        String severity3 = "medium";
        String result3 = (String) createCommentTextMethod.invoke(addTrivyComment, links3, severity3);
        
        assertNotNull("Comment text should not be null", result3);
        assertTrue("Comment should contain 'Link:' prefix", result3.contains("Link: "));
        assertTrue("Comment should contain the link", result3.contains("https://example.com/vulnerability"));
        assertTrue("Comment should contain severity information", result3.contains("| Severity: MEDIUM"));
        
        // Test case 4: Null severity
        List<String> links4 = Arrays.asList("https://avd.aquasec.com/nvd/cve-2021-44228");
        String severity4 = null;
        String result4 = (String) createCommentTextMethod.invoke(addTrivyComment, links4, severity4);
        
        assertNotNull("Comment text should not be null", result4);
        assertTrue("Comment should contain CVE ID", result4.contains("CVE-2021-44228"));
        assertTrue("Comment should contain the link", result4.contains("https://avd.aquasec.com/nvd/cve-2021-44228"));
        assertFalse("Comment should not contain severity information when severity is null", 
                   result4.contains("| Severity:"));
        
        // Test case 5: Empty severity
        List<String> links5 = Arrays.asList("https://avd.aquasec.com/nvd/cve-2021-44228");
        String severity5 = "";
        String result5 = (String) createCommentTextMethod.invoke(addTrivyComment, links5, severity5);
        
        assertNotNull("Comment text should not be null", result5);
        assertTrue("Comment should contain CVE ID", result5.contains("CVE-2021-44228"));
        assertTrue("Comment should contain the link", result5.contains("https://avd.aquasec.com/nvd/cve-2021-44228"));
        assertFalse("Comment should not contain severity information when severity is empty", 
                   result5.contains("| Severity:"));
        
        System.out.println("✅ All createCommentText tests passed!");
        System.out.println("Sample output with HIGH severity: " + result1);
        System.out.println("Sample output with CRITICAL severity: " + result2);
    }
} 