package org.sonarsource.plugins.trivy;

import org.sonarsource.plugins.trivy.model.TrivyData;
import org.sonar.api.batch.postjob.PostJob;
import org.sonar.api.batch.postjob.PostJobContext;
import org.sonar.api.batch.postjob.PostJobDescriptor;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonParser;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.sonar.api.rule.RuleKey;

/**
 * Add Trivy Vulnerability Comment
 *
 * Post Job that reads the cached Trivy data and creates Sonar comments with links to vulnerability details
 */
public class AddTrivyComment implements PostJob {

    private static final Logger LOGGER = Loggers.get(AddTrivyComment.class);
    private static final String LINK_TEXT = "Link:";

    private URI sonarHostUri;
    private HttpHost targetHost;
    private HttpClientContext httpContext;
    private CloseableHttpClient httpClient;

    @Override
    public void describe(PostJobDescriptor descriptor) {
        descriptor.name("Add issue comments with Trivy vulnerability links");
    }

    @Override
    public void execute(PostJobContext context) {
        LOGGER.info("Adding issue comments with Trivy vulnerability links");

        try {
            List<TrivyData> trivyDataList = TrivyDataStore.instance().getTrivyData();
            LOGGER.info("Fetched Trivy data: {}", trivyDataList.size());

            if (trivyDataList.isEmpty()) {
                LOGGER.info("No Trivy data found, skipping comment addition");
                return;
            }

            // Wait for background tasks to finish
            // Data from scanner is not immediately available in the backend
//            LOGGER.info("Waiting for background tasks...");
//            String pauseForTheCause = System.getProperty("trivy.pauseForTheCause", "1");
//            TimeUnit.MINUTES.sleep(Integer.parseInt(pauseForTheCause));

            setHttpContext(context);
            httpClient = HttpClientBuilder.create().build();

            // Wait for background tasks to finish
            // Data from scanner is not immediately available in the backend
            LOGGER.info("Waiting for background tasks...");
            String pauseForTheCause = System.getProperty("trivy.pauseForTheCause", "5");
            TimeUnit.SECONDS.sleep(Integer.parseInt(pauseForTheCause));

            // Process each TrivyData directly (already grouped by package in TrivyProcessor)
            for (TrivyData trivyData : trivyDataList) {
                LOGGER.info("Processing TrivyData: {} for package: {}", trivyData.getRuleId(), trivyData.getPackageName());
                
                // Get links for this TrivyData
                List<String> links = trivyData.getLinks();
                if (links == null || links.isEmpty()) {
                    // Fallback to helpUri if no links
                    String helpUri = trivyData.getHelpUri();
                    if (helpUri != null && !helpUri.isEmpty()) {
                        links = new ArrayList<>();
                        links.add(helpUri);
                    }
                }
                
                if (links != null && !links.isEmpty()) {
                    addVulnerabilityCommentForTrivyData(trivyData, links);
                } else {
                    LOGGER.warn("No links found for TrivyData: {}", trivyData.getRuleId());
                }
            }

            LOGGER.info("Successfully processed Trivy comments");

        } catch (Exception ex) {
            LOGGER.error("Trivy post job encountered an error: {}", ex.getMessage(), ex);

            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            ex.printStackTrace(pw);
            LOGGER.error(sw.toString());
        } finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (IOException e) {
                    LOGGER.error("Error closing HTTP client: {}", e.getMessage());
                }
            }
        }
    }



    private void addVulnerabilityCommentForTrivyData(TrivyData trivyData, List<String> links) {
        try {
            String ruleKey = getRuleKeyForSeverity(trivyData.getSeverity());
            
            String searchUri = sonarHostUri.toString() + "/api/issues/search?ps=500&additionalFields=comments"
                    + "&rules=" + ruleKey;

            HttpGet req = new HttpGet(searchUri);
            CloseableHttpResponse res = httpClient.execute(targetHost, req, httpContext);

            try {
                String response = EntityUtils.toString(res.getEntity());
                EntityUtils.consume(res.getEntity());

                JsonParser parser = new JsonParser();
                JsonObject root = parser.parse(response).getAsJsonObject();
                JsonArray issues = root.getAsJsonArray("issues");

                if (issues == null) {
                    LOGGER.debug("No issues found for rule: {}", ruleKey);
                    return;
                }

                LOGGER.info("Found {} issues for rule: {}", issues.size(), ruleKey);
                
                boolean found = false;
                // Find matching issue by package name
                for (JsonElement issueElement : issues) {
                    JsonObject issue = issueElement.getAsJsonObject();
                    String message = issue.get("message").getAsString();
                    String key = issue.get("key").getAsString();

                    LOGGER.debug("Checking issue: {} with message: {}", key, message);

                    // 只要是同一个包的issue都加comment（不break）
                    if (message.contains("Package: " + trivyData.getPackageName()) || message.contains(trivyData.getPackageName())) {
                        LOGGER.info("Found matching issue for package: {} - issue key: {}", trivyData.getPackageName(), key);
                        addCommentToIssue(issue, key, links, trivyData.getSeverity());
                        found = true;
                        // 不break，继续为所有相关issue加comment
                    }
                }
                
                if (!found) {
                    LOGGER.warn("No matching issue found for package: {}", trivyData.getPackageName());
                }

            } finally {
                res.close();
            }

        } catch (Exception e) {
            LOGGER.error("Error adding vulnerability comment for TrivyData {}: {}", 
                        trivyData.getRuleId(), e.getMessage(), e);
        }
    }
    
    private void addCommentToIssue(JsonObject issue, String issueKey, List<String> links, String severity) 
            throws URISyntaxException, IOException {
        
        // Check if comment already exists
        JsonArray comments = issue.getAsJsonArray("comments");
        if (comments != null) {
            for (JsonElement comment : comments) {
                JsonObject c = comment.getAsJsonObject();
                String markdown = c.get("markdown").getAsString();
                if (markdown.contains(LINK_TEXT)) {
                    LOGGER.debug("Comment already exists for issue: {}", issueKey);
                    return;
                }
            }
        }

        // Create comment with vulnerability link
        String commentText = createCommentText(links, severity);
        
        URIBuilder builder = new URIBuilder(sonarHostUri.toString() + "/api/issues/add_comment");
        builder.setParameter("issue", issueKey);
        builder.setParameter("text", commentText);

        HttpPost post = new HttpPost(builder.build());
        CloseableHttpResponse postRes = httpClient.execute(targetHost, post, httpContext);

        try {
            if (postRes.getStatusLine().getStatusCode() != 200) {
                LOGGER.error("Failed to add comment to issue: {}", issueKey);
            } else {
                LOGGER.debug("Successfully added comment to issue: {}", issueKey);
            }
        } finally {
            postRes.close();
        }
    }
    
    private String createCommentText(List<String> links, String severity) {
        StringBuilder commentText = new StringBuilder();
        for (int i = 0; i < links.size(); i++) {
            String link = links.get(i);
            String cveId = extractCveIdFromUrl(link);
            if (cveId != null) {
                commentText.append(cveId).append(": ").append(link);
            } else {
                commentText.append("Link: ").append(link);
            }
            
            // Add severity information after the link, separated by |
            if (severity != null && !severity.isEmpty()) {
                commentText.append(" | Severity: ").append(severity.toUpperCase());
            }
            
            // Add newline between links (except for the last one)
            if (i < links.size() - 1) {
                commentText.append("\n");
            }
        }
        return commentText.toString();
    }
    
    private String extractCveIdFromUrl(String url) {
        if (url != null && url.contains("cve-")) {
            // Extract CVE ID from URL like https://avd.aquasec.com/nvd/cve-2020-13956
            int cveIndex = url.indexOf("cve-");
            if (cveIndex != -1) {
                String cvePart = url.substring(cveIndex);
                // Take up to the next slash or end of string
                int slashIndex = cvePart.indexOf("/");
                if (slashIndex != -1) {
                    return cvePart.substring(0, slashIndex).toUpperCase();
                } else {
                    return cvePart.toUpperCase();
                }
            }
        }
        return null;
    }

    private String getRuleKeyForSeverity(String severity) {
        String sev = (severity == null || severity.isEmpty()) ? "high" : severity.toLowerCase();
        return RuleKey.of("trivy", sev).toString();
    }

    private void setHttpContext(PostJobContext context) throws URISyntaxException {
        // See: https://docs.sonarqube.org/latest/extend/web-api/
        // Login can be username or token. If token, password is blank.
        String login = context.config().get("sonar.login").orElse(null);
        String password = context.config().get("sonar.password").orElse("");
        String sonarHostUrl = context.config().get("sonar.host.url").orElse(null);

        if (login == null || sonarHostUrl == null) {
            throw new IllegalArgumentException("sonar.login and sonar.host.url are required");
        }

        // Set sonarHostUri
        sonarHostUri = new URI(sonarHostUrl);

        // Set targetHost
        targetHost = new HttpHost(sonarHostUri.getHost(), sonarHostUri.getPort(), sonarHostUri.getScheme());

        // Set httpContext with credentials
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(new AuthScope(targetHost.getHostName(), targetHost.getPort()),
                new UsernamePasswordCredentials(login, password));

        AuthCache authCache = new BasicAuthCache();
        BasicScheme basicAuth = new BasicScheme();
        authCache.put(targetHost, basicAuth);

        httpContext = HttpClientContext.create();
        httpContext.setCredentialsProvider(credsProvider);
        httpContext.setAuthCache(authCache);
    }
} 