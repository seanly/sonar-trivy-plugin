package org.sonarsource.plugins.trivy;

import org.sonarsource.plugins.trivy.config.TrivyVulnerabilityRulesDefinition;
import org.sonarsource.plugins.trivy.config.TrivyMetrics;
import org.sonarsource.plugins.trivy.config.Properties;

import org.sonar.api.Plugin;

public class TrivyPlugin implements Plugin {

	@Override
	public void define(Context context) {

		// plugin settings
		context.addExtensions(Properties.getProperties());
		
		// define rules for issues - Trivy SARIF
		context.addExtension(TrivyVulnerabilityRulesDefinition.class);
		
		// Trivy metrics
		context.addExtension(TrivyMetrics.class);
		
		// Trivy vulnerability sensor
		context.addExtension(TrivyVulnerabilitySensor.class);
		
		// post job - add Trivy vulnerability links to issues as comments
		context.addExtension(AddTrivyComment.class);
	}
} 