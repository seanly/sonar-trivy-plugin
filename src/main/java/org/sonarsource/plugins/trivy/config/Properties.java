package org.sonarsource.plugins.trivy.config;

import java.util.List;

import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;

import static java.util.Arrays.asList;

/**
 * Sonar Property Definitions for Trivy Plugin
 */
public class Properties {

	private Properties() {
		// Utility classes should not have public constructors
	}

	// Sonar UI
	public static final String CATEGORY = "Trivy";
	public static final String SUBCATEGORY_GENERAL = "General Settings";

	// Properties Keys
	public static final String TRIVY_SARIF_FILE_PATH = "trivy.sarif.file.path";
	public static final String DEFAULT_TRIVY_SARIF_FILE_PATH = "trivy-report.sarif";

	// Constants
	public static final String VIEW_NAME = "All Events";

	static final PropertyDefinition PROP_TRIVY_SARIF_FILE_PATH = PropertyDefinition.builder(TRIVY_SARIF_FILE_PATH)
			.name("Trivy SARIF File Path")
			.description("Path to the Trivy SARIF report file (e.g., Trivy vulnerability report)")
			.defaultValue(DEFAULT_TRIVY_SARIF_FILE_PATH)
			.category(CATEGORY)
			.subCategory(SUBCATEGORY_GENERAL)
			.type(PropertyType.STRING)
			.onQualifiers(Qualifiers.PROJECT)
			.index(1)
			.build();

	public static List<PropertyDefinition> getProperties() {
		return asList(
				PROP_TRIVY_SARIF_FILE_PATH
		);
	}
} 