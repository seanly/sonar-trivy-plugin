package org.sonarsource.plugins.trivy.config;

import java.util.List;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metrics;

import static java.util.Arrays.asList;

/**
 * Sonar Metrics Configuration for Trivy Plugin
 */
public class TrivyMetrics implements Metrics {

	public static final String TRIVY = "Trivy";

	public static final Metric<Integer> NEW = new Metric.Builder("trivy_new_vulnerabilities","New Vulnerabilities", Metric.ValueType.INT)
		.setDescription("New Vulnerabilities")
		.setDirection(Metric.DIRECTION_WORST)
		.setQualitative(true)
		.setDomain(TRIVY)
		.setBestValue(0.0)
		.create();

	public static final Metric<Integer> CRITICAL = new Metric.Builder("trivy_critical_vulnerabilities","Critical Vulnerabilities", Metric.ValueType.INT)
		.setDescription("Critical Vulnerabilities")
		.setDirection(Metric.DIRECTION_WORST)
		.setQualitative(true)
		.setDomain(TRIVY)
		.setBestValue(0.0)
		.create();

	public static final Metric<Integer> RESURFACED = new Metric.Builder("trivy_resurfaced_vulnerabilities","Resurfaced Vulnerabilities", Metric.ValueType.INT)
		.setDescription("Resurfaced Vulnerabilities")
		.setDirection(Metric.DIRECTION_WORST)
		.setQualitative(true)
		.setDomain(TRIVY)
		.setBestValue(0.0)
		.create();

	public static final Metric<Integer> UNIQUE = new Metric.Builder("trivy_unique_vulnerabilities","Unique Vulnerabilities", Metric.ValueType.INT)
		.setDescription("Unique Vulnerabilities")
		.setDirection(Metric.DIRECTION_WORST)
		.setQualitative(true)
		.setDomain(TRIVY)
		.setBestValue(0.0)
		.create();

	@Override
	public List<Metric> getMetrics() {
		return asList(NEW, CRITICAL, RESURFACED, UNIQUE);
	}
} 