#!/bin/bash

# Trivy Filesystem Scanner Script
# This script runs Trivy filesystem scan and generates a SARIF report

set -e

echo "🔍 Starting Trivy filesystem scan..."

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy is not installed. Please install Trivy first."
    echo "   Installation guide: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p reports

# Run Trivy filesystem scan
echo "📁 Scanning filesystem for vulnerabilities..."
trivy fs \
    --config trivy.yaml \
    --format sarif \
    --output reports/trivy-fs-scan.sarif \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --scanners vuln,secret,config \
    .

# Check if scan was successful
if [ $? -eq 0 ]; then
    echo "✅ Trivy filesystem scan completed successfully!"
    echo "📄 SARIF report generated: reports/trivy-fs-scan.sarif"
    
    # Display summary
    echo ""
    echo "📊 Scan Summary:"
    trivy fs --format table --severity CRITICAL,HIGH,MEDIUM,LOW . | head -20
    
    # Copy the report to the expected location for SonarQube plugin
    cp reports/trivy-fs-scan.sarif trivy-report.sarif
    echo "📋 Report copied to trivy-report.sarif for SonarQube integration"
    
else
    echo "❌ Trivy filesystem scan failed!"
    exit 1
fi

echo ""
echo "🚀 Ready to run SonarQube analysis with:"
echo "   sonar-scanner" 