#!/bin/bash

# Quick Trivy Filesystem Scanner Script
# This script runs a fast Trivy filesystem scan with only vulnerability scanning

set -e

echo "⚡ Starting quick Trivy filesystem scan..."

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy is not installed. Please install Trivy first."
    echo "   Installation guide: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p reports

# Run quick Trivy filesystem scan (vulnerability only)
echo "📁 Quick scanning filesystem for vulnerabilities..."
trivy fs \
    --format sarif \
    --output reports/trivy-quick-scan.sarif \
    --severity CRITICAL,HIGH \
    --scanners vuln \
    --skip-dirs target/,reports/ \
    .

# Check if scan was successful
if [ $? -eq 0 ]; then
    echo "✅ Quick Trivy filesystem scan completed successfully!"
    echo "📄 SARIF report generated: reports/trivy-quick-scan.sarif"
    
    # Display summary
    echo ""
    echo "📊 Quick Scan Summary:"
    trivy fs --format table --severity CRITICAL,HIGH --scanners vuln . | head -10
    
    # Copy the report to the expected location for SonarQube plugin
    cp reports/trivy-quick-scan.sarif trivy-report.sarif
    echo "📋 Report copied to trivy-report.sarif for SonarQube integration"
    
else
    echo "❌ Quick Trivy filesystem scan failed!"
    exit 1
fi

echo ""
echo "🚀 Ready to run SonarQube analysis with:"
echo "   sonar-scanner" 