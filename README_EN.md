# SonarQube Trivy Plugin

[![Java](https://img.shields.io/badge/Java-11+-orange.svg)](https://openjdk.java.net/)
[![SonarQube](https://img.shields.io/badge/SonarQube-9.9+-blue.svg)](https://www.sonarqube.org/)
[![Maven](https://img.shields.io/badge/Maven-3.6+-green.svg)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![English](https://img.shields.io/badge/English-README_EN.md-blue.svg)](README_EN.md) [![中文](https://img.shields.io/badge/中文-README.md-green.svg)](README.md)

A SonarQube plugin that integrates [Trivy](https://aquasecurity.github.io/trivy/) vulnerability scanner results into SonarQube analysis. This plugin reads Trivy SARIF reports and creates security issues in SonarQube, enabling comprehensive security analysis within your existing SonarQube workflow.

## 🚀 Features

- **SARIF Integration**: Seamlessly imports Trivy vulnerability reports in SARIF format
- **Multi-Severity Support**: Handles Critical, High, Medium, and Low severity vulnerabilities
- **Quality Gate Integration**: Provides metrics for quality gate conditions
- **Comprehensive Metrics**: Tracks Critical, New, Resurfaced, and Unique vulnerabilities
- **Automated Issue Creation**: Automatically creates SonarQube issues from Trivy findings
- **Docker Support**: Includes Docker Compose setup for easy testing

## 📋 Requirements

- **SonarQube**: 9.9 or higher
- **Java**: 11 or higher
- **Maven**: 3.6 or higher
- **Trivy**: Latest version (for generating SARIF reports)

## 🛠️ Installation

### Option 1: Download Pre-built Plugin

1. Download the latest plugin JAR from the [releases page](https://github.com/seanly/sonar-trivy-plugin/releases)
2. Copy the JAR file to your SonarQube `extensions/plugins` directory
3. Restart SonarQube

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/seanly/sonar-trivy-plugin.git
cd sonar-trivy-plugin

# Build the plugin
mvn clean package

# Copy the built plugin to SonarQube
cp target/sonar-trivy-plugin-9.0.0.jar /path/to/sonarqube/extensions/plugins/

# Restart SonarQube
```

### Option 3: Docker Setup (Recommended for Testing)

```bash
# Start SonarQube with the plugin pre-installed
docker-compose up -d

# Access SonarQube at http://localhost:9000
# Default credentials: admin/admin
```

## ⚙️ Configuration

### 1. Plugin Settings

Configure the plugin in your SonarQube project settings:

| Property | Key | Default | Description |
|----------|-----|---------|-------------|
| Trivy SARIF File Path | `trivy.sarif.file.path` | `trivy-report.sarif` | Path to the Trivy SARIF report file |

### 2. Activate Trivy Rules

1. Go to **Administration** → **Quality Profiles**
2. Select your project's quality profile
3. Search for "Trivy" rules
4. Activate the desired vulnerability rules:
   - **Critical** - Critical security vulnerabilities
   - **High** - High security vulnerabilities
   - **Medium** - Medium security vulnerabilities
   - **Low** - Low security vulnerabilities

### 3. Configure Quality Gates

Add Trivy metrics to your quality gate:

1. Go to **Administration** → **Quality Gates**
2. Add conditions for:
   - **Critical Vulnerabilities**
   - **New Vulnerabilities**
   - **Resurfaced Vulnerabilities**
   - **Unique Vulnerabilities**

## 🔍 Usage

### Step 1: Generate Trivy SARIF Report

#### Using the provided scripts:

```bash
# Full scan (vulnerabilities, secrets, misconfigurations)
./scan.sh

# Quick scan (vulnerabilities only)
./quick-scan.sh
```

#### Manual Trivy scan:

```bash
# Install Trivy (if not already installed)
# See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Run Trivy filesystem scan
trivy fs \
    --format sarif \
    --output trivy-report.sarif \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --scanners vuln,secret,config \
    .
```

### Step 2: Run SonarQube Analysis

```bash
# Configure SonarQube connection
export SONAR_HOST_URL="http://localhost:9000"
export SONAR_TOKEN="your-sonar-token"

# Run SonarQube scanner
sonar-scanner \
    -Dsonar.projectKey=my-project \
    -Dsonar.sources=src \
    -Dtrivy.sarif.file.path=trivy-report.sarif
```

### Step 3: View Results in SonarQube

- **Issues**: View Trivy vulnerabilities as SonarQube issues
- **Metrics**: Check vulnerability counts in project overview
- **Quality Gate**: Monitor security metrics in quality gates

## 📊 Metrics

The plugin provides four key metrics:

| Metric | Description |
|--------|-------------|
| **Critical Vulnerabilities** | Number of critical security vulnerabilities |
| **New Vulnerabilities** | Number of newly detected vulnerabilities |
| **Resurfaced Vulnerabilities** | Number of vulnerabilities that reappeared |
| **Unique Vulnerabilities** | Total number of unique vulnerabilities |

## 🔧 Development

### Project Structure

```
src/main/java/org/sonarsource/plugins/trivy/
├── TrivyPlugin.java                 # Main plugin entry point
├── TrivyVulnerabilitySensor.java    # Sensor for processing SARIF files
├── TrivyProcessor.java              # SARIF file processor
├── TrivyDataStore.java              # Data storage and management
├── AddTrivyComment.java             # Post-job for adding vulnerability links
├── config/
│   ├── Properties.java              # Plugin configuration properties
│   ├── TrivyMetrics.java            # Metrics definitions
│   └── TrivyVulnerabilityRulesDefinition.java  # Rule definitions
└── model/
    └── TrivyData.java               # Data models
```

### Building and Testing

```bash
# Build the project
mvn clean package

# Run tests
mvn test

# Run with Docker
docker-compose up -d
```

### Debug Mode

The Docker setup includes debug ports:
- **Web Server**: Port 8001
- **Compute Engine**: Port 8002

Connect your IDE to these ports for debugging.

## 📝 Configuration Files

### trivy.yaml

The project includes a comprehensive Trivy configuration file that covers:

- **Scanners**: Vulnerability, secret, and misconfiguration scanning
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW
- **Skip Patterns**: Excludes build artifacts and temporary files
- **Cache Settings**: Optimized for development workflow

### sonar-project.properties

Configure your SonarQube project settings:

```properties
sonar.projectKey=my-project
sonar.projectName=My Project
sonar.projectVersion=1.0
sonar.sources=src
sonar.host.url=http://localhost:9000
sonar.login=your-token
trivy.sarif.file.path=trivy-report.sarif
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Trivy](https://aquasecurity.github.io/trivy/) - Comprehensive security scanner
- [SonarQube](https://www.sonarqube.org/) - Code quality platform
- [SARIF](https://sarifweb.azurewebsites.net/) - Static Analysis Results Interchange Format

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/seanly/sonar-trivy-plugin/issues)
- **Documentation**: [Wiki](https://github.com/seanly/sonar-trivy-plugin/wiki)
- **Email**: seanly@opsbox.dev

---

**Made with ❤️ by [Seanly Liu](https://github.com/seanly)**

---

## 📚 Language Versions

- [English](README_EN.md) - English version (current)
- [中文](README.md) - Chinese version