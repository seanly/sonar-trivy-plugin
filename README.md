# SonarQube Trivy 插件

[![Java](https://img.shields.io/badge/Java-11+-orange.svg)](https://openjdk.java.net/)
[![SonarQube](https://img.shields.io/badge/SonarQube-9.9+-blue.svg)](https://www.sonarqube.org/)
[![Maven](https://img.shields.io/badge/Maven-3.6+-green.svg)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![English](https://img.shields.io/badge/English-README_EN.md-blue.svg)](README_EN.md) [![中文](https://img.shields.io/badge/中文-README.md-green.svg)](README.md)

一个将 [Trivy](https://aquasecurity.github.io/trivy/) 漏洞扫描器结果集成到 SonarQube 分析中的插件。该插件读取 Trivy SARIF 报告并在 SonarQube 中创建安全问题，使您能够在现有的 SonarQube 工作流程中进行全面的安全分析。

## 🚀 功能特性

- **SARIF 集成**: 无缝导入 Trivy 漏洞报告的 SARIF 格式
- **多严重级别支持**: 处理严重、高、中、低级别的漏洞
- **质量门集成**: 为质量门条件提供指标
- **全面指标**: 跟踪严重、新增、重新出现和唯一漏洞
- **自动问题创建**: 从 Trivy 发现自动创建 SonarQube 问题
- **Docker 支持**: 包含 Docker Compose 设置，便于测试

## 📋 系统要求

- **SonarQube**: 9.9 或更高版本
- **Java**: 11 或更高版本
- **Maven**: 3.6 或更高版本
- **Trivy**: 最新版本（用于生成 SARIF 报告）

## 🛠️ 安装

### 选项 1: 下载预构建插件

1. 从 [发布页面](https://github.com/seanly/sonar-trivy-plugin/releases) 下载最新插件 JAR
2. 将 JAR 文件复制到 SonarQube `extensions/plugins` 目录
3. 重启 SonarQube

### 选项 2: 从源码构建

```bash
# 克隆仓库
git clone https://github.com/seanly/sonar-trivy-plugin.git
cd sonar-trivy-plugin

# 构建插件
mvn clean package

# 将构建的插件复制到 SonarQube
cp target/sonar-trivy-plugin-9.0.0.jar /path/to/sonarqube/extensions/plugins/

# 重启 SonarQube
```

### 选项 3: Docker 设置（推荐用于测试）

```bash
# 启动预装插件的 SonarQube
docker-compose up -d

# 访问 SonarQube: http://localhost:9000
# 默认凭据: admin/admin
```

## ⚙️ 配置

### 1. 插件设置

在 SonarQube 项目设置中配置插件：

| 属性 | 键 | 默认值 | 描述 |
|------|----|--------|------|
| Trivy SARIF 文件路径 | `trivy.sarif.file.path` | `trivy-report.sarif` | Trivy SARIF 报告文件的路径 |

### 2. 激活 Trivy 规则

1. 转到 **管理** → **质量配置**
2. 选择项目的质量配置
3. 搜索 "Trivy" 规则
4. 激活所需的漏洞规则：
   - **严重** - 严重安全漏洞
   - **高** - 高级别安全漏洞
   - **中** - 中级别安全漏洞
   - **低** - 低级别安全漏洞

### 3. 配置质量门

将 Trivy 指标添加到质量门：

1. 转到 **管理** → **质量门**
2. 添加以下条件：
   - **严重漏洞**
   - **新增漏洞**
   - **重新出现漏洞**
   - **唯一漏洞**

## 🔍 使用方法

### 步骤 1: 生成 Trivy SARIF 报告

#### 使用提供的脚本：

```bash
# 完整扫描（漏洞、密钥、配置错误）
./scan.sh

# 快速扫描（仅漏洞）
./quick-scan.sh
```

#### 手动 Trivy 扫描：

```bash
# 安装 Trivy（如果尚未安装）
# 参见: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# 运行 Trivy 文件系统扫描
trivy fs \
    --format sarif \
    --output trivy-report.sarif \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --scanners vuln,secret,config \
    .
```

### 步骤 2: 运行 SonarQube 分析

```bash
# 配置 SonarQube 连接
export SONAR_HOST_URL="http://localhost:9000"
export SONAR_TOKEN="your-sonar-token"

# 运行 SonarQube 扫描器
sonar-scanner \
    -Dsonar.projectKey=my-project \
    -Dsonar.sources=src \
    -Dtrivy.sarif.file.path=trivy-report.sarif
```

### 步骤 3: 在 SonarQube 中查看结果

- **问题**: 将 Trivy 漏洞作为 SonarQube 问题查看
- **指标**: 在项目概览中检查漏洞计数
- **质量门**: 在质量门中监控安全指标

## 📊 指标

插件提供四个关键指标：

| 指标 | 描述 |
|------|------|
| **严重漏洞** | 严重安全漏洞的数量 |
| **新增漏洞** | 新检测到的漏洞数量 |
| **重新出现漏洞** | 重新出现的漏洞数量 |
| **唯一漏洞** | 唯一漏洞的总数 |

## 🔧 开发

### 项目结构

```
src/main/java/org/sonarsource/plugins/trivy/
├── TrivyPlugin.java                 # 主插件入口点
├── TrivyVulnerabilitySensor.java    # 处理 SARIF 文件的传感器
├── TrivyProcessor.java              # SARIF 文件处理器
├── TrivyDataStore.java              # 数据存储和管理
├── AddTrivyComment.java             # 添加漏洞链接的后置作业
├── config/
│   ├── Properties.java              # 插件配置属性
│   ├── TrivyMetrics.java            # 指标定义
│   └── TrivyVulnerabilityRulesDefinition.java  # 规则定义
└── model/
    └── TrivyData.java               # 数据模型
```

### 构建和测试

```bash
# 构建项目
mvn clean package

# 运行测试
mvn test

# 使用 Docker 运行
docker-compose up -d
```

### 调试模式

Docker 设置包含调试端口：
- **Web 服务器**: 端口 8001
- **计算引擎**: 端口 8002

将您的 IDE 连接到这些端口进行调试。

## 📝 配置文件

### trivy.yaml

项目包含一个全面的 Trivy 配置文件，涵盖：

- **扫描器**: 漏洞、密钥和配置错误扫描
- **严重级别**: 严重、高、中、低
- **跳过模式**: 排除构建工件和临时文件
- **缓存设置**: 针对开发工作流程优化

### sonar-project.properties

配置 SonarQube 项目设置：

```properties
sonar.projectKey=my-project
sonar.projectName=我的项目
sonar.projectVersion=1.0
sonar.sources=src
sonar.host.url=http://localhost:9000
sonar.login=your-token
trivy.sarif.file.path=trivy-report.sarif
```

## 🤝 贡献

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m '添加精彩功能'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- [Trivy](https://aquasecurity.github.io/trivy/) - 全面的安全扫描器
- [SonarQube](https://www.sonarqube.org/) - 代码质量平台
- [SARIF](https://sarifweb.azurewebsites.net/) - 静态分析结果交换格式

## 📞 支持

- **问题反馈**: [GitHub Issues](https://github.com/seanly/sonar-trivy-plugin/issues)
- **文档**: [Wiki](https://github.com/seanly/sonar-trivy-plugin/wiki)
- **邮箱**: seanly@opsbox.dev

---

**由 [Seanly Liu](https://github.com/seanly) 用 ❤️ 制作**

---

## 📚 语言版本

- [English](README_EN.md) - 英文版本
- [中文](README.md) - 中文版本（当前） 