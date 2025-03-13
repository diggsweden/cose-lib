# Development Guide

This guide outlines core essentials you need to know for developing in this project.

## Consuming SNAPSHOTS from Maven Central

Configure your pom.xml file with the following <repositories> section:

```xml
<repositories>
  <repository>
    <name>Central Portal Snapshots</name>
    <id>central-portal-snapshots</id>
    <url>https://central.sonatype.com/repository/maven-snapshots/</url>
    <releases>
      <enabled>false</enabled>
    </releases>
    <snapshots>
      <enabled>true</enabled>
    </snapshots>
  </repository>
</repositories>
```

## Testing, Formatting and Checkstyle

### Maven

```shell
mvn clean verify
```
## IDE

### Setup VSCode

1. Install a Checkstyle plugin - [Checkstyle For Java](https://marketplace.visualstudio.com/items?itemName=shengchen.vscode-checkstyle)

2. Open workspace settings - settings.json (for example with Ctrl+Shift+P -> Preferences: Workspace Settings (JSON)) and make sure you have the following settings:
```json
    "[java]": {
        "editor.defaultFormatter": "redhat.java",
    },
    "java.format.settings.url": "development/formatting/eclipse-java-google-style.xml",
    "java.format.settings.profile": "GoogleStyle",
    "editor.formatOnSave": true,
    "java.checkstyle.configuration": "development/checkstyle/google_checks.xml",
    "java.checkstyle.version": "10.21.2"
```

### Setup IntelliJ

1. Code Style
   - Settings -> `Editor -> Code Style -> Java`
   - Click gear -> `Import Scheme -> Eclipse XML Profile`
   - Select `development/formatting/eclipse-java-google-style.xml`

2. Checkstyle

   - Install "CheckStyle-IDEA" plugin
   - Settings -> `Tools -> Checkstyle`
   - Click the built-in Google Style Check

## Documentation

Generate Javadocs using:

```shell
mvn javadoc:javadoc
<browser> target/reports/apidocs/index.html


```
## The Release Workflow

Releases to Maven Central can be done in two ways - by CI or by local release.

<TO_DO: described need vars, like gpg key, token>

### Activate the CI-workflow with a tag and push

```shell
git tag -s v0.0.3-SNAPSHOT -m 'v0.0.3-SNAPSHOT'
git push origin tag v0.0.3-SNAPSHOT
```
NOTE: Always use the same tag for snapshots!! Don't incriminate when using snapshots!!

NOTE: The given tag will also set the POM-project version.

### Release from local

```shell
mvn deploy --settings .mvn/settings.xml -Pcentral-release
```

## Pull Request Workflow

When you submit a Pull Request, a Continuous Integration (CI) workflow will run several checks automatically.
To avoid surprises where it will fail with errors, we strongly recommend running these checks locally before submitting your PR.

### Prerequisites

- [Podman](https://podman.io/)

### Running Code Quality Checks Locally

1. Run the quality check script:

```console
./development/code_quality.sh
```

2. Fix any issues identified in your local environment
3. Update your Pull Request with fixes
4. Verify CI passes in the updated PR

### Quality Check Details

Includes:

1. **Linting with [megalinter](https://github.com/oxsecurity/megalinter)**
   - BASH script linting
   - Markdown linting
   - YAML linting
   - GitHub Action linting
   - Repository secret scanning (GitLeaks and Credentials scan)

2. **License Compliance with [REUSE](https://github.com/fsfe/reuse-tool)**
   - Ensures proper copyright information in every file

3. **Commit Structure with [Conform](https://github.com/siderolabs/conform)**
   - Checks commit messages against project guidelines
   - See CONTRIBUTING.md for details
   - For generating beatiful Changelogs

4. **Vulnerable Dependencies with [Dependency Analysis](https://github.com/actions/dependency-review-action)**
   - Automated scanning of project dependencies
   - Identifies known vulnerabilities
   - Checks for outdated packages
   - Validates license compatibility
   - Flags deprecated dependencies

5. **OpenSSF Scorecard Analysis**
   - [OpenSSF Scorecard](https://github.com/ossf/scorecard) checks:
     - Code review practices
     - Branch protection rules
     - Dependency update practices
     - CI/CD security configuration
     - SAST tools usage
     - Token permissions

### Handling Failed Checks

If any checks fail in the CI pipeline:

1. Review the CI error logs
2. Run checks locally to reproduce the issues
3. Make necessary fixes in your local environment
4. Update your Pull Request
5. Verify all checks pass in the updated PR
