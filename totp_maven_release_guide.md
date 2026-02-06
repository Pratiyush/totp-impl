# TOTP Maven Release Guide

This document consolidates all steps we discussed for preparing, signing, and deploying the TOTP library (`totp-impl`) to Maven Central from GitHub.

---

## 1. Maven Coordinates

```xml
<groupId>io.github.pratiyush</groupId>
<artifactId>totp-impl</artifactId>
<version>0.1.0</version>
```
- First release: `0.1.0`
- Follow semantic versioning for future releases.

---

## 2. POM Metadata (Mandatory for Sonatype)

```xml
<name>TOTP Implementation</name>
<description>Production-ready TOTP implementation compatible with RFC 6238</description>
<url>https://github.com/Pratiyush/totp-impl</url>

<licenses>
  <license>
    <name>Apache License, Version 2.0</name>
    <url>https://www.apache.org/licenses/LICENSE-2.0</url>
  </license>
</licenses>

<developers>
  <developer>
    <name>Pratiyush Singh</name>
  </developer>
</developers>

<scm>
  <connection>scm:git:git://github.com/Pratiyush/totp-impl.git</connection>
  <developerConnection>scm:git:ssh://github.com:Pratiyush/totp-impl.git</developerConnection>
  <url>https://github.com/Pratiyush/totp-impl</url>
  <tag>HEAD</tag>
</scm>
```

---

## 3. Distribution Management

```xml
<distributionManagement>
  <snapshotRepository>
    <id>ossrh</id>
    <url>https://s01.oss.sonatype.org/content/repositories/snapshots</url>
  </snapshotRepository>
  <repository>
    <id>ossrh</id>
    <url>https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/</url>
  </repository>
</distributionManagement>
```

---

## 4. GPG Signing Setup

### Install GPG
```bash
brew install gnupg
```

### Verify
```bash
gpg --version
```

### Key Generation (if not already)
```bash
gpg --full-generate-key
```
- RSA 4096, name/email, passphrase.

### Export Key for CI
```bash
gpg --armor --export-secret-keys CAADD90371C77C72
```
- Save as GitHub secret `GPG_PRIVATE_KEY`
- Passphrase: `GPG_PASSPHRASE` (already exported)

### Test Locally
```bash
export GPG_PASSPHRASE="...."
mvn clean verify gpg:sign
```

### Maven GPG Plugin Configuration
```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-gpg-plugin</artifactId>
  <version>3.2.4</version>
  <configuration>
    <keyname>CAADD90371C77C72</keyname>
    <passphrase>${gpg.passphrase}</passphrase>
    <batchMode>true</batchMode>
    <pinentryMode>loopback</pinentryMode>
  </configuration>
  <executions>
    <execution>
      <id>sign-artifacts</id>
      <phase>verify</phase>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

---

## 5. GitHub Actions Workflow (Release)

```yaml
name: Release to Maven Central

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'
          server-id: ossrh
          server-username: ${{ secrets.OSSRH_USERNAME }}
          server-password: ${{ secrets.OSSRH_TOKEN }}
          gpg-private-key: ${{ secrets.GPG_PRIVATE_KEY }}
          gpg-passphrase: ${{ secrets.GPG_PASSPHRASE }}

      - name: Publish
        run: mvn -B clean deploy -P release
        env:
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
```

- Tag your release locally:
```bash
git tag v0.1.0
git push origin v0.1.0
```
- Maven will deploy signed artifacts to Maven Central.

---

## 6. JavaDoc Notes
- Use `<pre>{@code ...}</pre>` for URLs, JSON, or OTP examples to avoid JavaDoc parsing errors.
- Method-level JavaDocs should avoid `<h2>` / `<h3>`; prefer `<b>` or `<p>` inside methods.
- Class-level JavaDocs can safely use `<h2>`.

---

## 7. Versioning Strategy
- First public release: `0.1.0`
- Minor fixes: `0.1.x`
- New features: `0.2.0`
- Stable API: `1.0.0`

---

## 8. Summary Checklist

1. Verify GPG key exists: `CAADD90371C77C72`
2. Export private key to GitHub Secrets
3. Add Maven GPG plugin with `batchMode` + `pinentryMode=loopback`
4. Configure POM metadata & distribution management
5. Tag release in GitHub
6. Push tag → triggers workflow → deploys signed artifacts to Maven Central
7. Ensure JavaDoc uses safe `<pre>{@code}</pre>` for technical examples
8. Consume library via:
```xml
<dependency>
  <groupId>io.github.pratiyush</groupId>
  <artifactId>totp-impl</artifactId>
  <version>0.1.0</version>
</dependency>
```

---

You now have a **full reference** for releasing `totp-impl` safely and correctly.
https://central.sonatype.com/
**mvn clean deploy -P gpg -Dgpg.passphrase=$GPG_PASSPHRASE**
