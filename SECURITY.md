# Security Policy

## Supported Versions

Currently, PostQuantum-Feldman-VSS is in beta. Only the latest beta version receives security updates. There is no stable release yet.

| Version    | Supported          |
| ---------- | ------------------ |
| 0.8.1b1   | :white_check_mark: |
| < 0.8.1b1 | :x:                |

## Reporting a Vulnerability

**Please do not create a public GitHub issue for security vulnerabilities.** This project is maintained by a single individual, and publicly disclosing vulnerabilities before a fix is available could put users at risk.

**To report a vulnerability, please use one of the following methods:**

1.  **GitHub Private Vulnerability Reporting:**  You can report vulnerabilities directly through GitHub's private vulnerability reporting feature:  [https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/security](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/security).  This is the preferred method as it keeps the report private and allows for easy tracking and collaboration.

2.  **Direct Contact:** If you prefer, you can contact David Osipov directly:
    *   Via [Signal](https://signal.me/#eu/d68l1UjrWlGVRzbfkVM1bvQMNqCqiae9GM86P_af8ZK2o5E5YSNKbL4MyM9y-2WH) messenger.
    *   Or via email at [personal@david-osipov.vision](mailto:personal@david-osipov.vision). You can encrypt your message using the following PGP key:

        *   **Binary:** [openpgpkey.david-osipov.vision/.../hu/pjmzw74d6on6w4o8hhtn9z5agk1cta8n](https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/hu/pjmzw74d6on6w4o8hhtn9z5agk1cta8n)
        *   **Armored:** [openpgpkey.david-osipov.vision/.../D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc](https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc)
        *   Verify the key at [keyoxide.org/wkd/business@david-osipov.vision](https://keyoxide.org/wkd/business@david-osipov.vision)

        You can also use WKD to get it (e.g. using Thunderbird or Protonmail).

Please provide the following information in your report:

1.  **Description of the vulnerability:** Explain the vulnerability in detail. Include information about the affected component(s) of the library (e.g., specific functions, classes).
2.  **Proof of Concept (PoC):** Provide a minimal, self-contained code example that demonstrates the vulnerability. This is *essential* for verifying and fixing the issue. Do *not* include any sensitive data (e.g., real secrets or shares).
3.  **Steps to Reproduce:** Clearly outline the steps required to reproduce the vulnerability using the PoC.
4.  **Affected Version(s):** Specify the version(s) of the library affected by the vulnerability. If you tested multiple versions, please list them all.
5.  **Potential Impact:** Describe the potential impact of exploiting the vulnerability. (e.g., "Could allow an attacker to recover the secret," "Could allow an attacker to forge valid shares," "Could cause a denial of service").
6.  **Your Environment:** Include information about your Python version, operating system, and any relevant dependencies (e.g., `gmpy2` version, `blake3` version if applicable).
7.  **GitHub Security Advisories (GHSA IDs):** If applicable, reference any relevant GitHub Security Advisories (GHSA IDs). This is especially important if you are reporting a known issue that is already documented. For example, include:
    *   `GHSA-r8gc-qc2c-c7vh`: Inadequate Fault Injection Countermeasures in `secure_redundant_execution`
    *   `GHSA-q65w-fg65-79f4`: Timing Side-Channels in Matrix Operations
    *   `GHSA-39v3-9v27-595x`: Use of Potentially Predictable PRNG in Share Refreshing (Note: This one is documented as *not* a vulnerability, but including the ID for completeness helps track discussions.)

**What to Expect:**

*   I will acknowledge receipt of your report within 72 hours (usually much sooner).
*   I will investigate the reported vulnerability and work to develop a fix. I will keep you updated on the progress. The time to develop a fix will depend on the complexity of the vulnerability.
*   Once a fix is available, I will release a new version of the library and credit you (if you wish) in the release notes and/or security advisories.
*   I will coordinate with you on the timing of public disclosure, if appropriate.

## Comprehensive Security and Quality Assurance

This project utilizes a comprehensive suite of security and quality assurance tools integrated into the development workflow via GitHub Actions.  These measures are designed to proactively identify and address potential vulnerabilities and code quality issues.

**Tools and Processes:**

*   **Static Code Analysis:**
    *   **Bandit:** A security-focused static analyzer for Python code.
    *   **Ruff:**  A fast Python linter that enforces style and helps identify potential errors.
    *   **MyPy:** A static type checker that helps catch type-related errors.
    *   **Pylint:** A static code analyzer that checks for errors, enforces coding standards, and looks for code smells.
    *   **CodeQL:**  A semantic code analysis engine that performs deep analysis to find security vulnerabilities and coding errors.

*   **Dependency Scanning:**
    *   **Snyk:** Scans project dependencies for known vulnerabilities and provides remediation guidance.  This includes scanning the `requirements.txt` file generated from the Poetry `pyproject.toml`.

* **Automated Testing:**
    * A test suite (currently under development, but defined within GitHub Actions) run with various Python versions (3.10, 3.11, 3.12, and 3.13) ensures consistent behavior and helps identify regressions.

* **Report Aggregation and Verification:**
    * All reports generated by the analysis tools are hashed using SHA3-256 to ensure integrity.
    * Reports are uploaded as artifacts and downloaded for processing.  Hashes are verified before processing to prevent tampering.
    * If a report is missing or fails hash verification, a fallback report is created to ensure that the SonarQube analysis can still proceed, albeit with potentially incomplete data.

*   **SonarQube Integration:**
    *   Results from all the above tools are aggregated and reported to SonarQube for unified analysis and tracking.
    *   SonarQube provides a dashboard to visualize code quality metrics, security vulnerabilities, and code smells.
    *   Specific SonarQube properties are configured to import reports from each tool:
        *   `sonar.python.bandit.reportPaths`
        *   `sonar.python.ruff.reportPaths`
        *   `sonar.python.mypy.reportPaths`
        *   `sonar.python.pylint.reportPaths`
        *   `sonar.sarifReportPaths` (for CodeQL and Snyk)

*   **Quality Gates:**
    *   A SonarQube Quality Gate is configured to enforce code quality and security standards.
    *   The Quality Gate defines specific conditions that must be met, such as no new blocker or critical issues, and minimum code coverage.
    *   The Quality Gate status is checked *before* publishing a new release to PyPI.  If the Quality Gate *fails*, the release process is *halted*, preventing the distribution of potentially vulnerable or low-quality code. This check uses the `qualitygates/project_status` API endpoint of SonarQube.

* **Release Signing:**
    * Release artifacts are signed using Sigstore, ensuring their integrity and authenticity.

**Important Considerations:**

*   This library is currently in beta and has *not* undergone a formal security audit. It is **not recommended for use in production environments** without a thorough independent security review.
*   The library includes several known potential vulnerabilities (documented in the `README.md` and in GitHub Security Advisories). Please review these before reporting a vulnerability to avoid duplication. The known issues, including those requiring mitigation through lower-level implementations (e.g., in Rust), are tracked via the linked GHSA IDs.
* **False-Positive Vulnerabilities**: The usage of `random.Random()` seeded with cryptographic material in `_refresh_shares_additive` is an intentional design decision and is *not* a vulnerability.

Thank you for helping to improve the security of `PostQuantum-Feldman-VSS`!
