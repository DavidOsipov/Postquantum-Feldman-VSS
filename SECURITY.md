# Security Policy

## Supported Versions

Currently, PostQuantum-Feldman-VSS is in beta.  Only the latest beta version receives security updates.  There is no stable release yet.

| Version    | Supported          |
| ---------- | ------------------ |
| 0.7.5b0   | :white_check_mark: |
| < 0.7.5b0 | :x:                |

## Reporting a Vulnerability

**Please do not create a public GitHub issue for security vulnerabilities.**  This project is maintained by a single individual, and publicly disclosing vulnerabilities before a fix is available could put users at risk.

**To report a vulnerability, please contact David Osipov directly**
1. Via [Signal](https://signal.me/#eu/d68l1UjrWlGVRzbfkVM1bvQMNqCqiae9GM86P_af8ZK2o5E5YSNKbL4MyM9y-2WH) messenger

2. Or via email at [personal@david-osipov.vision](mailto:personal@david-osipov.vision).  You can encrypt your message using the following PGP key:

*   **Binary:** [openpgpkey.david-osipov.vision/.../hu/pjmzw74d6on6w4o8hhtn9z5agk1cta8n](https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/hu/pjmzw74d6on6w4o8hhtn9z5agk1cta8n)
*   **Armored:** [openpgpkey.david-osipov.vision/.../D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc](https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc)
* Verify the key at [keyoxide.org/wkd/business@david-osipov.vision](https://keyoxide.org/wkd/business@david-osipov.vision)

You can also use WKD to get it (e.g. using Thunderbird or Protonmail).

Please provide the following information in your report:

1.  **Description of the vulnerability:**  Explain the vulnerability in detail.  Include information about the affected component(s) of the library (e.g., specific functions, classes).
2.  **Proof of Concept (PoC):**  Provide a minimal, self-contained code example that demonstrates the vulnerability.  This is *essential* for verifying and fixing the issue.  Do *not* include any sensitive data (e.g., real secrets or shares).
3.  **Steps to Reproduce:**  Clearly outline the steps required to reproduce the vulnerability using the PoC.
4.  **Affected Version(s):**  Specify the version(s) of the library affected by the vulnerability.  If you tested multiple versions, please list them all.
5. **Potential Impact:** Describe the potential impact of exploiting the vulnerability.  (e.g., "Could allow an attacker to recover the secret," "Could allow an attacker to forge valid shares," "Could cause a denial of service").
6. **Your Environment:** Include information about your Python version, operating system, and any relevant dependencies (e.g., `gmpy2` version, `blake3` version if applicable).

**What to Expect:**

*   I will acknowledge receipt of your report within 72 hours (usually much sooner).
*   I will investigate the reported vulnerability and work to develop a fix.  I will keep you updated on the progress.  The time to develop a fix will depend on the complexity of the vulnerability.
*   Once a fix is available, I will release a new version of the library and credit you (if you wish) in the release notes and/or security advisories.
*   I will coordinate with you on the timing of public disclosure, if appropriate.

**Important Considerations:**

*   This library is currently in beta and has *not* undergone a formal security audit.  It is **not recommended for use in production environments** without a thorough independent security review.
*   The library includes several known potential vulnerabilities (documented in the `README.md`).  Please review these before reporting a vulnerability to avoid duplication.

Thank you for helping to improve the security of `PostQuantum-Feldman-VSS`!
