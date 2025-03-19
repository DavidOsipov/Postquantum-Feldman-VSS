# Frequently Asked Questions (FAQ)

## General Questions

### What is Verifiable Secret Sharing (VSS)?
Verifiable Secret Sharing (VSS) is a cryptographic technique that allows a dealer to distribute shares of a secret to multiple parties such that any subset of parties can verify that their shares are correct without revealing the secret. Feldman's VSS is a specific implementation that uses commitments to enable this verification.

### What makes this library post-quantum secure?
This library uses hash-based commitments with secure hash functions like BLAKE3 or SHA3-256, which are designed to be resistant to attacks from quantum computers, unlike traditional cryptographic schemes that rely on the hardness of discrete logarithms.

### What license is this library under?
The library is licensed under the MIT License. See [LICENSE](attachment:1) for details.

## Usage Questions

### How do I create shares using this library?
To create shares, first create an instance of `FeldmanVSS` with your desired configuration. Then, generate polynomial coefficients, create commitments using `create_commitments`, and distribute shares based on those coefficients. See the usage examples in [README.md](attachment:5) for detailed instructions.

### How do I verify a share?
Use the `verify_share` method of the `FeldmanVSS` instance, providing the share (as a tuple of (x, y)) and the commitments.

### Can I integrate this with Shamir's Secret Sharing?
Yes, the library provides the `create_vss_from_shamir` function, which allows you to create a FeldmanVSS instance from a ShamirSecretSharing object, enabling you to add verification capabilities to Shamir's shares.

### What is share refreshing, and why is it useful?
Share refreshing is a process that allows the shares to be updated without changing the underlying secret. This is useful in scenarios where shares need to be re-distributed or when some shares might have been compromised. The library provides the `refresh_shares` method for this purpose, with support for Byzantine fault tolerance.

### How does batch verification work, and when should I use it?
Batch verification allows you to verify multiple shares at once, which is more efficient than verifying them individually, especially for large numbers of shares. You can use the `batch_verify_shares` method when you need to verify many shares simultaneously.

## Security Questions

### Is this library safe for production use?
No, the library is currently in beta (version 0.8.0b2 as of March 19, 2025) and has known vulnerabilities, including timing side-channel attacks. It is strongly recommended not to use it in production without a thorough security audit by cryptography experts.

### What are the known vulnerabilities in this library?
There are timing side-channel vulnerabilities in matrix operations and inadequate fault injection countermeasures. These issues are acknowledged and planned to be addressed in future versions with the integration of Rust for security-critical components.

### How can I report a security issue?
Security issues should be reported following the guidelines in [SECURITY.md](attachment:4), which includes using GitHub's Private Vulnerability Reporting or contacting via Signal or encrypted email with the provided PGP key.

## Performance and Reliability

### What are the memory requirements for this library?
For a threshold of 50 with 4096-bit values, the library requires approximately 2GB of memory. For a threshold of 100, it requires about 4GB. These requirements can vary based on the specific configuration and use case.

### Is this library suitable for large-scale deployments?
While the library is designed to handle large thresholds, it has high memory requirements. For very large deployments, ensure that your system has sufficient resources. Additionally, due to its beta status and known vulnerabilities, it is not recommended for production use at this time.

### How do I handle errors in this library?
The library raises specific exceptions like `SecurityError`, `VerificationError`, etc., with detailed messages. You can catch these exceptions to handle errors gracefully. Refer to the API documentation in [README.md](attachment:5) for more details on error handling.

## Contributing

### How can I contribute to this project?
Contributions are welcome! Please see [CONTRIBUTING.md](attachment:3) for guidelines on how to contribute code, documentation, or report issues.