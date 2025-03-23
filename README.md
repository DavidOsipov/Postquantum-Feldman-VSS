# Post-Quantum Secure Feldman's Verifiable Secret Sharing

[![Version](https://img.shields.io/badge/version-0.8.0b2-blue)](https://github.com/davidosipov/PostQuantum-Feldman-VSS)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
[![Tests](https://github.com/davidosipov/PostQuantum-Feldman-VSS/actions/workflows/tests.yml/badge.svg)](https://github.com/davidosipov/PostQuantum-Feldman-VSS/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/PostQuantum-Feldman-VSS.svg?icon=si%3Apython&icon_color=%23ffffff)](https://badge.fury.io/py/PostQuantum-Feldman-VSS)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

This library provides a Python implementation of Feldman's Verifiable Secret Sharing (VSS) scheme, designed with **post-quantum security** in mind. It builds upon Shamir's Secret Sharing, adding mathematical verification to ensure the integrity of distributed shares, and uses hash-based commitments to resist quantum attacks.

## ATTENTION:

This code was developed with the assistance of AI language models and has been supervised by a product manager (non-cryptographer and non-developer). **The code has not undergone a formal security audit.** While every effort has been made to implement best practices for security and performance, it is **strongly recommended not to use this code in a production environment** without a thorough independent security review by qualified cryptography experts. Use at your own risk.

## Key Features:

*   **Post-Quantum Security:** Employs hash-based commitments (using BLAKE3 or SHA3-256) and large prime fields (minimum 4096 bits) to provide resistance against quantum computers. No reliance on discrete logarithm problems.
*   **Verifiable Secret Sharing:** Allows participants to verify the correctness of their shares, ensuring that the dealer has distributed shares of a valid secret.
*   **Fault Injection Countermeasures:** Includes redundant computation (`secure_redundant_execution`) and checksum verification to mitigate fault injection attacks.
*   **Efficient Batch Verification:** Optimized for verifying multiple shares simultaneously using `batch_verify_shares`.
*   **Serialization and Deserialization:** Provides secure serialization and deserialization of commitment data (`serialize_commitments`, `deserialize_commitments`), including checksums for integrity checks and handling of extra entropy for low-entropy secrets.
*   **Integration with Shamir's Secret Sharing:** Designed for seamless integration with a standard Shamir Secret Sharing implementation (specifically, it provides a helper function `create_vss_from_shamir`).
*   **Zero-Knowledge Proofs:** Includes methods to generate and verify zero-knowledge proofs of polynomial knowledge (`create_polynomial_proof`, `verify_polynomial_proof`) and dual-commitment proofs (for integration with Pedersen VSS: `create_dual_commitment_proof`, `verify_dual_commitments`).
*   **Byzantine Fault Tolerance:** Robust handling of malicious participants, including detection of equivocation, inconsistent shares, and adaptive quorum-based detection during share refreshing. This includes methods like `_detect_byzantine_behavior`, `_process_echo_consistency`, and `_enhanced_collusion_detection`.
*   **Share Refreshing:** Implements an optimized version of Chen & Lindell's Protocol 5 (`refresh_shares`, `_refresh_shares_additive`) for securely refreshing shares without changing the underlying secret, with enhancements for asynchronous environments and improved Byzantine fault tolerance.
*   **Constant-Time Operations:** Utilizes constant-time comparison (`constant_time_compare`) and exponentiation (`secure_exp`) where appropriate to mitigate timing side-channel attacks. *However, see "Known Security Vulnerabilities" below.*
*   **Optimized Cyclic Group Operations:** Features an enhanced `CyclicGroup` class implementation with a thread-safe LRU caching (`SafeLRUCache`) and precomputation for improved performance.
*   **Comprehensive Error Handling:** Includes custom exceptions for security (`SecurityError`, `SecurityWarning`), parameter (`ParameterError`), verification (`VerificationError`), and serialization (`SerializationError`) errors with detailed forensic data.
*   **gmpy2-based Arithmetic:** Leverages the `gmpy2` library for high-performance, arbitrary-precision arithmetic, critical for cryptographic operations.
*   **Deterministic Hashing:** Uses fixed-size integer representation for commitment generation (`_compute_hash_commitment_single`, `_compute_hash_commitment`), to be platform independent.
*   **Memory Safety:** Implements a `MemoryMonitor` class and integrates memory safety checks throughout the code to prevent excessive memory allocation and potential denial-of-service vulnerabilities.

## Dependencies:

*   **gmpy2:** Required for efficient and secure large-number arithmetic. (`pip install gmpy2`)
*   **blake3:** (Highly Recommended) For fast and secure cryptographic hashing. (`pip install blake3`)
*   **msgpack:** For efficient and secure serialization. (`pip install msgpack`)

If `blake3` is not available, the library will fall back to SHA3-256, but `blake3` is strongly recommended for performance and security.

## Installation:

```bash
pip install PostQuantum-Feldman-VSS
```

The source code is also available on Github:

```bash
git clone https://github.com/DavidOsipov/PostQuantum-Feldman-VSS.git
cd PostQuantum-Feldman-VSS
```

## Basic Usage:

```python
from feldman_vss import FeldmanVSS, get_feldman_vss, VSSConfig, CyclicGroup, create_vss_from_shamir
from shamir_secret_sharing import ShamirSecretSharing  # Assuming you have a Shamir implementation

# Example using a Shamir instance
shamir = ShamirSecretSharing(5, 3)  # 5 shares, threshold of 3
secret = 1234567890
shares = shamir.split_secret(secret)

# Create a FeldmanVSS instance from the Shamir instance
vss = create_vss_from_shamir(shamir)

# Generate commitments and a zero-knowledge proof
coefficients = shamir.get_polynomial_coefficients(secret)  # Actual method may vary
commitments, proof = vss.create_commitments_with_proof(coefficients)

# Verify the proof
is_valid = vss.verify_commitments_with_proof(commitments, proof)
print(f"Proof Verification: {is_valid}")  # Expected: True

# Verify a share
share_id = list(shares.keys())[0]  # Get the first share ID
share_x, share_y = shares[share_id]  # Get the (x,y) coordinates
is_share_valid = vss.verify_share(share_x, share_y, commitments)
print(f"Share Verification: {is_share_valid}")  # Expected: True

# Serialize and deserialize commitments
serialized = vss.serialize_commitments(commitments)
deserialized_commitments, _, _, _, _ = vss.deserialize_commitments(serialized)
print(f"Commitments deserialized successfully: {commitments == deserialized_commitments}")

# Share refreshing example:
new_shares, new_commitments, verification_data = vss.refresh_shares(shares, 3, 5)
# ... further checks with verification_data ...

# --- Example without Shamir ---
# Example of direct usage (without Shamir, you need a field implementation)
from your_field_module import PrimeField  # Replace with your field implementation

# Create a field with a sufficiently large prime for post-quantum security
field = PrimeField(bits=4096)  # Using a 4096-bit prime field

# Create VSS instance
config = VSSConfig(prime_bits=4096, safe_prime=True)
vss = get_feldman_vss(field, config=config)

# Generate polynomial coefficients (first coefficient is the secret)
secret = 12345
coefficients = [secret]  # First coefficient is the secret
for i in range(2):  # Add 2 more coefficients for threshold t=3
    coefficients.append(field.random_element())

# Create commitments
commitments = vss.create_commitments(coefficients)

# Generate shares
shares = {}
for i in range(1, 6):  # Generate 5 shares
    y = vss._evaluate_polynomial(coefficients, i)
    shares[i] = (i, y)

# Verify a share
share_id = 1
share_x, share_y = shares[share_id]
is_valid = vss.verify_share(share_x, share_y, commitments)
print(f"Share {share_id} verification: {is_valid}")
```

## Security Considerations:

*   **Prime Size:** This library defaults to 4096-bit primes for post-quantum security. It enforces a minimum of 4096 bits. Using smaller primes is *strongly discouraged* and will trigger warnings.
*   **Safe Primes:** The library defaults to using safe primes (where `p` and `(p-1)/2` are both prime) to enhance security. This can be configured via the `safe_prime` parameter in `VSSConfig`.
*   **Hash Algorithm:** BLAKE3 is the preferred hash algorithm for its speed and security. The library falls back to SHA3-256 if BLAKE3 is not available.
*   **Entropy:** The library uses `secrets` for cryptographically secure random number generation.
*   **Side-Channel Attacks:** Constant-time operations are used where appropriate to mitigate timing attacks. *However, see "Known Security Vulnerabilities" below.*

## Known Security Vulnerabilities:

This beta version (0.8.0b2) has several known security vulnerabilities that cannot be adequately addressed in pure Python:

1.  **Timing Side-Channels in Matrix Operations:** Functions like `_find_secure_pivot` and `_secure_matrix_solve` cannot guarantee constant-time execution in Python, potentially leaking secret information. (See [GHSA-q65w-fg65-79f4](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/security/advisories/GHSA-q65w-fg65-79f4))

2.  **Inadequate Fault Injection Countermeasures in `secure_redundant_execution`:** The `secure_redundant_execution` function attempts to mitigate fault injection attacks, but several weaknesses exist due to Python's execution environment. (See [GHSA-r8gc-qc2c-c7vh](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/security/advisories/GHSA-r8gc-qc2c-c7vh))

3.  **Use of Potentially Predictable PRNG in Share Refreshing:** The `_refresh_shares_additive` function uses `random.Random()` seeded with cryptographically strong material. While `random.Random()` is *not* generally suitable for cryptographic purposes, its use *here* is intentional and secure. (See [GHSA-39v3-9v27-595x](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/security/advisories/GHSA-39v3-9v27-595x))

**Status:** These vulnerabilities require implementation in a lower-level language like Rust to fix properly. The library should be considered experimental until these issues are addressed.

**Planned Resolution:** Future versions will integrate with Rust components for security-critical operations.

## How the Script Works in Detail:

For a comprehensive explanation of the internal workings of the `PostQuantum-Feldman-VSS` library (version 0.8.0b2), please refer to the detailed documentation on the [How version 0.8.0b2 works in detail](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/wiki/How-version-0.8.0b2-works-in-detail) wiki page. This document provides an in-depth breakdown of each class and method, including design choices, security considerations, and potential vulnerabilities. It covers topics such as:

*   **Class Structure:** Detailed explanation of `FeldmanVSS`, `CyclicGroup`, `VSSConfig`, and `SafeLRUCache`.
*   **Core Methods:** Step-by-step walkthroughs of key methods like `create_commitments`, `verify_share`, `refresh_shares`, and more.
*   **Security Mechanisms:** In-depth discussion of how the library addresses post-quantum security, timing attacks, fault injection attacks, and Byzantine behavior.
*   **Helper Functions:** Explanation of supporting functions like `constant_time_compare`, `secure_redundant_execution`, and others.
*   **Serialization and Deserialization:** Details on how commitment data is securely serialized and deserialized.
*   **Zero-Knowledge Proofs:** How the library generates and verifies zero-knowledge proofs.
*   **Integration with Pedersen VSS:** Dual verification for binding and hiding.
*   **Memory Monitoring**: Details on usage and integration of the new `MemoryMonitor` class.

## References:

The following sources were used as references and inspiration for the creation of this library:

*   Feldman, P. (1987). A Practical Scheme for Non-interactive Verifiable Secret Sharing. In 28th Annual Symposium on Foundations of Computer Science (FOCS), pp. 427-437. IEEE. [Link](https://dl.acm.org/doi/10.1109/SFCS.1987.46)
*   Shamir, A. (1979). How to Share a Secret. Communications of the ACM, 22(11), 612-613. [Link](https://dl.acm.org/doi/10.1145/359168.359176)
*   Chen, X., & Lindell, Y. (2024). Fast Actively Secure Multi-Party Computation with Dishonest Majority. [Link](https://eprint.iacr.org/2024/311)
*   Baghery, K., Khazaei, S., & Sadeghi, A. R. (2025). A Unified Framework for Verifiable Secret Sharing. [Link](https://eprint.iacr.org/2024/1394)
*   Gennaro, R., Ishai, Y., Kushilevitz, E., & Rabin, T. (2007). The round complexity of verifiable secret sharing and secure multicast. In Proceedings of the thirty-ninth annual ACM symposium on Theory of computing, pp. 580-589. [Link](https://dl.acm.org/doi/10.1145/1250790.1250876)
*   Cramer, R., Damgård, I., & Nielsen, J. B. (2015). Secure Multiparty Computation and Secret Sharing. Cambridge University Press.
*   National Institute of Standards and Technology (NIST). (2013). Recommendation for Applications Using Approved Hash Algorithms. NIST Special Publication 800-107 Revision 1.
*   National Institute of Standards and Technology (NIST). (2020). Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography NIST Special Publication 800-56A, Revision 3.
*   Kivinen, T. & Kojo, M. (2003). More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE). RFC 3526. [Link](https://datatracker.ietf.org/doc/html/rfc3526).  *This RFC provides the safe prime values used in the library's default configuration for 3072, 4096, 6144, and 8192-bit groups.*

## License:

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author:

David Osipov (personal@david-osipov.vision)
*   ISNI: [0000 0005 1802 960X](https://isni.org/isni/000000051802960X)
*   ORCID: [0009-0005-2713-9242](https://orcid.org/0009-0005-2713-9242)
*   PGP key: https://openpgpkey.david-osipov.vision/.well-known/openpgpkey/david-osipov.vision/D3FC4983E500AC3F7F136EB80E55C4A47454E82E.asc
*   PGP fingerprint: D3FC 4983 E500 AC3F 7F13 6EB8 0E55 C4A4 7454 E82E
*   Website: https://david-osipov.vision
*   LinkedIn: https://www.linkedin.com/in/david-osipov/
