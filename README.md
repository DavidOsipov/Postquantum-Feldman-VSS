# Post-Quantum Secure Feldman's Verifiable Secret Sharing

[![Version](https://img.shields.io/badge/version-0.7.0--Alpha-blue)](https://github.com/davidosipov/feldman-vss-pq)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
[![Tests](https://github.com/davidosipov/feldman-vss-pq/actions/workflows/tests.yml/badge.svg)](https://github.com/davidosipov/feldman-vss-pq/actions/workflows/tests.yml)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

This library provides a Python implementation of Feldman's Verifiable Secret Sharing (VSS) scheme, designed with **post-quantum security** in mind.  It builds upon Shamir's Secret Sharing, adding mathematical verification to ensure the integrity of distributed shares, and uses hash-based commitments to resist quantum attacks.

**Key Features:**

*   **Post-Quantum Security:** Employs hash-based commitments (using BLAKE3 or SHA3-256) and large prime fields (minimum 4096 bits) to provide resistance against quantum computers.  No reliance on discrete logarithm problems.
*   **Verifiable Secret Sharing:**  Allows participants to verify the correctness of their shares, ensuring that the dealer has distributed shares of a valid secret.
*   **Fault Injection Countermeasures:** Includes redundant computation and checksum verification to mitigate fault injection attacks.
*   **Efficient Batch Verification:** Optimized for verifying multiple shares simultaneously.
*   **Serialization and Deserialization:**  Provides secure serialization and deserialization of commitment data, including checksums for integrity checks.
*   **Integration with Shamir's Secret Sharing:** Designed for seamless integration with a standard Shamir Secret Sharing implementation (specifically, it provides a helper function `create_vss_from_shamir`).
*   **Zero-Knowledge Proofs:** Includes methods to generate and verify zero-knowledge proofs of polynomial knowledge and dual-commitment proofs (for integration with Pedersen VSS).
*   **Byzantine Fault Tolerance:** Robust handling of malicious participants, including detection of equivocation and inconsistent shares.
*   **Share Refreshing:** Implements an optimized version of Chen & Lindell's Protocol 5 for securely refreshing shares without changing the underlying secret, with enhancements for asynchronous environments.
*   **Constant-Time Operations:** Utilizes constant-time comparison and exponentiation where appropriate to mitigate timing side-channel attacks.
*   **Optimized Cyclic Group Operations:** Features an enhanced cyclic group implementation with caching and precomputation for improved performance.
*   **Comprehensive Error Handling:** Includes custom exceptions for security, parameter, verification, and serialization errors.
*   **gmpy2-based Arithmetic:** Leverages the `gmpy2` library for high-performance, arbitrary-precision arithmetic, critical for cryptographic operations.

**Dependencies:**

*   **gmpy2:**  Required for efficient and secure large-number arithmetic.  (`pip install gmpy2`)
*   **blake3:** (Highly Recommended) For fast and secure cryptographic hashing. (`pip install blake3`)
*   **xxhash:** (Recommended) For high-performance checksums. (`pip install xxhash`)
*   **msgpack:** For efficient and secure serialization. (`pip install msgpack`)

If `blake3` is not available, the library will fall back to SHA3-256, but `blake3` is strongly recommended for performance and security.  If `xxhash` is not available, a cryptographic fallback (BLAKE3 or SHA3-256) will be used for checksums.

**Installation:**

```bash
pip install feldman-vss-pq
```
The source code is also available on Github:
```bash
git clone https://github.com/davidosipov/feldman-vss-pq.git
cd feldman-vss-pq
```

**Basic Usage:**

```python
from feldman_vss_pq import FeldmanVSS, get_feldman_vss, VSSConfig, CyclicGroup
from shamir_secret_sharing import ShamirSecretSharing # Assuming you have a Shamir implementation

# Example using a Shamir instance (replace with your actual Shamir implementation)
shamir = ShamirSecretSharing(5, 3)  # 5 shares, threshold of 3
secret = 1234567890
shares = shamir.split_secret(secret)

# Create a FeldmanVSS instance from the Shamir instance
vss = create_vss_from_shamir(shamir)

# Generate commitments and a zero-knowledge proof
coefficients = shamir.generate_coefficients(secret)
commitments, proof = vss.create_commitments_with_proof(coefficients)

# Verify the proof
is_valid = vss.verify_commitments_with_proof(commitments, proof)
print(f"Proof Verification: {is_valid}")  # Expected: True

# Verify a share
share_x, share_y = shares[1]  # Example share
is_share_valid = vss.verify_share(share_x, share_y, commitments)
print(f"Share Verification: {is_share_valid}") # Expected: True

# Serialize and deserialize commitments
serialized = vss.serialize_commitments(commitments)
deserialized_commitments, _, _, _, _ = vss.deserialize_commitments(serialized)
print(f"Commitments deserialized successfully: {commitments == deserialized_commitments}")

# Share refreshing example:
new_shares, new_commitments, verification_data = vss.refresh_shares(shares, 3, 5)
# ... further checks with verification_data ...

# --- Example without Shamir ---
# Example of direct usage (without Shamir)
from your_module import MersennePrimeField  # Replace with your field implementation

field = MersennePrimeField(4096) # Using a 4096-bit prime
vss = get_feldman_vss(field)
coefficients = [field.random_element() for _ in range(3)]
commitments = vss.create_commitments(coefficients)
# ... (rest of the example similar to above)
```

**Security Considerations:**

*   **Prime Size:** This library defaults to 4096-bit primes for post-quantum security.  It enforces a minimum of 4096 bits.  Using smaller primes is *strongly discouraged* and will trigger warnings.
*   **Safe Primes:** The library defaults to using safe primes (where `p` and `(p-1)/2` are both prime) to enhance security.
*   **Hash Algorithm:** BLAKE3 is the preferred hash algorithm for its speed and security.
*   **Entropy:**  The library uses `secrets` for cryptographically secure random number generation.
*   **Side-Channel Attacks:**  Constant-time operations are used where appropriate to mitigate timing attacks.

**Contributing:**

Contributions are welcome!  Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**License:**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Author:**

David Osipov (personal@david-osipov.vision)

