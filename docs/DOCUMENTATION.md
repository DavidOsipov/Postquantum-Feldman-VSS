# PostQuantum-Feldman-VSS API Reference (Version 0.8.0b3)

This document provides a detailed API reference for the `PostQuantum-Feldman-VSS` library, a Python implementation of Feldman's Verifiable Secret Sharing (VSS) scheme designed for post-quantum security.  It covers all public classes and methods, including parameters, return types, descriptions, examples, and security considerations.

**Important Note:** This library is currently in **beta (0.8.0b3)** and has *not* undergone a formal security audit.  It is **not recommended for use in production environments** without a thorough independent review by qualified cryptography experts.  Refer to the main `README.md` for known security vulnerabilities.

## Table of Contents

- [PostQuantum-Feldman-VSS API Reference (Version 0.8.0b3)](#postquantum-feldman-vss-api-reference-version-080b3)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Classes](#classes)
    - [`FeldmanVSS`](#feldmanvss)
      - [`__init__`](#__init__)
      - [`create_commitments`](#create_commitments)
      - [`create_enhanced_commitments`](#create_enhanced_commitments)
      - [`verify_share`](#verify_share)
      - [`batch_verify_shares`](#batch_verify_shares)
      - [`serialize_commitments`](#serialize_commitments)
      - [`deserialize_commitments`](#deserialize_commitments)
      - [`verify_share_from_serialized`](#verify_share_from_serialized)
      - [`create_polynomial_proof`](#create_polynomial_proof)
      - [`verify_polynomial_proof`](#verify_polynomial_proof)
      - [`create_commitments_with_proof`](#create_commitments_with_proof)
      - [`verify_commitments_with_proof`](#verify_commitments_with_proof)
      - [`serialize_commitments_with_proof`](#serialize_commitments_with_proof)
      - [`deserialize_commitments_with_proof`](#deserialize_commitments_with_proof)
      - [`verify_share_with_proof`](#verify_share_with_proof)
      - [`refresh_shares`](#refresh_shares)
      - [`detect_byzantine_party`](#detect_byzantine_party)
      - [`clear_cache`](#clear_cache)
    - [`VSSConfig`](#vssconfig)
      - [`__init__`](#__init__-1)
    - [`CyclicGroup`](#cyclicgroup)
      - [`__init__`](#__init__-2)
      - [`exp`](#exp)
      - [`mul`](#mul)
      - [`secure_random_element`](#secure_random_element)
      - [`hash_to_group`](#hash_to_group)
      - [`efficient_multi_exp`](#efficient_multi_exp)
      - [`secure_exp`](#secure_exp)
      - [`clear_cache`](#clear_cache-1)
    - [`SafeLRUCache`](#safelrucache)
      - [`__init__`](#__init__-3)
      - [`get`](#get)
      - [`put`](#put)
      - [`clear`](#clear)
      - [`__len__`](#__len__)
    - [`MemoryMonitor`](#memorymonitor)
      - [`__init__`](#__init__-4)
      - [`check_allocation`](#check_allocation)
      - [`allocate`](#allocate)
      - [`release`](#release)
      - [`get_usage_stats`](#get_usage_stats)
  - [Factory Functions](#factory-functions)
    - [`get_feldman_vss`](#get_feldman_vss)
    - [`create_vss_from_shamir`](#create_vss_from_shamir)
  - [Integration Helpers](#integration-helpers)
    - [`integrate_with_pedersen`](#integrate_with_pedersen)
    - [`create_dual_commitment_proof`](#create_dual_commitment_proof)
    - [`verify_dual_commitments`](#verify_dual_commitments)
  - [Helper Functions](#helper-functions)
    - [`constant_time_compare`](#constant_time_compare)
    - [`compute_checksum`](#compute_checksum)
    - [`secure_redundant_execution`](#secure_redundant_execution)
    - [`estimate_mpz_size`](#estimate_mpz_size)
    - [`estimate_mpz_operation_memory`](#estimate_mpz_operation_memory)
    - [`estimate_exp_result_size`](#estimate_exp_result_size)
    - [`get_system_memory`](#get_system_memory)
    - [`check_memory_safety`](#check_memory_safety)
    - [`validate_timestamp`](#validate_timestamp)
  - [Exceptions](#exceptions)
    - [`SecurityError`](#securityerror)
    - [`SerializationError`](#serializationerror)
    - [`VerificationError`](#verificationerror)
    - [`ParameterError`](#parametererror)
    - [`SecurityWarning`](#securitywarning)
  - [Type Definitions](#type-definitions)
  - [Security Considerations](#security-considerations)

## Introduction

The `PostQuantum-Feldman-VSS` library provides a robust and secure implementation of Feldman's Verifiable Secret Sharing (VSS) scheme.  It enhances Shamir's Secret Sharing with the ability to verify the correctness of distributed shares, ensuring the dealer has distributed a valid secret.  This implementation is designed with post-quantum security in mind, relying on hash-based commitments rather than discrete logarithm problems.

## Classes

### `FeldmanVSS`

The core class implementing the Feldman VSS scheme.

#### `__init__`

```python
def __init__(self, field: Any, config: Optional[VSSConfig] = None, group: Optional[CyclicGroup] = None) -> None:
```

**Description:** Initializes a `FeldmanVSS` instance.

**Parameters:**

*   `field`:  An object representing the finite field for polynomial operations.  Must have a `prime` attribute (an integer or `gmpy2.mpz`) representing the field's modulus.  Typically, this will be a field object from a Shamir Secret Sharing implementation.
*   `config` (Optional[`VSSConfig`]): A `VSSConfig` object specifying configuration parameters. If `None`, a default post-quantum secure configuration is used.
*   `group` (Optional[`CyclicGroup`]):  A pre-configured `CyclicGroup` instance. If `None`, a new `CyclicGroup` is created using parameters from the `config` (or defaults).

**Raises:**

*   `TypeError`: If `field` is `None` or does not have a `prime` attribute of the correct type.

**Example:**

```python
from feldman_vss import FeldmanVSS, VSSConfig
from your_field_module import PrimeField  # Replace with your field implementation

field = PrimeField(bits=4096)
vss = FeldmanVSS(field)  # Using default post-quantum secure configuration

config = VSSConfig(prime_bits=8192, safe_prime=True, use_blake3=True)
vss_custom = FeldmanVSS(field, config=config)
```

#### `create_commitments`

```python
def create_commitments(self, coefficients: List[FieldElement], context: Optional[str] = None) -> CommitmentList:
```

**Description:** Creates hash-based commitments to the polynomial coefficients.  These commitments are used to verify shares without revealing the secret.

**Parameters:**

*   `coefficients`: A list of `FieldElement` (integer or `gmpy2.mpz`) representing the polynomial coefficients `[a₀, a₁, ..., aₖ₋₁]`, where `a₀` is the secret.
*   `context` (Optional[str]): An optional string for domain separation, enhancing security.

**Returns:**

*   `CommitmentList`:  A list of `HashCommitment` tuples.  Each tuple contains `(hash, randomizer, extra_entropy)`. `hash` is the commitment value, `randomizer` is the blinding factor used, and `extra_entropy` is `None` or a `bytes` object used for low-entropy secrets.

**Raises:**

*   `TypeError`: If `coefficients` is not a list, or if `context` is not a string (if provided).
*   `ValueError`: If `coefficients` is empty.

**Example:**

```python
coefficients = [12345, 67890, 11121]  # Secret is 12345
commitments = vss.create_commitments(coefficients)
print(commitments)
```
#### `create_enhanced_commitments`

```python
def create_enhanced_commitments(self, coefficients: List[FieldElement], context: Optional[str] = None) -> CommitmentList:
```

**Description:** Create enhanced hash-based commitments with improved entropy handling for low-entropy secrets (Baghery's method, 2025).

**Parameters:**

*   `coefficients` (list): List of polynomial coefficients.
*   `context` (str, optional): Optional context string for domain separation.

**Returns:**

*   `CommitmentList`:  A list of `HashCommitment` tuples.

**Raises:**
*  `TypeError`: If `coefficients` is not a list, or if `context` is not a string (if provided).
*  `ParameterError`: If `coefficients` is empty.
**Example:**

```python
coefficients = [12345, 67890, 11121]  # Secret is 12345
commitments = vss.create_enhanced_commitments(coefficients)
print(commitments)
```

#### `verify_share`

```python
def verify_share(self, share_x: FieldElement, share_y: FieldElement, commitments: CommitmentList) -> bool:
```

**Description:** Verifies a single share against the provided commitments, using redundant execution for fault resistance.

**Parameters:**

*   `share_x`: The x-coordinate of the share (an integer or `gmpy2.mpz`).
*   `share_y`: The y-coordinate of the share (the share value, an integer or `gmpy2.mpz`).
*   `commitments`: The `CommitmentList` returned by `create_commitments`.

**Returns:**

*   `bool`: `True` if the share is valid, `False` otherwise.
**Raises:**
*   `TypeError`: If inputs have incorrect types or commitments is empty.

**Example:**

```python
share_x = 1
share_y = 79256  # Example y-value
is_valid = vss.verify_share(share_x, share_y, commitments)
print(f"Share is valid: {is_valid}")
```

#### `batch_verify_shares`

```python
def batch_verify_shares(self, shares: List[SharePoint], commitments: CommitmentList) -> VerificationResult:
```

**Description:** Efficiently verifies multiple shares against the same set of commitments.  Optimized for performance with large batches of shares.

**Parameters:**

*   `shares`: A list of `SharePoint` tuples, where each tuple is `(x, y)` representing a share.
*   `commitments`: The `CommitmentList` returned by `create_commitments`.

**Returns:**

*   `VerificationResult`: A tuple `(all_valid, results)`.
    *   `all_valid`: A boolean indicating if *all* shares are valid.
    *   `results`: A dictionary mapping share indices (from the input `shares` list) to boolean verification results (`True` for valid, `False` for invalid).

**Raises:**
*   `TypeError`: If inputs have incorrect types or are empty.
*   `ValueError`: If shares list is empty.

**Example:**

```python
shares = [(1, 79256), (2, 147266), (3, 226386)]  # Example shares
all_valid, results = vss.batch_verify_shares(shares, commitments)
print(f"All shares valid: {all_valid}")
print(f"Individual share results: {results}")
```

#### `serialize_commitments`

```python
def serialize_commitments(self, commitments: CommitmentList) -> str:
```

**Description:** Serializes commitment data (including a checksum) into a base64-encoded string for storage or transmission.

**Parameters:**

*   `commitments`: The `CommitmentList` returned by `create_commitments`.

**Returns:**

*   `str`: A base64-encoded string representing the serialized data.

**Raises:**

*   `TypeError`: If `commitments` is not a list or has an incorrect format.
*   `ValueError`: If `commitments` list is empty.
*   `SerializationError`: If serialization fails.

**Example:**

```python
serialized_data = vss.serialize_commitments(commitments)
print(f"Serialized commitments: {serialized_data}")
```

#### `deserialize_commitments`

```python
def deserialize_commitments(self, data: str) -> Tuple[CommitmentList, FieldElement, FieldElement, int, bool]:
```

**Description:** Deserializes commitment data from a base64-encoded string, verifying its integrity using a checksum.

**Parameters:**

*   `data`: The base64-encoded string returned by `serialize_commitments`.

**Returns:**

*   `Tuple[CommitmentList, FieldElement, FieldElement, int, bool]`:  A tuple containing:
    *   `CommitmentList`: The list of `HashCommitment` tuples.
    *   `FieldElement`: The generator of the cyclic group.
    *   `FieldElement`: The prime modulus of the cyclic group.
    *   `int`: The timestamp when the commitments were created.
    *   `bool`:  Indicates whether the commitments are hash-based (`True`) or not (`False`).

**Raises:**

*   `TypeError`: If `data` is not a string or is empty.
*   `ValueError`: If `data` is empty.
*   `SerializationError`: If deserialization or checksum validation fails.
*   `SecurityError`: If checksum or cryptographic parameter validation fails.

**Example:**

```python
deserialized_commitments, generator, prime, timestamp, is_hash_based = vss.deserialize_commitments(serialized_data)
print(f"Deserialized commitments: {deserialized_commitments}")
```

#### `verify_share_from_serialized`

```python
def verify_share_from_serialized(self, share_x: FieldElement, share_y: FieldElement, serialized_commitments: str) -> bool:

```

**Description:** Verifies a share directly against serialized commitment data.

**Parameters:**

*  `share_x`: The x-coordinate of the share.
*  `share_y`: The y-coordinate of the share.
*  `serialized_commitments`: The serialized commitment data (a base64-encoded string).

**Returns:**

*  `bool`: True if the share is valid, False otherwise.

**Raises:**
*   `TypeError`: If inputs have incorrect types or serialized_commitments is empty.
*   `VerificationError`: If deserialization or verification fails.
**Example:**

```python
is_valid = vss.verify_share_from_serialized(1, 79256, serialized_data)
print(f"Share verification from serialized data: {is_valid}")
```

#### `create_polynomial_proof`

```python
def create_polynomial_proof(self, coefficients: List[FieldElement], commitments: CommitmentList) -> ProofDict:
```

**Description:** Creates a zero-knowledge proof of knowledge of the polynomial coefficients, using hash-based commitments.

**Parameters:**

*   `coefficients`: The polynomial coefficients `[a₀, a₁, ..., aₖ₋₁]`.
*   `commitments`:  The `CommitmentList` corresponding to these coefficients.

**Returns:**

*   `ProofDict`: A dictionary representing the proof, containing:
    *   `blinding_commitments`: Commitments to blinding factors.
    *   `challenge`: The Fiat-Shamir challenge value.
    *   `responses`: The responses to the challenge.
    *   `commitment_randomizers`: Randomizers for the original commitments
    *   `blinding_randomizers`:  Randomizers for the blinding commitments.
    *   `timestamp`: Timestamp of proof creation.

**Raises:**
*  `TypeError`: If inputs have incorrect types or structures.
*  `ValueError`: If coefficients or commitments lists are empty.

**Example:**

```python
proof = vss.create_polynomial_proof(coefficients, commitments)
print(f"Generated proof: {proof}")
```

#### `verify_polynomial_proof`

```python
def verify_polynomial_proof(self, proof: ProofDict, commitments: CommitmentList) -> bool:
```

**Description:** Verifies a zero-knowledge proof of polynomial knowledge.

**Parameters:**

*   `proof`: The `ProofDict` returned by `create_polynomial_proof`.
*   `commitments`: The `CommitmentList` corresponding to the polynomial.

**Returns:**

*   `bool`: `True` if the proof is valid, `False` otherwise.

**Raises:**
*  `TypeError`: If inputs have incorrect types.
*  `ValueError`: If commitments list is empty or proof structure is invalid.

**Example:**

```python
is_valid = vss.verify_polynomial_proof(proof, commitments)
print(f"Proof verification: {is_valid}")
```

#### `create_commitments_with_proof`

```python
def create_commitments_with_proof(self, coefficients: List[FieldElement], context: Optional[str] = None) -> Tuple[CommitmentList, ProofDict]:
```

**Description:**  Creates commitments *and* a zero-knowledge proof of polynomial knowledge in a single, efficient operation.

**Parameters:**

*   `coefficients`: The polynomial coefficients.
*   `context` (Optional[str]):  An optional context string for domain separation.

**Returns:**

*   `Tuple[CommitmentList, ProofDict]`:  A tuple containing the `CommitmentList` and the `ProofDict`.

**Raises:**
*   `TypeError`: If inputs have incorrect types.

**Example:**

```python
commitments, proof = vss.create_commitments_with_proof(coefficients)
print(f"Commitments: {commitments}")
print(f"Proof: {proof}")
```

#### `verify_commitments_with_proof`

```python
def verify_commitments_with_proof(self, commitments: CommitmentList, proof: ProofDict, strict_verification: bool = False) -> bool:
```

**Description:** Verifies both the commitments and the associated zero-knowledge proof.

**Parameters:**

*   `commitments`: The `CommitmentList`.
*   `proof`: The `ProofDict`.
*   `strict_verification`: (bool) If `True`, raises `VerificationError` on challenge failure, else returns `False` with a `SecurityWarning`.

**Returns:**

*   `bool`: `True` if both commitments and proof are valid, `False` otherwise.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If commitments list is empty.
*   `SecurityWarning`: If proof is missing required keys.
*   `VerificationError`: If `strict_verification` is True and verification fails.

**Example:**

```python
is_valid = vss.verify_commitments_with_proof(commitments, proof)
print(f"Commitments and proof verification: {is_valid}")

```

#### `serialize_commitments_with_proof`

```python
def serialize_commitments_with_proof(self, commitments: CommitmentList, proof: ProofDict) -> str:
```

**Description:** Serializes both the commitments and the associated zero-knowledge proof into a single base64-encoded string.

**Parameters:**

*  `commitments`: The list of commitments.
*  `proof`: The proof data structure.

**Returns:**
*   `str`: A base64-encoded string.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If proof is missing required keys.
*   `SerializationError`: If serialization fails.

**Example:**

```python
serialized_data = vss.serialize_commitments_with_proof(commitments, proof)
print(f"Serialized commitments and proof: {serialized_data}")

```

#### `deserialize_commitments_with_proof`

```python
def deserialize_commitments_with_proof(self, data: str) -> Tuple[CommitmentList, ProofDict, FieldElement, FieldElement, int]:
```

**Description:** Deserializes both commitments and the associated proof from a base64-encoded string.

**Parameters:**

*   `data`: The base64-encoded string.

**Returns:**

*   `Tuple[CommitmentList, ProofDict, FieldElement, FieldElement, int]`: A tuple containing:
    *   `CommitmentList`: The list of commitments.
    *   `ProofDict`: The proof data.
    *   `FieldElement`: The generator of the cyclic group.
    *   `FieldElement`: The prime modulus of the cyclic group.
    *   `int`: The timestamp of commitment creation.

**Raises:**
*   `TypeError`: If data is not a string or is empty.
*   `SerializationError`: If deserialization or validation fails.
*   `SecurityError`: If data integrity checks fail.

**Example:**
```python
commitments, proof, generator, prime, timestamp = vss.deserialize_commitments_with_proof(serialized_data)
print(f"Deserialized commitments: {commitments}")
print(f"Deserialized proof: {proof}")

```

#### `verify_share_with_proof`

```python
def verify_share_with_proof(self, share_x: FieldElement, share_y: FieldElement, serialized_data: str) -> Tuple[bool, bool]:
```

**Description:** Verifies both a share and the associated proof of polynomial knowledge against serialized data.

**Parameters:**

*  `share_x`: The x-coordinate of the share.
*  `share_y`: The y-coordinate of the share.
*  `serialized_data`: Serialized commitment and proof data (base64 string).

**Returns:**
* `Tuple[bool, bool]`: A tuple `(share_valid, proof_valid)`.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `VerificationError`: If verification fails.

**Example:**

```python
share_valid, proof_valid = vss.verify_share_with_proof(1, 79256, serialized_data)
print(f"Share valid: {share_valid}, Proof valid: {proof_valid}")

```

#### `refresh_shares`

```python
def refresh_shares(
    self,
    shares: ShareDict,
    threshold: int,
    total_shares: int,
    original_commitments: Optional[CommitmentList] = None,
    participant_ids: Optional[List[int]] = None,
) -> RefreshingResult:
```

**Description:** Refreshes shares while preserving the original secret, using an optimized version of Chen & Lindell's Protocol 5. This method is designed for asynchronous environments and provides improved Byzantine fault tolerance.

**Parameters:**

*   `shares`: A dictionary mapping participant IDs to their shares (`{id: (x, y)}`).
*   `threshold`: The secret sharing threshold (`t`).
*   `total_shares`: The total number of shares (`n`).
*   `original_commitments` (Optional[`CommitmentList`]): The original commitments (optional, for proof validation).
*   `participant_ids` (Optional[`List[int]`]):  An optional list of participant IDs. If `None`, numeric IDs `(1 to total_shares)` are used.

**Returns:**

*   `RefreshingResult`: A tuple `(new_shares, new_commitments, verification_data)`.
    *   `new_shares`:  A dictionary of the new shares.
    *   `new_commitments`: Commitments to the new polynomial.
    *   `verification_data`: A dictionary containing verification information, including summaries of invalid shares, Byzantine behavior, and proof structures.

**Raises:**

*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If `threshold` or `total_shares` are invalid, or `participant_ids` length is incorrect.
*   `ParameterError`: If not enough shares are provided.
*   `SecurityError`: If insufficient valid shares are received during the refresh process, indicating a potential security issue.

**Example:**

```python
shares = {1: (1, 79256), 2: (2, 147266), 3: (3, 226386)}
threshold = 2
total_shares = 3
new_shares, new_commitments, verification_data = vss.refresh_shares(
    shares, threshold, total_shares
)
print(f"New shares: {new_shares}")
print(f"New commitments: {new_commitments}")
print(f"Verification data: {verification_data}")
```

#### `detect_byzantine_party`

```python
def detect_byzantine_party(
    self, party_id: int, commitments: CommitmentList, shares: ShareDict, consistency_results: Optional[Dict[Tuple[int, int], bool]] = None
) -> Tuple[bool, Dict[str, Any]]:
```

**Description:**  Detects Byzantine behavior from a specific party, checking for inconsistent shares, invalid commitments, and equivocation.

**Parameters:**

*  `party_id`: The ID of the party to check.
*  `commitments`: The commitments from the party.
*  `shares`: The shares distributed by the party.
*   `consistency_results`: (Optional[Dict[Tuple[int, int], bool]]) Optional consistency check results.

**Returns:**
*  `Tuple[bool, Dict[str, Any]]`: A tuple: `(is_byzantine, evidence_details)`.
    *   `is_byzantine`: `True` if Byzantine behavior is detected, `False` otherwise.
    *   `evidence_details`: A dictionary containing details about the detected issues.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If commitments list is empty.

**Example:**
```python
is_byzantine, evidence = vss.detect_byzantine_party(1, commitments, shares)
print(f"Party 1 is Byzantine: {is_byzantine}")
if is_byzantine:
   print(f"Evidence: {evidence}")
```

#### `clear_cache`
```python
def clear_cache(self) -> None:
```
**Description:** Clear verification cache to free memory.

**Parameters:**
*   None

**Returns:**
*   None

**Example:**
```python
vss.clear_cache()
```

### `VSSConfig`

A data class for configuring the `FeldmanVSS` instance.

#### `__init__`

```python
@dataclass
class VSSConfig:
    prime_bits: int = 4096
    safe_prime: bool = True
    secure_serialization: bool = True
    use_blake3: bool = True
    cache_size: int = 128
    sanitize_errors: bool = True
```

**Description:**  Initializes a `VSSConfig` object.

**Parameters:**

*   `prime_bits`: The number of bits for the prime modulus.  Defaults to 4096 (post-quantum secure).  **Minimum: 4096**.
*   `safe_prime`: Whether to use a safe prime (where `(p-1)/2` is also prime). Defaults to `True`.
*   `secure_serialization`: Whether to use secure serialization. Defaults to `True`.
*   `use_blake3`: Whether to use BLAKE3 for hashing (falls back to SHA3-256 if unavailable). Defaults to `True`.
*   `cache_size`: The size of the LRU cache for exponentiation results. Defaults to 128.
*   `sanitize_errors`:  Whether to sanitize error messages (preventing information leakage).  Defaults to `True`. Set to `False` only in secure debugging environments.

**Example:**

```python
config = VSSConfig(prime_bits=8192, safe_prime=False, cache_size=256)
```

### `CyclicGroup`

A class representing a cyclic group for cryptographic operations, optimized for performance and security.

#### `__init__`

```python
def __init__(
    self,
    prime: Optional[int] = None,
    generator: Optional[int] = None,
    prime_bits: int = 3072,
    use_safe_prime: bool = True,
    cache_size: int = 128,
) -> None:
```

**Description:** Initializes a `CyclicGroup` instance.

**Parameters:**

*   `prime` (Optional[`int`]): The prime modulus. If `None`, a safe prime is selected or generated.
*   `generator` (Optional[`int`]): The generator of the group.  If `None`, a generator is found.
*   `prime_bits`: The bit size for the prime if generating one.  Defaults to 3072 (post-quantum secure).
*   `use_safe_prime`: Whether to use a safe prime. Defaults to `True`.
*   `cache_size`: The size of the LRU cache for exponentiation. Defaults to 128.

**Example:**

```python
group = CyclicGroup(prime_bits=4096, use_safe_prime=True)
```

#### `exp`

```python
def exp(self, base: Union[int, "gmpy2.mpz"], exponent: Union[int, "gmpy2.mpz"]) -> "gmpy2.mpz":
```

**Description:**  Performs thread-safe, optimized exponentiation in the group (`base`<sup>`exponent`</sup> mod `prime`).  *Not suitable for secret exponents; use `secure_exp` for sensitive values.*

**Parameters:**

*   `base`: The base value.
*   `exponent`: The exponent value.

**Returns:**

*   `gmpy2.mpz`: The result of the exponentiation.
**Raises:**
*   `MemoryError`: If the operation would likely exceed available memory

**Example:**

```python
result = group.exp(group.generator, 12345)
```

#### `mul`

```python
def mul(self, a: Union[int, "gmpy2.mpz"], b: Union[int, "gmpy2.mpz"]) -> "gmpy2.mpz":
```

**Description:**  Multiplies two elements in the group (`(a * b) mod prime`).

**Parameters:**

*   `a`: The first element.
*   `b`: The second element.

**Returns:**
*   `gmpy2.mpz`: The result of the multiplication.
**Raises:**
*   `MemoryError`: If the operation would likely exceed available memory

**Example:**

```python
result = group.mul(123, 456)
```

#### `secure_random_element`

```python
def secure_random_element(self) -> "gmpy2.mpz":
```

**Description:**  Generates a cryptographically secure random element in the group (in the range `[1, prime-1]`).

**Returns:**

*   `gmpy2.mpz`: A random element in the group.

**Example:**

```python
random_element = group.secure_random_element()
```

#### `hash_to_group`

```python
def hash_to_group(self, data: bytes) -> "gmpy2.mpz":
```

**Description:** Hashes arbitrary data to a group element with a uniform distribution, using strict rejection sampling.

**Parameters:**

*   `data`: The data to hash (bytes).

**Returns:**

*   `gmpy2.mpz`: A group element.

**Raises:**
*   `TypeError`: If data is not bytes.
*   `SecurityError`: If unable to generate a uniformly distributed value.

**Example:**

```python
data = b"some data to hash"
group_element = group.hash_to_group(data)
```

#### `efficient_multi_exp`
```python
def efficient_multi_exp(self, bases: List[Union[int, "gmpy2.mpz"]], exponents: List[Union[int, "gmpy2.mpz"]]) -> "gmpy2.mpz":
```

**Description:** Efficient multi-exponentiation using simultaneous method. Computes Π(bases[i]^exponents[i]) mod prime.

**Parameters:**
* `bases`: List of base values.
* `exponents`: List of corresponding exponent values.

**Returns:**
* `gmpy2.mpz`: The result of the multi-exponentiation.

**Raises:**
*   `ValueError`: If the number of bases does not equal the number of exponents

**Example:**
```python
bases = [2, 3, 5]
exponents = [10, 5, 2]
result = group.efficient_multi_exp(bases, exponents)
```

#### `secure_exp`

```python
def secure_exp(self, base: Union[int, "gmpy2.mpz"], exponent: Union[int, "gmpy2.mpz"]) -> "gmpy2.mpz":
```

**Description:**  Performs constant-time exponentiation, suitable for sensitive cryptographic operations where the `exponent` is secret.  Avoids caching and timing side-channels.

**Parameters:**

*   `base`: The base value.
*   `exponent`: The exponent value (considered sensitive).

**Returns:**
*   `gmpy2.mpz`: The result of the exponentiation (`base`<sup>`exponent`</sup> mod `prime`).

**Raises:**
    *   `MemoryError`: If the operation would likely exceed available memory

**Example:**

```python
result = group.secure_exp(group.generator, 12345)  # 12345 is a secret exponent here
```

#### `clear_cache`

```python
def clear_cache(self) -> None:
```

**Description:** Clears the internal exponentiation cache (thread-safe).  Useful for freeing memory when the `CyclicGroup` instance is no longer needed or to reduce memory footprint.

**Example:**

```python
group.clear_cache()
```

### `SafeLRUCache`

A thread-safe Least Recently Used (LRU) cache implementation, used internally by `CyclicGroup` for caching exponentiation results.

#### `__init__`

```python
def __init__(self, capacity: int) -> None:
```

**Description:** Initializes a `SafeLRUCache` with a specified capacity.

**Parameters:**

*   `capacity`: The maximum number of items to store in the cache.

**Example:**

```python
from feldman_vss import SafeLRUCache

cache = SafeLRUCache(capacity=100)
```

#### `get`

```python
def get(self, key: K) -> Optional[V]:
```

**Description:** Retrieves an item from the cache.  If the item is found, it's moved to the most recently used position.

**Parameters:**

*   `key`: The key to retrieve.

**Returns:**

*   `Optional[V]`: The value associated with the key, or `None` if the key is not in the cache.

**Example:**

```python
value = cache.get("my_key")
if value is not None:
    print(f"Found value: {value}")
```

#### `put`

```python
def put(self, key: K, value: V) -> None:
```

**Description:** Adds or updates an item in the cache.  If the cache is full, the least recently used item is evicted.

**Parameters:**

*   `key`: The key to store.
*   `value`: The value to associate with the key.

**Example:**

```python
cache.put("my_key", "my_value")
```

#### `clear`

```python
def clear(self) -> None:
```

**Description:** Removes all items from the cache.

**Example:**

```python
cache.clear()
```

#### `__len__`

```python
def __len__(self) -> int:
```
**Description:** Return number of items in the cache.

**Outputs:**
*   `int`: The number of items in the cache.

**Example:**

```python
num_items = len(cache)
print(num_items)
```

### `MemoryMonitor`

A class for tracking estimated memory usage to prevent excessive allocation and potential denial-of-service vulnerabilities.

#### `__init__`
```python
def __init__(self, max_memory_mb: int = 1024) -> None:
```

**Description:** Initialize memory monitor with specified memory limits.

**Parameters:**
*   `max_memory_mb` (int, optional): Maximum allowed memory in megabytes. Defaults to 1024.

**Raises:**
*   `ValueError`: If max_memory_mb is not positive.

**Example:**

```python
monitor = MemoryMonitor(max_memory_mb=2048)  # Set a 2GB limit
```

#### `check_allocation`
```python
def check_allocation(self, size_bytes: int) -> bool:
```
**Description:** Check if an allocation would exceed memory limits without modifying usage tracker.

**Parameters:**
*  `size_bytes` (int): Size of proposed allocation in bytes.

**Outputs:**
*   `bool`: True if allocation is safe, False if it would exceed limits.

**Raises:**
*   `ValueError`: If size_bytes is negative.
*   `TypeError`: If size_bytes is not an integer.

**Example:**

```python
if monitor.check_allocation(50 * 1024 * 1024):  # Check if 50MB allocation is safe
    print("Allocation is safe")
else:
    print("Allocation would exceed limits")
```

#### `allocate`
```python
def allocate(self, size_bytes: int) -> bool:
```

**Description:** Track a memory allocation, raising exception if it would exceed limits.

**Parameters:**
*   `size_bytes` (int): Size of allocation in bytes.

**Outputs:**
*   `bool`: True if allocation succeeded.

**Raises:**
*   `MemoryError`: If allocation would exceed memory limit.
*   `ValueError`: If size_bytes is negative.
*   `TypeError`: If size_bytes is not an integer.

**Example:**
```python
try:
    monitor.allocate(100 * 1024 * 1024)  # Allocate 100MB
    print("Memory allocated successfully")
except MemoryError:
    print("Memory allocation failed")

```

#### `release`
```python
def release(self, size_bytes: int) -> None:
```

**Description:** Track memory release after operation is complete.

**Parameters:**
*  `size_bytes` (int): Size of memory to release in bytes.

**Raises:**
*   `ValueError`: If size_bytes is negative or exceeds current usage.
*   `TypeError`: If size_bytes is not an integer.

**Example:**
```python
monitor.release(50 * 1024 * 1024)  # Release 50MB
```

#### `get_usage_stats`
```python
def get_usage_stats(self) -> Dict[str, Union[int, float]]:
```
**Description:** Get current memory usage statistics.

**Outputs:**
*   `dict`: Dictionary containing current and peak memory usage information.

**Example:**
```python
stats = monitor.get_usage_stats()
print(f"Current usage: {stats['current_mb']:.2f} MB")
print(f"Peak usage: {stats['peak_mb']:.2f} MB")
```

## Factory Functions

### `get_feldman_vss`

```python
def get_feldman_vss(field: Any, **kwargs: Any) -> FeldmanVSS:
```

**Description:** A factory function to create a `FeldmanVSS` instance, configured for post-quantum security by default.

**Parameters:**

*   `field`: The finite field object (must have a `prime` attribute).
*   `**kwargs`:  Optional keyword arguments, primarily for passing a `VSSConfig` object.

**Returns:**

*   `FeldmanVSS`:  A configured `FeldmanVSS` instance.

**Raises:**
*   `TypeError`: If `field` is `None` or does not have a `prime` attribute of the correct type.

**Example:**

```python
from feldman_vss import get_feldman_vss
from your_field_module import PrimeField

field = PrimeField(bits=4096)
vss = get_feldman_vss(field)  # Uses default post-quantum secure configuration

config = VSSConfig(prime_bits=8192)
vss_custom = get_feldman_vss(field, config=config)
```

### `create_vss_from_shamir`

```python
def create_vss_from_shamir(shamir_instance: Any) -> FeldmanVSS:
```

**Description:** Creates a `FeldmanVSS` instance that is compatible with a given Shamir Secret Sharing implementation (e.g., the `ShamirSecretSharing` class from the main module).

**Parameters:**

*   `shamir_instance`: An instance of a Shamir Secret Sharing class.  Must have a `field` attribute, which in turn must have a `prime` attribute.

**Returns:**

*   `FeldmanVSS`: A `FeldmanVSS` instance configured to use the same field as the Shamir instance.

**Raises:**

*   `TypeError`: If `shamir_instance` does not have the required attributes.

**Example:**

```python
from feldman_vss import create_vss_from_shamir
from shamir_secret_sharing import ShamirSecretSharing  # Your Shamir implementation

shamir = ShamirSecretSharing(5, 3)  # 5 shares, threshold 3
vss = create_vss_from_shamir(shamir)
```

## Integration Helpers

These functions facilitate integration with Pedersen VSS for combined binding and hiding properties.

### `integrate_with_pedersen`

```python
def integrate_with_pedersen(feldman_vss: FeldmanVSS, pedersen_vss: Any, shares: ShareDict, coefficients: List[FieldElement]) -> Dict[str, Any]:
```

**Description:** Integrates Feldman VSS with Pedersen VSS to provide both binding and hiding properties.

**Parameters:**

*   `feldman_vss`: A `FeldmanVSS` instance.
*   `pedersen_vss`: A Pedersen VSS instance (must have `create_commitments` method).
*   `shares`:  The shares generated by Shamir Secret Sharing.
*   `coefficients`: The polynomial coefficients used for share generation.

**Returns:**

*  `Dict[str, Any]`: A dictionary containing serialized Feldman and Pedersen commitments, and a dual commitment proof.

**Raises:**
*   `TypeError`: If inputs have incorrect types.

**Example:**
```python
# Assuming you have a PedersenVSS class instance named 'pedersen'
integration_data = integrate_with_pedersen(vss, pedersen, shares, coefficients)
print(integration_data)
```

### `create_dual_commitment_proof`

```python
def create_dual_commitment_proof(
    feldman_vss: FeldmanVSS, pedersen_vss: Any, coefficients: List[FieldElement], feldman_commitments: CommitmentList, pedersen_commitments: List[FieldElement]
) -> Dict[str, Any]:
```

**Description:**  Creates a zero-knowledge proof demonstrating that the Feldman and Pedersen commitments are to the same polynomial coefficients.

**Parameters:**

*   `feldman_vss`: A `FeldmanVSS` instance.
*   `pedersen_vss`: A Pedersen VSS instance.
*   `coefficients`: The polynomial coefficients.
*   `feldman_commitments`: The commitments created by the Feldman scheme.
*   `pedersen_commitments`: The commitments created by the Pedersen scheme.

**Returns:**
*  `Dict[str, Any]`:  The proof data structure.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If input lists have inconsistent lengths.

**Example:**
```python
proof = create_dual_commitment_proof(vss, pedersen, coefficients, feldman_commitments, pedersen_commitments)
```
### `verify_dual_commitments`

```python
def verify_dual_commitments(
    feldman_vss: FeldmanVSS, pedersen_vss: Any, feldman_commitments: CommitmentList, pedersen_commitments: List[FieldElement], proof: Dict[str, Any]
) -> bool:
```

**Description:** Verifies the zero-knowledge proof that the Feldman and Pedersen commitments are to the same polynomial.

**Parameters:**

* `feldman_vss`:  A `FeldmanVSS` instance.
* `pedersen_vss`: A Pedersen VSS instance.
* `feldman_commitments`: The Feldman commitments.
* `pedersen_commitments`: The Pedersen commitments.
* `proof`: The proof data structure returned by `create_dual_commitment_proof`.

**Returns:**

*   `bool`: `True` if the verification succeeds, `False` otherwise.

**Raises:**
*   `TypeError`: If inputs have incorrect types.
*   `ValueError`: If input lists have inconsistent lengths.

**Example:**
```python
is_valid = verify_dual_commitments(vss, pedersen, feldman_commitments, pedersen_commitments, proof)
print(f"Dual commitment verification: {is_valid}")
```

## Helper Functions

These are internal helper functions, but they are documented here for completeness and because they may be useful for advanced users.  However, be aware that these functions may change in future versions of the library.

### `constant_time_compare`

```python
def constant_time_compare(a: Union[int, str, bytes], b: Union[int, str, bytes]) -> bool:
```

**Description:** Compares two values (integers, strings, or bytes) in constant time to mitigate timing attacks. *Note: While this function *attempts* constant-time comparison, true constant-time behavior is not guaranteed in pure Python.*

**Parameters:**

*   `a`: The first value.
*   `b`: The second value.

**Returns:**

*   `bool`: `True` if the values are equal, `False` otherwise.

### `compute_checksum`

```python
def compute_checksum(data: bytes) -> int:
```

**Description:** Computes a checksum of the provided data (using xxhash3_128 with cryptographic fallback if unavailable).

**Parameters:**

*  `data`: The data (bytes) to checksum.

**Returns:**
*   `int`: The computed checksum.
**Raises:**
*   `TypeError`: If data is not bytes

### `secure_redundant_execution`

```python
def secure_redundant_execution(
    func: RedundantExecutorFunc,
    *args: Any,
    sanitize_error_func: Optional[Callable[[str, Optional[str]], str]] = None,
    function_name: Optional[str] = None,
    context: Optional[str] = None,
    **kwargs: Any,
) -> Any:
```

**Description:** Executes a function multiple times with safeguards to detect fault injection attacks. *Note: This function provides *increased* resistance to fault injection, but full protection requires implementation in a lower-level language.*

**Parameters:**

*   `func`: The function to execute.
*   `*args`: Positional arguments to pass to the function.
*   `sanitize_error_func` (Optional[Callable[[str, Optional[str]], str]]): Function to sanitize error messages.
*   `function_name` (Optional[str]): Name of the function for error context.
*   `context` (Optional[str]): Additional context information for error messages.
*   `**kwargs`: Keyword arguments to pass to the function.

**Returns:**

*   `Any`: The result of the computation if all checks pass.

**Raises:**

*   `SecurityError`: If any computation results don't match.
*   `TypeError`: If func is not callable.

### `estimate_mpz_size`
```python
def estimate_mpz_size(n: Union[int, "gmpy2.mpz"]) -> int:
```
**Description:** Estimate memory required for a gmpy2.mpz number of given bit length.

**Parameters:**
* `n` (int or gmpy2.mpz): Number to estimate size for, or its bit length

**Returns:**
* `int`: Estimated memory size in bytes

### `estimate_mpz_operation_memory`
```python
def estimate_mpz_operation_memory(op_type: str, a_bits: int, b_bits: Optional[int] = None) -> int:
```

**Description:** Estimate memory requirements for gmpy2 mpz operations.

**Parameters:**
* `op_type` (str): Operation type ('add', 'mul', 'pow', etc.)
*  `a_bits` (int): Bit length of first operand.
* `b_bits` (int, optional): Bit length of second operand.

**Returns:**
* `int`: Estimated memory requirement in bytes.

**Raises:**
* `ValueError`: If operation type is unknown or inputs are invalid.

### `estimate_exp_result_size`
```python
def estimate_exp_result_size(base_bits: int, exponent: Union[int, "gmpy2.mpz"]) -> int:
```
**Description:** Estimate the bit length of base^exponent.

**Parameters:**
*  `base_bits` (int): Bit length of base
* `exponent` (int): Exponent value

**Returns:**
* `int`: Estimated bit length of result

### `get_system_memory`
```python
def get_system_memory() -> int:
```
**Description:** Get available system memory in bytes.

**Returns:**
* `int`: Available memory in bytes, or a conservative estimate if detection fails

### `check_memory_safety`
```python
def check_memory_safety(operation: str, *args: Any, max_size_mb: int = 1024, reject_unknown: bool = False) -> bool:
```

**Description:** Check if operation can be performed safely without exceeding memory limits.

**Parameters:**
* `operation` (str): Operation type ('exp', 'mul', etc.)
* `*args`: Arguments to the operation
* `max_size_mb` (int): Maximum allowed memory in MB
*  `reject_unknown` (bool): If True, rejects all unknown operations

**Returns:**
* `bool`: True if operation is likely safe, False otherwise

### `validate_timestamp`
```python
def validate_timestamp(timestamp: Optional[int], max_future_drift: int = MAX_TIME_DRIFT,
                   min_past_drift: int = 86400, allow_none: bool = True) -> int:
```

**Description**: Validate a timestamp value with comprehensive checks for security-sensitive operations.

**Parameters:**
*   `timestamp`: Timestamp to validate (seconds since epoch)
*   `max_future_drift`: Maximum allowed future drift in seconds (default: `MAX_TIME_DRIFT` constant)
*   `min_past_drift`: Maximum allowed past drift in seconds (default: 24 hours/86400 seconds)
*  `allow_none`: Whether to allow None values and replace with current time

**Returns:**
*  `int`: The validated timestamp or current time if timestamp was None and allow_none=True

**Raises:**
*   `TypeError`: If timestamp is not an integer or None when allow_none=True
*   `ValueError`: If timestamp is negative or outside acceptable drift ranges
## Exceptions

The library defines several custom exception classes for specific error conditions:

### `SecurityError`

Raised for security-related issues, such as potential attacks or cryptographic failures.

### `SerializationError`

Raised for errors during serialization or deserialization of data.

### `VerificationError`

Raised when share or proof verification fails.

### `ParameterError`

Raised when invalid parameters are passed to functions or methods.

### `SecurityWarning`
Warning for potentially insecure configurations or operations

## Type Definitions
This section provides an overview of the custom type definitions used throughout the library for improved type hinting and code clarity:

```python
# Type definitions
# More specific TypedDict definitions for nested structures
EvidenceEntryDict = TypedDict('EvidenceEntryDict', {
    'party_id': int,
    'action': str,
    'data': Dict[str, Union[int, str, bool]],
    'timestamp': int
})

ByzantineEvidenceDict = TypedDict('ByzantineEvidenceDict', {
    'type': str,
    'evidence': List[EvidenceEntryDict],
    'timestamp': int,
    'signature': str
})

FieldElement = Union[int, "gmpy2.mpz"]  # Integer field elements
SharePoint = Tuple[FieldElement, FieldElement]  # (x, y) coordinate
ShareDict = Dict[int, SharePoint]  # Maps participant ID to share
Randomizer = FieldElement  # Randomizer values for commitments

InvalidityProofDict = TypedDict('InvalidityProofDict', {
    'party_id': int,
    'participant_id': int,
    'share_x': FieldElement,
    'share_y': FieldElement,
    'expected_commitment': FieldElement,
    'actual_commitment': FieldElement,
    'combined_randomizer': FieldElement,
    'timestamp': int,
    'signature': str
})

VerificationSummaryDict = TypedDict('VerificationSummaryDict', {
    'total_zero_shares_created': int,
    'total_zero_shares_verified': int,
    'invalid_shares_detected': Dict[int, List[int]],
    'participants_with_full_verification': int,
    'potential_collusion_detected': bool,
    'byzantine_parties_excluded': int,
    'byzantine_party_ids': List[int]
})

VerificationDataDict = TypedDict('VerificationDataDict', {
    'original_shares_count': int,
    'threshold': int,
    'zero_commitment_count': int,
    'timestamp': int,
    'protocol': str,
    'verification_method': str,
    'hash_based': bool,
    'verification_summary': VerificationSummaryDict,
    'seed_fingerprint': str,
    'verification_proofs': Dict[int, Dict[int, Any]]
})

# New TypedDict definitions for more complex return types
MemoryUsageStatsDict = TypedDict('MemoryUsageStatsDict', {
    'current_bytes': int,
    'current_mb': float,
    'peak_bytes': int,
    'peak_mb': float,
    'max_mb': int,
    'usage_percent': float,
    'peak_percent': float
})

ForensicDataDict = TypedDict('ForensicDataDict', {
    'message': str,
    'severity': str,
    'timestamp': int,
    'error_type': str,
    'detailed_info': Optional[str],
    'share_info': Optional[Dict[str, Any]],
    'commitment_info': Optional[Dict[str, Any]]
})

ByzantineDetectionResultDict = TypedDict('ByzantineDetectionResultDict', {
    'is_byzantine': bool,
    'failure_count': int,
    'total_shares': int,
    'failure_rate': float,
    'evidence': List[Dict[str, Any]],
    'affected_participants': List[int],
    'timestamp': int
})

DualCommitmentProofDict = TypedDict('DualCommitmentProofDict', {
    'feldman_blinding_commitments': List[Union[Tuple[FieldElement, FieldElement], FieldElement]],
    'pedersen_blinding_commitments': List[FieldElement],
    'challenge': int,
    'responses': List[int],
    'response_randomizers': Optional[List[int]]
})

IntegrationResultDict = TypedDict('IntegrationResultDict', {
    'feldman_commitments': str,
    'pedersen_commitments': str,
    'dual_proof': DualCommitmentProofDict,
    'version': str
})

# Type Aliases for Complex Types
HashFunc = Callable[[bytes], Any]
RedundantExecutorFunc = Callable[..., Any]

HashCommitment = Tuple[FieldElement, Randomizer, Optional[bytes]]  # (hash, randomizer, entropy)
CommitmentList = List[HashCommitment]  # List of commitments

ProofDict = TypedDict('ProofDict', {
    'blinding_commitments': List[Tuple[FieldElement, FieldElement]],
    'challenge': FieldElement,
    'responses': List[FieldElement],
    'commitment_randomizers': List[FieldElement],
    'blinding_randomizers': List[FieldElement],
    'timestamp': int
})

VerificationResult = Tuple[bool, Dict[int, bool]]
RefreshingResult = Tuple[ShareDict, CommitmentList, Dict[str, Any]]
```

## Security Considerations

*   **Post-Quantum Security:** This library is designed for post-quantum security, using hash-based commitments and large prime fields (minimum 4096 bits).
*   **Safe Primes:**  The library defaults to using safe primes, which enhance security.
*   **Hash Algorithm:** BLAKE3 is the preferred hash algorithm. The library falls back to SHA3-256 if BLAKE3 is unavailable.
*   **Entropy:** The library uses the `secrets` module for cryptographically secure random number generation.
*   **Side-Channel Attacks:** Constant-time operations are used where appropriate to mitigate timing attacks.  However, *true* constant-time behavior is not guaranteed in pure Python.
* **Error Handling**: The library has a `sanitize_errors` parameter in `VSSConfig`. It defaults to `True`. Set it to `False` only in debugging environment.
* **Memory Safety**: The library uses `MemoryMonitor` and `check_memory_safety` to avoid memory issues.

**Known Vulnerabilities:**

Refer to the main `README.md` for a list of known security vulnerabilities that cannot be fully addressed in pure Python and require implementation in a lower-level language like Rust.
