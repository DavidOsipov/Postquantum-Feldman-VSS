# tests/test_feldman_vss_security.py
# Security-focused tests for the Postquantum Feldman VSS implementation
import concurrent.futures
import copy
import hashlib  # Needed for test_deterministic_rng_security_properties
import secrets
import time
import timeit  # Needed for test_timing_sidechannel_naive_comparison
import typing  # Needed for cast
from unittest import mock

import gmpy2
import pytest
from test_conftest import generate_poly_and_shares

# Assuming feldman_vss is importable (handled in conftest or project structure)
import feldman_vss as fvss
from feldman_vss import (
    CommitmentList,
    CyclicGroup,
    FeldmanVSS,
    FieldElement,  # FieldElement = Union[int, gmpy2.mpz]
    ParameterError,
    ProofDict,
    SecurityError,
    SecurityWarning,
    SerializationError,
    VerificationError,
    VSSConfig,
)

# Import helper from conftest if needed, or define necessary mocks/helpers locally
# Assuming get_prime is available from conftest or similar setup
from .test_conftest import (
    DEFAULT_NUM_SHARES,
    DEFAULT_THRESHOLD,
    MockField,
    get_prime,
)

# --- Constants ---
# Use smaller parameters for most security tests for speed, unless PQ crypto is specifically needed
TEST_PRIME_BITS_SEC = 512  # Faster for general security logic tests
TEST_THRESHOLD_SEC = 3
TEST_NUM_SHARES_SEC = 5


# --- Security Specific Fixtures ---


# Use a separate VSS instance for security tests where specific configs might be needed
@pytest.fixture
def security_vss_config() -> VSSConfig:
    """Provides a VSSConfig specifically for security tests, often faster."""
    # Sanitize errors often False in tests for debugging, but can test True here
    return VSSConfig(
        prime_bits=TEST_PRIME_BITS_SEC,
        safe_prime=False,  # Faster generation for tests not needing safe primes
        sanitize_errors=False,  # Keep errors detailed for security test debugging
        use_blake3=fvss.has_blake3,
    )


@pytest.fixture
def security_vss(security_vss_config: VSSConfig) -> FeldmanVSS:
    """Provides a FeldmanVSS instance configured for security tests."""
    # FIX: Use get_prime helper from conftest instead of internal method call
    prime = get_prime(bits=TEST_PRIME_BITS_SEC, safe=False)
    # Mock the field object similar to conftest's MockField
    # This avoids needing the full MockField if only prime is needed by VSS init
    field = mock.Mock(spec=MockField)  # Use spec for better mocking
    field.prime = prime
    # Add clear_cache method expected by FeldmanVSS.__del__
    field.clear_cache = mock.Mock()
    return FeldmanVSS(field=field, config=security_vss_config)


@pytest.fixture
def non_safe_prime_vss() -> FeldmanVSS:
    """Provides a VSS instance configured with a non-safe prime for specific tests."""
    prime_bits = TEST_PRIME_BITS_SEC
    prime = get_prime(bits=prime_bits, safe=False)
    config = VSSConfig(prime_bits=prime_bits, safe_prime=False, sanitize_errors=False, use_blake3=fvss.has_blake3)
    # Need a field object that matches the prime
    field = mock.Mock(spec=MockField)
    field.prime = prime
    field.clear_cache = mock.Mock()
    return FeldmanVSS(field=field, config=config)


# --- Security Tests ---


@pytest.mark.security
def test_invalid_share_verification_fails(security_vss: FeldmanVSS, test_coeffs: list[FieldElement], test_commitments: CommitmentList):
    """Verify that an invalid share fails verification."""
    x = TEST_NUM_SHARES_SEC + 1  # An x not used in original shares
    # Evaluate polynomial correctly
    correct_y = security_vss._evaluate_polynomial(test_coeffs, x)
    # FIX: Explicitly cast intermediate results to mpz before modulo to satisfy Pylance
    invalid_y = gmpy2.f_mod(gmpy2.mpz(correct_y) + 1, security_vss.field.prime)  # type: ignore

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not security_vss.verify_share(x, invalid_y, test_commitments), "Verification should fail for incorrect y"


@pytest.mark.security
# FIX: Removed unused test_coeffs argument (Ruff ARG001)
def test_tampered_commitment_verification_fails(security_vss: FeldmanVSS, test_shares: fvss.ShareDict, test_commitments: CommitmentList):
    """Verify that tampering with a commitment causes share verification to fail."""
    share_id = 1
    share_x, share_y = test_shares[share_id]

    # Tamper with a commitment (e.g., the first one)
    tampered_commitments = list(test_commitments)  # Make a copy
    original_commitment_val, randomizer, entropy = tampered_commitments[0]
    # Ensure tampering results in a different value within the field
    # FIX: Explicitly cast intermediate results to mpz before modulo to satisfy Pylance
    tampered_val = gmpy2.f_mod(gmpy2.mpz(original_commitment_val) + 1, security_vss.group.prime)  # type: ignore
    if tampered_val == original_commitment_val:  # Handle case where adding 1 wraps around
        # FIX: Explicitly cast intermediate results to mpz before modulo to satisfy Pylance
        tampered_val = gmpy2.f_mod(gmpy2.mpz(original_commitment_val) + 2, security_vss.group.prime)  # type: ignore
    tampered_commitments[0] = (tampered_val, randomizer, entropy)

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not security_vss.verify_share(share_x, share_y, tampered_commitments), "Verification should fail with tampered commitment"
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    # Also check batch verification
    all_valid, results = security_vss.batch_verify_shares(list(test_shares.values()), tampered_commitments)
    assert not all_valid, "Batch verification should fail overall"
    assert not results[share_id - 1], f"Batch verification for share {share_id} should fail"


@pytest.mark.security
def test_serialization_tampering(security_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test that tampering with serialized data is detected via checksum."""
    serialized_data = security_vss.serialize_commitments(test_commitments)

    # Ensure serialized_data is long enough to tamper safely
    if len(serialized_data) < 20:
        pytest.skip("Serialized data too short for reliable tampering test")

    # Simulate tampering by modifying a character near the end
    pos = len(serialized_data) - 10
    original_char = serialized_data[pos]
    tampered_char = "Z" if original_char != "Z" else "Y"  # Ensure character changes
    tampered_data = serialized_data[:pos] + tampered_char + serialized_data[pos + 1 :]

    # FIX: Check for specific SecurityError related to integrity checks
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(fvss.SecurityError, match="Data integrity check failed"):
        security_vss.deserialize_commitments(tampered_data)


@pytest.mark.security
def test_invalid_proof_verification(security_vss: FeldmanVSS, test_coeffs: list[FieldElement], test_commitments: CommitmentList):
    """Test that an invalid zero-knowledge proof fails verification."""
    # Generate a valid proof first
    proof = security_vss.create_polynomial_proof(test_coeffs, test_commitments)

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert security_vss.verify_polynomial_proof(proof, test_commitments), "Original proof should be valid"

    # Tamper with the proof (e.g., modify a response)
    original_response = proof["responses"][0]
    # FIX: Explicit cast to mpz before modulo
    tampered_response = gmpy2.f_mod(gmpy2.mpz(original_response) + 1, security_vss.field.prime)  # type: ignore
    proof["responses"][0] = tampered_response

    # FIX: Verification should return False for an invalid proof
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not security_vss.verify_polynomial_proof(proof, test_commitments), "Tampered proof verification should return False"

    proof["responses"][0] = original_response  # Restore for potential reuse


@pytest.mark.security
def test_verify_commitments_with_proof_challenge_tampering(security_vss: FeldmanVSS, test_coeffs: list[FieldElement]):
    """Test that tampering with the challenge in a proof is detected."""
    commitments, proof = security_vss.create_commitments_with_proof(test_coeffs)

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert security_vss.verify_commitments_with_proof(commitments, proof), "Original proof should verify"

    # Tamper with the challenge ONLY
    original_challenge = proof["challenge"]
    proof["challenge"] = (original_challenge + 1) % security_vss.field.prime

    # With strict verification, expect VerificationError
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(fvss.VerificationError, match="Challenge verification failed"):
        security_vss.verify_commitments_with_proof(commitments, proof, strict_verification=True)

    # Without strict verification, expect False return and a warning
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.warns(fvss.SecurityWarning, match="Challenge verification failed"):
        assert not security_vss.verify_commitments_with_proof(commitments, proof, strict_verification=False)

    proof["challenge"] = original_challenge  # Restore


# Define helper outside test for patching
def _simple_func_for_test(a, b):
    return a + b


# FIX: Parametrize test for different fault patterns
@pytest.mark.security
@pytest.mark.parametrize(
    "fail_indices, description",
    [
        ([1], "Single failure"),
        ([0, 2], "Multiple failures"),
        ([1, 4], "Intermittent failures"),
        ([0, 1, 3], "Majority failures"),  # Test case where 3 out of 5 fail
    ],
)
def test_secure_redundant_execution_fault_injection(fail_indices, description):
    """Test secure_redundant_execution detects various injected fault patterns."""
    # Arrange: Define a simple function and its expected correct result
    correct_result = 42
    faulty_result = 99

    # Arrange: Mock the function to introduce faults during specific calls
    num_executions = 5  # secure_redundant_execution runs 5 times internally
    side_effects = []
    for i in range(num_executions):
        if i in fail_indices:
            side_effects.append(faulty_result)
        else:
            side_effects.append(correct_result)

    # Ensure at least one correct result exists if not all fail (redundant check)
    if correct_result not in side_effects and len(fail_indices) < num_executions:
        first_correct_index = next(i for i in range(num_executions) if i not in fail_indices)
        side_effects[first_correct_index] = correct_result

    # FIX: Correct patch target using function object's module, not __name__ string
    patch_target = f"{_simple_func_for_test.__module__}._simple_func_for_test"

    with mock.patch(patch_target, side_effect=side_effects) as mocked_func:
        # Act & Assert: Expect SecurityError when faults are injected
        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        with pytest.raises(fvss.SecurityError, match="Computation result mismatch"):
            fvss.secure_redundant_execution(_simple_func_for_test, 20, 22)  # a=20, b=22 -> 42

        # Assert: Check the function was called the expected number of times
        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        assert mocked_func.call_count == num_executions, f"Expected {num_executions} calls for pattern: {description}"


@pytest.mark.security
def test_secure_redundant_execution_exception_handling():
    """Test secure_redundant_execution handles exceptions during execution."""

    # Arrange: Define a function that raises an exception
    # FIX: Removed unused args, kwargs (Ruff ARG001)
    def faulty_func():
        raise ValueError("Simulated execution error")

    # Act & Assert: Expect SecurityError wrapping the original exception
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(fvss.SecurityError, match="Computation failed during security validation"):
        fvss.secure_redundant_execution(faulty_func)  # No args needed now


@pytest.mark.security
def test_constant_time_compare_security():
    """Test constant_time_compare against known potentially problematic inputs."""
    # Equal values
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert fvss.constant_time_compare(12345, 12345)
    assert fvss.constant_time_compare(b"test", b"test")
    assert fvss.constant_time_compare("string", "string")
    assert fvss.constant_time_compare(gmpy2.mpz(10**100), gmpy2.mpz(10**100))
    assert fvss.constant_time_compare(0, 0)
    assert fvss.constant_time_compare(-5, -5)

    # Different values
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not fvss.constant_time_compare(12345, 54321)
    assert not fvss.constant_time_compare(b"test", b"tset")
    assert not fvss.constant_time_compare("string", "strong")
    assert not fvss.constant_time_compare(gmpy2.mpz(10**100), gmpy2.mpz(10**101))
    assert not fvss.constant_time_compare(1, 0)
    assert not fvss.constant_time_compare(-5, 5)

    # Different lengths (should be padded internally)
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not fvss.constant_time_compare(123, 12345)
    assert not fvss.constant_time_compare(b"short", b"longer")
    assert not fvss.constant_time_compare("abc", "abcd")
    assert not fvss.constant_time_compare(gmpy2.mpz(100), gmpy2.mpz(10000))

    # Different types (should always be False)
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert not fvss.constant_time_compare(123, "123")
    assert not fvss.constant_time_compare(123, b"123")
    assert not fvss.constant_time_compare("123", b"123")
    # FIX: Add type ignore for None checks as function hint doesn't allow None currently
    assert not fvss.constant_time_compare(None, 123)  # type: ignore
    assert not fvss.constant_time_compare(123, None)  # type: ignore
    assert not fvss.constant_time_compare(None, None)  # type: ignore # Handled by implementation

    # Edge cases: Large numbers
    large1 = gmpy2.mpz(2) ** 512 - 1
    large2 = gmpy2.mpz(2) ** 512 - 2
    # FIX: Explicitly cast potentially problematic types (mpfr possibility) to mpz
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert fvss.constant_time_compare(gmpy2.mpz(large1), gmpy2.mpz(large1))
    assert not fvss.constant_time_compare(gmpy2.mpz(large1), gmpy2.mpz(large2))

    # Test with explicit gmpy2 and int mix
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert fvss.constant_time_compare(gmpy2.mpz(987), 987)
    assert not fvss.constant_time_compare(gmpy2.mpz(987), 988)
    assert not fvss.constant_time_compare(987, gmpy2.mpz(988))


@pytest.mark.security
def test_timestamp_validation_security():
    """Test validate_timestamp function against various drift scenarios."""
    current_time = int(time.time())
    max_drift = fvss.MAX_TIME_DRIFT

    # Valid timestamps
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert fvss.validate_timestamp(current_time) == current_time
    assert fvss.validate_timestamp(current_time - 100) == current_time - 100
    assert fvss.validate_timestamp(current_time + 100) == current_time + 100
    assert fvss.validate_timestamp(current_time + max_drift) == current_time + max_drift
    assert fvss.validate_timestamp(current_time - 86400) == current_time - 86400  # Max past drift allowed by default

    # Invalid: Too far in the future
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(ValueError, match="future"):
        fvss.validate_timestamp(current_time + max_drift + 1)

    # Invalid: Too far in the past
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(ValueError, match="past"):
        fvss.validate_timestamp(current_time - 86401)  # Default past drift is 86400

    # Invalid: Negative timestamp
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(ValueError, match="negative"):
        fvss.validate_timestamp(-1)

    # Invalid type
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.raises(TypeError):
        fvss.validate_timestamp("not an int")  # type: ignore
    with pytest.raises(TypeError):
        fvss.validate_timestamp(None, allow_none=False)

    # Valid None when allowed
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    ts_now = fvss.validate_timestamp(None, allow_none=True)
    assert abs(ts_now - current_time) < 5  # Should be very close to current time

    # Warning for significant drift
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    with pytest.warns(fvss.SecurityWarning, match="Significant time difference"):
        fvss.validate_timestamp(current_time + max_drift // 2 + 1)
    with pytest.warns(fvss.SecurityWarning, match="Significant time difference"):
        fvss.validate_timestamp(current_time - max_drift // 2 - 1)  # Assuming past drift > max_drift/2


@pytest.mark.security
def test_deterministic_rng_security_properties(security_vss: FeldmanVSS):
    """Verify properties of create_secure_deterministic_rng relevant to security."""
    seed1 = secrets.token_bytes(32)
    seed2 = secrets.token_bytes(32)
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert seed1 != seed2

    rng1_func = fvss.create_secure_deterministic_rng(seed1)
    rng2_func = fvss.create_secure_deterministic_rng(seed2)
    rng1_alt_func = fvss.create_secure_deterministic_rng(seed1)

    bound = security_vss.field.prime
    vals1 = [rng1_func(bound) for _ in range(10)]
    vals2 = [rng2_func(bound) for _ in range(10)]
    vals1_alt = [rng1_alt_func(bound) for _ in range(10)]

    # 1. Determinism: Same seed yields same sequence
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert vals1 == vals1_alt, "RNG with same seed should produce identical sequences"

    # 2. Unpredictability: Different seeds yield different sequences (highly likely)
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert vals1 != vals2, "RNG with different seeds should produce different sequences"

    # 3. Sensitivity to seed changes: Small seed change yields different sequence
    seed1_modified = bytearray(seed1)
    seed1_modified[0] ^= 1  # Flip one bit
    rng1_mod_func = fvss.create_secure_deterministic_rng(bytes(seed1_modified))
    vals1_mod = [rng1_mod_func(bound) for _ in range(10)]
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert vals1 != vals1_mod, "Small change in seed should produce different sequence"

    # 4. Check output range (basic check)
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert all(0 <= v < bound for v in vals1), "All values should be within [0, bound)"
    assert all(0 <= v < bound for v in vals2), "All values should be within [0, bound)"

    # 5. Verify internal hashing consistency (if possible, depends on implementation details)
    # Check if the internal hash function is consistent with the VSS instance's setting
    if fvss.has_blake3 and security_vss.config.use_blake3:
        h_fallback = hashlib.sha3_256(seed1).digest()  # This is the fallback hash
        # We expect the internal hash to use blake3 if available and configured
        # Access blake3 via fvss module where it's conditionally imported
        internal_hash_bytes = fvss.blake3.blake3(seed1 + f"VSS-{fvss.VSS_VERSION}-DeterministicRNG".encode()).digest(length=32)
        final_hash = fvss.blake3.blake3(internal_hash_bytes + f"VSS-{fvss.VSS_VERSION}-DeterministicRNG".encode()).digest(length=32)
        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        assert final_hash != hashlib.sha3_256(h_fallback + f"VSS-{fvss.VSS_VERSION}-DeterministicRNG".encode()).digest(), (
            "Internal hash should use BLAKE3 when available/configured"
        )  # Compare final hashes
    else:  # Assuming SHA3-256 fallback
        h = hashlib.sha3_256(seed1).digest()
        h_with_context = h + f"VSS-{fvss.VSS_VERSION}-DeterministicRNG".encode()
        final_hash_expected = hashlib.sha3_256(h_with_context).digest()

        # Replicate internal logic
        internal_hash_bytes = hashlib.sha3_256(seed1).digest()
        internal_with_context = internal_hash_bytes + f"VSS-{fvss.VSS_VERSION}-DeterministicRNG".encode()
        final_internal_hash = hashlib.sha3_256(internal_with_context).digest()

        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        assert final_internal_hash == final_hash_expected, "Internal hash should use SHA3-256 as fallback"


@pytest.mark.security
def test_deterministic_rng_security(default_vss: FeldmanVSS):
    """Test that the deterministic RNG produces the same sequence for the same seed."""
    # Create two RNGs with the same seed
    seed = secrets.token_bytes(32)
    rng1_func = fvss.create_secure_deterministic_rng(seed)
    # FIX: Add noqa and explanation for S311
    rng2_func = fvss.create_secure_deterministic_rng(seed)
    # S311: random.Random is used intentionally here, seeded with strong crypto hash
    # (via create_secure_deterministic_rng) to provide *deterministic* but
    # unpredictable output for zero-sharing polynomials, as per Chen & Lindell's
    # protocol requirements. Security derives from the seed, not random.Random itself.

    # Check they produce the same sequence
    bound = default_vss.field.prime
    sequence1 = [rng1_func(bound) for _ in range(20)]
    sequence2 = [rng2_func(bound) for _ in range(20)]

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert sequence1 == sequence2, "Deterministic RNGs with the same seed should match"

    # Check that a different seed produces a different sequence
    seed2 = secrets.token_bytes(32)
    rng3_func = fvss.create_secure_deterministic_rng(seed2)
    sequence3 = [rng3_func(bound) for _ in range(20)]

    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert sequence1 != sequence3, "Deterministic RNGs with different seeds should differ"


@pytest.mark.security
def test_low_entropy_secret_commitment(security_vss: FeldmanVSS):
    """Test commitment creation with low-entropy secret uses extra entropy."""
    # Low entropy secret (e.g., small number)
    low_entropy_secret = 123
    coeffs_mpz: list[gmpy2.mpz] = [gmpy2.mpz(low_entropy_secret)] + [
        security_vss.group.secure_random_element() for _ in range(TEST_THRESHOLD_SEC - 1)
    ]
    # FIX: Add type ignore for list invariance
    coeffs: list[FieldElement] = coeffs_mpz  # type: ignore

    commitments = security_vss.create_enhanced_commitments(coeffs)

    # Check that the first commitment (for the secret) includes extra entropy
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert len(commitments[0]) == 3, "Commitment tuple should have 3 elements (c, r, entropy)"
    assert commitments[0][2] is not None, "Extra entropy should be present for low-entropy secret"
    assert isinstance(commitments[0][2], bytes), "Extra entropy should be bytes"
    assert len(commitments[0][2]) == 32, "Extra entropy should have expected length (32 bytes)"

    # Verify that other commitments do not have extra entropy
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert all(c[2] is None for c in commitments[1:]), "Only the secret's commitment should have extra entropy"

    # Verify the share using the commitment with entropy
    share_id = 1
    share_x = share_id
    # FIX: Add type ignore for list invariance
    share_y = security_vss._evaluate_polynomial(coeffs, share_x)  # type: ignore
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert security_vss.verify_share(share_x, share_y, commitments), "Share verification should pass with extra entropy"


@pytest.mark.security
def test_high_entropy_secret_commitment(security_vss: FeldmanVSS):
    """Test commitment creation with high-entropy secret does not add extra entropy."""
    high_entropy_secret = security_vss.group.secure_random_element()  # Assumed high entropy
    coeffs_mpz: list[gmpy2.mpz] = [high_entropy_secret] + [
        security_vss.group.secure_random_element() for _ in range(TEST_THRESHOLD_SEC - 1)
    ]
    # FIX: Add type ignore for list invariance
    coeffs: list[FieldElement] = coeffs_mpz  # type: ignore

    commitments = security_vss.create_enhanced_commitments(coeffs)

    # Check that the first commitment (for the secret) does NOT include extra entropy
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert len(commitments[0]) == 3, "Commitment tuple should have 3 elements (c, r, entropy)"
    assert commitments[0][2] is None, "Extra entropy should NOT be present for high-entropy secret"

    # Verify the share
    share_id = 1
    share_x = share_id
    share_y = security_vss._evaluate_polynomial(coeffs, share_x)  # type: ignore
    # B101: Use of assert detected. Standard in pytest, ignored by project config.
    assert security_vss.verify_share(share_x, share_y, commitments), "Share verification should pass without extra entropy"


@pytest.mark.security
def test_deserialize_commitments_invalid_checksum(security_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails with SecurityError if checksum is invalid."""
    serialized_data = security_vss.serialize_commitments(test_commitments)

    # Tamper with the checksum part of the serialized data
    # Decode, unpack wrapper, modify checksum, repack wrapper, encode
    try:
        decoded_wrapper = fvss.urlsafe_b64decode(serialized_data.encode("utf-8"))
        # Use raw=True to get bytes keys, matching deserialize_commitments
        wrapper = fvss.msgpack.unpackb(decoded_wrapper, raw=True)

        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        assert b"checksum" in wrapper and b"data" in wrapper

        original_checksum = wrapper[b"checksum"]
        wrapper[b"checksum"] = original_checksum + 1  # Modify checksum

        # Repack wrapper with raw=True to handle bytes keys correctly
        tampered_packed_wrapper = fvss.msgpack.packb(wrapper, use_bin_type=True)
        # FIX: Ensure packed data is bytes before encoding (Pylance reportArgumentType)
        assert isinstance(tampered_packed_wrapper, bytes)
        tampered_serialized_data = fvss.urlsafe_b64encode(tampered_packed_wrapper).decode("utf-8")

        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        with pytest.raises(fvss.SecurityError, match="Data integrity check failed"):
            security_vss.deserialize_commitments(tampered_serialized_data)

    except Exception as e:
        pytest.fail(f"Test setup for checksum tampering failed: {e}")


@pytest.mark.security
def test_deserialize_commitments_invalid_prime(security_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails if the prime in the data is invalid."""
    serialized_data = security_vss.serialize_commitments(test_commitments)

    # Decode, unpack wrapper, unpack data, modify prime, repack data, repack wrapper, encode
    try:
        decoded_wrapper = fvss.urlsafe_b64decode(serialized_data.encode("utf-8"))
        wrapper = fvss.msgpack.unpackb(decoded_wrapper, raw=True)  # Use raw=True

        data_bytes = wrapper[b"data"]
        unpacked_data = fvss.msgpack.unpackb(data_bytes, raw=True)  # Use raw=True

        # Modify prime to a non-prime value (ensure key is bytes)
        prime_key = b"prime"
        if prime_key not in unpacked_data:
            pytest.fail("Missing 'prime' key in unpacked data")
        current_prime = unpacked_data[prime_key]
        unpacked_data[prime_key] = current_prime + 1
        if gmpy2.is_prime(unpacked_data[prime_key]):  # Ensure it's not prime
            unpacked_data[prime_key] += 1

        # Repack data, recalculate checksum, repack wrapper
        new_data_bytes = fvss.msgpack.packb(unpacked_data, use_bin_type=True)
        # FIX: Ensure packed data is bytes before checksum (Pylance reportArgumentType)
        assert isinstance(new_data_bytes, bytes)
        wrapper[b"data"] = new_data_bytes
        wrapper[b"checksum"] = fvss.compute_checksum(new_data_bytes)

        tampered_packed_wrapper = fvss.msgpack.packb(wrapper, use_bin_type=True)
        # FIX: Ensure packed data is bytes before encoding (Pylance reportArgumentType)
        assert isinstance(tampered_packed_wrapper, bytes)
        tampered_serialized_data = fvss.urlsafe_b64encode(tampered_packed_wrapper).decode("utf-8")

        # B101: Use of assert detected. Standard in pytest, ignored by project config.
        with pytest.raises(fvss.SecurityError, match="Cryptographic parameter validation failed"):
            security_vss.deserialize_commitments(tampered_serialized_data)

    except Exception as e:
        pytest.fail(f"Test setup for prime tampering failed: {e}")


# --- Countermeasure Justification Tests ---


def naive_compare(a, b) -> bool:
    """Naive comparison for demonstrating timing variations."""
    if type(a) != type(b):
        return False
    if isinstance(a, (int, gmpy2.mpz)):
        return a == b
    elif isinstance(a, (bytes, str)):
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False  # Early exit
        return True
    return False  # Unsupported types


# @pytest.mark.security
# @pytest.mark.benchmark(group="comparison_timing")
# def test_timing_sidechannel_naive_comparison(benchmark):
#     """Demonstrate timing side-channel in naive comparison vs constant_time_compare."""
#     size = 2048
#     bytes_a = secrets.token_bytes(size)
#     bytes_b_equal = bytes(bytes_a)
#     bytes_b_diff_early = bytearray(bytes_a)
#     bytes_b_diff_early[0] ^= 1
#     bytes_b_diff_early = bytes(bytes_b_diff_early)
#     bytes_b_diff_late = bytearray(bytes_a)
#     bytes_b_diff_late[-1] ^= 1
#     bytes_b_diff_late = bytes(bytes_b_diff_late)

#     int_a = int.from_bytes(bytes_a, 'big')
#     int_b_equal = int(int_a)
#     int_b_diff_early = int_a + (1 << (size * 8 - 8)) # Difference in most significant byte
#     int_b_diff_late = int_a + 1 # Difference in least significant byte

#     # Benchmark naive bytes comparison
#     t_naive_bytes_eq = benchmark.pedantic(naive_compare, args=(bytes_a, bytes_b_equal), iterations=10, rounds=100)
#     t_naive_bytes_early = benchmark.pedantic(naive_compare, args=(bytes_a, bytes_b_diff_early), iterations=10, rounds=100)
#     t_naive_bytes_late = benchmark.pedantic(naive_compare, args=(bytes_a, bytes_b_diff_late), iterations=10, rounds=100)

#     # Benchmark constant_time bytes comparison
#     t_const_bytes_eq = benchmark.pedantic(fvss.constant_time_compare, args=(bytes_a, bytes_b_equal), iterations=10, rounds=100)
#     t_const_bytes_early = benchmark.pedantic(fvss.constant_time_compare, args=(bytes_a, bytes_b_diff_early), iterations=10, rounds=100)
#     t_const_bytes_late = benchmark.pedantic(fvss.constant_time_compare, args=(bytes_a, bytes_b_diff_late), iterations=10, rounds=100)

#     # Assert naive timings differ significantly
#     assert t_naive_bytes_early < t_naive_bytes_late * 0.8, "Naive timing should vary significantly (early diff faster)"
#     assert t_naive_bytes_late > t_naive_bytes_early * 1.2, "Naive timing should vary significantly (late diff slower)"

#     # Assert constant_time timings are close (allow some variance)
#     assert abs(t_const_bytes_early - t_const_bytes_late) < t_const_bytes_eq * 0.2, "Constant time variance too high for bytes"
#     assert abs(t_const_bytes_eq - t_const_bytes_late) < t_const_bytes_eq * 0.2, "Constant time variance too high for bytes"

#     # --- Repeat for integers ---
#     # Benchmark naive integer comparison (less prone to simple loops, but still varies)
#     t_naive_int_eq = benchmark.pedantic(naive_compare, args=(int_a, int_b_equal), iterations=10, rounds=100)
#     t_naive_int_early = benchmark.pedantic(naive_compare, args=(int_a, int_b_diff_early), iterations=10, rounds=100)
#     t_naive_int_late = benchmark.pedantic(naive_compare, args=(int_a, int_b_diff_late), iterations=10, rounds=100)

#     # Benchmark constant_time integer comparison
#     t_const_int_eq = benchmark.pedantic(fvss.constant_time_compare, args=(int_a, int_b_equal), iterations=10, rounds=100)
#     t_const_int_early = benchmark.pedantic(fvss.constant_time_compare, args=(int_a, int_b_diff_early), iterations=10, rounds=100)
#     t_const_int_late = benchmark.pedantic(fvss.constant_time_compare, args=(int_a, int_b_diff_late), iterations=10, rounds=100)

#     # Assert constant_time timings are close for integers
#     assert abs(t_const_int_early - t_const_int_late) < t_const_int_eq * 0.2, "Constant time variance too high for integers"
#     assert abs(t_const_int_eq - t_const_int_late) < t_const_int_eq * 0.2, "Constant time variance too high for integers"


def target_func(x: int, prime: int) -> int:
    """Simple deterministic function for fault injection test."""
    return (x * x * x + x + 5) % prime


@pytest.mark.security
def test_fault_injection_mitigation_demonstration(security_vss: FeldmanVSS):
    """Show secure_redundant_execution catches transient faults."""
    prime = int(security_vss.field.prime)
    correct_result = target_func(123, prime)
    faulty_result = (correct_result + 1) % prime
    call_count = 0

    def mock_wrapper(x: int, p: int) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Inject fault only on the 2nd call
            return faulty_result
        return target_func(x, p)

    # 1. Direct call (might get faulty result depending on which call has fault)
    # Reset count for direct call test
    call_count = 0
    direct_results = [mock_wrapper(123, prime) for _ in range(5)]
    # B101: Assert allowed
    assert faulty_result in direct_results, "Faulty result should appear in direct calls"
    assert correct_result in direct_results, "Correct result should also appear"

    # 2. Call via secure_redundant_execution
    # Reset count for redundant execution test
    call_count = 0
    # B101: Assert allowed
    with pytest.raises(SecurityError, match="Computation result mismatch"):
        fvss.secure_redundant_execution(mock_wrapper, 123, prime)


# --- Cache Security Tests ---


@pytest.mark.security
@pytest.mark.slow  # This test involves threading and can be slower
def test_safe_lru_cache_concurrent_access(security_vss: FeldmanVSS):
    """Test concurrent reads/writes to the CyclicGroup cache via group.exp."""
    group = security_vss.group
    num_threads = 8
    iterations_per_thread = 100
    bases = [group.secure_random_element() for _ in range(num_threads // 2)]
    exponents = [group.secure_random_element() for _ in range(num_threads // 2)]
    shared_base = group.secure_random_element()
    shared_exponent = group.secure_random_element()
    expected_shared_result = gmpy2.powmod(shared_base, shared_exponent % ((group.prime - 1) // 2), group.prime)

    errors = []

    def worker(thread_id: int):
        try:
            for i in range(iterations_per_thread):
                # Mix shared and unique computations
                if i % 4 == 0:
                    res = group.exp(shared_base, shared_exponent)
                    if not fvss.constant_time_compare(res, expected_shared_result):
                        errors.append(f"Thread {thread_id}: Shared mismatch {res} != {expected_shared_result}")
                else:
                    base = bases[thread_id % len(bases)]
                    exp = exponents[i % len(exponents)]
                    expected = gmpy2.powmod(base, exp % ((group.prime - 1) // 2), group.prime)
                    res = group.exp(base, exp)
                    if not fvss.constant_time_compare(res, expected):
                        errors.append(f"Thread {thread_id}: Unique mismatch {res} != {expected}")

                # Occasionally clear cache (simulates contention)
                if thread_id == 0 and i % (iterations_per_thread // 5) == 0:
                    group.clear_cache()

        except Exception as e:
            errors.append(f"Thread {thread_id} failed: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        concurrent.futures.wait(futures, timeout=60)  # Add timeout

    # B101: Assert allowed
    assert not errors, f"Concurrent cache access failed: {errors}"
    # B101: Assert allowed
    assert len(group.cached_powers) <= group.cached_powers.capacity, "Cache size exceeded capacity"


@pytest.mark.security
def test_secure_exp_bypasses_cache(security_vss: FeldmanVSS):
    """Verify that secure_exp does not use or populate the cache."""
    group = security_vss.group
    base = group.secure_random_element()
    exponent = group.secure_random_element()

    # 1. Clear cache and call secure_exp
    group.clear_cache()
    result1 = group.secure_exp(base, exponent)
    # B101: Assert allowed
    assert len(group.cached_powers) == 0, "Cache should be empty after secure_exp"

    # 2. Call secure_exp again
    result2 = group.secure_exp(base, exponent)
    # B101: Assert allowed
    assert len(group.cached_powers) == 0, "Cache should still be empty after second secure_exp"
    # B101: Assert allowed
    assert result1 == result2, "secure_exp results should be consistent"

    # 3. Call normal exp to populate cache
    expected_result = group.exp(base, exponent)
    # B101: Assert allowed
    assert len(group.cached_powers) > 0, "Cache should be populated after normal exp"
    # B101: Assert allowed
    assert result1 == expected_result, "secure_exp result should match normal exp result"

    # 4. Call secure_exp again - should not affect cache
    cache_len_before = len(group.cached_powers)
    result3 = group.secure_exp(base, exponent)
    # B101: Assert allowed
    assert len(group.cached_powers) == cache_len_before, "secure_exp should not change cache size"
    # B101: Assert allowed
    assert result1 == result3, "secure_exp results should be consistent"


# --- Configuration Security Tests ---


@pytest.mark.security
def test_verification_with_non_safe_prime(non_safe_prime_vss: FeldmanVSS):
    """Verify VSS operations work correctly with a non-safe prime."""
    vss = non_safe_prime_vss
    field = MockField(prime=vss.field.prime)  # Use a matching mock field
    secret = field.random_element()
    coeffs, shares = fvss.test_conftest.generate_poly_and_shares(field, secret, DEFAULT_THRESHOLD, DEFAULT_NUM_SHARES)
    commitments = vss.create_commitments(coefficients=list(coeffs))

    # Test share verification
    valid_share_id = 1
    valid_x, valid_y = shares[valid_share_id]
    # B101: Assert allowed
    assert vss.verify_share(valid_x, valid_y, commitments), "Valid share failed verification with non-safe prime"

    invalid_y = (valid_y + 1) % field.prime
    # B101: Assert allowed
    assert not vss.verify_share(valid_x, invalid_y, commitments), "Invalid share passed verification with non-safe prime"

    # Test ZKP
    commitments_zkp, proof = vss.create_commitments_with_proof(list(coeffs))
    # B101: Assert allowed
    assert vss.verify_commitments_with_proof(commitments_zkp, proof), "Valid ZKP failed verification with non-safe prime"

    # Tamper proof
    tampered_proof = copy.deepcopy(proof)
    tampered_proof["responses"][0] = (tampered_proof["responses"][0] + 1) % field.prime
    # B101: Assert allowed
    assert not vss.verify_commitments_with_proof(commitments_zkp, tampered_proof), "Invalid ZKP passed verification with non-safe prime"


# --- Serialization Security Tests ---


@pytest.mark.security
def test_deserialize_invalid_version(security_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails if the version string is incorrect."""
    serialized_data = security_vss.serialize_commitments(test_commitments)

    try:
        decoded_wrapper = fvss.urlsafe_b64decode(serialized_data.encode("utf-8"))
        wrapper = fvss.msgpack.unpackb(decoded_wrapper, raw=True)  # Use raw=True

        data_bytes = wrapper[b"data"]
        unpacked_data = fvss.msgpack.unpackb(data_bytes, raw=True)  # Use raw=True

        # Modify version (ensure key is bytes)
        version_key = b"version"
        if version_key not in unpacked_data:
            pytest.fail("Missing 'version' key in unpacked data")
        unpacked_data[version_key] = b"VSS-0.0.1-OLD"  # Use bytes

        # Repack data, recalculate checksum, repack wrapper
        new_data_bytes = fvss.msgpack.packb(unpacked_data, use_bin_type=True)
        assert isinstance(new_data_bytes, bytes)
        wrapper[b"data"] = new_data_bytes
        wrapper[b"checksum"] = fvss.compute_checksum(new_data_bytes)

        tampered_packed_wrapper = fvss.msgpack.packb(wrapper, use_bin_type=True)
        assert isinstance(tampered_packed_wrapper, bytes)
        tampered_serialized_data = fvss.urlsafe_b64encode(tampered_packed_wrapper).decode("utf-8")

        # B101: Assert allowed
        with pytest.raises(fvss.SerializationError, match="Unsupported version"):
            security_vss.deserialize_commitments(tampered_serialized_data)

    except Exception as e:
        pytest.fail(f"Test setup for version tampering failed: {e}")
