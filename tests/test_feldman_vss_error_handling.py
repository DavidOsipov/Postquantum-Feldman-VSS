# tests/test_feldman_vss_error_handling.py
# Tests for error handling, edge cases, and robustness of the Feldman VSS implementation.

import copy
import secrets
import time
import warnings
from base64 import urlsafe_b64decode, urlsafe_b64encode
from unittest.mock import patch

import msgpack
import pytest
from gmpy2 import mpz

# Import necessary components from the main module and conftest
from feldman_vss import (
    MIN_PRIME_BITS,
    VSS_VERSION,
    CommitmentList,
    CyclicGroup,
    FeldmanVSS,
    ParameterError,
    ProofDict,
    SecurityError,
    SecurityWarning,
    SerializationError,
    ShareDict,
    VerificationError,
    VSSConfig,
    compute_checksum,
    validate_timestamp,
)

from .conftest import DEFAULT_NUM_SHARES, DEFAULT_THRESHOLD, HAS_PSUTIL, TEST_PRIME_BITS_FAST, MockField, generate_poly_and_shares

# --- Test Edge Cases ---

def test_edge_threshold_2(default_vss: FeldmanVSS, mock_field_fast: MockField):
    """Test VSS with the minimum threshold t=2."""
    threshold = 2
    num_shares = 3
    secret = mock_field_fast.random_element()
    coeffs, shares = generate_poly_and_shares(mock_field_fast, secret, threshold, num_shares)

    commitments = default_vss.create_commitments(coeffs)
    assert len(commitments) == threshold

    # Verify shares
    for x, y in shares.values():
        assert default_vss.verify_share(x, y, commitments) is True

    # Verify ZKP
    proof = default_vss.create_polynomial_proof(coeffs, commitments)
    assert default_vss.verify_polynomial_proof(proof, commitments) is True

    # Verify reconstruction (using mock field interpolation)
    share_subset = list(shares.values())[:threshold]
    reconstructed = mock_field_fast.interpolate(share_subset)
    assert reconstructed == secret

def test_edge_threshold_equals_n(default_vss: FeldmanVSS, mock_field_fast: MockField):
    """Test VSS when threshold t equals the number of shares n."""
    threshold = 4
    num_shares = 4
    secret = mock_field_fast.random_element()
    coeffs, shares = generate_poly_and_shares(mock_field_fast, secret, threshold, num_shares)

    commitments = default_vss.create_commitments(coeffs)
    assert len(commitments) == threshold

    # Verify shares
    for x, y in shares.values():
        assert default_vss.verify_share(x, y, commitments) is True

    # Verify ZKP
    proof = default_vss.create_polynomial_proof(coeffs, commitments)
    assert default_vss.verify_polynomial_proof(proof, commitments) is True

    # Verify reconstruction (using mock field interpolation)
    share_subset = list(shares.values()) # Need all shares
    reconstructed = mock_field_fast.interpolate(share_subset)
    assert reconstructed == secret

def test_zero_secret(default_vss: FeldmanVSS, mock_field_fast: MockField):
    """Test VSS with a secret value of zero."""
    threshold = 3
    num_shares = 5
    secret = mpz(0)
    coeffs, shares = generate_poly_and_shares(mock_field_fast, secret, threshold, num_shares)

    commitments = default_vss.create_commitments(coeffs)
    assert len(commitments) == threshold

    # Verify shares
    for x, y in shares.values():
        assert default_vss.verify_share(x, y, commitments) is True

    # Verify ZKP
    proof = default_vss.create_polynomial_proof(coeffs, commitments)
    assert default_vss.verify_polynomial_proof(proof, commitments) is True

    # Verify reconstruction
    share_subset = list(shares.values())[:threshold]
    reconstructed = mock_field_fast.interpolate(share_subset)
    assert reconstructed == secret

# --- Test Invalid Parameter Handling ---

def test_invalid_threshold_config():
    """Test error when threshold t < 2 or t > n."""
    field = MockField(prime=mpz(17))
    vss = FeldmanVSS(field)
    secret = mpz(5)

    # t < 2
    with pytest.raises((ValueError, ParameterError)):
        generate_poly_and_shares(field, secret, 1, 5)

    # t > n
    with pytest.raises((ValueError, ParameterError)):
        generate_poly_and_shares(field, secret, 6, 5)

def test_feldman_init_invalid_params():
    """Test FeldmanVSS raises errors for invalid initialization parameters."""
    field = MockField(prime=mpz(17))
    # Invalid field
    with pytest.raises(TypeError, match="Field must have a 'prime' attribute"):
        FeldmanVSS("not a field") # type: ignore
    # Invalid config
    with pytest.raises(AttributeError): # Because config methods will be called internally
         FeldmanVSS(field, config="not a config") # type: ignore
    # Invalid group
    with pytest.raises(AttributeError): # Because group methods will be called internally
         FeldmanVSS(field, group="not a group") # type: ignore

def test_verify_share_empty_commitments(default_vss: FeldmanVSS):
    """Test verify_share handles empty commitment list."""
    # Should return False gracefully, not raise an unhandled error
    assert default_vss.verify_share(1, 1, []) is False

def test_batch_verify_shares_empty_commitments(default_vss: FeldmanVSS):
    """Test batch_verify_shares handles empty commitment list."""
    with pytest.raises(TypeError, match="commitments must be a non-empty list"):
        default_vss.batch_verify_shares([(1, 1)], [])

def test_create_polynomial_proof_empty_inputs(default_vss: FeldmanVSS, test_coeffs: List[mpz], test_commitments: CommitmentList):
    """Test create_polynomial_proof handles empty inputs."""
    with pytest.raises(ValueError, match="cannot be empty"):
        default_vss.create_polynomial_proof([], test_commitments)
    with pytest.raises(ValueError, match="cannot be empty"):
        default_vss.create_polynomial_proof(test_coeffs, [])

def test_verify_polynomial_proof_empty_inputs(default_vss: FeldmanVSS, test_coeffs: List[mpz], test_commitments: CommitmentList):
    """Test verify_polynomial_proof handles empty inputs."""
    proof = default_vss.create_polynomial_proof(test_coeffs, test_commitments)
    with pytest.raises(ValueError, match="cannot be empty"):
        default_vss.verify_polynomial_proof(proof, [])

# --- Test Serialization / Deserialization Errors ---

def test_deserialize_garbage_input(default_vss: FeldmanVSS):
    """Test deserialization with various forms of invalid/garbage input."""
    garbage_inputs = [
        "clearly not base64%%%%", # Invalid base64
        urlsafe_b64encode(b"not msgpack").decode(), # Valid base64, invalid msgpack
        urlsafe_b64encode(msgpack.packb({"wrong": "structure"})).decode(), # Valid msgpack, wrong structure (missing checksum wrapper)
        urlsafe_b64encode(msgpack.packb({b"checksum": 123, b"data": b"abc"})).decode(), # Correct wrapper keys (bytes), checksum doesn't match data
        urlsafe_b64encode(msgpack.packb({b"checksum": compute_checksum(b"abc"), b"data": b"abc"})).decode(), # Correct checksum, but inner data is not VSS struct
        urlsafe_b64encode(msgpack.packb({b"checksum": compute_checksum(msgpack.packb({"version": VSS_VERSION.encode()})), b"data": msgpack.packb({"version": VSS_VERSION.encode()})})).decode(), # Correct inner structure start, but missing fields
    ]
    for garbage in garbage_inputs:
        with pytest.raises((SerializationError, SecurityError, ValueError, TypeError, msgpack.exceptions.UnpackException, msgpack.exceptions.ExtraData)):
            default_vss.deserialize_commitments(garbage)
        with pytest.raises((SerializationError, SecurityError, ValueError, TypeError, msgpack.exceptions.UnpackException, msgpack.exceptions.ExtraData)):
            # Also test the proof deserialization path
            default_vss.deserialize_commitments_with_proof(garbage)

def test_deserialize_checksum_fail(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails when checksum is incorrect."""
    # Create valid serialized data
    serialized = default_vss.serialize_commitments(test_commitments)
    decoded = urlsafe_b64decode(serialized.encode('utf-8'))
    wrapper = msgpack.unpackb(decoded, raw=True, use_list=False)

    # Tamper with checksum
    tampered_wrapper = {b'data': wrapper[b'data'], b'checksum': wrapper[b'checksum'] + 1}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')

    with pytest.raises(SecurityError, match="Data integrity check failed"):
        default_vss.deserialize_commitments(tampered_serialized)

def test_deserialize_tampered_data(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails if data is tampered after checksum calculation (requires re-packing)."""
    # Create valid serialized data
    serialized = default_vss.serialize_commitments(test_commitments)
    decoded = urlsafe_b64decode(serialized.encode('utf-8'))
    wrapper = msgpack.unpackb(decoded, raw=True, use_list=False)
    packed_data = wrapper[b'data']

    # Unpack inner data, tamper it, repack, recalculate checksum
    unpacked = dict(msgpack.unpackb(packed_data, raw=True, use_list=False))
    # Tamper prime (use bytes key)
    unpacked[b'prime'] = unpacked[b'prime'] + 10 # Make it likely non-prime
    tampered_packed_data = msgpack.packb(unpacked)
    new_checksum = compute_checksum(tampered_packed_data)

    # Create new wrapper with tampered data and correct checksum for it
    tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')

    # Deserialization should now fail during cryptographic parameter validation
    with pytest.raises(SecurityError, match="parameter validation failed"):
        default_vss.deserialize_commitments(tampered_serialized)

def test_deserialize_version_mismatch(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails on VSS version mismatch."""
    serialized = default_vss.serialize_commitments(test_commitments)
    decoded = urlsafe_b64decode(serialized.encode('utf-8'))
    wrapper = msgpack.unpackb(decoded, raw=True, use_list=False)
    packed_data = wrapper[b'data']

    unpacked = dict(msgpack.unpackb(packed_data, raw=True, use_list=False))
    unpacked[b'version'] = b"VSS-different-version" # Tamper version
    tampered_packed_data = msgpack.packb(unpacked)
    new_checksum = compute_checksum(tampered_packed_data)
    tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')

    with pytest.raises(SerializationError, match="Unsupported VSS version"):
        default_vss.deserialize_commitments(tampered_serialized)

def test_deserialize_invalid_crypto_params(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test deserialization fails if crypto parameters (prime, generator) are invalid."""
    serialized = default_vss.serialize_commitments(test_commitments)
    decoded = urlsafe_b64decode(serialized.encode('utf-8'))
    wrapper = msgpack.unpackb(decoded, raw=True, use_list=False)
    packed_data = wrapper[b'data']
    unpacked = dict(msgpack.unpackb(packed_data, raw=True, use_list=False))

    # --- Tamper with prime to be non-prime ---
    unpacked_bad_prime = copy.deepcopy(unpacked)
    unpacked_bad_prime[b'prime'] = int(default_vss.group.prime + 1) # Likely not prime
    tampered_packed_data = msgpack.packb(unpacked_bad_prime)
    new_checksum = compute_checksum(tampered_packed_data)
    tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')
    with pytest.raises(SecurityError, match="failed primality test"):
        default_vss.deserialize_commitments(tampered_serialized)

    # --- Tamper with generator to be invalid ---
    unpacked_bad_gen = copy.deepcopy(unpacked)
    unpacked_bad_gen[b'generator'] = 1 # Invalid generator
    tampered_packed_data = msgpack.packb(unpacked_bad_gen)
    new_checksum = compute_checksum(tampered_packed_data)
    tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')
    with pytest.raises(SecurityError, match="generator is outside valid range"):
        default_vss.deserialize_commitments(tampered_serialized)

    # --- Tamper commitment value range ---
    unpacked_bad_commit_val = copy.deepcopy(unpacked)
    commits_tuple = unpacked_bad_commit_val[b'commitments']
    commits_list = list(commits_tuple) # Convert tuple to list
    # Tamper first commitment value to be >= prime
    if commits_list:
        c0, r0, e0_hex = commits_list[0]
        commits_list[0] = (int(default_vss.group.prime) + 5, r0, e0_hex)
        unpacked_bad_commit_val[b'commitments'] = tuple(commits_list) # Convert back to tuple
        tampered_packed_data = msgpack.packb(unpacked_bad_commit_val)
        new_checksum = compute_checksum(tampered_packed_data)
        tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
        tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')
        with pytest.raises(SecurityError, match="outside valid range"):
            default_vss.deserialize_commitments(tampered_serialized)

# --- Test Verification Errors ---

def test_verify_share_from_serialized_error(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verify_share_from_serialized raises VerificationError on failure."""
    serialized = default_vss.serialize_commitments(test_commitments)
    share_id = random.choice(list(test_shares.keys()))
    x, y = test_shares[share_id]
    invalid_y = (y + 1) % default_vss.field.prime

    # Verification should fail, but raise VerificationError because it's the public method
    with pytest.raises(VerificationError, match="Failed to verify share"):
        # We expect the internal verify_share to return False, which should be caught
        # and raised as VerificationError by verify_share_from_serialized
        # Mock verify_share to force return False to ensure the error raising path is tested
         with patch.object(FeldmanVSS, 'verify_share', return_value=False) as mock_verify:
              result = default_vss.verify_share_from_serialized(x, invalid_y, serialized)
              # The mock should cause verify_share_from_serialized to raise VerificationError
              # If it returns False instead, the test fails.
              assert result is False # Should not reach here if error is raised correctly

    # Test with bad serialized data causing deserialization error
    with pytest.raises(VerificationError, match="Failed to verify share"):
         default_vss.verify_share_from_serialized(x, y, "garbage data")

def test_verify_commitments_with_proof_strict_error(default_vss: FeldmanVSS, test_coeffs: List[mpz], test_commitments: CommitmentList):
    """Test strict verification raises VerificationError on challenge inconsistency."""
    proof = default_vss.create_polynomial_proof(test_coeffs, test_commitments)
    # Tamper challenge
    tampered_proof = copy.deepcopy(proof)
    tampered_proof['challenge'] = (proof['challenge'] + 1) % default_vss.field.prime

    # With strict=False, should return False and warn
    with warnings.catch_warnings(record=True) as w:
        assert default_vss.verify_commitments_with_proof(test_commitments, tampered_proof, strict_verification=False) is False
        assert any("Challenge verification failed" in str(warn.message) for warn in w)

    # With strict=True, should raise VerificationError
    with pytest.raises(VerificationError, match="Challenge verification failed"):
        default_vss.verify_commitments_with_proof(test_commitments, tampered_proof, strict_verification=True)

# --- Test Memory Errors & Safety ---

@pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed, skipping memory tests")
def test_memory_exhaustion_matrix_solve(mock_field_fast: MockField):
    """Attempt to trigger memory error during matrix solve with large T."""
    # Use a smaller prime but larger threshold for this test
    prime = mpz(17) # Very small prime
    field = MockField(prime)
    vss = FeldmanVSS(field, VSSConfig(prime_bits=8)) # Config doesn't affect field here

    # Threshold large enough to potentially cause issues, but feasible for testing
    large_t_mem = 200
    # Check if the estimated size is large enough to be meaningful but not excessive
    estimated_bytes = (large_t_mem * large_t_mem * prime.bit_length()) // 8 * 3 # Rough estimate with overhead
    max_allowed_test_mem = 500 * 1024 * 1024 # 500MB limit for this test

    if estimated_bytes > max_allowed_test_mem:
        pytest.skip(f"Skipping large matrix memory test, estimated size {estimated_bytes / (1024*1024):.1f}MB exceeds limit.")

    coeffs_large_t, shares_large_t = generate_poly_and_shares(field, 1, large_t_mem, large_t_mem)
    x_vals = [s[0] for s in shares_large_t.values()]
    y_vals = [s[1] for s in shares_large_t.values()]

    # Mock check_memory_safety to allow the operation, but monitor actual usage
    with patch('feldman_vss.check_memory_safety', return_value=True):
        try:
            # Expect either success or MemoryError/gmpy2 error/VerificationError(singular)
            vss._reconstruct_polynomial_coefficients(x_vals, y_vals, large_t_mem)
        except (MemoryError, OverflowError, ValueError, VerificationError) as e:
            # ValueError can occur in gmpy2 with excessive allocation
            # VerificationError if matrix happens to be singular
            test_logger.info(f"Caught expected error during large matrix solve: {type(e).__name__}: {e}")
            # Expected potential failure
        except Exception as e:
            pytest.fail(f"Unexpected error during large matrix solve: {e}")

def test_memory_safety_check_prevents_large_op(default_vss: FeldmanVSS):
    """Test that check_memory_safety prevents potentially huge operations."""
    # Simulate an extremely large exponentiation that should be blocked by check_memory_safety
    base = mpz(2)
    # Exponent bit size that would lead to huge result if not modular
    large_exp_bits = 10000
    large_exp_val = mpz(1) << large_exp_bits

    # Mock the internal check_memory_safety call within the group's exp method
    # to ensure it returns False for this large operation
    with patch('feldman_vss.check_memory_safety', return_value=False) as mock_check:
        with pytest.raises(MemoryError, match="exceed memory limits"):
             # Attempting non-modular exponentiation (implicitly, as no modulus provided)
             # This path might not exist directly if only modular exp is used,
             # let's test multiplication instead.
             large_a = mpz(1) << (1024 * 1024 * 5) # 5MB worth of bits
             large_b = mpz(1) << (1024 * 1024 * 5)
             # We need to test a function that uses check_memory_safety internally
             # Let's test the group multiplication which should use it
             try:
                  # Need a group instance
                  group = default_vss.group
                  group.mul(large_a, large_b) # Should raise MemoryError due to mocked check
             except MemoryError:
                  # Check that the safety check was indeed called with 'mul'
                  found_mul_call = False
                  for call_args in mock_check.call_args_list:
                      if call_args[0][0] == 'mul':
                           found_mul_call = True
                           break
                  assert found_mul_call, "check_memory_safety was not called for 'mul'"
                  # Test passed if MemoryError is raised and check was called
             except Exception as e:
                  pytest.fail(f"Expected MemoryError due to check_memory_safety mock, but got {type(e).__name__}: {e}")


# --- Test Exception Forensics ---

def test_parameter_error_forensics():
    """Check ParameterError contains forensic data."""
    param_name = "threshold"
    param_value = 1 # Invalid value
    try:
        raise ParameterError("Invalid threshold", parameter_name=param_name, parameter_value=param_value, expected_type="int >= 2")
    except ParameterError as e:
        forensic = e.get_forensic_data(detail_level='high')
        assert forensic["error_type"] == "ParameterError"
        assert forensic["message"] == "Invalid threshold"
        assert forensic["parameter_name"] == param_name
        assert forensic["parameter_value"] == param_value
        assert forensic["expected_type"] == "int >= 2"
        assert "timestamp" in forensic

def test_serialization_error_forensics(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Check SerializationError contains forensic data."""
    # Trigger version mismatch error
    serialized = default_vss.serialize_commitments(test_commitments)
    decoded = urlsafe_b64decode(serialized.encode('utf-8'))
    wrapper = msgpack.unpackb(decoded, raw=True, use_list=False)
    packed_data = wrapper[b'data']
    unpacked = dict(msgpack.unpackb(packed_data, raw=True, use_list=False))
    unpacked[b'version'] = b"fake_version"
    tampered_packed_data = msgpack.packb(unpacked)
    new_checksum = compute_checksum(tampered_packed_data)
    tampered_wrapper = {b'data': tampered_packed_data, b'checksum': new_checksum}
    tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode('utf-8')

    try:
        default_vss.deserialize_commitments(tampered_serialized)
    except SerializationError as e:
        forensic = e.get_forensic_data(detail_level='high')
        assert forensic["error_type"] == "SerializationError"
        assert "Unsupported VSS version" in forensic["message"]
        assert "checksum_info" in forensic # Checksum is checked first
        assert forensic["checksum_info"]["valid"] is True # Checksum was valid for tampered data
        assert forensic["data_format"] == "" # Not explicitly set in this error path
        assert "timestamp" in forensic

def test_verification_error_forensics(default_vss: FeldmanVSS):
    """Check VerificationError contains forensic data."""
    share_info = {"x": 1, "y": 10}
    commitment_info = {"index": 0, "value": "abc"}
    try:
        raise VerificationError("Share validation failed", share_info=share_info, commitment_info=commitment_info)
    except VerificationError as e:
        forensic = e.get_forensic_data(detail_level='high')
        assert forensic["error_type"] == "VerificationError"
        assert forensic["message"] == "Share validation failed"
        assert forensic["share_info"] == share_info
        assert forensic["commitment_info"] == commitment_info
        assert "timestamp" in forensic

def test_security_error_forensics():
    """Check SecurityError contains forensic data."""
    detail = "Checksum mismatch detected"
    try:
        raise SecurityError("Integrity check failed", detailed_info=detail, severity="critical")
    except SecurityError as e:
        # Note: SecurityError doesn't have get_forensic_data method in the provided code.
        # We test the attributes directly.
        assert e.message == "Integrity check failed"
        assert e.detailed_info == detail
        assert e.severity == "critical"
        assert isinstance(e.timestamp, int)

# --- Test Timestamp Validation Errors ---

def test_validate_timestamp_errors():
    """Test specific errors from validate_timestamp."""
    now = int(time.time())
    with pytest.raises(TypeError, match="timestamp must be an integer"):
        validate_timestamp("not a number") # type: ignore
    with pytest.raises(ValueError, match="timestamp cannot be negative"):
        validate_timestamp(-1)
    with pytest.raises(ValueError, match="seconds in the future"):
        validate_timestamp(now + fvss.MAX_TIME_DRIFT * 2)
    with pytest.raises(ValueError, match="seconds in the past"):
        validate_timestamp(now - 86400 * 2) # Default past drift is 86400
