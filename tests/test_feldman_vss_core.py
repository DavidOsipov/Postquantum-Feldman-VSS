# tests/test_feldman_vss_core.py
# Tests for core components and helper functions of the Feldman VSS implementation.

import copy
import hashlib
import math
import secrets
import time
import warnings
from unittest.mock import patch

import pytest
from gmpy2 import mpz

# Import necessary components from the main module and conftest
from feldman_vss import (
    CyclicGroup,
    FeldmanVSS,
    VSSConfig,
    ParameterError,
    SecurityError,
    SecurityWarning,
    MIN_PRIME_BITS,
    constant_time_compare,
    validate_timestamp,
    estimate_mpz_size,
    estimate_mpz_operation_memory,
    check_memory_safety,
    compute_checksum,
    create_secure_deterministic_rng,
    secure_redundant_execution,
    sanitize_error,
    get_feldman_vss,
)
from .conftest import (
    MockField,
    generate_poly_and_shares,
    HAS_BLAKE3,
    TEST_PRIME_BITS_FAST,
    DEFAULT_PRIME_BITS,
    DEFAULT_THRESHOLD,
    DEFAULT_NUM_SHARES,
)

# --- Test VSSConfig ---

def test_vssconfig_defaults():
    """Test VSSConfig default values."""
    config = VSSConfig()
    assert config.prime_bits == DEFAULT_PRIME_BITS
    assert config.safe_prime is True
    assert config.secure_serialization is True
    assert config.use_blake3 is True # Default assumes blake3 might be available
    assert config.cache_size == 128
    assert config.sanitize_errors is True

def test_vssconfig_prime_bits_enforcement():
    """Test that prime_bits is enforced to be at least MIN_PRIME_BITS."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        config = VSSConfig(prime_bits=1024)
        assert config.prime_bits == MIN_PRIME_BITS
        assert len(w) == 1
        assert issubclass(w[0].category, SecurityWarning)
        assert f"less than {MIN_PRIME_BITS} bits" in str(w[0].message)

    # Test with value already meeting the minimum
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        config = VSSConfig(prime_bits=MIN_PRIME_BITS)
        assert config.prime_bits == MIN_PRIME_BITS
        assert len(w) == 0

def test_vssconfig_blake3_fallback(monkeypatch):
    """Test VSSConfig falls back from blake3 if unavailable."""
    # Simulate blake3 not being available
    monkeypatch.setattr(fvss, "has_blake3", False)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", RuntimeWarning)
        config = VSSConfig(use_blake3=True)
        assert config.use_blake3 is True # Config value remains True
        assert len(w) == 1
        assert issubclass(w[0].category, RuntimeWarning)
        assert "BLAKE3 requested but not installed" in str(w[0].message)

    # Test explicit SHA3 usage (should not warn)
    with warnings.catch_warnings(record=True) as w:
        config_sha3 = VSSConfig(use_blake3=False)
        assert config_sha3.use_blake3 is False
        assert len(w) == 0

# --- Test CyclicGroup ---

class TestCyclicGroup:

    def test_init_with_prime(self, test_prime_fast: mpz):
        """Test initialization with a provided prime."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        assert group.prime == test_prime_fast
        assert group._is_generator(group.generator)

    def test_init_with_safe_prime(self, test_prime_pq: mpz):
        """Test initialization with a known safe prime."""
        group = CyclicGroup(prime=int(test_prime_pq), use_safe_prime=True)
        assert group.prime == test_prime_pq
        assert group._is_generator(group.generator)

    def test_init_with_bits(self):
        """Test initialization by specifying bit size (uses helper)."""
        # Use small bits for faster generation in test
        group = CyclicGroup(prime_bits=64, use_safe_prime=False)
        assert group.prime.bit_length() >= 64
        assert CyclicGroup._is_probable_prime(group.prime)
        assert group._is_generator(group.generator)

    def test_init_non_prime_error(self):
        """Test initialization with a non-prime number raises ParameterError."""
        with pytest.raises(ParameterError, match="Provided value is not a prime"):
            CyclicGroup(prime=10, use_safe_prime=False)

    def test_init_non_safe_prime_error(self, test_prime_fast: mpz):
        """Test using a non-safe prime when safe_prime=True raises ParameterError."""
        if not CyclicGroup._is_safe_prime(test_prime_fast): # Only run if test_prime_fast isn't safe
            with pytest.raises(ParameterError, match="Provided prime is not a safe prime"):
                CyclicGroup(prime=int(test_prime_fast), use_safe_prime=True)
        else:
            pytest.skip("test_prime_fast happens to be a safe prime, skipping non-safe check.")

    def test_init_invalid_generator_error(self, test_prime_fast: mpz):
        """Test providing an invalid generator raises ParameterError."""
        with pytest.raises(ParameterError, match="Provided value is not a generator"):
            CyclicGroup(prime=int(test_prime_fast), generator=1, use_safe_prime=False) # 1 is never a generator

    def test_primality_tests(self, test_prime_fast: mpz, test_prime_pq: mpz):
        """Test the internal primality test helpers."""
        assert CyclicGroup._is_probable_prime(test_prime_pq) is True
        assert CyclicGroup._is_safe_prime(test_prime_pq) is True
        assert CyclicGroup._is_probable_prime(test_prime_fast) is True
        # A non-safe prime might fail the safe prime check
        assert CyclicGroup._is_safe_prime(test_prime_fast) is (test_prime_fast == 7 or gmpy2.is_prime((test_prime_fast-1)//2))

        # Test edge cases
        assert CyclicGroup._is_probable_prime(1) is False
        assert CyclicGroup._is_probable_prime(0) is False
        assert CyclicGroup._is_probable_prime(-5) is False
        assert CyclicGroup._is_probable_prime(4) is False
        assert CyclicGroup._is_probable_prime(2) is True
        assert CyclicGroup._is_probable_prime(3) is True
        assert CyclicGroup._is_safe_prime(7) is True # 7 = 2*3 + 1
        assert CyclicGroup._is_safe_prime(11) is False # (11-1)/2 = 5 (prime), but 11 is not safe prime form? Check definition. Safe prime p = 2q+1. Yes, 11 is safe.
        assert CyclicGroup._is_safe_prime(11) is True # (11-1)/2 = 5 (prime)
        assert CyclicGroup._is_safe_prime(13) is False # (13-1)/2 = 6 (not prime)

    def test_generator_verification(self, test_prime_pq: mpz):
        """Test generator verification logic, especially for safe primes."""
        group = CyclicGroup(prime=int(test_prime_pq), use_safe_prime=True)
        g = group.generator
        q = (test_prime_pq - 1) // 2

        assert group._is_generator(g) is True
        # For safe prime p=2q+1, g is generator if g^q mod p != 1
        assert gmpy2.powmod(g, q, test_prime_pq) != 1

        # Test known non-generators
        assert group._is_generator(1) is False
        if test_prime_pq > 3:
            assert group._is_generator(test_prime_pq - 1) is False # Order 2

        # Test quadratic residue (should have order q)
        quad_res = gmpy2.powmod(g, 2, test_prime_pq)
        if quad_res != 1:
             # A quadratic residue (non-1) should be a generator of the q-order subgroup
             assert group._is_generator(quad_res) is True
             assert gmpy2.powmod(quad_res, q, test_prime_pq) == 1 # Belongs to subgroup

    def test_arithmetic_operations(self, test_prime_fast: mpz):
        """Test basic modular arithmetic operations."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        a = group.secure_random_element()
        b = group.secure_random_element()
        one = mpz(1)
        zero = mpz(0)

        # Multiplication
        prod = group.mul(a, b)
        assert prod == (a * b) % test_prime_fast

        # Exponentiation (non-secure, uses cache)
        exp_val = group.exp(a, 5)
        assert exp_val == gmpy2.powmod(a, 5, test_prime_fast)

        # Secure Exponentiation (no cache)
        exp_sec = group.secure_exp(a, 5)
        assert exp_sec == gmpy2.powmod(a, 5, test_prime_fast)

        # Identity elements
        assert group.mul(a, one) == a % test_prime_fast # a*1 = a
        assert group.exp(a, zero) == one # a^0 = 1
        assert group.secure_exp(a, zero) == one

        # Associativity (mul)
        c = group.secure_random_element()
        assert group.mul(group.mul(a, b), c) == group.mul(a, group.mul(b, c))

        # Commutativity (mul)
        assert group.mul(a, b) == group.mul(b, a)

        # Power laws (exp) - use small exponents
        exp1 = mpz(3); exp2 = mpz(4)
        # a^(e1+e2) == a^e1 * a^e2
        assert group.exp(a, exp1 + exp2) == group.mul(group.exp(a, exp1), group.exp(a, exp2))
        # (a^e1)^e2 == a^(e1*e2)
        assert group.exp(group.exp(a, exp1), exp2) == group.exp(a, exp1 * exp2)

    def test_exp_cache_behavior(self, test_prime_fast: mpz):
        """Verify secure_exp does not use the cache, while exp does."""
        group = CyclicGroup(prime=int(test_prime_fast), cache_size=10, use_safe_prime=False)
        base = group.secure_random_element()
        # Use exponent relative to subgroup order q if safe prime, else p-1
        q = (test_prime_fast - 1) // 2 if CyclicGroup._is_safe_prime(test_prime_fast) else test_prime_fast - 1
        exponent = secrets.randbelow(int(q))
        cache_key = (mpz(base), mpz(exponent))

        # Clear cache initially
        group.clear_cache()
        assert group.cached_powers.get(cache_key) is None

        # Normal exp should cache
        res1 = group.exp(base, exponent)
        assert group.cached_powers.get(cache_key) == res1

        # Clear cache again
        group.clear_cache()
        assert group.cached_powers.get(cache_key) is None

        # Secure exp should NOT cache
        res_sec = group.secure_exp(base, exponent)
        assert res_sec == res1
        assert group.cached_powers.get(cache_key) is None, "secure_exp incorrectly used the cache"

        # Put a fake value in cache and check secure_exp ignores it
        fake_result = (res_sec + 1) % test_prime_fast
        group.cached_powers.put(cache_key, fake_result)
        res_sec_again = group.secure_exp(base, exponent)
        assert res_sec_again == res1 # Should recalculate correct value
        assert group.cached_powers.get(cache_key) == fake_result # Cache still holds fake value

    def test_multi_exp(self, test_prime_fast: mpz):
        """Test multi-exponentiation."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        num_bases = 5
        bases = [group.secure_random_element() for _ in range(num_bases)]
        exponents = [secrets.randbelow(int(test_prime_fast - 1)) for _ in range(num_bases)]

        # Calculate expected result manually
        expected = mpz(1)
        for b, e in zip(bases, exponents):
            term = group.exp(b, e) # Use group's exp for consistency
            expected = group.mul(expected, term)

        # Calculate using multi_exp
        result = group.efficient_multi_exp(bases, exponents)

        assert result == expected

    def test_multi_exp_edge_cases(self, test_prime_fast: mpz):
        """Test multi-exponentiation with edge cases."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)

        # Empty lists
        assert group.efficient_multi_exp([], []) == 1

        # Single element list
        base = group.secure_random_element()
        exponent = secrets.randbelow(int(test_prime_fast - 1))
        assert group.efficient_multi_exp([base], [exponent]) == group.exp(base, exponent)

        # Mismatched list lengths
        with pytest.raises(ValueError):
            group.efficient_multi_exp([base], [exponent, exponent])

    def test_hash_to_group(self, test_prime_fast: mpz):
        """Test hash_to_group generates values within the correct range."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        count = 50
        hashes = set()
        for i in range(count):
            data = secrets.token_bytes(16) + i.to_bytes(4, 'big') # Ensure unique data
            h = group.hash_to_group(data)
            assert 1 <= h < group.prime
            hashes.add(h)

        # Check for variability (highly unlikely to have collisions for good hash)
        # Allow for some small chance of collision, e.g., > 95% unique
        assert len(hashes) > count * 0.95

    def test_hash_to_group_type_error(self, test_prime_fast: mpz):
        """Test hash_to_group raises TypeError for non-bytes input."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        with pytest.raises(TypeError):
            group.hash_to_group("not bytes") # type: ignore


# --- Test Helper Functions ---

@pytest.mark.parametrize(
    "a, b, expected",
    [
        (100, 100, True),
        (mpz(100), 100, True),
        (100, mpz(100), True),
        (mpz(100), mpz(100), True),
        (100, 101, False),
        (mpz(100), 101, False),
        (100, mpz(101), False),
        (mpz(100), mpz(101), False),
        (-10, -10, True),
        (-10, 10, False),
        (0, 0, True),
        (0, 1, False),
        (b"test", b"test", True),
        (b"test", b"tesT", False),
        (b"test", b"test ", False),
        ("test", "test", True),
        ("test", "tesT", False),
        ("test", "test ", False),
        # Mixed types
        (1, "1", False),
        (b"1", 1, False),
        (1, None, False),
        (None, 1, False),
        (None, None, False), # Consistent failure
        # Large values
        (mpz(1) << 2048, mpz(1) << 2048, True),
        (mpz(1) << 2048, (mpz(1) << 2048) + 1, False),
        (b'a' * 1000, b'a' * 1000, True),
        (b'a' * 1000, b'a' * 999 + b'b', False),
    ]
)
def test_constant_time_compare(a, b, expected):
    """Test constant_time_compare with various inputs."""
    assert constant_time_compare(a, b) is expected

def test_constant_time_compare_large_value_error():
    """Test constant_time_compare raises ValueError for excessively large inputs."""
    large_int = mpz(1) << 1_100_000 # > 1M bits
    with pytest.raises(ValueError, match="too large for secure comparison"):
        constant_time_compare(large_int, large_int)

    large_bytes = b'a' * 11_000_000 # > 10MB
    with pytest.raises(ValueError, match="too large for secure comparison"):
        constant_time_compare(large_bytes, large_bytes)

def test_validate_timestamp():
    """Test timestamp validation logic."""
    now = int(time.time())
    max_drift = fvss.MAX_TIME_DRIFT

    # Valid timestamps
    assert validate_timestamp(now) == now
    assert validate_timestamp(now - 100) == now - 100
    assert validate_timestamp(now + max_drift // 2) == now + max_drift // 2

    # Valid None (returns current time)
    assert abs(validate_timestamp(None) - now) < 5 # Allow small diff

    # Invalid types
    with pytest.raises(TypeError):
        validate_timestamp("not an int") # type: ignore
    with pytest.raises(TypeError):
        validate_timestamp(None, allow_none=False)

    # Invalid values
    with pytest.raises(ValueError, match="negative"):
        validate_timestamp(-100)
    with pytest.raises(ValueError, match="future"):
        validate_timestamp(now + max_drift + 100)
    with pytest.raises(ValueError, match="past"):
        # Use default past drift (86400)
        validate_timestamp(now - 86400 - 100)

    # Warning for significant drift
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        validate_timestamp(now + max_drift // 2 + 100)
        assert len(w) == 1
        assert issubclass(w[0].category, SecurityWarning)
        assert "Significant time difference" in str(w[0].message)

def test_estimate_mpz_size():
    """Test estimation of mpz object size."""
    size_1k = estimate_mpz_size(mpz(1) << 1024)
    assert size_1k > 1024 // 8 # Should be larger than raw bytes
    assert size_1k < (1024 // 8) * 2 # But reasonably close

    size_4k = estimate_mpz_size(mpz(1) << 4096)
    assert size_4k > 4096 // 8
    assert size_4k < (4096 // 8) * 2

    size_0 = estimate_mpz_size(0)
    assert size_0 > 0 # Still has object overhead

def test_estimate_mpz_operation_memory():
    """Test estimation of memory for mpz operations."""
    bits = 4096
    mem_add = estimate_mpz_operation_memory('add', bits, bits)
    mem_mul = estimate_mpz_operation_memory('mul', bits, bits)
    mem_pow_small_exp = estimate_mpz_operation_memory('pow', bits, 10) # Exponent value 10
    mem_pow_large_exp_bits = estimate_mpz_operation_memory('pow', bits, 30) # Exponent bit size 30

    assert mem_mul > mem_add
    # pow result size is roughly base_bits * exponent_value
    assert mem_pow_small_exp < estimate_mpz_size(bits * 10 * 1.5)
    # pow result size approx base_bits * 2^exponent_bits
    assert mem_pow_large_exp_bits < estimate_mpz_size(bits * (2**30) * 1.5)

    with pytest.raises(ValueError, match="Exponent too large"):
        estimate_mpz_operation_memory('pow', bits, 100) # Exponent bit size 100

    with pytest.raises(ValueError, match="Unknown operation type"):
        estimate_mpz_operation_memory('unknown', bits, bits)

def test_check_memory_safety():
    """Test memory safety checks for operations."""
    # Safe operations
    assert check_memory_safety("mul", mpz(10)**10, mpz(10)**10, max_size_mb=100) is True
    assert check_memory_safety("exp", mpz(2)**100, 5, mpz(2)**1000, max_size_mb=100) is True # Modular exp

    # Unsafe operations
    assert check_memory_safety("mul", mpz(1) << 500000, mpz(1) << 500000, max_size_mb=10) is False
    # Non-modular exponentiation likely to fail
    assert check_memory_safety("exp", mpz(1) << 10000, 10, max_size_mb=10) is False

    # Unknown operation handling
    assert check_memory_safety("unknown", mpz(100), max_size_mb=100, reject_unknown=False) is True
    with warnings.catch_warnings(record=True) as w:
        assert check_memory_safety("unknown", mpz(1) << 500000, max_size_mb=10, reject_unknown=False) is False
        assert any("conservative estimation" in str(warn.message) for warn in w)
    # Reject unknown
    assert check_memory_safety("unknown", mpz(100), max_size_mb=100, reject_unknown=True) is False

def test_compute_checksum():
    """Test checksum computation consistency."""
    data1 = b"some data for checksum"
    data2 = b"other data"
    cs1a = compute_checksum(data1)
    cs1b = compute_checksum(data1)
    cs2 = compute_checksum(data2)

    assert isinstance(cs1a, int)
    assert cs1a == cs1b
    assert cs1a != cs2

    with pytest.raises(TypeError):
        compute_checksum("not bytes") # type: ignore

def test_create_secure_deterministic_rng():
    """Test the deterministic RNG creation and properties."""
    seed1 = secrets.token_bytes(32)
    seed2 = secrets.token_bytes(32)
    rng1a_func = create_secure_deterministic_rng(seed1)
    rng1b_func = create_secure_deterministic_rng(seed1)
    rng2_func = create_secure_deterministic_rng(seed2)
    bound = mpz(1) << 256

    seq1a = [rng1a_func(bound) for _ in range(20)]
    seq1b = [rng1b_func(bound) for _ in range(20)]
    seq2 = [rng2_func(bound) for _ in range(20)]

    assert all(isinstance(x, int) for x in seq1a) # Ensure output is int
    assert seq1a == seq1b, "RNG with same seed produced different sequences"
    assert seq1a != seq2, "RNG with different seeds produced same sequence"
    for val in seq1a:
        assert 0 <= val < bound

    # Test invalid inputs to factory
    with pytest.raises(TypeError):
        create_secure_deterministic_rng("not bytes") # type: ignore
    with pytest.raises(ValueError, match="empty"):
        create_secure_deterministic_rng(b"")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        create_secure_deterministic_rng(b"too short")

    # Test invalid inputs to generated function
    rng_test = create_secure_deterministic_rng(seed1)
    with pytest.raises(TypeError):
        rng_test("not an int") # type: ignore
    with pytest.raises(ValueError, match="positive"):
        rng_test(0)
    with pytest.raises(ValueError, match="positive"):
        rng_test(-100)

def test_secure_redundant_execution():
    """Test secure_redundant_execution detects mismatches and errors."""
    def stable_func(a, b):
        return a + b

    def faulty_func(a, b):
        # Sometimes returns wrong result
        if secrets.randbelow(3) == 0:
            return a + b + 1
        return a + b

    def error_func(a, b):
        # Sometimes raises error
        if secrets.randbelow(3) == 0:
            raise ValueError("Intentional error")
        return a + b

    # Test stable function
    assert secure_redundant_execution(stable_func, 5, 10) == 15

    # Test faulty function raises SecurityError (mismatch)
    with pytest.raises(SecurityError, match="mismatch"):
        # Run multiple times as fault is probabilistic
        for _ in range(20):
            secure_redundant_execution(faulty_func, 5, 10)

    # Test error function raises SecurityError (computation failed)
    with pytest.raises(SecurityError, match="Computation failed"):
        for _ in range(20):
            secure_redundant_execution(error_func, 5, 10)

    # Test non-callable func
    with pytest.raises(TypeError):
        secure_redundant_execution("not callable", 1, 2) # type: ignore

def test_sanitize_error():
    """Test error message sanitization."""
    detailed = "Detailed technical error message with specifics"
    assert sanitize_error("Commitment verification failed", detailed, sanitize=True) == "Cryptographic verification failed"
    assert sanitize_error("Checksum mismatch", detailed, sanitize=True) == "Data integrity check failed"
    assert sanitize_error("Byzantine behavior detected", detailed, sanitize=True) == "Protocol security violation detected"
    assert sanitize_error("Some unknown error", detailed, sanitize=True) == "Cryptographic operation failed"

    # Test no sanitization
    assert sanitize_error("Commitment verification failed", detailed, sanitize=False) == "Commitment verification failed"

# --- Test FeldmanVSS Core Methods ---

def test_feldman_init(mock_field_fast: MockField, default_vss_config: VSSConfig):
    """Test FeldmanVSS initialization."""
    vss = FeldmanVSS(mock_field_fast, default_vss_config)
    assert vss.field == mock_field_fast
    assert vss.config == default_vss_config
    assert isinstance(vss.group, CyclicGroup)
    assert vss.group.prime == mock_field_fast.prime
    assert vss.generator == vss.group.generator
    if HAS_BLAKE3:
        assert vss.hash_algorithm.__name__ == 'blake3'
    else:
        assert vss.hash_algorithm.__name__ == 'sha3_256'

def test_feldman_init_invalid_field():
    """Test FeldmanVSS init fails with invalid field object."""
    class BadField:
        pass
    with pytest.raises(TypeError, match="Field must have a 'prime' attribute"):
        FeldmanVSS(BadField()) # type: ignore

    class BadFieldWithPrime:
        prime = "not a number"
    with pytest.raises(TypeError, match="integer or gmpy2.mpz"):
        FeldmanVSS(BadFieldWithPrime()) # type: ignore

def test_create_commitments(default_vss: FeldmanVSS, test_coeffs: List[mpz]):
    """Test basic commitment creation."""
    commitments = default_vss.create_commitments(test_coeffs)
    assert isinstance(commitments, list)
    assert len(commitments) == len(test_coeffs)
    # Check structure of hash-based commitment: (hash_value, randomizer, optional_entropy)
    assert isinstance(commitments[0], tuple)
    assert len(commitments[0]) == 3
    assert isinstance(commitments[0][0], mpz) # Hash value
    assert isinstance(commitments[0][1], mpz) # Randomizer
    assert isinstance(commitments[0][2], (bytes, type(None))) # Entropy

def test_create_commitments_empty_coeffs_error(default_vss: FeldmanVSS):
    """Test create_commitments raises error for empty coefficients."""
    with pytest.raises((ValueError, ParameterError), match="cannot be empty"):
        default_vss.create_commitments([])

def test_create_commitments_type_error(default_vss: FeldmanVSS):
    """Test create_commitments raises error for non-list coefficients."""
    with pytest.raises(TypeError, match="must be a list"):
        default_vss.create_commitments("not a list") # type: ignore

def test_create_commitments_low_entropy_secret(default_vss: FeldmanVSS, mock_field_fast: MockField):
    """Test that extra entropy is added for low-entropy secrets."""
    low_entropy_secret = mpz(5) # Very small secret
    coeffs = [low_entropy_secret] + [mock_field_fast.random_element() for _ in range(DEFAULT_THRESHOLD - 1)]
    commitments = default_vss.create_commitments(coeffs)
    # The first commitment (for the secret) should have non-None entropy
    assert commitments[0][2] is not None
    assert isinstance(commitments[0][2], bytes)
    # Other commitments should have None entropy
    if len(commitments) > 1:
        assert commitments[1][2] is None

def test_create_commitments_high_entropy_secret(default_vss: FeldmanVSS, test_coeffs: List[mpz]):
    """Test that extra entropy is None for high-entropy secrets."""
    # Assume test_coeffs[0] generated by random_element() is high entropy
    commitments = default_vss.create_commitments(test_coeffs)
    # The first commitment should have None entropy if secret is large enough
    if test_coeffs[0].bit_length() >= 256: # Threshold defined in create_enhanced_commitments
        assert commitments[0][2] is None
    else:
        # If the randomly generated secret happens to be small, entropy might be added
        assert isinstance(commitments[0][2], (bytes, type(None)))

def test_verify_share_valid(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification of a valid share."""
    # Pick a random valid share
    share_id = random.choice(list(test_shares.keys()))
    x, y = test_shares[share_id]
    assert default_vss.verify_share(x, y, test_commitments) is True

def test_verify_share_invalid_y(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification fails for an invalid share (wrong y value)."""
    share_id = random.choice(list(test_shares.keys()))
    x, y = test_shares[share_id]
    invalid_y = (y + 1) % default_vss.field.prime
    assert default_vss.verify_share(x, invalid_y, test_commitments) is False

def test_verify_share_invalid_commitments(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification fails if commitments are tampered with."""
    share_id = random.choice(list(test_shares.keys()))
    x, y = test_shares[share_id]

    # Tamper with one commitment value
    tampered_commitments = copy.deepcopy(test_commitments)
    original_c0, r0, e0 = tampered_commitments[0]
    tampered_commitments[0] = ((original_c0 + 1) % default_vss.group.prime, r0, e0)

    assert default_vss.verify_share(x, y, tampered_commitments) is False

    # Tamper with one randomizer value
    tampered_commitments_r = copy.deepcopy(test_commitments)
    c1, original_r1, e1 = tampered_commitments_r[1]
    tampered_commitments_r[1] = (c1, (original_r1 + 1) % default_vss.group.prime, e1)

    assert default_vss.verify_share(x, y, tampered_commitments_r) is False

def test_verify_share_invalid_types(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test verify_share handles invalid input types gracefully (returns False)."""
    assert default_vss.verify_share("invalid", 1, test_commitments) is False # type: ignore
    assert default_vss.verify_share(1, "invalid", test_commitments) is False # type: ignore
    assert default_vss.verify_share(1, 1, "invalid") is False # type: ignore
    assert default_vss.verify_share(1, 1, []) is False # Empty commitments
    # Malformed commitment list
    malformed_commitments = [(1,)] # Missing randomizer
    assert default_vss.verify_share(1, 1, malformed_commitments) is False # type: ignore

def test_batch_verify_shares_all_valid(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test batch verification when all shares are valid."""
    share_list = list(test_shares.values())
    all_valid, results = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid is True
    assert len(results) == len(share_list)
    assert all(results.values())

def test_batch_verify_shares_one_invalid(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test batch verification with one invalid share."""
    share_list = list(test_shares.values())
    # Make the first share invalid
    x0, y0 = share_list[0]
    invalid_y0 = (y0 + 1) % default_vss.field.prime
    share_list[0] = (x0, invalid_y0)

    all_valid, results = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid is False
    assert len(results) == len(share_list)
    assert results[0] is False # First share should be invalid
    assert all(results[i] for i in range(1, len(share_list))) # Others should be valid

def test_batch_verify_with_duplicates(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test batch verification when the same share is included multiple times."""
    share_list = list(test_shares.values())
    original_len = len(share_list)
    share_list.append(share_list[0]) # Duplicate the first share
    share_list.append(share_list[1]) # Duplicate the second share

    all_valid, results = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid is True
    assert len(results) == len(share_list)
    assert all(results.values())

    # Introduce an invalid share among duplicates
    x_inv, y_inv = share_list[0] # Get original x, y of the first share
    share_list.append((x_inv, (y_inv + 1) % default_vss.field.prime)) # Add an invalid version of the first share
    idx_invalid = len(share_list) - 1

    all_valid_inv, results_inv = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid_inv is False
    assert len(results_inv) == len(share_list)
    assert results_inv[idx_invalid] is False # The explicitly invalid one
    # Ensure the original valid duplicates are still marked valid
    assert results_inv[0] is True # Original first share
    assert results_inv[original_len] is True # First duplicate of the first share

def test_batch_verify_empty_shares_error(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test batch_verify_shares raises error for empty shares list."""
    with pytest.raises((ValueError, ParameterError), match="cannot be empty"):
        default_vss.batch_verify_shares([], test_commitments)

def test_batch_verify_type_errors(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test batch_verify_shares raises error for invalid input types."""
    with pytest.raises(TypeError, match="shares must be a list"):
        default_vss.batch_verify_shares("not a list", test_commitments) # type: ignore
    with pytest.raises(TypeError, match="Each share must be a tuple"):
        default_vss.batch_verify_shares([(1, 2), 3], test_commitments) # type: ignore
    with pytest.raises(TypeError, match="commitments must be a non-empty list"):
        default_vss.batch_verify_shares([(1,1)], "invalid") # type: ignore
    with pytest.raises(TypeError, match="commitments must be a non-empty list"):
        default_vss.batch_verify_shares([(1,1)], [])

def test_get_feldman_vss_factory(mock_field_fast: MockField):
    """Test the factory function get_feldman_vss."""
    vss = get_feldman_vss(mock_field_fast)
    assert isinstance(vss, FeldmanVSS)
    assert vss.field == mock_field_fast
    # Check default config is PQ secure
    assert vss.config.prime_bits >= MIN_PRIME_BITS
    assert vss.config.safe_prime is True

    # Test factory with custom config
    custom_config = VSSConfig(cache_size=64, sanitize_errors=False)
    vss_custom = get_feldman_vss(mock_field_fast, config=custom_config)
    assert vss_custom.config.cache_size == 64
    assert vss_custom.config.sanitize_errors is False
    # Prime bits should still be enforced
    assert vss_custom.config.prime_bits >= MIN_PRIME_BITS

def test_get_feldman_vss_factory_warning(mock_field_fast: MockField):
    """Test factory issues warning if field prime is too small."""
    # Create a field with a prime smaller than MIN_PRIME_BITS
    small_prime = 17
    small_field = MockField(mpz(small_prime))
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        # Factory doesn't directly check field's prime size, VSSConfig does.
        # Let's test the VSS constructor path via the factory
        vss = get_feldman_vss(small_field)
        # The warning comes from VSSConfig __post_init__
        assert vss.config.prime_bits == MIN_PRIME_BITS # Config gets upgraded
        assert len(w) >= 1
        assert any(f"less than {MIN_PRIME_BITS} bits" in str(warn.message) for warn in w)

def test_get_feldman_vss_factory_invalid_field():
    """Test factory raises TypeError for invalid field."""
    with pytest.raises(TypeError, match="field cannot be None"):
        get_feldman_vss(None) # type: ignore
    with pytest.raises(TypeError, match="field must have 'prime' attribute"):
        get_feldman_vss(object()) # type: ignore