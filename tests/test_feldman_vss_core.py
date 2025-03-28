# tests/test_feldman_vss_core.py
# Tests for core components and helper functions of the Feldman VSS implementation.

import copy
import hashlib
import random
import secrets
import time
import warnings
from collections.abc import Sequence
from typing import Any, Union, cast  # Added cast

import gmpy2
import pytest
from gmpy2 import mpz

# Import necessary components from the main module and conftest
# Assuming feldman_vss is imported directly based on conftest structure
import feldman_vss
from feldman_vss import (
    MIN_PRIME_BITS,
    CommitmentList,
    CyclicGroup,
    FeldmanVSS,
    FieldElement,
    MemoryMonitor,
    ParameterError,
    SafeLRUCache,
    SecurityError,
    SecurityWarning,
    SerializationError,
    ShareDict,
    VerificationError,
    VSSConfig,
    check_memory_safety,
    compute_checksum,
    constant_time_compare,
    create_secure_deterministic_rng,
    estimate_exp_result_size,
    estimate_mpz_operation_memory,
    estimate_mpz_size,
    get_feldman_vss,
    get_system_memory,
    sanitize_error,
    secure_redundant_execution,
    validate_timestamp,
)
from tests.conftest import (
    DEFAULT_PRIME_BITS,
    DEFAULT_THRESHOLD,
    HAS_BLAKE3,
    TEST_PRIME_BITS_FAST,
    MockField,
)

# --- Test VSSConfig ---


def test_vssconfig_defaults():
    """Test VSSConfig default values."""
    config = VSSConfig()
    assert config.prime_bits == DEFAULT_PRIME_BITS
    assert config.safe_prime is True
    assert config.secure_serialization is True
    assert config.use_blake3 is True  # Default assumes blake3 might be available
    assert config.cache_size == 128
    assert config.sanitize_errors is True


def test_vssconfig_prime_bits_enforcement():
    """Test that prime_bits is enforced to be at least MIN_PRIME_BITS."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        config = VSSConfig(prime_bits=1024)
        assert config.prime_bits == MIN_PRIME_BITS
        # Check if at least one warning matches, allowing for multiple similar warnings
        assert any(f"less than {MIN_PRIME_BITS} bits" in str(warning.message) for warning in w)
        assert any(issubclass(warning.category, SecurityWarning) for warning in w)

    # Test with value already meeting the minimum
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        config = VSSConfig(prime_bits=MIN_PRIME_BITS)
        assert config.prime_bits == MIN_PRIME_BITS
        assert len(w) == 0


def test_vssconfig_blake3_fallback(monkeypatch):
    """Test VSSConfig falls back from blake3 if unavailable."""
    # Simulate blake3 not being available
    monkeypatch.setattr(feldman_vss, "has_blake3", False)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", RuntimeWarning)
        config = VSSConfig(use_blake3=True)
        assert config.use_blake3 is True  # Config value remains True
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
        if not CyclicGroup._is_safe_prime(test_prime_fast):  # Only run if test_prime_fast isn't safe
            with pytest.raises(ParameterError, match="Provided prime is not a safe prime"):
                CyclicGroup(prime=int(test_prime_fast), use_safe_prime=True)
        else:
            pytest.skip("test_prime_fast happens to be a safe prime, skipping non-safe check.")

    def test_init_invalid_generator_error(self, test_prime_fast: mpz):
        """Test providing an invalid generator raises ParameterError."""
        with pytest.raises(ParameterError, match="Provided value is not a generator"):
            CyclicGroup(prime=int(test_prime_fast), generator=1, use_safe_prime=False)  # 1 is never a generator

    def test_primality_tests(self, test_prime_fast: mpz, test_prime_pq: mpz):
        """Test the internal primality test helpers."""
        assert CyclicGroup._is_probable_prime(test_prime_pq) is True
        assert CyclicGroup._is_safe_prime(test_prime_pq) is True
        assert CyclicGroup._is_probable_prime(test_prime_fast) is True
        # Revised check: Test the helper against the definition
        is_actually_safe = gmpy2.is_prime((test_prime_fast - 1) // 2)  # type: ignore[reportOperatorIssue] # mpz supports // int
        assert CyclicGroup._is_safe_prime(test_prime_fast) is is_actually_safe

        # Test edge cases
        assert CyclicGroup._is_probable_prime(1) is False
        assert CyclicGroup._is_probable_prime(0) is False
        assert CyclicGroup._is_probable_prime(-5) is False
        assert CyclicGroup._is_probable_prime(4) is False
        assert CyclicGroup._is_probable_prime(2) is True
        assert CyclicGroup._is_probable_prime(3) is True
        assert CyclicGroup._is_safe_prime(7) is True  # 7 = 2*3 + 1
        assert CyclicGroup._is_safe_prime(11) is True  # 11 = 2*5 + 1
        assert CyclicGroup._is_safe_prime(13) is False  # (13-1)/2 = 6 (not prime)

    def test_generator_verification(self, test_prime_pq: mpz):
        """Test generator verification logic, especially for safe primes."""
        group = CyclicGroup(prime=int(test_prime_pq), use_safe_prime=True)
        g = group.generator
        q = (test_prime_pq - 1) // 2  # type: ignore[reportOperatorIssue] # mpz supports // int

        assert group._is_generator(g) is True
        # For safe prime p=2q+1, g is generator if g^q mod p != 1
        assert gmpy2.powmod(g, q, test_prime_pq) != 1

        # Test known non-generators
        assert group._is_generator(1) is False
        if test_prime_pq > 3:
            assert group._is_generator(mpz(test_prime_pq - 1)) is False  # Order 2

        # Test quadratic residue (should have order q)
        quad_res = gmpy2.powmod(g, 2, test_prime_pq)
        if quad_res != 1:
            # A quadratic residue (non-1) should be a generator of the q-order subgroup
            # Pylance struggles with mpz vs mpfr possibilities from gmpy2 functions
            assert group._is_generator(quad_res) is True  # type: ignore[reportArgumentType] # mpz is compatible
            assert gmpy2.powmod(quad_res, q, test_prime_pq) == 1  # Belongs to subgroup

    def test_arithmetic_operations(self, test_prime_fast: mpz):
        """Test basic modular arithmetic operations."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        a = group.secure_random_element()
        b = group.secure_random_element()
        one = mpz(1)
        zero = mpz(0)

        # Multiplication
        prod = group.mul(a, b)
        assert prod == (a * b) % test_prime_fast  # type: ignore[reportOperatorIssue] # mpz supports %

        # Exponentiation (non-secure, uses cache)
        exp_val = group.exp(a, 5)
        assert exp_val == gmpy2.powmod(a, 5, test_prime_fast)

        # Secure Exponentiation (no cache)
        exp_sec = group.secure_exp(a, 5)
        assert exp_sec == gmpy2.powmod(a, 5, test_prime_fast)

        # Identity elements
        assert group.mul(a, one) == a % test_prime_fast  # a*1 = a # type: ignore[reportOperatorIssue] # mpz supports %
        assert group.exp(a, zero) == one  # a^0 = 1
        assert group.secure_exp(a, zero) == one

        # Associativity (mul)
        c = group.secure_random_element()
        assert group.mul(group.mul(a, b), c) == group.mul(a, group.mul(b, c))

        # Commutativity (mul)
        assert group.mul(a, b) == group.mul(b, a)

        # Power laws (exp) - use small exponents
        exp1 = mpz(3)
        exp2 = mpz(4)
        # a^(e1+e2) == a^e1 * a^e2
        assert group.exp(a, exp1 + exp2) == group.mul(group.exp(a, exp1), group.exp(a, exp2))  # type: ignore[reportArgumentType] # mpz compatible
        # (a^e1)^e2 == a^(e1*e2)
        assert group.exp(group.exp(a, exp1), exp2) == group.exp(a, exp1 * exp2)  # type: ignore[reportArgumentType] # mpz compatible

    def test_exp_cache_behavior(self, test_prime_fast: mpz):
        """Verify secure_exp does not use the cache, while exp does."""
        group = CyclicGroup(prime=int(test_prime_fast), cache_size=10, use_safe_prime=False)
        base = group.secure_random_element()
        # Use exponent relative to subgroup order q if safe prime, else p-1
        q = (test_prime_fast - 1) // 2 if CyclicGroup._is_safe_prime(test_prime_fast) else test_prime_fast - 1  # type: ignore[reportOperatorIssue] # mpz supports // int
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
        fake_result = (res_sec + 1) % test_prime_fast  # type: ignore[reportOperatorIssue] # mpz supports %
        group.cached_powers.put(cache_key, fake_result)
        res_sec_again = group.secure_exp(base, exponent)
        assert res_sec_again == res1  # Should recalculate correct value
        assert group.cached_powers.get(cache_key) == fake_result  # Cache still holds fake value

    def test_multi_exp(self, test_prime_fast: mpz):
        """Test multi-exponentiation."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        num_bases = 5
        bases = [group.secure_random_element() for _ in range(num_bases)]
        exponents = [secrets.randbelow(int(test_prime_fast - 1)) for _ in range(num_bases)]

        # Calculate expected result manually
        expected = mpz(1)
        for b, e in zip(bases, exponents):
            term = group.exp(b, e)  # Use group's exp for consistency
            expected = group.mul(expected, term)

        # Calculate using multi_exp
        result = group.efficient_multi_exp(bases, exponents)  # type: ignore[reportArgumentType] # list[mpz]/list[int] compatible

        assert result == expected

    def test_multi_exp_edge_cases(self, test_prime_fast: mpz):
        """Test multi-exponentiation with edge cases."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)

        # Empty lists
        assert group.efficient_multi_exp([], []) == 1

        # Single element list
        base = group.secure_random_element()
        exponent = secrets.randbelow(int(test_prime_fast - 1))
        assert group.efficient_multi_exp([base], [exponent]) == group.exp(base, exponent)  # type: ignore[reportArgumentType] # list[mpz]/list[int] compatible

        # Mismatched list lengths
        with pytest.raises(ValueError):
            group.efficient_multi_exp([base], [exponent, exponent])  # type: ignore[reportArgumentType] # list[mpz]/list[int] compatible

    def test_hash_to_group(self, test_prime_fast: mpz):
        """Test hash_to_group generates values within the correct range."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        count = 50
        hashes = set()
        for i in range(count):
            data = secrets.token_bytes(16) + i.to_bytes(4, "big")  # Ensure unique data
            h = group.hash_to_group(data)
            assert 1 <= h < group.prime
            hashes.add(h)

        # Check for variability (highly unlikely to have collisions for good hash)
        # Allow for some small chance of collision, e.g., > 95% unique
        assert len(hashes) > count * 0.95, "Hash function produced too many collisions"

    def test_hash_to_group_type_error(self, test_prime_fast: mpz):
        """Test hash_to_group raises TypeError for non-bytes input."""
        group = CyclicGroup(prime=int(test_prime_fast), use_safe_prime=False)
        with pytest.raises(TypeError):
            group.hash_to_group("not bytes")  # type: ignore

    # Added test for Gap 6
    def test_enhanced_encode_for_hash(self, default_vss: FeldmanVSS):  # Use default_vss fixture
        """Test the internal enhanced encoding for hashing."""
        group = default_vss.group  # Get group from VSS instance
        # Test different types and contexts
        enc1 = group._enhanced_encode_for_hash(1, "a", b"b", context="C1")
        enc2 = group._enhanced_encode_for_hash(1, "a", b"b", context="C2")
        enc3 = group._enhanced_encode_for_hash("a", 1, b"b", context="C1")  # Different order
        enc4 = group._enhanced_encode_for_hash(mpz(1), "a", b"b", context="C1")  # mpz vs int

        assert isinstance(enc1, bytes)
        assert enc1 != enc2  # Context matters
        assert enc1 != enc3  # Order matters
        assert enc1 == enc4  # mpz(1) should encode same as int(1)

        # Check structure (presence of type/length prefixes - simplified check)
        assert b"\x02" in enc1  # Type tag for int
        assert b"\x01" in enc1  # Type tag for str
        assert b"\x00" in enc1  # Type tag for bytes
        assert b"C1" in enc1


# --- Test Helper Functions ---


# Added test for Gap 1
def test_estimate_exp_result_size():
    """Test the estimation of exponentiation result size."""
    # base_bits, exponent -> expected_bits
    assert estimate_exp_result_size(10, 3) == 30
    assert estimate_exp_result_size(10, mpz(3)) == 30
    # Test large exponent (should be capped by implementation)
    large_exp = mpz(1) << 40  # Exponent much larger than 2**30
    # Implementation caps exponent value estimate at 2**30
    assert estimate_exp_result_size(10, large_exp) == 10 * (2**30)
    assert estimate_exp_result_size(0, 5) == 0  # Base 0
    assert estimate_exp_result_size(10, 0) == 0  # Exponent 0
    assert estimate_exp_result_size(10, 1) == 10  # Exponent 1


# Added test for Gap 2
def test_get_system_memory_fallback(monkeypatch):
    """Test get_system_memory fallback when psutil is unavailable."""
    # Simulate psutil not being imported/available
    monkeypatch.setattr(feldman_vss, "psutil", None)
    fallback_mem = get_system_memory()
    # Check if it returns the hardcoded fallback value (1GB)
    assert fallback_mem == 1 * 1024 * 1024 * 1024


@pytest.mark.security
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
        (None, None, False),  # Consistent failure
        # Large values
        (mpz(1) << 2048, mpz(1) << 2048, True),
        (mpz(1) << 2048, (mpz(1) << 2048) + 1, False),
        (b"a" * 1000, b"a" * 1000, True),
        (b"a" * 1000, b"a" * 999 + b"b", False),
    ],
)
def test_constant_time_compare(a, b, expected):
    """Test constant_time_compare with various inputs."""
    assert constant_time_compare(a, b) is expected


@pytest.mark.security
def test_constant_time_compare_large_value_error():
    """Test constant_time_compare raises ValueError for excessively large inputs."""
    large_int = mpz(1) << 1_100_000  # > 1M bits
    with pytest.raises(ValueError, match="too large for secure comparison"):
        constant_time_compare(large_int, large_int)

    large_bytes = b"a" * 11_000_000  # > 10MB
    with pytest.raises(ValueError, match="too large for secure comparison"):
        constant_time_compare(large_bytes, large_bytes)


@pytest.mark.security
def test_validate_timestamp():
    """Test timestamp validation logic."""
    now = int(time.time())
    max_drift = feldman_vss.MAX_TIME_DRIFT

    # Valid timestamps
    assert validate_timestamp(now) == now
    assert validate_timestamp(now - 100) == now - 100
    assert validate_timestamp(now + max_drift // 2) == now + max_drift // 2

    # Valid None (returns current time)
    assert abs(validate_timestamp(timestamp=None) - now) < 5  # Allow small diff

    # Invalid types
    with pytest.raises(expected_exception=TypeError):
        validate_timestamp(timestamp="not an int")  # type: ignore
    with pytest.raises(expected_exception=TypeError):
        validate_timestamp(timestamp=None, allow_none=False)

    # Invalid values
    with pytest.raises(expected_exception=ValueError, match="negative"):
        validate_timestamp(timestamp=-100)
    with pytest.raises(expected_exception=ValueError, match="future"):
        validate_timestamp(timestamp=now + max_drift + 100)
    with pytest.raises(expected_exception=ValueError, match="past"):
        # Use default past drift (86400)
        validate_timestamp(timestamp=now - 86400 - 100)

    # Warning for significant drift
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        validate_timestamp(now + max_drift // 2 + 100)
        assert len(w) >= 1  # Use >= 1 as other warnings might occur
        assert any(issubclass(warn.category, SecurityWarning) for warn in w)
        assert any("Significant time difference" in str(warn.message) for warn in w)


def test_estimate_mpz_size():
    """Test estimation of mpz object size."""
    size_1k = estimate_mpz_size(mpz(1) << 1024)
    assert size_1k > 1024 // 8  # Should be larger than raw bytes
    assert size_1k < (1024 // 8) * 2  # But reasonably close

    size_4k = estimate_mpz_size(mpz(1) << 4096)
    assert size_4k > 4096 // 8
    assert size_4k < (4096 // 8) * 2

    size_0 = estimate_mpz_size(0)
    assert size_0 > 0  # Still has object overhead


def test_estimate_mpz_operation_memory():
    """Test estimation of memory for mpz operations."""
    bits = 4096
    mem_add: int = estimate_mpz_operation_memory("add", bits, bits)
    mem_mul: int = estimate_mpz_operation_memory("mul", bits, bits)
    mem_pow_small_exp: int = estimate_mpz_operation_memory("pow", bits, 10)  # Exponent value 10
    mem_pow_large_exp_bits: int = estimate_mpz_operation_memory("pow", bits, 30)  # Exponent bit size 30

    assert mem_mul > mem_add
    # pow result size is roughly base_bits * exponent_value
    # Fixed: Cast estimated bits to int for estimate_mpz_size
    assert mem_pow_small_exp < estimate_mpz_size(int(bits * 10 * 1.5))
    # pow result size approx base_bits * 2^exponent_bits
    # Fixed: Cast estimated bits to int for estimate_mpz_size
    assert mem_pow_large_exp_bits < estimate_mpz_size(int(bits * (2**30) * 1.5))

    with pytest.raises(ValueError, match="Exponent too large"):
        estimate_mpz_operation_memory("pow", bits, 100)  # Exponent bit size 100

    with pytest.raises(ValueError, match="Unknown operation type"):
        estimate_mpz_operation_memory("unknown", bits, bits)


def test_check_memory_safety():
    """Test memory safety checks for operations."""
    # Safe operations
    assert check_memory_safety("mul", mpz(10) ** 10, mpz(10) ** 10, max_size_mb=100) is True
    assert check_memory_safety("exp", mpz(2) ** 100, 5, mpz(2) ** 1000, max_size_mb=100) is True  # Modular exp

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
        compute_checksum("not bytes")  # type: ignore


# Added test for Gap 4
@pytest.mark.security
def test_compute_checksum_fallback(monkeypatch):
    """Test compute_checksum falls back to SHA3-256."""
    # Simulate blake3 not being available
    monkeypatch.setattr(feldman_vss, "has_blake3", False)
    monkeypatch.setattr(feldman_vss, "blake3", None)

    data = b"checksum fallback test"
    checksum = compute_checksum(data)

    # Calculate expected SHA3-based checksum
    expected_digest = hashlib.sha3_256(data).digest()[:16]
    expected_checksum = int.from_bytes(expected_digest, byteorder="big")
    assert checksum == expected_checksum


@pytest.mark.security
def test_create_secure_deterministic_rng():
    """Test the deterministic RNG creation and properties."""
    seed1: bytes = secrets.token_bytes(nbytes=32)
    seed2: bytes = secrets.token_bytes(nbytes=32)
    rng1a_func = create_secure_deterministic_rng(seed1)
    rng1b_func = create_secure_deterministic_rng(seed1)
    rng2_func = create_secure_deterministic_rng(seed2)
    bound = mpz(1) << 256

    seq1a = [rng1a_func(bound) for _ in range(20)]
    seq1b = [rng1b_func(bound) for _ in range(20)]
    seq2 = [rng2_func(bound) for _ in range(20)]

    assert all(isinstance(x, int) for x in seq1a)  # Ensure output is int
    assert seq1a == seq1b, "RNG with same seed produced different sequences"
    assert seq1a != seq2, "RNG with different seeds produced same sequence"
    for val in seq1a:
        assert 0 <= val < bound

    # Test invalid inputs to factory
    with pytest.raises(expected_exception=TypeError):
        create_secure_deterministic_rng("not bytes")  # type: ignore
    with pytest.raises(expected_exception=ValueError, match="empty"):
        create_secure_deterministic_rng(b"")
    with pytest.raises(expected_exception=ValueError, match="at least 32 bytes"):
        create_secure_deterministic_rng(b"too short")

    # Test invalid inputs to generated function
    rng_test = create_secure_deterministic_rng(seed1)
    with pytest.raises(expected_exception=TypeError):
        rng_test("not an int")  # type: ignore
    with pytest.raises(expected_exception=ValueError, match="positive"):
        rng_test(0)
    with pytest.raises(expected_exception=ValueError, match="positive"):
        rng_test(-100)


@pytest.mark.security
def test_secure_redundant_execution() -> None:
    """Test secure_redundant_execution detects mismatches and errors."""

    def stable_func(a, b):
        return a + b

    def faulty_func(a, b):
        # Sometimes returns wrong result
        if secrets.randbelow(exclusive_upper_bound=3) == 0:
            return a + b + 1
        return a + b

    def error_func(a, b):
        # Sometimes raises error
        if secrets.randbelow(exclusive_upper_bound=3) == 0:
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
    with pytest.raises(expected_exception=TypeError):
        secure_redundant_execution("not callable", 1, 2)  # type: ignore


@pytest.mark.security
def test_sanitize_error():
    """Test error message sanitization."""
    detailed = "Detailed technical error message with specifics"
    assert sanitize_error("Commitment verification failed", detailed, sanitize=True) == "Cryptographic verification failed"
    assert sanitize_error("Checksum mismatch", detailed, sanitize=True) == "Data integrity check failed"
    assert sanitize_error("Byzantine behavior detected", detailed, sanitize=True) == "Protocol security violation detected"
    assert sanitize_error("Some unknown error", detailed, sanitize=True) == "Cryptographic operation failed"

    # Test no sanitization
    assert sanitize_error("Commitment verification failed", detailed, sanitize=False) == "Commitment verification failed"

    # Test no sanitization
    assert sanitize_error("Commitment verification failed", detailed, sanitize=False) == "Commitment verification failed"


# --- Test FeldmanVSS Core Methods ---


def test_feldman_init(mock_field_fast: MockField, default_vss_config: VSSConfig):
    """Test FeldmanVSS initialization."""
    vss = FeldmanVSS(field=mock_field_fast, config=default_vss_config)
    assert vss.field == mock_field_fast
    assert vss.config == default_vss_config
    assert isinstance(vss.group, CyclicGroup)
    # Group prime might be different if VSSConfig prime_bits overrides field prime
    # assert vss.group.prime == mock_field_fast.prime # This might not hold if config overrides
    assert vss.generator == vss.group.generator
    if HAS_BLAKE3 and vss.config.use_blake3:  # Check config setting too
        assert vss.hash_algorithm.__name__ == "blake3"
    else:
        assert vss.hash_algorithm.__name__ == "sha3_256"


def test_feldman_init_invalid_field() -> None:
    """Test FeldmanVSS init fails with invalid field object."""

    class BadField:
        pass

    with pytest.raises(expected_exception=TypeError, match="Field must have a 'prime' attribute"):
        FeldmanVSS(BadField())  # type: ignore

    class BadFieldWithPrime:
        prime = "not a number"

    with pytest.raises(expected_exception=TypeError, match="integer or gmpy2.mpz"):
        FeldmanVSS(BadFieldWithPrime())  # type: ignore


def test_create_commitments(default_vss: FeldmanVSS, test_coeffs: Sequence[mpz]):  # Use Sequence
    """Test basic commitment creation."""
    coeffs_list: list[FieldElement] = list(test_coeffs)  # Explicit list of compatible type
    commitments = default_vss.create_commitments(coeffs_list)
    assert isinstance(commitments, list)
    assert len(commitments) == len(test_coeffs)
    # Check structure of hash-based commitment: (hash_value, randomizer, optional_entropy)
    assert isinstance(commitments[0], tuple)
    assert len(commitments[0]) == 3
    assert isinstance(commitments[0][0], mpz)  # Hash value
    assert isinstance(commitments[0][1], mpz)  # Randomizer
    assert isinstance(commitments[0][2], (bytes, type(None)))  # Entropy


def test_create_commitments_empty_coeffs_error(default_vss: FeldmanVSS) -> None:
    """Test create_commitments raises error for empty coefficients."""
    with pytest.raises(expected_exception=(ValueError, ParameterError), match="cannot be empty"):
        default_vss.create_commitments(coefficients=[])


def test_create_commitments_type_error(default_vss: FeldmanVSS):
    """Test create_commitments raises error for non-list coefficients."""
    with pytest.raises(expected_exception=TypeError, match="must be a list"):
        default_vss.create_commitments(coefficients="not a list")  # type: ignore


def test_create_commitments_low_entropy_secret(default_vss: FeldmanVSS, mock_field_fast: MockField):
    """Test that extra entropy is added for low-entropy secrets."""
    low_entropy_secret = mpz(5)  # Very small secret
    # Annotate with Sequence for covariance, create list[mpz] which is Sequence[FieldElement] compatible
    coeffs_seq: Sequence[FieldElement] = [low_entropy_secret] + [mock_field_fast.random_element() for _ in range(DEFAULT_THRESHOLD - 1)]
    commitments = default_vss.create_commitments(list(coeffs_seq))  # Pass as list
    # The first commitment (for the secret) should have non-None entropy
    assert commitments[0][2] is not None
    assert isinstance(commitments[0][2], bytes)
    # Other commitments should have None entropy
    if len(commitments) > 1:
        assert commitments[1][2] is None


def test_create_commitments_high_entropy_secret(default_vss: FeldmanVSS, test_coeffs: Sequence[mpz]):  # Use Sequence
    """Test that extra entropy is None for high-entropy secrets."""
    # Assume test_coeffs[0] generated by random_element() is high entropy
    # Pass the list of coefficients directly
    commitments = default_vss.create_commitments(list(test_coeffs))
    # The first commitment should have None entropy if secret is large enough
    if test_coeffs[0].bit_length() >= 256:  # Threshold defined in create_enhanced_commitments
        assert commitments[0][2] is None
    else:
        # If the randomly generated secret happens to be small, entropy might be added
        assert isinstance(commitments[0][2], (bytes, type(None)))


def test_verify_share_valid(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification of a valid share."""
    # Pick a random valid share
    share_id = random.choice(list(test_shares.keys()))  # noqa: S311 - random choice for test case selection is ok
    x, y = test_shares[share_id]
    assert default_vss.verify_share(x, y, test_commitments) is True


def test_verify_share_invalid_y(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification fails for an invalid share (wrong y value)."""
    share_id = random.choice(list(test_shares.keys()))  # noqa: S311 - random choice for test case selection is ok
    x, y = test_shares[share_id]
    invalid_y = (y + 1) % default_vss.field.prime  # type: ignore[reportOperatorIssue] # mpz % mpz is valid
    assert default_vss.verify_share(x, invalid_y, test_commitments) is False


def test_verify_share_invalid_commitments(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test verification fails if commitments are tampered with."""
    share_id = random.choice(list(test_shares.keys()))  # noqa: S311 - random choice for test case selection is ok
    x, y = test_shares[share_id]

    # Tamper with one commitment value
    tampered_commitments = copy.deepcopy(test_commitments)
    original_c0, r0, e0 = tampered_commitments[0]
    tampered_commitments[0] = ((original_c0 + 1) % default_vss.group.prime, r0, e0)  # type: ignore[reportOperatorIssue] # mpz % mpz is valid

    assert default_vss.verify_share(x, y, tampered_commitments) is False

    # Tamper with one randomizer value
    tampered_commitments_r = copy.deepcopy(test_commitments)
    # Ensure index 1 exists before accessing
    if len(tampered_commitments_r) <= 1:
        pytest.skip("Skipping randomizer tampering test: not enough commitments.")

    # This code block will only run if the skip condition above is not met
    c1, original_r1, e1 = tampered_commitments_r[1]
    tampered_commitments_r[1] = (c1, (original_r1 + 1) % default_vss.group.prime, e1)  # type: ignore[reportOperatorIssue] # mpz % mpz is valid
    assert default_vss.verify_share(x, y, tampered_commitments_r) is False


def test_verify_share_invalid_types(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test verify_share handles invalid input types gracefully (returns False)."""
    assert default_vss.verify_share("invalid", 1, test_commitments) is False  # type: ignore
    assert default_vss.verify_share(1, "invalid", test_commitments) is False  # type: ignore
    assert default_vss.verify_share(1, 1, "invalid") is False  # type: ignore
    assert default_vss.verify_share(1, 1, []) is False  # Empty commitments
    # Malformed commitment list
    malformed_commitments = [(1,)]  # Missing randomizer
    assert default_vss.verify_share(1, 1, malformed_commitments) is False  # type: ignore


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
    invalid_y0 = (y0 + 1) % default_vss.field.prime  # type: ignore[reportOperatorIssue] # mpz % mpz is valid
    share_list[0] = (x0, invalid_y0)

    all_valid, results = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid is False
    assert len(results) == len(share_list)
    assert results[0] is False  # First share should be invalid
    assert all(results[i] for i in range(1, len(share_list)))  # Others should be valid


def test_batch_verify_with_duplicates(default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
    """Test batch verification when the same share is included multiple times."""
    share_list = list(test_shares.values())
    original_len = len(share_list)
    if original_len < 2:
        pytest.skip("Need at least 2 shares to test duplicates properly.")

    share_list.append(share_list[0])  # Duplicate the first share
    share_list.append(share_list[1])  # Duplicate the second share

    all_valid, results = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid is True
    assert len(results) == len(share_list)
    assert all(results.values())

    # Introduce an invalid share among duplicates
    x_inv, y_inv = share_list[0]  # Get original x, y of the first share
    share_list.append((x_inv, (y_inv + 1) % default_vss.field.prime))  # type: ignore[reportOperatorIssue] # Add an invalid version
    idx_invalid = len(share_list) - 1

    all_valid_inv, results_inv = default_vss.batch_verify_shares(share_list, test_commitments)
    assert all_valid_inv is False
    assert len(results_inv) == len(share_list)
    assert results_inv[idx_invalid] is False  # The explicitly invalid one
    # Ensure the original valid duplicates are still marked valid
    assert results_inv[0] is True  # Original first share
    assert results_inv[original_len] is True  # First duplicate of the first share


def test_batch_verify_empty_shares_error(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test batch_verify_shares raises error for empty shares list."""
    with pytest.raises((ValueError, ParameterError), match="cannot be empty"):
        default_vss.batch_verify_shares([], test_commitments)


def test_batch_verify_type_errors(default_vss: FeldmanVSS, test_commitments: CommitmentList):
    """Test batch_verify_shares raises error for invalid input types."""
    with pytest.raises(TypeError, match="shares must be a list"):
        default_vss.batch_verify_shares("not a list", test_commitments)  # type: ignore
    with pytest.raises(TypeError, match="Each share must be a tuple"):
        default_vss.batch_verify_shares([(1, 2), 3], test_commitments)  # type: ignore
    with pytest.raises(TypeError, match="commitments must be a non-empty list"):
        default_vss.batch_verify_shares([(1, 1)], "invalid")  # type: ignore
    with pytest.raises(TypeError, match="commitments must be a non-empty list"):
        default_vss.batch_verify_shares([(1, 1)], [])


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


def test_get_feldman_vss_factory_warning(mock_field_fast: MockField):  # noqa: ARG001
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
        assert vss.config.prime_bits == MIN_PRIME_BITS  # Config gets upgraded
        assert len(w) >= 1
        assert any(f"less than {MIN_PRIME_BITS} bits" in str(warn.message) for warn in w)


def test_get_feldman_vss_factory_invalid_field():
    """Test factory raises TypeError for invalid field."""
    with pytest.raises(TypeError, match="field cannot be None"):
        get_feldman_vss(None)  # type: ignore
    with pytest.raises(TypeError, match="field must have 'prime' attribute"):
        get_feldman_vss(object())  # type: ignore


def test_vss_method_error_sanitization(mock_field_fast: MockField):
    """Test that errors raised by VSS methods are sanitized when configured."""
    # Use a config where sanitization is explicitly True
    sanitized_config = VSSConfig(
        prime_bits=TEST_PRIME_BITS_FAST,
        safe_prime=False,
        sanitize_errors=True,  # Ensure sanitization is on
        use_blake3=HAS_BLAKE3,
    )
    vss = FeldmanVSS(field=mock_field_fast, config=sanitized_config)

    # Example 1: Trigger ParameterError in create_commitments
    with pytest.raises(ParameterError) as excinfo_param:
        vss.create_commitments([])
    # Check if the message is the *sanitized* version
    detailed_message = "Coefficients list cannot be empty"
    expected_sanitized_message = sanitize_error(detailed_message, sanitize=True)
    assert detailed_message not in str(excinfo_param.value), "Detailed error message was exposed"
    assert expected_sanitized_message in str(excinfo_param.value), "Sanitized message not found"

    # Example 2: Trigger TypeError in create_commitments
    with pytest.raises(TypeError) as excinfo_type:
        vss.create_commitments("not a list")  # type: ignore
    detailed_message_type = "coefficients must be a list"
    # Check against potential sanitized messages based on sanitize_error logic
    possible_sanitized = [
        "Cryptographic parameter validation failed",
        "Cryptographic operation failed",
        "Verification of cryptographic parameters failed",
    ]
    assert detailed_message_type not in str(excinfo_type.value), "Detailed error message was exposed"
    assert any(sanitized in str(excinfo_type.value) for sanitized in possible_sanitized), "No expected sanitized message found"

    # Example 3: Trigger VerificationError (simulated)
    # We need valid commitments first
    # Annotate with Sequence for covariance
    coeffs_seq: Sequence[FieldElement] = [mock_field_fast.random_element() for _ in range(DEFAULT_THRESHOLD)]
    commitments = vss.create_commitments(list(coeffs_seq))  # Pass as list
    x_val, y_val = 1, mock_field_fast.random_element()  # Use a valid x, random y
    # Temporarily disable sanitization to see the detailed error for the test setup
    vss.config.sanitize_errors = False
    detailed_error_text = ""
    try:
        # This should raise VerificationError if sanitization was off
        with pytest.raises(VerificationError) as excinfo_detailed:
            # Use verify_share_from_serialized which internally raises VerificationError
            serialized = vss.serialize_commitments(commitments)
            vss.verify_share_from_serialized(x_val, (y_val + 1) % vss.field.prime, serialized)  # type: ignore[reportOperatorIssue]
        detailed_error_text = str(excinfo_detailed.value)
    except Exception as e:
        pytest.fail(f"Setup for VerificationError test failed: {e}")
    finally:
        vss.config.sanitize_errors = True  # Turn sanitization back on

    assert detailed_error_text, "Failed to capture detailed error message during setup"

    # Now test with sanitization on
    with pytest.raises(VerificationError) as excinfo_sanitized:
        serialized = vss.serialize_commitments(commitments)
        vss.verify_share_from_serialized(x_val, (y_val + 1) % vss.field.prime, serialized)  # type: ignore[reportOperatorIssue]
    sanitized_error_text = str(excinfo_sanitized.value)

    assert detailed_error_text not in sanitized_error_text, "Detailed verification error was exposed"
    assert "Cryptographic verification failed" in sanitized_error_text or "Verification failed" in sanitized_error_text

    # Example 4: Trigger SecurityError during deserialization (e.g., checksum)
    # Create valid commitments and serialize them
    coeffs_seq_sec: Sequence[FieldElement] = [mock_field_fast.random_element() for _ in range(DEFAULT_THRESHOLD)]
    commitments_sec = vss.create_commitments(list(coeffs_seq_sec))
    valid_serialized = vss.serialize_commitments(commitments_sec)

    # Tamper with the serialized data slightly to cause checksum failure
    # Ensure tampering doesn't create valid base64 but invalid msgpack
    tampered_serialized = valid_serialized[:-5] + "XXXXX"  # Simple tampering

    with pytest.raises(SecurityError) as excinfo_security:
        # Ensure sanitization is on for this check
        vss.config.sanitize_errors = True
        try:
            # Attempt to deserialize tampered data
            vss.deserialize_commitments(tampered_serialized)
        except (SerializationError, SecurityError) as e:
            # We expect SecurityError due to checksum, but catch SerializationError too
            if isinstance(e, SecurityError):
                raise  # Re-raise the expected SecurityError
            else:
                # If it's a SerializationError instead, fail the test setup
                pytest.fail(f"Expected SecurityError due to tampering, but got SerializationError: {e}")
        except Exception as e:
            pytest.fail(f"Unexpected error during tampered deserialization: {e}")

    # Check if the message is sanitized
    # The detailed message would likely contain "Checksum mismatch" or similar
    detailed_checksum_message = "Checksum mismatch"  # Example detail
    expected_sanitized_checksum_message = "Data integrity check failed"  # From sanitize_error logic
    assert detailed_checksum_message not in str(excinfo_security.value), "Detailed checksum error message was exposed"
    assert expected_sanitized_checksum_message in str(excinfo_security.value), "Sanitized checksum message not found"


# --- Added Tests for Gaps ---


# Test for Gap 3: MemoryMonitor Class
class TestMemoryMonitor:
    def test_monitor_init_and_stats(self):
        monitor = MemoryMonitor(max_memory_mb=512)
        assert monitor.max_memory_mb == 512
        stats = monitor.get_usage_stats()
        assert stats["current_bytes"] == 0
        assert stats["peak_bytes"] == 0
        assert stats["max_mb"] == 512

    def test_monitor_allocate_release(self):
        monitor = MemoryMonitor(max_memory_mb=10)  # 10MB
        size1 = 5 * 1024 * 1024
        size2 = 3 * 1024 * 1024
        assert monitor.check_allocation(size1) is True
        assert monitor.allocate(size1) is True
        assert monitor.current_usage == size1
        assert monitor.peak_usage == size1
        assert monitor.allocate(size2) is True
        assert monitor.current_usage == size1 + size2
        assert monitor.peak_usage == size1 + size2
        monitor.release(size1)
        assert monitor.current_usage == size2
        assert monitor.peak_usage == size1 + size2  # Peak doesn't decrease

    def test_monitor_errors(self):
        monitor = MemoryMonitor(max_memory_mb=1)  # 1MB
        size_ok = 512 * 1024
        size_too_big = 600 * 1024
        monitor.allocate(size_ok)
        # Check allocation fails
        assert monitor.check_allocation(size_too_big) is False
        # Allocate fails
        with pytest.raises(MemoryError):
            monitor.allocate(size_too_big)
        # Release too much fails
        with pytest.raises(ValueError, match="Cannot release more memory"):
            monitor.release(size_ok + 1)
        # Release negative fails
        with pytest.raises(ValueError, match="cannot be negative"):
            monitor.release(-100)
        # Release wrong type fails
        with pytest.raises(TypeError):
            monitor.release("abc")  # type: ignore


# Test for Gap 5: SafeLRUCache Class
class TestSafeLRUCache:
    def test_cache_eviction(self):
        cache: SafeLRUCache[str, str] = SafeLRUCache(capacity=2)
        cache.put("key1", "val1")
        cache.put("key2", "val2")
        assert cache.get("key1") == "val1"
        cache.put("key3", "val3")  # Should evict key2 (oldest access was key1)
        assert cache.get("key2") is None
        assert cache.get("key1") == "val1"
        assert cache.get("key3") == "val3"
        assert len(cache) == 2

    def test_cache_get_reorders(self):
        cache: SafeLRUCache[str, str] = SafeLRUCache(capacity=2)
        cache.put("key1", "val1")
        cache.put("key2", "val2")
        _ = cache.get("key1")  # Access key1, making key2 LRU
        cache.put("key3", "val3")  # Should evict key2
        assert cache.get("key2") is None
        assert cache.get("key1") == "val1"
        assert cache.get("key3") == "val3"

    def test_cache_clear(self):
        cache: SafeLRUCache[str, str] = SafeLRUCache(capacity=2)
        cache.put("key1", "val1")
        cache.clear()
        assert len(cache) == 0
        assert cache.get("key1") is None


# Test for Gap 7: FeldmanVSS Internal Helpers
def test_feldman_internal_helpers(default_vss: FeldmanVSS):
    """Unit test internal VSS helper methods."""
    coeffs: list[FieldElement] = [mpz(10), mpz(5), mpz(2)]  # 10 + 5x + 2x^2
    randomizers: list[FieldElement] = [mpz(3), mpz(7), mpz(1)]  # r0, r1, r2
    # (Value, Randomizer, Entropy)
    commits: CommitmentList = [(mpz(100), mpz(3), None), (mpz(200), mpz(7), None), (mpz(300), mpz(1), None)]
    prime = default_vss.field.prime

    # _evaluate_polynomial
    assert default_vss._evaluate_polynomial(coeffs, 2) == 28 % prime

    # _compute_combined_randomizer
    # x=2 -> r0 + r1*2 + r2*2^2 = 3 + 7*2 + 1*4 = 21
    assert default_vss._compute_combined_randomizer(randomizers, 2) == 21 % prime

    # _compute_expected_commitment
    # x=2 -> C0 + C1*2 + C2*2^2 = 100 + 200*2 + 300*4 = 1700
    # Extract only the commitment values (first element of each tuple)
    commit_values: list[FieldElement] = [c[0] for c in commits]
    # Cast the list[FieldElement] to the type expected by the function signature to satisfy Pylance/Pyright due to list invariance.
    # The function's internal logic correctly handles processing a list containing only FieldElements.
    commitments_for_func = cast(list[Union[tuple[FieldElement, ...], FieldElement]], commit_values)
    assert default_vss._compute_expected_commitment(commitments_for_func, 2) == 1700 % prime
