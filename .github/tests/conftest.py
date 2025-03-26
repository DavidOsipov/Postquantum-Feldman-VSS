# tests/conftest.py
# Shared fixtures, helper functions, and configuration for the Feldman VSS test suite

import copy
import hashlib
import logging
import math
import os
import random
import secrets
import sys
import time
import warnings
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Callable
from typing import Any, Optional

import pytest

# --- Dependency Handling & Checks ---
try:
    import gmpy2
    from gmpy2 import mpz
except ImportError:
    print("CRITICAL ERROR: gmpy2 library not found. FeldmanVSS requires gmpy2. Aborting tests.")
    sys.exit(1) # gmpy2 is mandatory

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False
    print("Warning: blake3 library not found, falling back to SHA3-256 for some tests.")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("Warning: psutil not found, some memory usage tests and benchmarks will be skipped or limited.")

try:
    import msgpack
except ImportError:
    print("CRITICAL ERROR: msgpack library not found. Serialization requires msgpack. Aborting tests.")
    sys.exit(1) # msgpack is mandatory for serialization

# Import the module to be tested
# Assuming tests are run from the directory containing the 'tests' folder
# and the feldman_vss.py file. Adjust path if necessary.
try:
    # This assumes feldman_vss.py is in the parent directory of the tests folder
    # or accessible via PYTHONPATH
    import feldman_vss as fvss
    from feldman_vss import (
        MIN_PRIME_BITS,
        CommitmentList,
        CyclicGroup,
        FeldmanVSS,
        FieldElement,
        ParameterError,
        ProofDict,
        SecurityError,
        SecurityWarning,
        SerializationError,
        ShareDict,
        SharePoint,
        VerificationError,
        VSSConfig,
    )
except ImportError as e:
    print(f"ERROR: Could not import feldman_vss module: {e}. Ensure it's in the Python path.")
    sys.exit(1)

# --- Test Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
test_logger = logging.getLogger("feldman_vss_pytest")

# Use smaller primes for faster testing where appropriate, but default to PQ-secure
DEFAULT_PRIME_BITS = fvss.MIN_PRIME_BITS # 4096 for PQ security
TEST_PRIME_BITS_FAST = 512 # For faster unit/property tests
DEFAULT_THRESHOLD = 3
DEFAULT_NUM_SHARES = 5
LARGE_N = int(os.environ.get("VSS_LARGE_N", 100)) # Smaller default for faster CI
LARGE_T = int(os.environ.get("VSS_LARGE_T", 30))  # Smaller default for faster CI

# Performance test flag
RUN_PERFORMANCE_TESTS = os.environ.get("RUN_PERFORMANCE_TESTS", "0") == "1"

# --- Helper Functions ---

_prime_cache: dict[tuple[int, bool], mpz] = {}

def get_prime(bits: int, safe: bool = True) -> mpz:
    """
    Gets a prime, preferring precomputed safe primes or generating one.
    Uses a simple cache to avoid re-generation within the same test session.
    """
    cache_key: tuple[int, bool] = (bits, safe)
    if cache_key in _prime_cache:
        return _prime_cache[cache_key]

    if safe and bits in fvss.SAFE_PRIMES:
        p = mpz(fvss.SAFE_PRIMES[bits])
        _prime_cache[cache_key] = p
        return p

    # Fallback: generate prime for testing
    test_logger.warning(f"Generating a {bits}-bit prime for tests (safe={safe}). This might take time if large.")
    start_time = time.monotonic()
    min_bits = max(bits, 32) # Ensure reasonable size for gmpy2

    if safe:
        # Generate safe prime (slow)
        q_bits = min_bits - 1
        while True:
            q = mpz(secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1)
            while not gmpy2.is_prime(q, 25): # Miller-Rabin test
                 q = mpz(secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1)
            p = 2 * q + 1
            if gmpy2.is_prime(p, 25):
                break
    else:
        # Generate non-safe prime (faster)
        p = mpz(secrets.randbits(min_bits) | (1 << (min_bits - 1)) | 1)
        while not gmpy2.is_prime(p, 25):
            p = mpz(secrets.randbits(min_bits) | (1 << (min_bits - 1)) | 1)

    end_time = time.monotonic()
    test_logger.info(f"Prime generation complete in {end_time - start_time:.2f}s.")
    _prime_cache[cache_key] = p
    return p

# --- Mock Classes (Based on original test suite) ---

class MockField:
    """Robust MockField matching expected interface for testing."""
    def __init__(self, prime: mpz):
        if not gmpy2.is_prime(prime):
             raise ValueError("MockField requires a prime number")
        self.prime = prime
        self.modulus = self.prime # For compatibility

    def random_element(self, zero_ok: bool = False) -> mpz:
        """Generate a random element using cryptographically secure source."""
        if self.prime <= 1: return mpz(0)
        upper_bound = self.prime if zero_ok else self.prime - 1
        if upper_bound <= 0: return mpz(0)
        val = mpz(secrets.randbelow(upper_bound))
        return val if zero_ok else val + 1

    def inverse(self, value: FieldElement) -> mpz:
        """Modular inverse needed for interpolation."""
        try:
            inv = gmpy2.invert(mpz(value), self.prime)
            if inv == 0 and mpz(value) % self.prime != 0: # Should not happen if prime is prime
                 raise ValueError(f"Inversion failed unexpectedly for non-zero {value} mod {self.prime}")
            return inv
        except ZeroDivisionError:
            raise ValueError(f"Cannot invert zero modulo {self.prime}")

    def add(self, a: FieldElement, b: FieldElement) -> mpz:
        return (mpz(a) + mpz(b)) % self.prime

    def sub(self, a: FieldElement, b: FieldElement) -> mpz:
        return (mpz(a) - mpz(b)) % self.prime

    def mul(self, a: FieldElement, b: FieldElement) -> mpz:
        return (mpz(a) * mpz(b)) % self.prime

    def div(self, a: FieldElement, b: FieldElement) -> mpz:
        return self.mul(a, self.inverse(b))

    def eval_poly(self, poly: list[FieldElement], x: FieldElement) -> mpz:
        """Evaluates polynomial (coefficient list) at x using Horner's method."""
        x_val = mpz(x)
        y = mpz(0)
        for coeff in reversed(poly):
            y = (y * x_val + mpz(coeff)) % self.prime
        return y

    def interpolate(self, shares: list[SharePoint]) -> mpz:
        """Basic Lagrange interpolation."""
        if not shares: return mpz(0)
        xs = [s[0] for s in shares]
        ys = [s[1] for s in shares]
        secret = mpz(0)
        k = len(shares)

        for i in range(k):
            xi, yi = mpz(shares[i][0]), mpz(shares[i][1])
            li = mpz(1)
            for j in range(k):
                if i == j:
                    continue
                xj = mpz(shares[j][0])
                # Calculate L_i(x) = product_{j!=i} (x - x_j) / (x_i - x_j)
                # We evaluate at x=0 to find the secret (a_0)
                num = mpz(0 - xj)  # x - xj where x=0
                den_inv = self.inverse(xi - xj)
                li = self.mul(li, self.mul(num, den_inv))

            secret = self.add(secret, self.mul(yi, li))
        return secret

    def clear_cache(self): # Add method expected by FeldmanVSS.__del__
        pass

class MockShamirSecretSharing:
    """Mock Shamir using MockField."""
    def __init__(self, field: MockField):
        self.field = field
        self.prime = field.prime

    def create_shares(self, secret: FieldElement, threshold: int, num_shares: int) -> tuple[ShareDict, list[mpz]]:
        if not (2 <= threshold <= num_shares):
            raise ValueError("Invalid threshold/num_shares configuration: 2 <= t <= n required.")
        if threshold > num_shares:
             raise ValueError(f"Threshold {threshold} cannot be greater than number of shares {num_shares}")

        coefficients = [mpz(secret)] + [self.field.random_element() for _ in range(threshold - 1)]
        shares: ShareDict = {}
        for i in range(1, num_shares + 1):
            x = mpz(i)
            y = self.field.eval_poly(coefficients, x)
            shares[i] = (x, y)
        return shares, coefficients

    def reconstruct_secret(self, shares_dict: ShareDict) -> mpz:
        """Reconstruct secret from a dictionary of shares."""
        if not shares_dict:
            raise ValueError("Cannot reconstruct secret from empty shares dictionary.")
        share_list = list(shares_dict.values())
        if len(share_list) < 2: # Need at least t shares, assume t=2 for simplest check
             raise ValueError("Not enough shares to reconstruct secret (minimum 2 required for interpolation).")
        # Use field's interpolation
        return self.field.interpolate(share_list)

class MockPedersenVSS:
    """Improved Mock PedersenVSS for integration testing."""
    def __init__(self, group: CyclicGroup):
        self.group = group
        self.prime = group.prime
        # Assuming safe prime for simplicity, order q = (p-1)/2
        if not CyclicGroup._is_safe_prime(self.prime):
             test_logger.warning("MockPedersenVSS initialized with a non-safe prime. Assuming subgroup order is (p-1).")
             self.q = self.prime - 1 # Order for non-safe prime
        else:
             self.q = (self.prime - 1) // 2 # Order for safe prime

        self.g = group.generator
        self.h = self._find_another_generator(group, self.g)
        self.randomizers: dict[int, mpz] = {} # Store {coeff_index: randomizer}
        self.blinding_randomizers: dict[int, mpz] = {} # Store {coeff_index: blinding_randomizer}

    def _find_another_generator(self, group: CyclicGroup, existing_gen: mpz) -> mpz:
        """Find a generator different from existing_gen in the same subgroup."""
        count = 0
        while count < 1000: # Limit attempts
            # Generate a random element and square it (likely in subgroup of order q for safe prime)
            base = group.secure_random_element()
            h_val = group.exp(base, 2) # Quadratic residue

            # Ensure it has order q (for safe prime) and is different from g
            if h_val != 1 and h_val != existing_gen:
                 # Check order q explicitly for safe prime case
                 is_gen = True
                 if CyclicGroup._is_safe_prime(self.prime):
                      if group.exp(h_val, self.q) != 1:
                          is_gen = False
                 # If non-safe prime, just ensure it's not 1
                 if is_gen:
                    return h_val
            count += 1
        raise RuntimeError("Could not find a second generator h for MockPedersenVSS")

    def create_commitments(self, coefficients: list[FieldElement]) -> list[mpz]:
        """C_i = g^a_i * h^r_i mod p"""
        commitments = []
        self.randomizers.clear()
        for i, coeff in enumerate(coefficients):
            r_i = secrets.randbelow(int(self.q)) # Randomizer in exponent group Z_q
            self.randomizers[i] = mpz(r_i)
            c_g = self.group.secure_exp(self.g, coeff)
            c_h = self.group.secure_exp(self.h, r_i)
            commitments.append(self.group.mul(c_g, c_h))
        return commitments

    def commit_to_blinding_factors(self, blindings: list[FieldElement]) -> list[mpz]:
        """Commitments to blinding factors b_i: g^b_i * h^s_i"""
        commitments = []
        self.blinding_randomizers.clear()
        for i, b in enumerate(blindings):
            s_i = secrets.randbelow(int(self.q)) # Randomizer in exponent group Z_q
            self.blinding_randomizers[i] = mpz(s_i)
            c_g = self.group.secure_exp(self.g, b)
            c_h = self.group.secure_exp(self.h, s_i)
            commitments.append(self.group.mul(c_g, c_h))
        return commitments

    def serialize_commitments(self, commitments: list[mpz]) -> str:
        """Simplified serialization for mock."""
        data = {
            "g": str(self.g),
            "h": str(self.h),
            "prime": str(self.prime),
            "commitments": [str(c) for c in commitments]
        }
        packed = msgpack.packb(data)
        return urlsafe_b64encode(packed).decode('utf-8')

    def deserialize_commitments(self, serialized_data: str) -> list[mpz]:
        """Simplified deserialization."""
        try:
            decoded = urlsafe_b64decode(serialized_data.encode('utf-8'))
            data = msgpack.unpackb(decoded, raw=False)
            # Basic validation
            if not all(k in data for k in ["g", "h", "prime", "commitments"]):
                raise ValueError("Invalid Pedersen serialized data structure")
            # Here we would normally validate g, h, prime match the instance
            # For mock, just return the commitments
            return [mpz(c) for c in data["commitments"]]
        except Exception as e:
            raise fvss.SerializationError(f"Mock Failed to deserialize Pedersen data: {e}")

    def verify_response_equation(self, response: FieldElement, challenge: FieldElement, blinding_commitment: FieldElement, commitment: FieldElement, index: int) -> bool:
        """Verify Pedersen ZKP equation for one coefficient.
           Checks: g^response * h^response_randomizer == blinding_commitment * commitment^challenge
           Requires response_randomizer = s_i + challenge * r_i
        """
        # Check if randomizers are available for this index
        if index not in self.blinding_randomizers or index not in self.randomizers:
             test_logger.warning(f"MockPedersenVSS missing randomizers for index {index}. Cannot perform strict ZKP check.")
             # In a real scenario, this might indicate an issue or require state retrieval.
             # For this mock, we might return True to allow integration tests to pass structure checks,
             # or False for stricter behavior depending on the test's goal. Let's return False for stricter mock.
             return False # Indicate verification cannot be completed without state

        s_i = self.blinding_randomizers[index]
        r_i = self.randomizers[index]
        response_randomizer = (s_i + mpz(challenge) * r_i) % self.q

        # Left side: g^response * h^response_randomizer
        lhs_g = self.group.secure_exp(self.g, response)
        lhs_h = self.group.secure_exp(self.h, response_randomizer)
        lhs = self.group.mul(lhs_g, lhs_h)

        # Right side: blinding_commitment * commitment^challenge
        rhs_c_pow = self.group.secure_exp(commitment, challenge)
        rhs = self.group.mul(blinding_commitment, rhs_c_pow)

        # Use constant time compare for security practice
        return fvss.constant_time_compare(lhs, rhs)

# --- Helper to generate test data ---

def generate_poly_and_shares(field: MockField, secret: FieldElement, threshold: int, num_shares: int) -> tuple[list[mpz], ShareDict]:
    """Helper to generate polynomial coefficients and shares using MockField."""
    if not (2 <= threshold <= num_shares):
        raise ValueError("Invalid threshold/num_shares configuration: 2 <= t <= n required.")
    coefficients = [mpz(secret)] + [field.random_element() for _ in range(threshold - 1)]
    shares: ShareDict = {}
    for i in range(1, num_shares + 1):
        x = mpz(i)
        y = field.eval_poly(coefficients, x)
        shares[i] = (x, y)
    return coefficients, shares


# --- Pytest Fixtures ---

# Session-scoped fixtures for potentially slow prime generation
@pytest.fixture(scope="session")
def test_prime_fast() -> mpz:
    """Provides a smaller prime for faster tests."""
    return get_prime(TEST_PRIME_BITS_FAST, safe=False)

@pytest.fixture(scope="session")
def test_prime_pq() -> mpz:
    """Provides a large, PQ-secure safe prime."""
    return get_prime(DEFAULT_PRIME_BITS, safe=True)

# Fixtures for MockField instances
@pytest.fixture
def mock_field_fast(test_prime_fast: mpz) -> MockField:
    """Provides a MockField instance with a smaller prime."""
    return MockField(test_prime_fast)

@pytest.fixture
def mock_field_pq(test_prime_pq: mpz) -> MockField:
    """Provides a MockField instance with a PQ-secure prime."""
    return MockField(test_prime_pq)

# Fixtures for VSSConfig
@pytest.fixture
def default_vss_config(test_prime_fast: mpz) -> VSSConfig:
    """Provides a default VSSConfig for faster tests."""
    # Use sanitize_errors=False for easier debugging in tests
    return VSSConfig(
        prime_bits=TEST_PRIME_BITS_FAST,
        safe_prime=False,
        sanitize_errors=False,
        use_blake3=HAS_BLAKE3 # Use BLAKE3 if available
    )

@pytest.fixture
def pq_vss_config(test_prime_pq: mpz) -> VSSConfig:
    """Provides a VSSConfig for PQ-secure parameters."""
    return VSSConfig(
        prime_bits=DEFAULT_PRIME_BITS,
        safe_prime=True,
        sanitize_errors=False,
        use_blake3=HAS_BLAKE3
    )

# Fixtures for FeldmanVSS instances
@pytest.fixture
def default_vss(mock_field_fast: MockField, default_vss_config: VSSConfig) -> FeldmanVSS:
    """Provides a standard FeldmanVSS instance for most tests (uses smaller prime)."""
    return FeldmanVSS(mock_field_fast, default_vss_config)

@pytest.fixture
def pq_vss(mock_field_pq: MockField, pq_vss_config: VSSConfig) -> FeldmanVSS:
    """Provides a FeldmanVSS instance configured with PQ-secure parameters."""
    return FeldmanVSS(mock_field_pq, pq_vss_config)

# Fixtures for Mocks needed in integration tests
@pytest.fixture
def mock_shamir(mock_field_fast: MockField) -> MockShamirSecretSharing:
    """Provides a MockShamirSecretSharing instance."""
    return MockShamirSecretSharing(mock_field_fast)

@pytest.fixture
def mock_pedersen(default_vss: FeldmanVSS) -> MockPedersenVSS:
    """Provides a MockPedersenVSS instance linked to the default_vss group."""
    # Need a real CyclicGroup for Pedersen mock, get it from default_vss
    return MockPedersenVSS(default_vss.group)

# Fixtures for basic test data (secret, coefficients, shares)
@pytest.fixture
def test_secret(mock_field_fast: MockField) -> mpz:
    """Provides a random secret for testing."""
    return mock_field_fast.random_element()

@pytest.fixture
def test_coeffs_shares(mock_field_fast: MockField, test_secret: mpz) -> tuple[list[mpz], ShareDict]:
    """Generates coefficients and shares for the test secret."""
    return generate_poly_and_shares(
        mock_field_fast, test_secret, DEFAULT_THRESHOLD, DEFAULT_NUM_SHARES
    )

@pytest.fixture
def test_coeffs(test_coeffs_shares: tuple[list[mpz], ShareDict]) -> list[mpz]:
    """Provides the generated coefficients."""
    return test_coeffs_shares[0]

@pytest.fixture
def test_shares(test_coeffs_shares: tuple[list[mpz], ShareDict]) -> ShareDict:
    """Provides the generated shares."""
    return test_coeffs_shares[1]

@pytest.fixture
def test_commitments(default_vss: FeldmanVSS, test_coeffs: list[mpz]) -> CommitmentList:
    """Provides commitments generated for the test coefficients."""
    return default_vss.create_commitments(test_coeffs)

# Fixture for large-scale test data (used by performance tests)
# Session-scoped because setup can be slow.
@pytest.fixture(scope="session")
def large_test_data(test_prime_pq: mpz) -> Optional[dict[str, Any]]:
    """
    Provides large-scale coefficients, shares, and commitments for performance tests.
    Only runs setup if RUN_PERFORMANCE_TESTS is True.
    """
    if not RUN_PERFORMANCE_TESTS:
        return None # Skip setup if performance tests are disabled

    # Ensure N/T are valid
    local_large_n = max(5, LARGE_N)
    local_large_t = max(2, min(LARGE_T, local_large_n))
    if local_large_t > local_large_n:
        pytest.skip(f"Cannot run large tests: T ({local_large_t}) > N ({local_large_n})")

    test_logger.info(f"\nSetting up Large Scale Test Data (n={local_large_n}, t={local_large_t})...")
    start_setup = time.perf_counter()

    field = MockField(test_prime_pq)
    config = VSSConfig(prime_bits=DEFAULT_PRIME_BITS, safe_prime=True, sanitize_errors=False, use_blake3=HAS_BLAKE3)
    vss = FeldmanVSS(field, config)

    secret = field.random_element()
    try:
        coeffs, shares = generate_poly_and_shares(field, secret, local_large_t, local_large_n)
        commitments = vss.create_commitments(coeffs)
    except (ValueError, MemoryError) as e:
         pytest.skip(f"Skipping large tests due to resource constraints during setup: {e}")

    share_list = list(shares.values())
    end_setup = time.perf_counter()
    test_logger.info(f"Large scale setup complete ({end_setup - start_setup:.2f}s).")

    return {
        "field": field,
        "vss": vss,
        "n": local_large_n,
        "t": local_large_t,
        "secret": secret,
        "coeffs": coeffs,
        "shares": shares,
        "commitments": commitments,
        "share_list": share_list
    }

# --- Pytest Hooks ---

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "performance: mark test as a performance benchmark (skipped by default)"
    )
    config.addinivalue_line(
        "markers", "security: mark test as specifically security-related"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "properties: mark test as a property-based test (requires Hypothesis)"
    )

    # Ensure security warnings are always shown during tests
    warnings.simplefilter("always", fvss.SecurityWarning)
    # Show default RuntimeWarnings as well
    warnings.simplefilter("default", RuntimeWarning)


def pytest_collection_modifyitems(config, items):
    """Modify test items, e.g., skip performance tests by default."""
    if not RUN_PERFORMANCE_TESTS:
        skip_performance = pytest.mark.skip(reason="Performance tests not requested (set RUN_PERFORMANCE_TESTS=1)")
        for item in items:
            if "performance" in item.keywords:
                item.add_marker(skip_performance)

    # Skip property tests if Hypothesis is not available
    if not pytest.importorskip("hypothesis", reason="Hypothesis not found, skipping property-based tests"):
        skip_hypothesis = pytest.mark.skip(reason="Hypothesis not found, skipping property-based tests")
        for item in items:
            if "properties" in item.keywords:
                item.add_marker(skip_hypothesis)

# Optional: Add fixture for memory tracing if psutil is available
@pytest.fixture(autouse=True) # Apply automatically to relevant tests
def trace_memory(request):
    """Fixture to trace memory usage during performance tests."""
    marker = request.node.get_closest_marker("performance")
    if marker and HAS_PSUTIL and RUN_PERFORMANCE_TESTS:
        tracemalloc = pytest.importorskip("tracemalloc")
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss
        tracemalloc.start()
        yield # Run the test
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        mem_after = process.memory_info().rss
        test_logger.debug(
            f" Test Memory ({request.node.name}): Peak Alloc={peak/(1024*1024):.2f}MB, "
            f"Process RSS diff={(mem_after-mem_before)/(1024*1024):.2f}MB"
        )
    else:
        yield # Just run the test without tracing
