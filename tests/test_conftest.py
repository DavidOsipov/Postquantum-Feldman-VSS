# tests/test_conftest.py
# Shared fixtures, helper functions, and configuration for the Postquantum Feldman VSS test suite
# This file is part of the Postquantum Feldman VSS library.
import logging
import os
import secrets
import sys
import time
import warnings
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Generator, Sequence
from typing import Any, Optional, Union

import pytest  # This import is correct for pytest fixtures
from gmpy2 import mpfr, mpz

from feldman_vss import CyclicGroup

# --- Dependency Handling & Checks ---
try:
    import gmpy2
    from gmpy2 import mpz
except ImportError:
    print("CRITICAL ERROR: gmpy2 library not found. FeldmanVSS requires gmpy2. Aborting tests.")
    sys.exit(1)  # gmpy2 is mandatory

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
    sys.exit(1)  # msgpack is mandatory for serialization

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
        FieldElement,  # FieldElement is Union[int, mpz]
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
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
test_logger = logging.getLogger("feldman_vss_pytest")

# Use smaller primes for faster testing where appropriate, but default to PQ-secure
DEFAULT_PRIME_BITS = fvss.MIN_PRIME_BITS  # 4096 for PQ security
TEST_PRIME_BITS_FAST = 512  # For faster unit/property tests
DEFAULT_THRESHOLD = 3
DEFAULT_NUM_SHARES = 5
LARGE_N = int(os.environ.get("VSS_LARGE_N", "100"))  # Smaller default for faster CI (Use string default)
LARGE_T = int(os.environ.get("VSS_LARGE_T", "30"))  # Smaller default for faster CI (Use string default)

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
    if (cache_key) in _prime_cache:
        return _prime_cache[cache_key]

    if safe and bits in fvss.SAFE_PRIMES:
        p = mpz(fvss.SAFE_PRIMES[bits])
        _prime_cache[cache_key] = p
        return p

    # Fallback: generate prime for testing
    test_logger.warning("Generating a %d-bit prime for tests (safe=%s). This might take time if large.", bits, safe)
    start_time: float = time.monotonic()
    min_bits: int = max(bits, 32)  # Ensure reasonable size for gmpy2

    if safe:
        # Generate safe prime (slow)
        q_bits: int = min_bits - 1
        while True:
            q = mpz(secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1)
            # Force bool conversion and explicitly convert result to handle mpfr return type
            while not bool(gmpy2.is_prime(q, 25)):
                q = mpz(secrets.randbits(q_bits) | (1 << (q_bits - 1)) | 1)
            p = mpz(2 * q + 1)  # Ensure result is mpz
            # Force bool conversion to handle mpfr return type
            if bool(gmpy2.is_prime(p, 25)):
                break
    else:
        # Generate non-safe prime (faster)
        p = mpz(secrets.randbits(min_bits) | (1 << (min_bits - 1)) | 1)
        # Force bool conversion to handle mpfr return type
        while not bool(gmpy2.is_prime(p, 25)):
            p = mpz(secrets.randbits(min_bits) | (1 << (min_bits - 1)) | 1)

    end_time = time.monotonic()
    test_logger.info("Prime generation complete in %.2fs.", end_time - start_time)
    _prime_cache[cache_key] = p
    return p


# --- Mock Classes (Based on original test suite) ---


class MockField:
    """Robust MockField matching expected interface for testing."""

    # Ignore Pylance error about constructor return type
    def __init__(self, prime: Union[int, mpz]):  # type: ignore[reportReturnType]
        # Explicitly cast input prime to mpz and check primality
        prime_mpz = mpz(prime)
        # Pass mpz to is_prime
        if not gmpy2.is_prime(prime_mpz):  # type: ignore[reportArgumentType] # Pylance struggles with mpz vs mpfr possibility
            raise ValueError("MockField requires a prime number")
        # Ignore Pylance error about assignment type
        self.prime: mpz = prime_mpz  # type: ignore[reportAssignmentType]
        self.modulus: mpz = self.prime  # For compatibility

    def random_element(self, zero_ok: bool = False) -> mpz:
        """Generate a random element using cryptographically secure source."""
        if self.prime <= 1:
            return mpz(0)
        # Use int() for randbelow bound, which is safe for mpz
        upper_bound: int = int(self.prime) if zero_ok else int(self.prime - 1)
        if upper_bound <= 0:
            return mpz(0)
        # Generate a random value and ensure it's mpz
        val = mpz(secrets.randbelow(upper_bound))
        # Explicitly cast to mpz before returning to ensure correct type
        return mpz(val if zero_ok else val + 1)

    def inverse(self, value: FieldElement) -> mpz:
        """Modular inverse needed for interpolation."""
        val_mpz = mpz(value)
        try:
            # gmpy2.invert returns mpz or raises error
            inv = gmpy2.invert(val_mpz, self.prime)
            # Check if inversion resulted in 0 for a non-zero input modulo prime
            # Use f_mod which takes mpz
            # Ignore Pylance error about f_mod argument type
            if inv == 0 and gmpy2.f_mod(val_mpz, self.prime) != 0:  # type: ignore[reportArgumentType]
                raise ValueError(f"Inversion failed unexpectedly for non-zero {val_mpz} mod {self.prime}")
        except ZeroDivisionError:
            raise ValueError(f"Cannot invert zero modulo {self.prime}")
        else:
            # Return type is mpz
            return mpz(inv)  # Explicitly cast to mpz to ensure correct return type

    def add(self, a: FieldElement, b: FieldElement) -> mpz:
        # f_mod takes int/mpz, returns mpz
        # Ignore Pylance error about f_mod argument type
        return gmpy2.f_mod(mpz(a) + mpz(b), self.prime)  # type: ignore[reportArgumentType]

    def sub(self, a: FieldElement, b: FieldElement) -> mpz:
        # f_mod takes int/mpz, returns mpz
        # Ignore Pylance error about f_mod argument type
        return gmpy2.f_mod(mpz(a) - mpz(b), self.prime)  # type: ignore[reportArgumentType]

    def mul(self, a: FieldElement, b: FieldElement) -> mpz:
        # f_mod takes int/mpz, returns mpz
        # Ignore Pylance error about f_mod argument type
        return gmpy2.f_mod(mpz(a) * mpz(b), self.prime)  # type: ignore[reportArgumentType]

    def div(self, a: FieldElement, b: FieldElement) -> mpz:
        # mul returns mpz
        return self.mul(a, self.inverse(b))

    # Use Sequence for poly type hint
    def eval_poly(self, poly: Sequence[FieldElement], x: FieldElement) -> mpz:
        """Evaluates polynomial (coefficient list) at x using Horner's method."""
        x_val = mpz(x)
        y = mpz(0)
        for coeff in reversed(poly):
            # Ensure coeff is mpz before arithmetic, use f_mod
            # Convert result back to mpz to ensure correct type
            # This fixes the issue where f_mod could return mpfr in some cases
            result: mpz = gmpy2.f_mod(mpz(y * x_val + mpz(coeff)), self.prime)
            y = mpz(result)  # Explicitly cast back to mpz
        return y

    def interpolate(self, shares: list[SharePoint]) -> mpz:
        """Basic Lagrange interpolation."""
        if not shares:
            return mpz(0)
        # Ensure coordinates are mpz
        xs: list[mpz] = [mpz(s[0]) for s in shares]
        ys: list[mpz] = [mpz(s[1]) for s in shares]
        secret = mpz(0)
        k = len(shares)

        for i in range(k):
            xi, yi = xs[i], ys[i]
            li = mpz(1)
            for j in range(k):
                if i == j:
                    continue
                xj: mpz = xs[j]
                # Calculate L_i(x) = product_{j!=i} (x - x_j) / (x_i - x_j)
                # We evaluate at x=0 to find the secret (a_0)
                num = mpz(0 - xj)  # x - xj where x=0
                # Ignore Pylance error about inverse argument type
                den_inv: mpz = self.inverse(mpz(xi - xj))  # type: ignore[reportArgumentType] # Pass mpz
                li: mpz = self.mul(li, self.mul(num, den_inv))  # mul returns mpz

            secret: mpz = self.add(secret, self.mul(yi, li))  # add/mul return mpz
        # Return type is mpz
        return secret

    def clear_cache(self) -> None:  # Add method expected by FeldmanVSS.__del__
        pass


class MockShamirSecretSharing:
    """Mock Shamir using MockField."""

    def __init__(self, field: MockField) -> None:
        self.field: MockField = field
        self.prime: mpz = field.prime  # Already mpz from MockField

    # Use Sequence for coefficients return type hint (though list[mpz] is returned)
    def create_shares(self, secret: FieldElement, threshold: int, num_shares: int) -> tuple[ShareDict, Sequence[mpz]]:
        if not (2 <= threshold <= num_shares):
            raise ValueError("Invalid threshold/num_shares configuration: 2 <= t <= n required.")
        if threshold > num_shares:
            raise ValueError(f"Threshold {threshold} cannot be greater than number of shares {num_shares}")

        # Ensure coefficients are mpz
        coefficients: list[mpz] = [mpz(secret)] + [self.field.random_element() for _ in range(threshold - 1)]  # random_element returns mpz
        shares: ShareDict = {}
        for i in range(1, num_shares + 1):
            x = mpz(i)
            # Pass Sequence[mpz] to eval_poly
            y: mpz = self.field.eval_poly(coefficients, x)  # eval_poly returns mpz
            shares[i] = (x, y)
        return shares, coefficients

    def reconstruct_secret(self, shares_dict: ShareDict) -> mpz:
        """Reconstruct secret from a dictionary of shares."""
        if not shares_dict:
            raise ValueError("Cannot reconstruct secret from empty shares dictionary.")
        share_list = list(shares_dict.values())
        if len(share_list) < 2:  # Need at least t shares, assume t=2 for simplest check
            raise ValueError("Not enough shares to reconstruct secret (minimum 2 required for interpolation).")
        # Use field's interpolation
        return self.field.interpolate(shares=share_list)  # interpolate returns mpz


class MockPedersenVSS:
    """Improved Mock PedersenVSS for integration testing."""

    def __init__(self, group: CyclicGroup) -> None:
        self.group: CyclicGroup = group
        self.prime: mpz = group.prime  # Already mpz from CyclicGroup
        # Derive q correctly from the group's prime
        # Use f_div for floor division if needed, though // works for mpz/int
        if CyclicGroup._is_safe_prime(self.prime):
            # Ignore Pylance error about // operator type
            self.q = mpz((self.prime - 1) // 2)  # type: ignore[reportOperatorIssue] # Ensure mpz
        else:
            test_logger.warning("MockPedersenVSS initialized with a non-safe prime. Assuming subgroup order is p-1.")
            self.q: mpz | mpfr = self.prime - 1  # mpz - int -> mpz

        self.g = group.generator  # Already mpz
        self.h = mpz(self._find_another_generator(group, existing_gen=self.g))  # Ensure h is mpz
        self.randomizers: dict[int, mpz] = {}  # Store {coeff_index: randomizer}
        self.blinding_randomizers: dict[int, mpz] = {}  # Store {coeff_index: blinding_randomizer}

    def _find_another_generator(self, group: CyclicGroup, existing_gen: mpz) -> mpz:
        """Find a generator different from existing_gen in the same subgroup."""
        count = 0
        while count < 1000:  # Limit attempts
            # Generate a random element and square it (likely in subgroup of order q for safe prime)
            base: mpz = group.secure_random_element()  # Returns mpz
            # Pass mpz to exp
            h_val: mpz = group.exp(base, exponent=2)  # Quadratic residue, returns mpz

            # Ensure it has order q (for safe prime) and is different from g
            # Use `not in` for cleaner check
            if h_val not in (mpz(1), existing_gen) and (
                not CyclicGroup._is_safe_prime(self.prime) or group.exp(h_val, exponent=mpz(self.q)) == mpz(1)
            ):
                return h_val  # Return mpz
            count += 1
        raise RuntimeError("Could not find a second generator h for MockPedersenVSS")

    # Use Sequence for coefficients type hint
    def create_commitments(self, coefficients: Sequence[FieldElement]) -> list[mpz]:
        """C_i = g^a_i * h^r_i mod p"""
        commitments = []
        self.randomizers.clear()
        for i, coeff in enumerate(coefficients):
            coeff_mpz = mpz(coeff)  # Ensure mpz
            # Use int(self.q) for randbelow bound
            r_i = mpz(secrets.randbelow(exclusive_upper_bound=int(self.q)))  # Ensure mpz
            self.randomizers[i] = r_i
            # Pass mpz to secure_exp
            c_g: mpz = self.group.secure_exp(self.g, exponent=coeff_mpz)
            c_h: mpz = self.group.secure_exp(self.h, exponent=r_i)
            commitments.append(self.group.mul(c_g, c_h))  # mul returns mpz
        return commitments

    # Use Sequence for blindings type hint
    def commit_to_blinding_factors(self, blindings: Sequence[FieldElement]) -> list[mpz]:
        """Commitments to blinding factors b_i: g^b_i * h^s_i"""
        commitments = []
        self.blinding_randomizers.clear()
        for i, b in enumerate(iterable=blindings):
            b_mpz = mpz(b)  # Ensure mpz
            # Use int(self.q) for randbelow bound
            s_i = mpz(secrets.randbelow(exclusive_upper_bound=int(self.q)))  # Ensure mpz
            self.blinding_randomizers[i] = s_i
            # Pass mpz to secure_exp
            c_g: mpz = self.group.secure_exp(self.g, exponent=b_mpz)
            c_h: mpz = self.group.secure_exp(self.h, exponent=s_i)
            commitments.append(self.group.mul(c_g, c_h))  # mul returns mpz
        return commitments

    def serialize_commitments(self, commitments: list[mpz]) -> str:
        """Simplified serialization for mock."""
        data = {"g": str(self.g), "h": str(self.h), "prime": str(self.prime), "commitments": [str(c) for c in commitments]}
        # Add assertion for type check to help Pylance
        packed_val = msgpack.packb(data)
        assert isinstance(packed_val, bytes)
        packed: bytes = packed_val
        return urlsafe_b64encode(packed).decode(encoding="utf-8")

    def deserialize_commitments(self, serialized_data: str) -> list[mpz]:
        """Simplified deserialization."""
        try:
            decoded: bytes = urlsafe_b64decode(serialized_data.encode(encoding="utf-8"))
            data = msgpack.unpackb(decoded, raw=False)
            # Basic validation
            if not all(k in data for k in ["g", "h", "prime", "commitments"]):
                raise ValueError("Invalid Pedersen serialized data structure")
            # Here we would normally validate g, h, prime match the instance
            # For mock, just return the commitments
            return [mpz(c) for c in data["commitments"]]
        except Exception as e:
            raise fvss.SerializationError(message="Mock Failed to deserialize Pedersen data: {e}")

    def verify_response_equation(
        self, response: FieldElement, challenge: FieldElement, blinding_commitment: FieldElement, commitment: FieldElement, index: int
    ) -> bool:
        """Verify Pedersen ZKP equation for one coefficient.
        Checks: g^response * h^response_randomizer == blinding_commitment * commitment^challenge
        Requires response_randomizer = s_i + challenge * r_i
        """
        # Cast inputs to mpz immediately
        response_mpz = mpz(response)
        challenge_mpz = mpz(challenge)
        blinding_commitment_mpz = mpz(blinding_commitment)
        commitment_mpz = mpz(commitment)

        # Check if randomizers are available for this index
        if index not in self.blinding_randomizers or index not in self.randomizers:
            test_logger.warning("MockPedersenVSS missing randomizers for index %d. Cannot perform strict ZKP check.", index)
            return False  # Indicate verification cannot be completed without state

        s_i = self.blinding_randomizers[index]  # Already mpz
        r_i = self.randomizers[index]  # Already mpz
        # Calculate response_randomizer and ensure it's mpz - ensure all inputs to f_mod are int or mpz
        temp_result = mpz(s_i + challenge_mpz * r_i)
        # Explicitly cast temp_result and self.q to int to avoid mpfr issues with f_mod
        response_randomizer = mpz(gmpy2.f_mod(int(temp_result), int(self.q)))

        # Left side: g^response * h^response_randomizer
        lhs_g: mpz = self.group.secure_exp(base=self.g, exponent=response_mpz)  # Takes mpz
        lhs_h: mpz = self.group.secure_exp(base=self.h, exponent=response_randomizer)  # Takes mpz
        lhs: mpz = self.group.mul(lhs_g, lhs_h)  # Takes mpz

        # Right side: blinding_commitment * commitment^challenge
        rhs_c_pow: mpz = self.group.secure_exp(base=commitment_mpz, exponent=challenge_mpz)  # Takes mpz
        rhs: mpz = self.group.mul(blinding_commitment_mpz, rhs_c_pow)  # Takes mpz

        # Cast mpz values to int for constant_time_compare
        return bool(fvss.constant_time_compare(int(lhs), int(rhs)))  # Ensure boolean return


# --- Helper to generate test data ---


# Use Sequence for return type hint
def generate_poly_and_shares(field: MockField, secret: FieldElement, threshold: int, num_shares: int) -> tuple[Sequence[mpz], ShareDict]:
    """Helper to generate polynomial coefficients and shares using MockField."""
    if not (2 <= threshold <= num_shares):
        raise ValueError("Invalid threshold/num_shares configuration: 2 <= t <= n required.")
    # Ensure coefficients are mpz
    coefficients: list[mpz] = [mpz(secret)] + [field.random_element() for _ in range(threshold - 1)]  # random_element returns mpz
    shares: ShareDict = {}
    for i in range(1, num_shares + 1):
        x = mpz(i)
        # Pass Sequence[mpz] to eval_poly
        y: mpz = field.eval_poly(coefficients, x)  # eval_poly returns mpz
        shares[i] = (x, y)
    return coefficients, shares


# --- Pytest Fixtures ---


# Session-scoped fixtures for potentially slow prime generation
@pytest.fixture(scope="session")
def test_prime_fast() -> mpz:
    """Provides a smaller prime for faster tests."""
    return get_prime(bits=TEST_PRIME_BITS_FAST, safe=False)


@pytest.fixture(scope="session")
def test_prime_pq() -> mpz:
    """Provides a large, PQ-secure safe prime."""
    return get_prime(DEFAULT_PRIME_BITS, safe=True)


# Fixtures for MockField instances
@pytest.fixture
def mock_field_fast(test_prime_fast: mpz) -> MockField:
    """Provides a MockField instance with a smaller prime."""
    return MockField(prime=test_prime_fast)


@pytest.fixture
def mock_field_pq(test_prime_pq: mpz) -> MockField:
    """Provides a MockField instance with a PQ-secure prime."""
    return MockField(prime=test_prime_pq)


# Fixtures for VSSConfig
@pytest.fixture
def default_vss_config() -> VSSConfig:
    """Provides a default VSSConfig for faster tests."""
    # Use sanitize_errors=False for easier debugging in tests
    return VSSConfig(
        prime_bits=TEST_PRIME_BITS_FAST,
        safe_prime=False,
        sanitize_errors=False,
        use_blake3=HAS_BLAKE3,  # Use BLAKE3 if available
    )


@pytest.fixture
def pq_vss_config() -> VSSConfig:
    """Provides a VSSConfig for PQ-secure parameters."""
    return VSSConfig(prime_bits=DEFAULT_PRIME_BITS, safe_prime=True, sanitize_errors=False, use_blake3=HAS_BLAKE3)


# Fixtures for FeldmanVSS instances
@pytest.fixture
def default_vss(mock_field_fast: MockField, default_vss_config: VSSConfig) -> FeldmanVSS:
    """Provides a standard FeldmanVSS instance for most tests (uses smaller prime)."""
    return FeldmanVSS(field=mock_field_fast, config=default_vss_config)


@pytest.fixture
def pq_vss(mock_field_pq: MockField, pq_vss_config: VSSConfig) -> FeldmanVSS:
    """Provides a FeldmanVSS instance configured with PQ-secure parameters."""
    return FeldmanVSS(field=mock_field_pq, config=pq_vss_config)


# Fixtures for Mocks needed in integration tests
@pytest.fixture
def mock_shamir(mock_field_fast: MockField) -> MockShamirSecretSharing:
    """Provides a MockShamirSecretSharing instance."""
    return MockShamirSecretSharing(field=mock_field_fast)


@pytest.fixture
def mock_pedersen(default_vss: FeldmanVSS) -> MockPedersenVSS:
    """Provides a MockPedersenVSS instance linked to the default_vss group."""
    # Need a real CyclicGroup for Pedersen mock, get it from default_vss
    return MockPedersenVSS(group=default_vss.group)


# Fixtures for basic test data (secret, coefficients, shares)
@pytest.fixture
def test_secret(mock_field_fast: MockField) -> mpz:
    """Provides a random secret for testing."""
    return mock_field_fast.random_element()  # Returns mpz


# Use Sequence for coefficient list type hint
@pytest.fixture
def test_coeffs_shares(mock_field_fast: MockField, test_secret: mpz) -> tuple[Sequence[mpz], ShareDict]:
    """Generates coefficients and shares for the test secret."""
    # generate_poly_and_shares returns Sequence[mpz]
    return generate_poly_and_shares(mock_field_fast, test_secret, DEFAULT_THRESHOLD, DEFAULT_NUM_SHARES)


# Use Sequence for coefficient list type hint
@pytest.fixture
def test_coeffs(test_coeffs_shares: tuple[Sequence[mpz], ShareDict]) -> Sequence[mpz]:
    """Provides the generated coefficients."""
    return test_coeffs_shares[0]


@pytest.fixture
def test_shares(test_coeffs_shares: tuple[Sequence[mpz], ShareDict]) -> ShareDict:
    """Provides the generated shares."""
    return test_coeffs_shares[1]


# Use Sequence for coefficient list type hint
@pytest.fixture
def test_commitments(default_vss: FeldmanVSS, test_coeffs: Sequence[mpz]) -> CommitmentList:
    """Provides commitments generated for the test coefficients."""
    # create_commitments accepts Sequence[FieldElement], Sequence[mpz] is compatible
    # Explicitly convert Sequence[mpz] to List[FieldElement] to satisfy Pylance
    return default_vss.create_commitments(coefficients=list(test_coeffs))  # type: ignore[reportArgumentType]


# Fixture for large-scale test data (used by performance tests)
# Session-scoped because setup can be slow.
@pytest.fixture(scope="session")
def large_test_data(test_prime_pq: mpz) -> Optional[dict[str, Any]]:
    """
    Provides large-scale coefficients, shares, and commitments for performance tests.
    Only runs setup if RUN_PERFORMANCE_TESTS is True.
    """
    if not RUN_PERFORMANCE_TESTS:
        return None  # Skip setup if performance tests are disabled

    # Ensure N/T are valid
    local_large_n: int = max(5, LARGE_N)
    local_large_t: int = max(2, min(LARGE_T, local_large_n))
    if local_large_t > local_large_n:
        pytest.skip(reason=f"Cannot run large tests: T ({local_large_t}) > N ({local_large_n})")

    test_logger.info("\nSetting up Large Scale Test Data (n=%d, t=%d)...", local_large_n, local_large_t)
    start_setup: float = time.perf_counter()

    field = MockField(prime=test_prime_pq)
    config = VSSConfig(prime_bits=DEFAULT_PRIME_BITS, safe_prime=True, sanitize_errors=False, use_blake3=HAS_BLAKE3)
    vss = FeldmanVSS(field=field, config=config)

    secret = field.random_element()  # Returns mpz
    coeffs: Optional[Sequence[mpz]] = None  # Use Sequence
    shares: Optional[ShareDict] = None
    commitments: Optional[CommitmentList] = None
    try:
        coeffs, shares = generate_poly_and_shares(
            field=field, secret=secret, threshold=local_large_t, num_shares=local_large_n
        )  # Returns Sequence[mpz]
        # create_commitments accepts Sequence[FieldElement], Sequence[mpz] is compatible
        # Explicitly convert Sequence[mpz] to List[FieldElement] to satisfy Pylance
        commitments = vss.create_commitments(coefficients=list(coeffs))  # type: ignore[reportArgumentType]
    except (ValueError, MemoryError) as e:
        pytest.skip(reason=f"Skipping large tests due to resource constraints during setup: {e}")
    # Add check after try-except to ensure variables are assigned if no skip occurred
    if coeffs is None or shares is None or commitments is None:
        pytest.fail(reason="Failed to generate large test data unexpectedly.")

    share_list = list(shares.values())
    end_setup: float = time.perf_counter()
    test_logger.info("Large scale setup complete (%.2fs).", end_setup - start_setup)

    return {
        "field": field,
        "vss": vss,
        "n": local_large_n,
        "t": local_large_t,
        "secret": secret,
        "coeffs": coeffs,
        "shares": shares,
        "commitments": commitments,
        "share_list": share_list,
    }


# --- Pytest Hooks ---


def pytest_configure(config) -> None:
    """Register custom markers."""
    # Use the config parameter to register markers
    config.addinivalue_line("markers", "performance: mark test as a performance benchmark (skipped by default)")
    config.addinivalue_line("markers", "security: mark test as specifically security-related")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "properties: mark test as a property-based test (requires Hypothesis)")

    # Ensure security warnings are always shown during tests
    warnings.simplefilter(action="always", category=fvss.SecurityWarning)
    # Show default RuntimeWarnings as well
    warnings.simplefilter(action="default", category=RuntimeWarning)


def pytest_collection_modifyitems(config, items) -> None:  # noqa: ARG001
    """Modify test items, e.g., skip performance tests by default."""
    if not RUN_PERFORMANCE_TESTS:
        skip_performance: pytest.MarkDecorator = pytest.mark.skip(reason="Performance tests not requested (set RUN_PERFORMANCE_TESTS=1)")
        for item in items:
            if "performance" in item.keywords:
                item.add_marker(skip_performance)

    # Safely check for hypothesis
    hypothesis_found = False
    try:
        # Use importlib to test if hypothesis is available, avoiding undefined names
        import importlib.util

        if importlib.util.find_spec("hypothesis") is not None:
            hypothesis_found = True
    except ImportError:
        pass

    # Skip property tests if Hypothesis is not available
    if not hypothesis_found:
        skip_hypothesis: pytest.MarkDecorator = pytest.mark.skip(reason="Hypothesis not found, skipping property-based tests")
        for item in items:
            if "properties" in item.keywords:
                item.add_marker(skip_hypothesis)


# Optional: Add fixture for memory tracing if psutil is available
@pytest.fixture(autouse=True)  # Apply automatically to relevant tests
def trace_memory(request: pytest.FixtureRequest) -> Generator[None, Any, None]:
    """Fixture to trace memory usage during performance tests."""
    marker = request.node.get_closest_marker("performance")
    # Correctly guard psutil usage
    if marker and RUN_PERFORMANCE_TESTS:
        if HAS_PSUTIL:
            import psutil  # Import inside the conditional to avoid unbound variable

            tracemalloc = pytest.importorskip(modname="tracemalloc")
            process = psutil.Process(pid=os.getpid())
            mem_before = process.memory_info().rss
            tracemalloc.start()
            yield  # Run the test
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            mem_after = process.memory_info().rss
            test_logger.debug(
                " Test Memory (%s): Peak Alloc=%.2fMB, Process RSS diff=%.2fMB",
                request.node.name,
                peak / (1024 * 1024),
                (mem_after - mem_before) / (1024 * 1024),
            )
        else:
            # psutil not available, but performance test requested
            yield  # Run test without tracing
    else:
        yield  # Just run the test without tracing
