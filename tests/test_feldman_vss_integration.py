# tests/test_feldman_vss_integration.py
# Tests for integration points: Shamir/Pedersen mocks, serialization, share refreshing.

import copy
import random
import warnings
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Dict, List, Tuple

import pytest
from gmpy2 import mpz

# Import necessary components from the main module and conftest
from feldman_vss import (
    CommitmentList,
    FeldmanVSS,
    FieldElement,
    ParameterError,
    ProofDict,
    SecurityError,
    SecurityWarning,
    SerializationError,
    ShareDict,
    VerificationError,
    VSSConfig,
    compute_checksum,
    create_dual_commitment_proof,
    create_vss_from_shamir,
    integrate_with_pedersen,
    verify_dual_commitments,
)

from .test_conftest import (
    DEFAULT_NUM_SHARES,
    DEFAULT_THRESHOLD,
    HAS_BLAKE3,
    MockField,
    MockPedersenVSS,
    MockShamirSecretSharing,
    generate_poly_and_shares,
)

# --- Test Shamir Integration ---


def test_create_vss_from_shamir(mock_shamir: MockShamirSecretSharing):
    """Test creating a FeldmanVSS instance from a MockShamir instance."""
    vss = create_vss_from_shamir(mock_shamir)
    assert isinstance(vss, FeldmanVSS)
    assert vss.field == mock_shamir.field
    # The factory function ensures PQ-secure config by default
    assert vss.config.prime_bits >= fvss.MIN_PRIME_BITS
    assert vss.group.prime.bit_length() >= fvss.MIN_PRIME_BITS


def test_create_vss_from_shamir_warning(mock_field_fast: MockField):
    """Test factory issues warning if Shamir field prime is too small."""
    # Create Shamir with a field smaller than MIN_PRIME_BITS
    shamir_small = MockShamirSecretSharing(mock_field_fast)  # Uses TEST_PRIME_BITS_FAST
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always", SecurityWarning)
        vss = create_vss_from_shamir(shamir_small)
        # Check if the warning about small prime was issued
        assert any(f"less than the recommended {fvss.MIN_PRIME_BITS}" in str(warn.message) for warn in w)
        # The VSS instance itself should still use a PQ-secure group internally
        assert vss.group.prime.bit_length() >= fvss.MIN_PRIME_BITS


def test_create_vss_from_shamir_invalid_type():
    """Test factory raises TypeError for invalid Shamir instance."""

    class BadShamir:
        pass

    with pytest.raises(TypeError, match="must have a 'field' attribute"):
        create_vss_from_shamir(BadShamir())  # type: ignore

    class BadShamirField:
        def __init__(self):
            self.field = object()  # Field without prime

    with pytest.raises(TypeError, match="must have a 'prime' attribute"):
        create_vss_from_shamir(BadShamirField())  # type: ignore


# --- Test Serialization ---


class TestSerialization:
    @pytest.fixture
    def vss_blake3(self, mock_field_fast: MockField) -> FeldmanVSS:
        """VSS instance configured to use BLAKE3 if available."""
        config = VSSConfig(prime_bits=mock_field_fast.prime.bit_length(), sanitize_errors=False, use_blake3=True)
        return FeldmanVSS(mock_field_fast, config)

    @pytest.fixture
    def vss_sha3(self, mock_field_fast: MockField) -> FeldmanVSS:
        """VSS instance configured to use SHA3-256."""
        config = VSSConfig(prime_bits=mock_field_fast.prime.bit_length(), sanitize_errors=False, use_blake3=False)
        return FeldmanVSS(mock_field_fast, config)

    @pytest.fixture
    def commitments_blake3(self, vss_blake3: FeldmanVSS, test_coeffs: list[mpz]) -> CommitmentList:
        return vss_blake3.create_commitments(test_coeffs)

    @pytest.fixture
    def commitments_sha3(self, vss_sha3: FeldmanVSS, test_coeffs: list[mpz]) -> CommitmentList:
        # Note: randomizers will differ from blake3 version
        return vss_sha3.create_commitments(test_coeffs)

    def test_commitment_serialization_roundtrip(self, default_vss: FeldmanVSS, test_commitments: CommitmentList):
        """Test serialization and deserialization of commitments."""
        serialized = default_vss.serialize_commitments(test_commitments)
        assert isinstance(serialized, str)

        deserialized, gen, prime, ts, is_hash = default_vss.deserialize_commitments(serialized)

        assert isinstance(deserialized, list)
        assert gen == default_vss.generator
        assert prime == default_vss.group.prime
        assert ts > 0
        assert is_hash is True
        assert len(deserialized) == len(test_commitments)
        for i in range(len(test_commitments)):
            # Compare tuple elements: (commitment_hash, randomizer, extra_entropy)
            assert deserialized[i][0] == test_commitments[i][0]
            assert deserialized[i][1] == test_commitments[i][1]
            assert deserialized[i][2] == test_commitments[i][2]

    def test_commitment_proof_serialization_roundtrip(self, default_vss: FeldmanVSS, test_coeffs: list[mpz]):
        """Test serialization/deserialization of commitments with proof."""
        commitments, proof = default_vss.create_commitments_with_proof(test_coeffs)

        serialized = default_vss.serialize_commitments_with_proof(commitments, proof)
        assert isinstance(serialized, str)

        deser_comms, deser_proof, gen, prime, ts = default_vss.deserialize_commitments_with_proof(serialized)

        assert isinstance(deser_comms, list)
        assert isinstance(deser_proof, dict)
        assert gen == default_vss.generator
        assert prime == default_vss.group.prime
        assert ts > 0
        assert len(deser_comms) == len(commitments)
        # Deep comparison of commitments
        for i in range(len(commitments)):
            assert deser_comms[i] == commitments[i]

        # Deep comparison of proof structure and values (converting mpz back for comparison if needed)
        assert deser_proof.keys() == proof.keys()
        assert deser_proof["challenge"] == proof["challenge"]
        assert deser_proof["timestamp"] == proof["timestamp"]
        assert len(deser_proof["responses"]) == len(proof["responses"])
        assert all(deser_proof["responses"][i] == proof["responses"][i] for i in range(len(proof["responses"])))
        # Compare blinding commitments (tuples)
        assert len(deser_proof["blinding_commitments"]) == len(proof["blinding_commitments"])
        assert all(
            deser_proof["blinding_commitments"][i] == proof["blinding_commitments"][i] for i in range(len(proof["blinding_commitments"]))
        )
        # Compare randomizers
        assert deser_proof["commitment_randomizers"] == proof["commitment_randomizers"]
        assert deser_proof["blinding_randomizers"] == proof["blinding_randomizers"]

    def test_verify_share_from_serialized(self, default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList):
        """Test verifying a share using serialized commitments."""
        serialized = default_vss.serialize_commitments(test_commitments)
        share_id = random.choice(list(test_shares.keys()))
        x, y = test_shares[share_id]

        # Verify valid share
        assert default_vss.verify_share_from_serialized(x, y, serialized) is True

        # Verify invalid share
        invalid_y = (y + 1) % default_vss.field.prime
        assert default_vss.verify_share_from_serialized(x, invalid_y, serialized) is False

    def test_verify_share_with_proof(self, default_vss: FeldmanVSS, test_coeffs: list[mpz], test_shares: ShareDict):
        """Test verifying share and proof using serialized data."""
        commitments, proof = default_vss.create_commitments_with_proof(test_coeffs)
        serialized = default_vss.serialize_commitments_with_proof(commitments, proof)

        share_id = random.choice(list(test_shares.keys()))
        x, y = test_shares[share_id]

        # Verify valid share and valid proof
        share_valid, proof_valid = default_vss.verify_share_with_proof(x, y, serialized)
        assert share_valid is True
        assert proof_valid is True

        # Verify invalid share and valid proof
        invalid_y = (y + 1) % default_vss.field.prime
        share_valid_inv, proof_valid_inv = default_vss.verify_share_with_proof(x, invalid_y, serialized)
        assert share_valid_inv is False
        assert proof_valid_inv is True  # Proof itself is still valid

    @pytest.mark.skipif(not HAS_BLAKE3, reason="BLAKE3 not available, cannot test hash switching.")
    def test_deserialization_different_hash(
        self, vss_blake3: FeldmanVSS, vss_sha3: FeldmanVSS, commitments_blake3: CommitmentList, commitments_sha3: CommitmentList
    ):
        """Test deserializing data created with a different hash algorithm."""
        serialized_blake3 = vss_blake3.serialize_commitments(commitments_blake3)
        serialized_sha3 = vss_sha3.serialize_commitments(commitments_sha3)

        # Deserialize BLAKE3 data using SHA3 instance (should work, hash is for checksum)
        deser_b3_comms, _, _, _, _ = vss_sha3.deserialize_commitments(serialized_blake3)
        assert len(deser_b3_comms) == len(commitments_blake3)
        # Commitment values might differ due to different randomizers/hashing, but structure is ok

        # Deserialize SHA3 data using BLAKE3 instance
        deser_s3_comms, _, _, _, _ = vss_blake3.deserialize_commitments(serialized_sha3)
        assert len(deser_s3_comms) == len(commitments_sha3)

        # Verification requires matching VSS instance and commitments
        # Pick a share (assuming test_shares corresponds to the coefficients used for both)
        # x, y = random.choice(list(test_shares.values()))
        # assert vss_blake3.verify_share(x, y, deser_b3_comms) # This might fail if randomizers differ
        # assert vss_sha3.verify_share(x, y, deser_s3_comms) # This might fail if randomizers differ

    def test_deserialization_missing_optional_fields(self, default_vss: FeldmanVSS, mock_field_fast: MockField):
        """Test deserialization when optional 'extra_entropy' was None during serialization."""
        # Use a high-entropy secret so extra_entropy is None
        high_entropy_secret = mock_field_fast.random_element()
        if high_entropy_secret.bit_length() < 256:
            high_entropy_secret = mpz(1) << 300  # Ensure it's large enough
        coeffs_high_entropy, _ = generate_poly_and_shares(mock_field_fast, high_entropy_secret, 3, 5)
        commits_no_entropy = default_vss.create_commitments(coeffs_high_entropy)
        assert commits_no_entropy[0][2] is None  # Check entropy is None for secret commitment

        serialized = default_vss.serialize_commitments(commits_no_entropy)
        deserialized, _, _, _, _ = default_vss.deserialize_commitments(serialized)

        assert len(deserialized) == len(commits_no_entropy)
        assert deserialized[0][2] is None  # Entropy should still be None after deserialization

    def test_deserialization_tampered_checksum(self, default_vss: FeldmanVSS, test_commitments: CommitmentList):
        """Test deserialization fails if checksum is incorrect."""
        serialized = default_vss.serialize_commitments(test_commitments)
        decoded = urlsafe_b64decode(serialized.encode("utf-8"))
        import msgpack

        wrapper = msgpack.unpackb(decoded, raw=True)

        # Tamper with the checksum
        tampered_wrapper = {b"data": wrapper[b"data"], b"checksum": wrapper[b"checksum"] + 1}
        tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode("utf-8")

        with pytest.raises(SecurityError, match="Data integrity check failed"):
            default_vss.deserialize_commitments(tampered_serialized)

    def test_deserialization_tampered_data(self, default_vss: FeldmanVSS, test_commitments: CommitmentList):
        """Test deserialization fails if data is tampered (checksum mismatch)."""
        serialized = default_vss.serialize_commitments(test_commitments)
        decoded = urlsafe_b64decode(serialized.encode("utf-8"))
        import msgpack

        wrapper = msgpack.unpackb(decoded, raw=True)

        # Tamper with the data slightly
        tampered_data = wrapper[b"data"] + b"\x00"
        # Keep original checksum
        tampered_wrapper = {b"data": tampered_data, b"checksum": wrapper[b"checksum"]}
        tampered_serialized = urlsafe_b64encode(msgpack.packb(tampered_wrapper)).decode("utf-8")

        with pytest.raises(SecurityError, match="Data integrity check failed"):
            default_vss.deserialize_commitments(tampered_serialized)


# --- Test Pedersen Integration ---


@pytest.mark.integration
class TestPedersenIntegration:
    @pytest.fixture
    def setup_integration(self, default_vss: FeldmanVSS, mock_pedersen: MockPedersenVSS, test_coeffs: list[mpz]):
        """Setup common data for Pedersen integration tests."""
        # Ensure Pedersen mock has randomizers populated for the coeffs
        pedersen_commits = mock_pedersen.create_commitments(test_coeffs)
        feldman_commits = default_vss.create_commitments(test_coeffs)
        return default_vss, mock_pedersen, test_coeffs, feldman_commits, pedersen_commits

    def test_integrate_with_pedersen(self, setup_integration):
        """Test the integrate_with_pedersen helper function."""
        feldman_vss, pedersen_vss, coeffs, _, _ = setup_integration
        # Need shares for the helper, generate if not available
        shares, _ = generate_poly_and_shares(feldman_vss.field, coeffs[0], len(coeffs), DEFAULT_NUM_SHARES)

        result = integrate_with_pedersen(feldman_vss, pedersen_vss, shares, coeffs)

        assert "feldman_commitments" in result
        assert "pedersen_commitments" in result
        assert "dual_proof" in result
        assert "version" in result
        assert isinstance(result["feldman_commitments"], str)
        assert isinstance(result["pedersen_commitments"], str)
        assert isinstance(result["dual_proof"], dict)

        # Basic check of proof structure
        proof = result["dual_proof"]
        assert "challenge" in proof
        assert "responses" in proof
        assert "feldman_blinding_commitments" in proof
        assert "pedersen_blinding_commitments" in proof

    def test_create_dual_commitment_proof(self, setup_integration):
        """Test creating the dual commitment proof."""
        feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits = setup_integration

        proof = create_dual_commitment_proof(feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits)

        assert isinstance(proof, dict)
        assert "challenge" in proof
        assert "responses" in proof
        assert "feldman_blinding_commitments" in proof
        assert "pedersen_blinding_commitments" in proof
        assert len(proof["responses"]) == len(coeffs)
        assert len(proof["feldman_blinding_commitments"]) == len(coeffs)
        assert len(proof["pedersen_blinding_commitments"]) == len(coeffs)
        # Check for response_randomizers if Feldman is hash-based (which it is)
        assert "response_randomizers" in proof
        assert len(proof["response_randomizers"]) == len(coeffs)

    def test_verify_dual_commitments_valid(self, setup_integration):
        """Test verifying a valid dual commitment proof."""
        feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits = setup_integration
        proof = create_dual_commitment_proof(feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits)

        is_valid = verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits, proof)
        assert is_valid is True

    def test_verify_dual_commitments_invalid_proof(self, setup_integration):
        """Test verification fails with a tampered proof."""
        feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits = setup_integration
        proof = create_dual_commitment_proof(feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits)

        # Tamper with a response
        tampered_proof = copy.deepcopy(proof)
        tampered_proof["responses"][0] = (tampered_proof["responses"][0] + 1) % feldman_vss.field.prime

        is_valid = verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits, tampered_proof)
        assert is_valid is False

        # Tamper with challenge
        tampered_proof_chal = copy.deepcopy(proof)
        tampered_proof_chal["challenge"] = (tampered_proof_chal["challenge"] + 1) % feldman_vss.field.prime
        is_valid_chal = verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits, tampered_proof_chal)
        assert is_valid_chal is False  # Verification logic depends on challenge

    def test_verify_dual_commitments_mismatched_commits(self, setup_integration):
        """Test verification fails if commitments don't match the proof context."""
        feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits = setup_integration
        proof = create_dual_commitment_proof(feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits)

        # Create different commitments
        coeffs2 = [c + 1 for c in coeffs]
        feldman_commits_alt = feldman_vss.create_commitments(coeffs2)
        pedersen_commits_alt = pedersen_vss.create_commitments(coeffs2)

        # Verify original proof against altered commitments
        is_valid = verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits_alt, pedersen_commits_alt, proof)
        assert is_valid is False

    def test_verify_dual_commitments_length_errors(self, setup_integration):
        """Test verification raises ValueError for mismatched lengths."""
        feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits = setup_integration
        proof = create_dual_commitment_proof(feldman_vss, pedersen_vss, coeffs, feldman_commits, pedersen_commits)

        # Mismatched commitments length
        with pytest.raises(ValueError, match="same length"):
            verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits[:-1], pedersen_commits, proof)
        with pytest.raises(ValueError, match="same length"):
            verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits[:-1], proof)

        # Mismatched proof lengths
        short_proof = copy.deepcopy(proof)
        short_proof["responses"].pop()
        with pytest.raises(ValueError, match="Number of responses"):
            verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits, short_proof)

        short_proof_rand = copy.deepcopy(proof)
        if "response_randomizers" in short_proof_rand:
            short_proof_rand["response_randomizers"].pop()
            # This might not raise ValueError directly but cause verify to fail safely
            is_valid = verify_dual_commitments(feldman_vss, pedersen_vss, feldman_commits, pedersen_commits, short_proof_rand)
            assert is_valid is False


# --- Test Share Refreshing ---


@pytest.mark.integration
class TestShareRefreshing:
    def test_refresh_shares_preserves_secret(
        self,
        default_vss: FeldmanVSS,
        test_coeffs: list[mpz],
        test_shares: ShareDict,
        test_commitments: CommitmentList,
        mock_shamir: MockShamirSecretSharing,
    ):
        """Test that refreshing shares preserves the original secret."""
        original_secret = test_coeffs[0]
        n = DEFAULT_NUM_SHARES
        t = DEFAULT_THRESHOLD
        participant_ids = list(range(1, n + 1))

        # Ensure we have enough shares for the test
        if len(test_shares) < t:
            pytest.skip("Not enough shares provided by fixture to test reconstruction after refresh.")

        new_shares, new_commitments, verification_data = default_vss.refresh_shares(test_shares, t, n, test_commitments, participant_ids)

        assert isinstance(new_shares, dict)
        assert len(new_shares) == n
        assert isinstance(new_commitments, list)
        assert len(new_commitments) == t
        assert isinstance(verification_data, dict)
        assert "verification_summary" in verification_data

        # Verify reconstruction from a random subset of new shares
        subset_ids = random.sample(list(new_shares.keys()), t)
        subset_shares = {pid: new_shares[pid] for pid in subset_ids}

        reconstructed_secret = mock_shamir.reconstruct_secret(subset_shares)
        assert reconstructed_secret == original_secret

    @pytest.mark.parametrize("t, n", [(2, 3), (3, 3), (4, 5)])
    def test_refresh_shares_threshold_cases(
        self, t: int, n: int, default_vss: FeldmanVSS, mock_field_fast: MockField, mock_shamir: MockShamirSecretSharing
    ):
        """Test share refreshing with different threshold configurations."""
        secret = mock_field_fast.random_element()
        coeffs, shares = generate_poly_and_shares(mock_field_fast, secret, t, n)
        commitments = default_vss.create_commitments(coeffs)
        participant_ids = list(range(1, n + 1))

        new_shares, new_commitments, _ = default_vss.refresh_shares(shares, t, n, commitments, participant_ids)

        assert len(new_shares) == n
        assert len(new_commitments) == t

        # Verify reconstruction
        subset_ids = random.sample(list(new_shares.keys()), t)
        subset_shares = {pid: new_shares[pid] for pid in subset_ids}
        reconstructed = mock_shamir.reconstruct_secret(subset_shares)
        assert reconstructed == secret

    def test_refresh_shares_insufficient_input_shares(
        self, default_vss: FeldmanVSS, test_shares: ShareDict, test_commitments: CommitmentList
    ):
        """Test refresh fails if fewer than t input shares are provided."""
        n = DEFAULT_NUM_SHARES
        t = DEFAULT_THRESHOLD
        participant_ids = list(range(1, n + 1))

        # Provide fewer than t shares
        insufficient_shares = dict(list(test_shares.items())[: t - 1])

        with pytest.raises(ParameterError, match=f"Need at least {t} shares"):
            default_vss.refresh_shares(insufficient_shares, t, n, test_commitments, participant_ids)
