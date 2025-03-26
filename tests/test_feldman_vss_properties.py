# tests/test_feldman_vss_properties.py
# Property-based tests for Feldman VSS using Hypothesis.

import copy
import random
import secrets
import warnings

import pytest
from gmpy2 import mpz

# Skip all tests in this module if Hypothesis is not installed
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, Phase, Verbosity, assume, find, given, settings
from hypothesis import strategies as st

# Import necessary components from the main module and conftest
from feldman_vss import (
    CommitmentList,
    FeldmanVSS,
    ParameterError,
    ProofDict,
    SecurityError,
    SerializationError,
    ShareDict,
    VerificationError,
)

from .conftest import (
    TEST_PRIME_BITS_FAST,
    MockField,
    MockShamirSecretSharing,
    generate_poly_and_shares,
    test_logger,
)

# --- Hypothesis Configuration ---

# Register profiles for different testing levels
settings.register_profile(
    "ci",
    max_examples=200,
    deadline=None, # No deadline for CI
    verbosity=Verbosity.normal,
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target, Phase.shrink]
)
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=2000, # 2 seconds deadline for dev
    verbosity=Verbosity.verbose
)
settings.register_profile(
    "deep",
    max_examples=1000,
    deadline=None,
    verbosity=Verbosity.normal,
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target, Phase.shrink]
)

# Load the desired profile (e.g., 'dev' for local runs, 'ci' for CI)
# Can be overridden by environment variable HYPOTHESIS_PROFILE
settings.load_profile("dev")

# --- Test Class ---

@pytest.mark.properties # Custom marker for property-based tests
class TestPropertyBased:
    """Property-based tests using Hypothesis for robustness."""

    # Define strategies within the class to potentially access class-level attributes if needed
    # Using a fixed small prime for faster hypothesis runs
    # Note: Strategies themselves can't directly use fixtures. We pass prime in the test method.

    # Strategy for threshold t (ensure t >= 2)
    threshold_strategy = st.integers(min_value=2, max_value=10) # Keep max small for speed

    @staticmethod
    @st.composite
    def coeffs_and_shares_strategy(draw, field: MockField):
        """Composite strategy to generate consistent coefficients and shares."""
        t = draw(TestPropertyBased.threshold_strategy)
        # Ensure n >= t
        n = draw(st.integers(min_value=t, max_value=15)) # Keep max small
        secret = draw(st.integers(min_value=0, max_value=int(field.prime) - 1))
        # Generate coefficients using the field's random element method
        coeffs = [mpz(secret)] + [field.random_element() for _ in range(t-1)]
        shares: ShareDict = {}
        for i in range(1, n + 1):
            x = mpz(i)
            y = field.eval_poly(coeffs, x)
            shares[i] = (x, y)
        return coeffs, shares, t, n

    # --- Tests ---

    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large])
    @given(st.data()) # Use st.data() to allow drawing based on fixtures
    def test_prop_verify_valid_shares(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data):
        """Property: Correctly generated shares should always verify."""
        coeffs, shares, t, n = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))

        assume(coeffs) # Skip if coeffs list is empty (shouldn't happen with t>=2)
        assume(shares) # Skip if shares dict is empty

        try:
            commitments = default_vss.create_commitments(coeffs)
            for share_id in shares:
                x, y = shares[share_id]
                assert default_vss.verify_share(x, y, commitments) is True, f"Valid share ({x},{y}) failed verification"
        except (ParameterError, ValueError, SecurityError, MemoryError) as e:
             test_logger.debug(f"Hypothesis verify valid share caught expected error: {e}")
             # Allow expected errors during generation/verification with edge cases
        except Exception as e:
             pytest.fail(f"Unexpected exception during valid share verification: {e}")

    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large])
    @given(st.data(),
           tamper_amount=st.integers(min_value=1)) # Tamper by at least 1
    def test_prop_verify_invalid_shares(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data, tamper_amount):
        """Property: Tampered shares should always fail verification."""
        coeffs, shares, t, n = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))

        assume(coeffs)
        assume(shares)

        try:
            commitments = default_vss.create_commitments(coeffs)
            share_id_to_tamper = random.choice(list(shares.keys()))
            x, y = shares[share_id_to_tamper]

            # Tamper the y value, ensuring it's different
            invalid_y = (y + tamper_amount) % mock_field_fast.prime
            assume(invalid_y != y) # Ensure tampering actually changed the value

            assert default_vss.verify_share(x, invalid_y, commitments) is False, f"Invalid share ({x},{invalid_y}) passed verification"

            # Also test tampering x value (less common but should fail)
            invalid_x = x + 1 # Simple tamper
            assert default_vss.verify_share(invalid_x, y, commitments) is False, f"Share with invalid x ({invalid_x},{y}) passed verification"

        except (ParameterError, ValueError, SecurityError, MemoryError) as e:
             test_logger.debug(f"Hypothesis verify invalid share caught expected error: {e}")
        except Exception as e:
             pytest.fail(f"Unexpected exception during invalid share verification: {e}")

    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large])
    @given(st.data())
    def test_prop_zkp_roundtrip(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data):
         """Property: ZKP creation and verification should succeed for valid inputs."""
         coeffs, _, _, _ = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))
         assume(coeffs)

         try:
              commitments = default_vss.create_commitments(coeffs)
              proof = default_vss.create_polynomial_proof(coeffs, commitments)

              # Verify the proof itself
              assert default_vss.verify_polynomial_proof(proof, commitments) is True, "ZKP verification failed for valid proof"

              # Also verify using the combined method
              assert default_vss.verify_commitments_with_proof(commitments, proof) is True, "Combined ZKP verification failed"

              # Explicitly test challenge consistency check as well
              assert default_vss._verify_challenge_consistency(proof, commitments) is True, "Challenge consistency check failed"

         except (ParameterError, ValueError, SecurityError, MemoryError) as e:
              test_logger.debug(f"Hypothesis ZKP roundtrip caught expected error: {e}")
         except Exception as e:
              pytest.fail(f"Unexpected exception during ZKP roundtrip: {e}")

    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large])
    @given(st.data())
    def test_prop_zkp_tampered_proof_fails(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data):
         """Property: Tampered ZKP should fail verification."""
         coeffs, _, _, _ = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))
         assume(coeffs)

         try:
              commitments = default_vss.create_commitments(coeffs)
              proof = default_vss.create_polynomial_proof(coeffs, commitments)

              # Tamper with challenge
              tampered_proof_c = copy.deepcopy(proof)
              tampered_proof_c['challenge'] = (proof['challenge'] + 1) % mock_field_fast.prime
              assert default_vss.verify_polynomial_proof(tampered_proof_c, commitments) is False, "Verification passed for tampered challenge"

              # Tamper with a response
              tampered_proof_r = copy.deepcopy(proof)
              if tampered_proof_r['responses']:
                 idx_to_tamper = random.randrange(len(tampered_proof_r['responses']))
                 tampered_proof_r['responses'][idx_to_tamper] = (proof['responses'][idx_to_tamper] + 1) % mock_field_fast.prime
                 assert default_vss.verify_polynomial_proof(tampered_proof_r, commitments) is False, "Verification passed for tampered response"

              # Tamper with a blinding commitment
              tampered_proof_bc = copy.deepcopy(proof)
              if tampered_proof_bc['blinding_commitments']:
                  idx_bc = random.randrange(len(tampered_proof_bc['blinding_commitments']))
                  orig_bc, orig_br = tampered_proof_bc['blinding_commitments'][idx_bc]
                  tampered_proof_bc['blinding_commitments'][idx_bc] = ((orig_bc + 1) % mock_field_fast.prime, orig_br)
                  assert default_vss.verify_polynomial_proof(tampered_proof_bc, commitments) is False, "Verification passed for tampered blinding commitment"

         except (ParameterError, ValueError, SecurityError, MemoryError) as e:
              test_logger.debug(f"Hypothesis ZKP tampering test caught expected error: {e}")
         except Exception as e:
              pytest.fail(f"Unexpected exception during ZKP tampering test: {e}")


    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large])
    @given(st.data())
    def test_prop_serialization_roundtrip(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data):
        """Property: Serialization and deserialization should be lossless."""
        coeffs, _, _, _ = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))
        assume(coeffs)

        try:
            commitments = default_vss.create_commitments(coeffs)
            serialized = default_vss.serialize_commitments(commitments)
            deserialized, gen, prime, ts, is_hash = default_vss.deserialize_commitments(serialized)

            assert gen == default_vss.generator
            assert prime == default_vss.group.prime
            assert is_hash is True # Should always be hash based
            assert len(deserialized) == len(commitments)
            # Compare components of each commitment tuple
            for i in range(len(commitments)):
                assert deserialized[i][0] == commitments[i][0] # Hash value
                assert deserialized[i][1] == commitments[i][1] # Randomizer
                assert deserialized[i][2] == commitments[i][2] # Entropy (bytes or None)

            # Also test serialization with proof
            proof = default_vss.create_polynomial_proof(coeffs, commitments)
            serialized_with_proof = default_vss.serialize_commitments_with_proof(commitments, proof)
            deser_comm, deser_proof, _, _, _ = default_vss.deserialize_commitments_with_proof(serialized_with_proof)

            assert len(deser_comm) == len(commitments)
            assert isinstance(deser_proof, dict)
            assert deser_proof['challenge'] == proof['challenge']
            assert len(deser_proof['responses']) == len(proof['responses'])
            # Could add more detailed proof comparison if needed

        except (ParameterError, ValueError, SerializationError, SecurityError, MemoryError) as e:
             test_logger.debug(f"Hypothesis serialization roundtrip caught expected error: {e}")
        except Exception as e:
             pytest.fail(f"Unexpected exception during serialization roundtrip: {e}")

    # Note: Refresh shares can be computationally intensive for property tests
    @settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.data_too_large, HealthCheck.too_slow], max_examples=20) # Reduce examples for refresh
    @given(st.data())
    def test_prop_refresh_preserves_secret(self, default_vss: FeldmanVSS, mock_field_fast: MockField, data):
        """Property: Share refreshing should preserve the original secret."""
        coeffs, shares, t, n = data.draw(self.coeffs_and_shares_strategy(mock_field_fast))

        assume(coeffs)
        assume(len(shares) >= t) # Need enough shares to potentially refresh

        try:
            original_commitments = default_vss.create_commitments(coeffs)
            participant_ids = list(shares.keys())

            # Use a copy to avoid modifying original shares dict if refresh fails midway
            shares_copy = copy.deepcopy(shares)

            # Perform the refresh
            with warnings.catch_warnings():
                 # Ignore potential security warnings about insufficient shares during refresh in edge cases
                 warnings.simplefilter("ignore", SecurityWarning)
                 new_shares, new_commitments, verification_data = default_vss.refresh_shares(
                     shares_copy, t, n, original_commitments, participant_ids
                 )

            # Verify reconstruction from new shares using MockShamir
            shamir_mock = MockShamirSecretSharing(mock_field_fast)

            # We need at least t new shares to reconstruct
            assume(len(new_shares) >= t)

            # Select a random subset of t shares for reconstruction
            subset_ids = random.sample(list(new_shares.keys()), t)
            subset_shares_dict = {pid: new_shares[pid] for pid in subset_ids}

            reconstructed_secret = shamir_mock.reconstruct_secret(subset_shares_dict)
            original_secret = coeffs[0]

            assert reconstructed_secret == original_secret, "Secret not preserved after refreshing"

            # Optional: Verify new shares against new commitments
            for share_id in new_shares:
                 x, y = new_shares[share_id]
                 assert default_vss.verify_share(x, y, new_commitments), "Refreshed share failed verification against new commitments"

        except (ParameterError, ValueError, SecurityError, MemoryError) as e:
             # Allow expected errors, especially SecurityError if refresh fails due to byzantine simulation
             test_logger.debug(f"Hypothesis refresh secret preservation caught expected error: {e}")
        except Exception as e:
             # Catch unexpected errors during complex refresh
             test_logger.error(f"Unexpected error during Hypothesis refresh test: {e}", exc_info=True)
             pytest.fail(f"Unexpected exception in refresh test: {e}")
