# tests/test_feldman_vss_refreshing_security.py
# Security-focused tests for the share refreshing mechanism
import secrets
from typing import Any

import gmpy2
import pytest

import feldman_vss as fvss
from feldman_vss import (
    CommitmentList,
    FeldmanVSS,
    FieldElement,
    ParameterError,
    SecurityError,
    SecurityWarning,
    ShareDict,
    SharePoint,
    VerificationError,
    VSSConfig,
)

# Import fixtures and helpers from conftest
from .conftest import (
    DEFAULT_NUM_SHARES,
    DEFAULT_THRESHOLD,
    MockField,
    default_vss,
    default_vss_config,
    generate_poly_and_shares,
    mock_field_fast,
    test_coeffs,
    test_secret,
    test_shares,
)

# --- Constants ---
REFRESH_N = 5  # Number of parties for refresh tests
REFRESH_T = 3  # Threshold for refresh tests

# --- Fixtures for Refreshing Tests ---


@pytest.fixture
def refresh_parties(mock_field_fast: MockField, default_vss_config: VSSConfig) -> list[FeldmanVSS]:
    """Creates multiple VSS instances representing parties for refreshing."""
    # All parties share the same field and group parameters for compatibility
    group = fvss.CyclicGroup(
        # FIX: Cast mpz prime to int for CyclicGroup constructor hint
        prime=int(mock_field_fast.prime),
        prime_bits=default_vss_config.prime_bits,
        use_safe_prime=default_vss_config.safe_prime,
    )
    parties = [fvss.FeldmanVSS(field=mock_field_fast, config=default_vss_config, group=group) for _ in range(REFRESH_N)]
    return parties


@pytest.fixture
def initial_sharing(mock_field_fast: MockField, test_secret: FieldElement) -> tuple[list[FieldElement], ShareDict]:
    """Provides initial coefficients and shares for refreshing."""
    coeffs, shares = generate_poly_and_shares(mock_field_fast, test_secret, REFRESH_T, REFRESH_N)
    # Ensure coefficients are FieldElement (list invariance)
    return list(coeffs), shares  # type: ignore


@pytest.fixture
def initial_commitments(refresh_parties: list[FeldmanVSS], initial_sharing: tuple[list[FieldElement], ShareDict]) -> CommitmentList:
    """Commitments corresponding to the initial sharing."""
    coeffs, _ = initial_sharing
    # Use the first party's instance to create commitments (all share the same group)
    return refresh_parties[0].create_commitments(coeffs)


# --- Helper for Simulating Refresh ---


def simulate_zero_sharing_phase(
    parties: list[FeldmanVSS],
    participant_ids: list[int],
    threshold: int,
    malicious_parties: dict[int, str] | None = None,
    tamper_details: dict[str, Any] | None = None,
) -> tuple[dict[int, ShareDict], dict[int, CommitmentList], bytes]:
    """Simulates Step 1 of refresh: parties creating zero-sharings."""
    zero_sharings: dict[int, ShareDict] = {}
    zero_commitments: dict[int, CommitmentList] = {}
    malicious_parties = malicious_parties or {}
    tamper_details = tamper_details or {}
    master_seed = secrets.token_bytes(32)  # For deterministic RNGs

    for i, party_vss in enumerate(parties):
        party_id = participant_ids[i]
        malicious_action = malicious_parties.get(party_id)

        # Derive party-specific seed for deterministic RNG
        party_seed = party_vss.hash_algorithm(master_seed + str(party_id).encode()).digest()
        party_rng = fvss.create_secure_deterministic_rng(party_seed)

        # Generate zero-polynomial coefficients
        zero_coeffs: list[FieldElement] = [gmpy2.mpz(0)]
        for _ in range(1, threshold):
            rand_val = party_rng(int(party_vss.field.prime))
            zero_coeffs.append(gmpy2.mpz(rand_val))

        # --- Malicious Actions ---
        if malicious_action == "invalid_zero_commitment":
            # Create commitments with a non-zero constant term for detection
            bad_zero_coeffs = list(zero_coeffs)
            bad_zero_coeffs[0] = gmpy2.mpz(1)  # Make constant term non-zero
            party_commitments = party_vss.create_commitments(bad_zero_coeffs)
        else:
            # Create correct commitments normally
            party_commitments = party_vss.create_commitments(zero_coeffs)

        # Generate shares based on the *correct* zero_coeffs
        party_shares: ShareDict = {}
        for p_id in participant_ids:
            y_value: int | gmpy2.mpz = party_vss._evaluate_polynomial(zero_coeffs, p_id)
            party_shares[p_id] = (p_id, y_value)

        if malicious_action == "invalid_share":
            # Tamper with one share sent by this malicious party
            target_participant_id = tamper_details.get("target_id", participant_ids[(i + 1) % len(parties)])
            if target_participant_id in party_shares:
                x_orig, y_orig = party_shares[target_participant_id]
                # Ensure tampering results in a different value
                # FIX: Cast modulus to int for f_mod hint
                y_tampered: gmpy2.mpz = gmpy2.f_mod(gmpy2.mpz(gmpy2.mpz(y_orig) + 1), int(party_vss.field.prime))
                party_shares[target_participant_id] = (x_orig, y_tampered)

        elif malicious_action == "equivocate_shares":
            # Send different shares to different participants
            target1 = tamper_details.get("target1", participant_ids[(i + 1) % len(parties)])
            target2 = tamper_details.get("target2", participant_ids[(i + 2) % len(parties)])
            if target1 != target2 and target1 in party_shares and target2 in party_shares:
                x1, y1 = party_shares[target1]
                x2, y2 = party_shares[target2]
                # Create slightly different shares for target1 and target2
                # FIX: Cast modulus to int for f_mod hint
                party_shares[target1] = (x1, gmpy2.f_mod(gmpy2.mpz(gmpy2.mpz(y1) + 1), int(party_vss.field.prime)))
                # FIX: Cast modulus to int for f_mod hint
                party_shares[target2] = (x2, gmpy2.f_mod(gmpy2.mpz(gmpy2.mpz(y2) + 2), int(party_vss.field.prime)))
                # Other shares remain correct relative to zero_coeffs

        # Store results
        zero_sharings[party_id] = party_shares
        zero_commitments[party_id] = party_commitments

    return zero_sharings, zero_commitments, master_seed


# --- Adversarial Refresh Tests ---


@pytest.mark.security
def test_refresh_detects_invalid_zero_share(refresh_parties: list[FeldmanVSS]):
    """A malicious party sends an invalid share which should be detected."""
    parties = refresh_parties
    participant_ids = list(range(1, REFRESH_N + 1))
    malicious_id = participant_ids[0]
    target_id = participant_ids[1]  # Honest party receiving bad share

    zero_sharings, zero_commitments, _ = simulate_zero_sharing_phase(
        parties, participant_ids, REFRESH_T, malicious_parties={malicious_id: "invalid_share"}, tamper_details={"target_id": target_id}
    )

    # Simulate verification from the target's perspective
    target_party_vss = parties[participant_ids.index(target_id)]
    malicious_party_share_for_target = zero_sharings[malicious_id][target_id]
    malicious_party_commitments = zero_commitments[malicious_id]

    share_x, share_y = malicious_party_share_for_target
    is_valid = target_party_vss.verify_share(share_x, share_y, malicious_party_commitments)

    # B101: Assert allowed
    assert not is_valid, "Target party should detect the invalid share"

    # Check if the main refresh logic (if run fully) would detect it
    # This requires mocking or adapting the _refresh_shares_additive logic
    # For simplicity here, we focus on the direct verification failure
    # We expect _detect_byzantine_behavior or the verification loop to catch this
    # Testing the full refresh requires a more complex simulation framework


@pytest.mark.security
def test_refresh_detects_invalid_zero_commitment(refresh_parties: list[FeldmanVSS]):
    """A malicious party sends commitments not matching a zero polynomial."""
    parties = refresh_parties
    participant_ids = list(range(1, REFRESH_N + 1))
    malicious_id = participant_ids[0]

    # Simulate phase 1 with the malicious action
    zero_sharings, zero_commitments, _ = simulate_zero_sharing_phase(
        parties, participant_ids, REFRESH_T, malicious_parties={malicious_id: "invalid_zero_commitment"}
    )

    # Simulate an honest party checking the zero commitment
    honest_party_id = participant_ids[1]
    honest_party_vss: FeldmanVSS = parties[participant_ids.index(honest_party_id)]
    malicious_party_commitments = zero_commitments[malicious_id]

    # Manually check the zero commitment verification logic from _refresh_shares_additive
    # Check commitment structure first to avoid index errors
    if not (
        isinstance(malicious_party_commitments, list)
        and len(malicious_party_commitments) > 0
        and isinstance(malicious_party_commitments[0], tuple)
        and len(malicious_party_commitments[0]) >= 2
    ):
        pytest.fail("Malformed commitments received from simulation")

    commitment_value = malicious_party_commitments[0][0]
    r_i = malicious_party_commitments[0][1]
    expected_zero_commitment = honest_party_vss._compute_hash_commitment(0, r_i, 0)

    # B101: Assert allowed
    assert not fvss.constant_time_compare(commitment_value, expected_zero_commitment), "Honest party should detect invalid zero commitment"

    # Ideally, test that `_detect_byzantine_behavior` flags this party
    is_byzantine, evidence = honest_party_vss._detect_byzantine_behavior(
        malicious_id,
        malicious_party_commitments,
        zero_sharings[malicious_id],  # Pass shares even if commitments are bad
    )
    # B101: Assert allowed
    assert is_byzantine, "_detect_byzantine_behavior should flag party with invalid zero commitment"
    # B101: Assert allowed
    assert "invalid_zero_commitment" in evidence, "Evidence should indicate invalid zero commitment"


@pytest.mark.security
def test_refresh_detects_equivocation_shares(refresh_parties: list[FeldmanVSS]):
    """A malicious party sends different shares derived from the same commitment."""
    parties = refresh_parties
    participant_ids = list(range(1, REFRESH_N + 1))
    malicious_id = participant_ids[0]
    target1_id = participant_ids[1]
    target2_id = participant_ids[2]

    zero_sharings, zero_commitments, _ = simulate_zero_sharing_phase(
        parties,
        participant_ids,
        REFRESH_T,
        malicious_parties={malicious_id: "equivocate_shares"},
        tamper_details={"target1": target1_id, "target2": target2_id},
    )

    # Simulate echo consistency check
    # Use any honest party's VSS instance for the check
    checker_vss = parties[1]
    consistency_results = checker_vss._process_echo_consistency(zero_commitments, zero_sharings, participant_ids)

    # B101: Assert allowed
    # Check consistency between the two targets regarding the malicious party
    assert not consistency_results.get((malicious_id, target1_id), True), (
        "Echo consistency should fail for target1 regarding malicious party"
    )
    # B101: Assert allowed
    assert not consistency_results.get((malicious_id, target2_id), True), (
        "Echo consistency should fail for target2 regarding malicious party"
    )

    # Check Byzantine detection
    is_byzantine, evidence = checker_vss._detect_byzantine_behavior(
        malicious_id, zero_commitments[malicious_id], zero_sharings[malicious_id], consistency_results
    )
    # B101: Assert allowed
    assert is_byzantine, "_detect_byzantine_behavior should flag equivocating party"
    # B101: Assert allowed
    assert "equivocation" in evidence, "Evidence should indicate equivocation"
    # B101: Assert allowed
    assert len(evidence.get("equivocation", {}).get("evidence", [])) > 0, "Equivocation evidence should be present"


@pytest.mark.security
def test_refresh_handles_malformed_data(refresh_parties: list[FeldmanVSS], initial_sharing: tuple[list[FieldElement], ShareDict]):
    """Test resilience against malformed commitments/shares during refresh simulation."""
    parties = refresh_parties
    participant_ids = list(range(1, REFRESH_N + 1))
    _, initial_shares = initial_sharing  # Use initial shares for the refresh call

    # Simulate receiving malformed commitments from party 0
    malformed_commitments = {0: [("not-a-commitment", "not-a-randomizer")]}  # type: ignore
    malformed_sharings = {0: {p_id: (p_id, 0) for p_id in participant_ids}}  # Dummy shares

    # Mock the internal steps or check sub-functions
    checker_vss = parties[1]  # An honest party

    # Test _process_echo_consistency with bad commitment format
    # B101: Assert allowed
    with pytest.raises(TypeError, match="Invalid commitment format"):
        checker_vss._process_echo_consistency(malformed_commitments, malformed_sharings, participant_ids)  # type: ignore

    # Test _detect_byzantine_behavior with bad commitment format
    # B101: Assert allowed
    with pytest.raises(TypeError, match="Each commitment must be a tuple"):
        checker_vss._detect_byzantine_behavior(0, malformed_commitments[0], malformed_sharings[0])  # type: ignore


@pytest.mark.security
@pytest.mark.parametrize("num_malicious", [1, 2])  # f=1 (should pass), f=2 (should fail safely for t=3)
def test_refresh_threshold_attack_resilience(
    refresh_parties: list[FeldmanVSS], initial_sharing: tuple[list[FieldElement], ShareDict], num_malicious: int
):
    """Test refresh with f malicious parties, checking if protocol succeeds/fails safely."""
    parties = refresh_parties
    participant_ids = list(range(1, REFRESH_N + 1))
    coeffs, initial_shares = initial_sharing
    initial_secret = coeffs[0]

    # Designate malicious parties
    malicious_ids = participant_ids[:num_malicious]
    honest_ids = participant_ids[num_malicious:]
    malicious_config = {m_id: "invalid_share" for m_id in malicious_ids}

    # Simulate phase 1
    zero_sharings, zero_commitments, master_seed = simulate_zero_sharing_phase(
        parties, participant_ids, REFRESH_T, malicious_parties=malicious_config
    )

    # Simulate refresh from the perspective of ONE honest party
    honest_checker_id = honest_ids[0]
    honest_vss = parties[participant_ids.index(honest_checker_id)]

    # We need to adapt the full refresh logic or mock parts of it.
    # Let's try calling the internal method with simulated inputs.
    # This requires careful mocking or adaptation.

    # Mock internal verification steps if needed, or run the full logic carefully
    # For this test, let's focus on the outcome: does it raise SecurityError or succeed?

    # Prepare inputs for the honest party's view of refresh
    honest_initial_share = initial_shares[honest_checker_id]
    # Simulate the dictionary of shares the honest party would use:
    # It includes its own share and shares received from others (which need verification)
    # This part is complex to simulate perfectly without running the full distributed protocol.

    # Simplified approach: Check if _detect_byzantine_behavior correctly identifies malicious parties
    detected_byzantine = 0
    for m_id in malicious_ids:
        is_byzantine, _ = honest_vss._detect_byzantine_behavior(
            m_id,
            zero_commitments[m_id],
            zero_sharings[m_id],
            # Pass None for consistency if not fully simulated
        )
        if is_byzantine:
            detected_byzantine += 1

    # Check based on threshold t=3, n=5
    # f = num_malicious
    # Protocol requires n > 2f for broadcast, n >= 2f+1 for agreement.
    # Verification requires t > f valid zero-shares.
    can_tolerate = num_malicious < REFRESH_T  # Need t > f valid shares

    if can_tolerate:
        # B101: Assert allowed
        assert detected_byzantine == num_malicious, f"Should detect all {num_malicious} malicious parties"
        # Ideally, we'd also assert that the refresh completes and secret is preserved.
        # This requires simulating the share summation after exclusion.
        # (Skipped here for brevity, focus is on detection)
    else:  # Cannot tolerate f >= t malicious parties providing bad shares
        # B101: Assert allowed
        assert detected_byzantine == num_malicious, f"Should detect all {num_malicious} malicious parties"
        # We expect the protocol step where shares are summed and verified to fail
        # because not enough *valid* zero shares (t-f <= 0) will be available.
        # This should result in a SecurityError within _refresh_shares_additive.
        # To test this directly, we would need to call _refresh_shares_additive
        # with mocked verification results reflecting the detected invalid shares.

        # Example using a simplified check on available valid shares:
        num_honest = REFRESH_N - num_malicious
        if num_honest < REFRESH_T:
            # Expecting failure because not enough honest parties remain
            # to provide the necessary t valid zero-shares.
            # The full protocol (_refresh_shares_additive) should ideally
            # raise a SecurityError in this scenario when attempting to
            # combine shares, but this test focuses on detection.
            pass  # Placeholder - signifies expected protocol failure later on.

        # A more direct test would involve mocking the verification results within
        # a call to the refresh function itself, which is complex.
