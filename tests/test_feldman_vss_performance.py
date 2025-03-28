# tests/test_feldman_vss_performance.py
# Performance benchmarks for the Feldman VSS implementation.

import logging
import os
import time
from collections.abc import Callable
from typing import Any, Dict, List, Optional, Tuple

import pytest
from gmpy2 import mpz

# Import necessary components from the main module and conftest
from feldman_vss import (
    CommitmentList,
    FeldmanVSS,
    ProofDict,
    ShareDict,
    SharePoint,
)

from .conftest import (
    HAS_PSUTIL,
    LARGE_N,
    LARGE_T,
    RUN_PERFORMANCE_TESTS,
    MockField,
    generate_poly_and_shares,
    test_logger,  # Use the logger defined in conftest
)

# --- Test Setup ---

# Mark all tests in this module as performance tests
pytestmark = pytest.mark.performance

# Skip the entire module if performance tests are not requested
if not RUN_PERFORMANCE_TESTS:
    pytest.skip("Performance tests not requested (set RUN_PERFORMANCE_TESTS=1)", allow_module_level=True)


# --- Benchmarking Helper ---


def _benchmark(func: Callable, *args: Any, iterations: int = 5, **kwargs: Any) -> tuple[float, float, float, float, list[Any]]:
    """Runs a function multiple times and returns performance statistics."""
    times = []
    results = []  # Store results to prevent optimization issues
    if iterations <= 0:
        iterations = 1

    test_logger.debug(f"Benchmarking {func.__name__} with {iterations} iterations...")
    for i in range(iterations):
        iter_start_time = time.perf_counter()
        results.append(func(*args, **kwargs))
        iter_end_time = time.perf_counter()
        times.append(iter_end_time - iter_start_time)
        test_logger.debug(f"  Iter {i + 1}/{iterations}: {times[-1]:.4f}s")

    if not times:
        return 0.0, 0.0, 0.0, 0.0, results  # Should not happen if iterations >= 1

    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    # Calculate standard deviation safely
    if len(times) > 1:
        variance = sum([(t - avg_time) ** 2 for t in times]) / (len(times) - 1)
        std_dev = variance**0.5
    else:
        std_dev = 0.0

    return avg_time, min_time, max_time, std_dev, results


# --- Performance Test Class ---


class TestPerformance:
    # Number of iterations for benchmarks (can be overridden per test)
    ITERATIONS = 5

    def test_perf_1_create_commitments_large(self, large_test_data: Optional[dict[str, Any]]):
        """Benchmark commitment creation for large T."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        vss: FeldmanVSS = large_test_data["vss"]
        coeffs: list[mpz] = large_test_data["coeffs"]
        t: int = large_test_data["t"]

        avg_time, min_t, max_t, std_dev, _ = _benchmark(vss.create_commitments, coeffs, iterations=self.ITERATIONS)
        test_logger.info(
            f"[Benchmark] Create Commitments (t={t}): Avg={avg_time:.4f}s (Min={min_t:.4f}, Max={max_t:.4f}, StdDev={std_dev:.4f})"
        )
        # Basic assertion: time should be positive
        assert avg_time >= 0

    def test_perf_2_batch_verify_large(self, large_test_data: Optional[dict[str, Any]]):
        """Benchmark batch share verification for large N and T."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        vss: FeldmanVSS = large_test_data["vss"]
        share_list: list[SharePoint] = large_test_data["share_list"]
        commitments: CommitmentList = large_test_data["commitments"]
        n: int = large_test_data["n"]
        t: int = large_test_data["t"]

        avg_time, min_t, max_t, std_dev, results = _benchmark(vss.batch_verify_shares, share_list, commitments, iterations=self.ITERATIONS)
        test_logger.info(
            f"[Benchmark] Batch Verify (n={n}, t={t}): Avg={avg_time:.4f}s (Min={min_t:.4f}, Max={max_t:.4f}, StdDev={std_dev:.4f})"
        )
        assert avg_time >= 0
        # Check result validity
        assert results[0][0] is True  # First result tuple, first element (all_valid)

    def test_perf_3_sequential_verification(self, large_test_data: Optional[dict[str, Any]]):
        """Benchmark sequential single share verification for comparison."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        vss: FeldmanVSS = large_test_data["vss"]
        share_list: list[SharePoint] = large_test_data["share_list"]
        commitments: CommitmentList = large_test_data["commitments"]
        n: int = large_test_data["n"]
        t: int = large_test_data["t"]

        # Limit number of sequential verifications for reasonable test duration
        num_verify = min(100, n)
        shares_to_verify = share_list[:num_verify]

        def run_sequential():
            results = []
            for x, y in shares_to_verify:
                results.append(vss.verify_share(x, y, commitments))
            return all(results)  # Return overall validity

        # Reduce iterations for this potentially slower test
        current_iterations = max(1, self.ITERATIONS // 2)
        avg_time, min_t, max_t, std_dev, results = _benchmark(run_sequential, iterations=current_iterations)

        avg_time_per_share = avg_time / num_verify if num_verify > 0 else 0
        test_logger.info(
            f"[Benchmark] Sequential Verify ({num_verify} shares, t={t}): AvgTotal={avg_time:.4f}s, AvgPerShare={avg_time_per_share:.6f}s"
        )
        assert avg_time >= 0
        assert results[0] is True  # Check result validity

        # Optional: Compare batch vs sequential (batch should be faster per share)
        # Need result from test_perf_2_batch_verify_large for direct comparison
        # This requires careful test ordering or storing results, maybe skip direct assert

    def test_perf_4_zkp_creation_verification_large(self, large_test_data: Optional[dict[str, Any]]):
        """Benchmark ZKP creation and verification for large T."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        vss: FeldmanVSS = large_test_data["vss"]
        coeffs: list[mpz] = large_test_data["coeffs"]
        commitments: CommitmentList = large_test_data["commitments"]
        t: int = large_test_data["t"]

        # Benchmark ZKP Creation
        avg_time_create, min_t_c, max_t_c, std_dev_c, proof_results = _benchmark(
            vss.create_polynomial_proof, coeffs, commitments, iterations=self.ITERATIONS
        )
        test_logger.info(
            f"[Benchmark] ZKP Create (t={t}): Avg={avg_time_create:.4f}s (Min={min_t_c:.4f}, Max={max_t_c:.4f}, StdDev={std_dev_c:.4f})"
        )
        assert avg_time_create >= 0

        # Use one of the generated proofs for verification benchmark
        proof: ProofDict = proof_results[0]

        # Benchmark ZKP Verification
        avg_time_verify, min_t_v, max_t_v, std_dev_v, verify_results = _benchmark(
            vss.verify_polynomial_proof, proof, commitments, iterations=self.ITERATIONS
        )
        test_logger.info(
            f"[Benchmark] ZKP Verify (t={t}): Avg={avg_time_verify:.4f}s (Min={min_t_v:.4f}, Max={max_t_v:.4f}, StdDev={std_dev_v:.4f})"
        )
        assert avg_time_verify >= 0
        assert verify_results[0] is True  # Check verification passed

        # Verification should generally be faster than creation
        # Allow some margin (e.g., 1.5x) due to potential variations
        if avg_time_create > 0.001:  # Avoid assertion for very fast cases
            assert avg_time_verify < avg_time_create * 1.5

    @pytest.mark.skipif(LARGE_N < 50 or LARGE_T < 10, reason="Skipping refresh benchmark, N/T too small for meaningful performance test")
    def test_perf_5_refresh_shares_large(self, large_test_data: Optional[dict[str, Any]]):
        """Benchmark share refreshing for large N and T."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        vss: FeldmanVSS = large_test_data["vss"]
        shares: ShareDict = large_test_data["shares"]
        commitments: CommitmentList = large_test_data["commitments"]
        n: int = large_test_data["n"]
        t: int = large_test_data["t"]
        participant_ids = list(shares.keys())

        # Refresh is computationally intensive, reduce iterations
        current_iterations = max(1, self.ITERATIONS // 2)
        test_logger.info(f"Starting Refresh Shares benchmark (iters={current_iterations})...")

        avg_time, min_t, max_t, std_dev, results = _benchmark(
            vss.refresh_shares,
            shares,
            t,
            n,
            commitments,
            participant_ids,  # Pass participant_ids explicitly
            iterations=current_iterations,
        )
        test_logger.info(
            f"[Benchmark] Refresh Shares (n={n}, t={t}): Avg={avg_time:.4f}s (Min={min_t:.4f}, Max={max_t:.4f}, StdDev={std_dev:.4f})"
        )
        assert avg_time >= 0
        # Basic check on results structure
        assert isinstance(results[0], tuple)
        assert len(results[0]) == 3  # new_shares, new_commitments, verification_data
        assert isinstance(results[0][0], dict)  # new_shares
        assert isinstance(results[0][1], list)  # new_commitments

    @pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed, skipping memory tests")
    def test_perf_6_memory_growth_pattern(self, large_test_data: Optional[dict[str, Any]]):
        """Check memory usage growth pattern for increasing threshold T."""
        if large_test_data is None:
            pytest.skip("Large test data setup skipped.")

        # Use the field and vss instance from large_test_data for consistency
        field: MockField = large_test_data["field"]
        vss: FeldmanVSS = large_test_data["vss"]
        prime_bits = vss.group.prime.bit_length()

        results_peak_mem = {}
        # Define thresholds to test, ensuring they are feasible
        max_t_mem_test = 75  # Limit max T for test duration, adjust based on system
        thresholds_to_test = [t for t in [10, 25, 50, max_t_mem_test] if t <= LARGE_T * 1.2]

        if not thresholds_to_test or max(thresholds_to_test) <= 10:
            pytest.skip("Skipping memory growth test, thresholds too small or empty.")

        # Use the tracemalloc fixture implicitly enabled by conftest.py
        tracemalloc = pytest.importorskip("tracemalloc")

        for t in thresholds_to_test:
            # Ensure n >= t+1, keep n reasonable relative to t
            n = max(t + 1, min(int(t * 1.5), LARGE_N * 2))

            test_logger.info(f"Memory Growth Check: n={n}, t={t} (prime_bits={prime_bits})")
            secret = field.random_element()
            try:
                coeffs, shares = generate_poly_and_shares(field, secret, t, n)
                share_list = list(shares.values())

                # --- Start Memory Intensive Operations ---
                tracemalloc.clear_traces()  # Clear before operation
                snapshot1 = tracemalloc.take_snapshot()

                commits = vss.create_commitments(coeffs)
                # Batch verify is often memory intensive due to intermediate calculations
                vss.batch_verify_shares(share_list, commits)
                # Optionally include ZKP creation/verification if desired
                # proof = vss.create_polynomial_proof(coeffs, commits)
                # vss.verify_polynomial_proof(proof, commits)

                snapshot2 = tracemalloc.take_snapshot()
                # --- End Memory Intensive Operations ---

                top_stats = snapshot2.compare_to(snapshot1, "lineno")
                peak = sum(stat.size for stat in top_stats)  # Sum of sizes of new allocations

            except (MemoryError, ValueError) as e:
                test_logger.warning(f"Memory Growth Check failed for t={t}: {e}")
                results_peak_mem[t] = float("inf")  # Mark as failed due to memory
                continue  # Skip to next threshold

            results_peak_mem[t] = peak / (1024 * 1024)  # Peak memory delta in MB
            test_logger.info(f"  -> Peak Memory Delta (tracemalloc): {results_peak_mem[t]:.2f} MB")

            # Basic check: Memory should not grow excessively faster than quadratic in t
            # O(t^2 * log(p)) is expected for some ops. Check ratio t vs t/2
            t_prev = t // 2
            if t > 10 and t_prev in results_peak_mem and results_peak_mem[t_prev] > 0.01:  # Avoid division by zero/small numbers
                if results_peak_mem[t] == float("inf"):
                    test_logger.warning(f"Cannot calculate ratio for t={t} due to previous memory error.")
                    continue

                ratio = results_peak_mem[t] / results_peak_mem[t_prev]
                # Expect roughly O(t^2), so ratio around 4. Allow generous margin (e.g., 8-10)
                # due to Python overheads, GC behavior, and specific algorithm steps.
                # If batch verify dominates, it might be closer to O(n*t) or O(n + t^2).
                # Let's use a threshold of 10.
                allowed_ratio = 10.0
                assert ratio < allowed_ratio, (
                    f"Memory growth potentially excessive: t={t} vs t={t_prev}, "
                    f"peak_delta={results_peak_mem[t]:.2f}MB, ratio={ratio:.2f} > {allowed_ratio}"
                )

        test_logger.info(f"Memory Growth Results (Peak Delta MB): {results_peak_mem}")
