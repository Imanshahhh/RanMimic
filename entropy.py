# entropy.py
"""
Entropy and statistical analysis - Shannon entropy and Chi-Square goodness-
of-fit test, used to detect the byte-distribution signature of encrypted
data. Encrypted/compressed data approaches uniform random distribution;
plaintext does not.
"""

import math
from collections import Counter
from pathlib import Path
from scipy.stats import chisquare


def shannon_entropy(data: bytes) -> float:
    """
    Returns Shannon entropy in bits per byte, range 0.0 (no randomness,
    e.g. all zero bytes) to 8.0 (maximum randomness, e.g. AES ciphertext
    or compressed data).
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)

    entropy = 0.0
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def chi_square_test(data: bytes) -> dict:
    """
    Chi-Square goodness-of-fit test against a uniform byte distribution
    (expected for truly random/encrypted data). Returns the statistic and
    p-value.

    Low p-value (< 0.05) = distribution significantly differs from uniform
                           random -> more likely plaintext/structured data
    High p-value          = distribution is statistically close to uniform
                           random -> more likely encrypted/compressed data

    This is the inverse intuition of most stats tests, so don't get it
    backwards when writing the report: LOW p-value here is the "normal
    file" signal, HIGH p-value is the "looks encrypted" signal.
    """
    if not data:
        return {"statistic": 0.0, "p_value": 1.0}

    byte_counts = Counter(data)
    observed = [byte_counts.get(b, 0) for b in range(256)]
    expected_count = len(data) / 256
    expected = [expected_count] * 256

    statistic, p_value = chisquare(observed, expected)
    return {"statistic": float(statistic), "p_value": float(p_value)}


def analyze_file(filepath: Path) -> dict:
    """
    Single entry point used by scorer.py — reads a file once, returns
    both entropy and chi-square results together to avoid double I/O.
    """
    try:
        data = filepath.read_bytes()
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "entropy": None, "chi_square": None}

    return {
        "entropy": shannon_entropy(data),
        "chi_square": chi_square_test(data),
        "size_bytes": len(data),
    }


def compute_delta(before: dict, after: dict) -> dict:
    """
    Compares before/after analyze_file() results for the same file.
    Returns entropy_delta and whether the chi-square p-value crossed
    from 'structured' to 'random-looking' (the actual signal scorer.py
    cares about, not just the raw numbers).
    """
    if before.get("entropy") is None or after.get("entropy") is None:
        return {"entropy_delta": None, "p_value_shift": None}

    entropy_delta = after["entropy"] - before["entropy"]
    p_before = before["chi_square"]["p_value"]
    p_after = after["chi_square"]["p_value"]

    return {
        "entropy_delta": round(entropy_delta, 4),
        "p_value_before": round(p_before, 6),
        "p_value_after": round(p_after, 6),
        "p_value_shift": round(p_after - p_before, 6),
    }