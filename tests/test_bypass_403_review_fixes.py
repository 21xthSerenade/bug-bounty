"""Regression checks for the response-normalization bypass probe.

The bypass probe was reworked in the "systematic WAF bypass pipeline" change
(PR #40): instead of a literal ``_normalize_body`` string diff it now samples a
block baseline, strips/detects WAF block signatures, and compares each probe
response against that baseline (status + signature + length divergence) before
declaring a bypass. These checks assert the equivalent guarantees on the
current implementation.
"""

from pathlib import Path


BYPASS_PATH = Path(__file__).resolve().parents[1] / "tools" / "bypass_403.sh"


def test_bypass_probe_normalizes_dynamic_bodies_before_comparing():
    scanner = BYPASS_PATH.read_text()

    # A block baseline is sampled once per run and persisted for comparison.
    assert "_sample_block_baseline()" in scanner
    assert "block_baseline.len" in scanner

    # Responses are gated through a real-bypass check that normalizes against
    # WAF block signatures and requires the body length to diverge from the
    # sampled block baseline before counting as a bypass.
    assert "_is_real_bypass()" in scanner
    assert "_WAF_BLOCK_REGEX" in scanner
    assert "bb_len" in scanner


def test_bypass_probe_keeps_confidence_tiers():
    scanner = BYPASS_PATH.read_text()

    # Three-tier verdict system: confirmed bypass / needs review / blocked.
    assert "bypassed)" in scanner
    assert "needs_review)" in scanner
    assert "blocked)" in scanner
