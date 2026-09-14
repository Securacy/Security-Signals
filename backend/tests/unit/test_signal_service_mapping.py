"""Unit tests for _map_principle_and_recommended_action - the pure mapping
function that derives Signal.principle/recommended_action from the AI's
validated secure_design_principles. No database needed; these test the
mapping logic in isolation.
"""

import pytest

from app.services.signal_service import (
    _map_principle_and_recommended_action,
    _PLACEHOLDER_PRINCIPLE,
    _PLACEHOLDER_RECOMMENDED_ACTION,
    _SIGNAL_PRINCIPLE_MAX_LENGTH,
)
from app.intelligence.schemas.signal_request import (
    AISignalGenerationResponse,
    SecureDesignPrinciple,
)


def _make_response(secure_design_principles):
    return AISignalGenerationResponse(
        signal_title="Test Signal Title",
        signal_description="A sufficiently long description of the test signal for validation purposes.",
        category="vulnerability",
        ai_subcategory=None,
        confidence=0.9,
        evidence_summary="Evidence grounded in the provided source material.",
        secure_design_principles=secure_design_principles,
    )


class TestMapPrincipleAndRecommendedAction:
    def test_empty_principles_falls_back_to_placeholders(self):
        response = _make_response([])

        principle, recommended_action = _map_principle_and_recommended_action(response)

        assert principle == _PLACEHOLDER_PRINCIPLE
        assert recommended_action == _PLACEHOLDER_RECOMMENDED_ACTION

    def test_single_principle_mapped_directly(self):
        response = _make_response(
            [SecureDesignPrinciple(principle="Least Privilege", connection="Excess IAM permissions", confidence=0.85)]
        )

        principle, recommended_action = _map_principle_and_recommended_action(response)

        assert principle == "Least Privilege"
        assert recommended_action == "Least Privilege: Excess IAM permissions"

    def test_multiple_principles_joined(self):
        response = _make_response(
            [
                SecureDesignPrinciple(principle="Input Validation", connection="Buffer overflow via malformed input", confidence=0.9),
                SecureDesignPrinciple(principle="Memory Safety", connection="Unchecked buffer length", confidence=0.8),
                SecureDesignPrinciple(principle="Defense in Depth", connection="No secondary mitigation", confidence=0.7),
            ]
        )

        principle, recommended_action = _map_principle_and_recommended_action(response)

        assert principle == "Input Validation; Memory Safety; Defense in Depth"
        assert recommended_action == (
            "Input Validation: Buffer overflow via malformed input "
            "Memory Safety: Unchecked buffer length "
            "Defense in Depth: No secondary mitigation"
        )

    def test_never_returns_the_old_discarded_placeholders_when_principles_exist(self):
        """Guards against silently regressing back to the bug this fix
        addresses: previously ALL signals got this exact placeholder text
        regardless of what the AI actually generated."""
        response = _make_response(
            [SecureDesignPrinciple(principle="Encryption", connection="Plaintext credential storage", confidence=0.95)]
        )

        principle, recommended_action = _map_principle_and_recommended_action(response)

        assert principle != _PLACEHOLDER_PRINCIPLE
        assert recommended_action != _PLACEHOLDER_RECOMMENDED_ACTION

    def test_principle_truncated_to_column_limit(self):
        """Signal.principle is VARCHAR(500) at the database level - a long
        join of many/verbose principle names must be truncated so the
        INSERT can never fail on this derived value."""
        many_principles = [
            SecureDesignPrinciple(
                principle=f"Very Long Principle Name Number {i} That Takes Up Considerable Space",
                connection="Some connection text",
                confidence=0.9,
            )
            for i in range(20)
        ]
        response = _make_response(many_principles)

        principle, _ = _map_principle_and_recommended_action(response)

        assert len(principle) <= _SIGNAL_PRINCIPLE_MAX_LENGTH
        assert principle.endswith("…")

    def test_recommended_action_not_truncated(self):
        """recommended_action maps to a Text column (unbounded), so no
        truncation should apply there even when principle is truncated."""
        many_principles = [
            SecureDesignPrinciple(
                principle=f"Principle {i}",
                connection="A reasonably detailed explanation of the connection " * 3,
                confidence=0.9,
            )
            for i in range(20)
        ]
        response = _make_response(many_principles)

        _, recommended_action = _map_principle_and_recommended_action(response)

        assert len(recommended_action) > _SIGNAL_PRINCIPLE_MAX_LENGTH
        assert "Principle 0" in recommended_action
        assert "Principle 19" in recommended_action
