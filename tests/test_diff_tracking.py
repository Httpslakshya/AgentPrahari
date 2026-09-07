"""
Tests for Diff Tracking and Input Change Logging.
Verifies that what was removed and what is new are tracked with exact character spans.
"""

import pytest
from agentprahari import AgentPrahari, PrahariConfig


def test_diff_tracking_pii_redaction():
    shield = AgentPrahari.from_preset("strict")
    raw_prompt = "Contact me at alice@wonderland.com or call 555-123-4567."
    
    result = shield.validate_input(raw_prompt)

    assert result.is_valid is True
    assert result.diff is not None
    assert result.diff.has_changes is True

    # Verify original and sanitized text
    assert result.diff.original_text == raw_prompt
    assert "alice@wonderland.com" not in result.diff.sanitized_text
    assert "[REDACTED_EMAIL]" in result.diff.sanitized_text
    assert "[REDACTED_PHONE]" in result.diff.sanitized_text

    # Verify discrete modifications
    mods = result.diff.modifications
    assert len(mods) == 2

    # First modification should be email
    email_mod = next(m for m in mods if m.rule_id == "PII_EMAIL")
    assert email_mod.original == "alice@wonderland.com"
    assert email_mod.replacement == "[REDACTED_EMAIL]"

    # Second modification should be phone
    phone_mod = next(m for m in mods if m.rule_id == "PII_PHONE")
    assert phone_mod.original == "555-123-4567"
    assert phone_mod.replacement == "[REDACTED_PHONE]"

    # Check show_diff outputs
    cli_diff = result.show_diff(style="cli")
    assert "[- REMOVED: alice@wonderland.com -]" in cli_diff
    assert "{+ NEW: [REDACTED_EMAIL] +}" in cli_diff

    markdown_diff = result.diff.show_diff(style="markdown")
    assert "[AgentPrahari] Input Sanitization Diff" in markdown_diff


def test_diff_tracking_pristine_input():
    shield = AgentPrahari.from_preset("strict")
    prompt = "What is the capital of France?"
    
    result = shield.validate_input(prompt)
    assert result.is_valid is True
    assert result.diff.has_changes is False
    assert result.diff.original_text == result.diff.sanitized_text
    assert len(result.diff.modifications) == 0
