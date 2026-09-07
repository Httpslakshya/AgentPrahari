"""
Tests for PII Masking, Redaction, and Custom Rules.
"""

from agentprahari import AgentPrahari, PrahariConfig


def test_ssn_and_email_redaction():
    shield = AgentPrahari.from_preset("strict")
    text = "My SSN is 000-12-3456 and email is user.test@domain.org."
    
    result = shield.validate_input(text)
    assert result.is_valid is True
    assert "[REDACTED_SSN]" in result.sanitized_content
    assert "[REDACTED_EMAIL]" in result.sanitized_content
    assert "000-12-3456" not in result.sanitized_content


def test_api_key_redaction():
    shield = AgentPrahari.from_preset("strict")
    text = "Use this key: sk-abcdef1234567890abcdef1234567890"
    
    result = shield.validate_input(text)
    assert "[REDACTED_API_KEY]" in result.sanitized_content
    assert "sk-abcdef1234567890" not in result.sanitized_content


def test_asterisk_mask_style():
    cfg = PrahariConfig.from_preset("strict", pii_mask_style="asterisk")
    shield = AgentPrahari(config=cfg)

    text = "Contact mark@example.com"
    result = shield.validate_input(text)
    assert "@example.com" in result.sanitized_content
    assert "mark@example.com" not in result.sanitized_content
    assert "m***@example.com" in result.sanitized_content


def test_custom_regex_rule():
    custom_rules = [
        {
            "name": "employee_id",
            "pattern": r"\bEMP-\d{5}\b",
            "replacement": "[EMPLOYEE_ID_PROTECTED]",
        }
    ]
    cfg = PrahariConfig.from_preset("strict", custom_regex_rules=custom_rules)
    shield = AgentPrahari(config=cfg)

    text = "Assigned to worker EMP-98214 in department 4."
    result = shield.validate_input(text)
    assert "[EMPLOYEE_ID_PROTECTED]" in result.sanitized_content
    assert "EMP-98214" not in result.sanitized_content
