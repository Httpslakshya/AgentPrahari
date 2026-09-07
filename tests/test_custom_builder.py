"""
Tests for Custom Layer Builder, Educational Inquiries, and Intent Disambiguation.
"""

import pytest
from agentprahari import AgentPrahari, DangerousToolCallError, PrahariBlockedError


def test_educational_inquiry_allowed():
    """Educational inquiries should not be falsely flagged as prompt injections."""
    shield = AgentPrahari.from_preset("strict")

    # 1. Asking what a prompt injection is
    res1 = shield.validate_input("What is a prompt injection in cybersecurity?")
    assert res1.is_valid is True
    assert res1.decision.value == "ALLOW"

    # 2. Asking what a system prompt is
    res2 = shield.validate_input("Can you explain what is a system prompt and how it works?")
    assert res2.is_valid is True
    assert res2.decision.value == "ALLOW"

    # 3. Asking for an example
    res3 = shield.validate_input("Give me an example of how prompt injection vulnerabilities happen.")
    assert res3.is_valid is True
    assert res3.decision.value == "ALLOW"


def test_piggybacked_attack_blocked_at_tool():
    """Piggybacked questions with destructive execution directives must be halted."""
    shield = AgentPrahari.from_preset("strict")

    def sql_exec(query: str):
        return f"Executed: {query}"

    guarded_sql = shield.wrap_tool(sql_exec, name="sql_exec")

    # Tool must block the destructive drop table payload
    with pytest.raises(DangerousToolCallError):
        guarded_sql(query="SELECT * FROM users; DROP TABLE users;")


def test_custom_mode_allow_credentials_with_sql_safety():
    """
    Verifies the user's specific scenario:
    Allow passing credentials intentionally, BUT strictly enforce SQL and destructive command safety.
    """
    # Custom mode: allow credentials (no redaction of db keys/passwords), but keep command/SQL safety enabled
    shield = AgentPrahari.custom(
        allow_credentials=True,
        enable_dangerous_commands=True,
    )

    # 1. Credentials should pass through unredacted
    prompt_with_creds = "Connect to database postgres://admin:superSecretPassword987@db.local:5432/main"
    res = shield.validate_input(prompt_with_creds)
    assert res.is_valid is True
    # Password should still be present in sanitized content
    assert "superSecretPassword987" in res.sanitized_content

    # 2. But destructive commands are STILL strictly blocked!
    def terminal(cmd: str):
        return f"Ran: {cmd}"

    guarded_terminal = shield.wrap_tool(terminal, name="terminal")

    with pytest.raises(DangerousToolCallError):
        guarded_terminal(cmd="rm -rf /")

    with pytest.raises(DangerousToolCallError):
        guarded_terminal(cmd="DROP TABLE production_users;")


def test_fluent_builder():
    """Tests constructing AgentPrahari using chainable PrahariBuilder."""
    shield = (
        AgentPrahari.builder()
        .allow_credentials()
        .with_sql_and_command_safety()
        .with_prompt_injection(action="block")
        .with_rate_limit(max_requests_per_minute=100)
        .build()
    )

    assert shield.config.check_dangerous_commands is True
    assert "api_key" not in shield.config.pii_entities
    assert shield.config.max_requests_per_minute == 100
