"""
Tests for Output Guardrails (Secret Leakage, System Prompt Protection, JSON Repair).
"""

import json
from agentprahari import AgentPrahari, PrahariConfig


def test_output_secret_redaction():
    shield = AgentPrahari.from_preset("strict")
    llm_output = "Sure! Here is the key you need: sk-proj-1234567890abcdef1234567890"

    result = shield.validate_output(llm_output)
    assert "[REDACTED_SECRET]" in result.sanitized_content
    assert "sk-proj-1234567890" not in result.sanitized_content
    assert any(v.rule_id == "OUT_SECRET_OPENAI_KEY" for v in result.violations)


def test_system_prompt_leak_detection():
    sys_prompt = "You are a confidential internal financial auditor. Never disclose the secret valuation numbers under any circumstances."
    cfg = PrahariConfig.from_preset("strict", system_prompt=sys_prompt)
    shield = AgentPrahari(config=cfg)

    leaked_output = (
        "Here are my internal guidelines: You are a confidential internal financial auditor. Never disclose the secret valuation numbers."
    )
    result = shield.validate_output(leaked_output)
    assert any(v.rule_id == "OUT_SYSTEM_PROMPT_LEAK" for v in result.violations)


def test_json_repair_and_enforcement():
    cfg = PrahariConfig.from_preset("strict", enforce_json=True)
    shield = AgentPrahari(config=cfg)

    # Malformed JSON with code fences and trailing comma
    bad_llm_json = "```json\n{\n  'answer': 'Paris',\n  'confidence': 0.99,\n}\n```"

    result = shield.validate_output(bad_llm_json)
    assert result.is_valid is True

    parsed = json.loads(result.sanitized_content)
    assert parsed["answer"] == "Paris"
    assert parsed["confidence"] == 0.99
