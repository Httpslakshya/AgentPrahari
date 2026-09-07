"""
Tests for Agent Tool Call Safety, Destructive Action Blocking, and Loop Prevention.
"""

import pytest
from agentprahari import AgentPrahari, DangerousToolCallError


def test_destructive_rm_rf_blocked():
    shield = AgentPrahari.from_preset("strict")
    
    result = shield.validate_tool_call(
        tool_name="bash",
        tool_args={"command": "rm -rf /var/log"}
    )
    assert result.is_valid is False
    assert result.decision.value == "BLOCK"
    assert any(v.rule_id == "TOOL_CMD_DESTRUCTIVE_DELETE" for v in result.violations)


def test_destructive_sql_drop_blocked():
    shield = AgentPrahari.from_preset("strict")

    result = shield.validate_tool_call(
        tool_name="sql_executor",
        tool_args={"query": "DROP TABLE users;"}
    )
    assert result.is_valid is False
    assert any(v.rule_id == "TOOL_SQL_DESTRUCTIVE_DDL" for v in result.violations)


def test_path_traversal_blocked():
    shield = AgentPrahari.from_preset("strict")

    result = shield.validate_tool_call(
        tool_name="file_reader",
        tool_args={"path": "../../etc/shadow"}
    )
    assert result.is_valid is False
    assert any("TRAVERSAL" in v.rule_id or "BLOCKED_FILE" in v.rule_id for v in result.violations)


def test_agent_infinite_loop_detection():
    shield = AgentPrahari.from_preset("strict")
    shield.reset_agent_session()

    # Call same tool 3 times consecutively with same args
    res1 = shield.validate_tool_call("web_search", {"q": "weather"})
    assert res1.is_valid is True

    res2 = shield.validate_tool_call("web_search", {"q": "weather"})
    assert res2.is_valid is True

    res3 = shield.validate_tool_call("web_search", {"q": "weather"})
    assert res3.is_valid is False
    assert any(v.rule_id == "TOOL_LOOP_IDENTICAL_REPEATS" for v in res3.violations)


def test_wrap_tool_function_raises_error():
    shield = AgentPrahari.from_preset("strict")

    def run_bash(command: str) -> str:
        return f"Executed: {command}"

    guarded_bash = shield.wrap_tool(run_bash, name="bash")

    # Safe call should succeed
    res = guarded_bash(command="echo 'hello world'")
    assert "Executed: echo 'hello world'" in res

    # Dangerous call must raise DangerousToolCallError
    with pytest.raises(DangerousToolCallError):
        guarded_bash(command="format c:")
