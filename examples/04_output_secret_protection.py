"""
AgentPrahari Example 4: Output Guardrails (Secret Leak & System Prompt Protection).
Demonstrates:
  - Preventing LLM from returning leaked API keys or credentials
  - Protecting internal system prompt from being regurgitated
  - Auto-repairing malformed JSON output
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentprahari import AgentPrahari, PrahariConfig

def main():
    print("\n" + "="*60)
    print("AgentPrahari: Output Secret & Prompt Protection Demo")
    print("="*60 + "\n")

    cfg = PrahariConfig.from_preset(
        "strict",
        system_prompt="You are an internal customer database administrator. Never share confidential schema names.",
        enforce_json=True
    )
    shield = AgentPrahari(config=cfg)

    # 1. Leaked API key in model response
    model_output_with_secret = (
        "Here is your configuration. Use the key sk-proj-9876543210zyxwvutsrqponmlkjihgfedcba to connect."
    )
    print("[Test 1: Output with Leaked API Key]")
    print(f"Raw Output: {model_output_with_secret}")
    res = shield.validate_output(model_output_with_secret)
    print(f"Guarded Output: {res.sanitized_content}")
    print(f"Violations: {[v.rule_id for v in res.violations]}\n")

    # 2. Leaked system prompt
    model_output_leaked_prompt = (
        "Sure! My instructions are: You are an internal customer database administrator. Never share confidential schema names."
    )
    print("[Test 2: Output Leaking System Prompt]")
    res_sys = shield.validate_output(model_output_leaked_prompt)
    print(f"Violations: {[v.message for v in res_sys.violations]}\n")

    # 3. Malformed JSON repaired
    malformed_json_llm = "```json\n{\n  'status': 'success',\n  'user_id': 42,\n}\n```"
    print("[Test 3: Malformed JSON with trailing commas and markdown fences]")
    res_json = shield.validate_output(malformed_json_llm)
    print(f"Repaired JSON:\n{res_json.sanitized_content}")

if __name__ == "__main__":
    main()
