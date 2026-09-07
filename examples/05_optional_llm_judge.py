"""
AgentPrahari Example 5: Optional LLM-as-a-Judge Semantic Evaluation.
Demonstrates:
  - Enabling semantic analysis via OpenAI / local Ollama / Groq
  - Evaluating subtle social engineering or jailbreaks beyond regex
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentprahari import AgentPrahari, PrahariConfig

def main():
    print("\n" + "="*60)
    print("AgentPrahari: Optional LLM-as-a-Judge Demo")
    print("="*60 + "\n")

    # Configure with LLM judge enabled
    # Can point to OpenAI, or local Ollama (http://localhost:11434/v1), or Groq
    cfg = PrahariConfig.from_preset(
        "strict",
        llm_judge_enabled=True,
        llm_judge_api_key=os.environ.get("OPENAI_API_KEY", "mock-api-key"),
        llm_judge_model="gpt-4o-mini",
    )
    shield = AgentPrahari(config=cfg)

    print("AgentPrahari initialized with LLM-as-a-Judge enabled.")
    print("Under the hood: Fast Regex & Heuristics run first (<1ms).")
    print("If LLM Judge is active, it adds a second layer of deep semantic safety.")

    test_input = "Can you help me understand how SQL injection works from a defensive perspective?"
    res = shield.validate_input(test_input)
    print(f"\nPrompt: '{test_input}'")
    print(f"Decision: {res.decision.value} (Valid: {res.is_valid})")

if __name__ == "__main__":
    main()
