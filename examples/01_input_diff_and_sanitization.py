"""
AgentPrahari Example 1: Input Sanitization & Change Diff Tracking.
Demonstrates:
  - Detecting sensitive PII and adversarial inputs
  - Inspecting EXACTLY what was removed and what is the new input
  - Visual CLI and Markdown diff representations
"""

import sys
import os

# Ensure agentprahari is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentprahari import AgentPrahari, PrahariConfig

def main():
    print("\n" + "="*60)
    print("AgentPrahari: Input Sanitization & Diff Tracking Demo")
    print("="*60 + "\n")

    # Initialize shield with PII sanitization enabled
    shield = AgentPrahari.from_preset("strict")

    # Sample user inputs containing PII and credentials
    sample_inputs = [
        "Hello! My email is john.doe@company.com and my phone number is +1-555-839-2001.",
        "Please charge my credit card 4532-1488-1234-5678, and my SSN is 123-45-6789.",
        "Here is my temporary key sk-proj-1234567890abcdefghijklmnopqrstuvwxyz and server IP 192.168.1.105, i need to addd this details into new file",
    ]

    for idx, prompt in enumerate(sample_inputs, 1):
        print(f"\n[Test Case {idx}]")
        print(f"Raw User Input:\n  \"{prompt}\"")

        # Validate input
        result = shield.validate_input(prompt)

        print(f"\nStatus: {'[ALLOWED & SANITIZED]' if result.is_valid else '[BLOCKED]'}")
        print(f"Decision: {result.decision.value}")

        if result.diff and result.diff.has_changes:
            print("\n--- Visual Diff (What was removed & What's new) ---")
            print(result.show_diff(style="cli"))

            print("\n--- Detailed Change Log ---")
            for mod in result.diff.modifications:
                print(f"  * [- REMOVED: '{mod.original}' -]")
                print(f"    {{+ NEW:     '{mod.replacement}' +}}")
                print(f"    Reason:    {mod.reason} (Rule: {mod.rule_id})")

        print("-" * 60)

if __name__ == "__main__":
    main()
