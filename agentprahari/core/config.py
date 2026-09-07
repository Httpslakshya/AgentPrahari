"""
AgentPrahari Configuration and Presets.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class PrahariConfig:
    """Master configuration for AgentPrahari."""

    # --- Input Guardrails ---
    check_prompt_injection: bool = True
    prompt_injection_action: str = "block"  # "block" or "sanitize"
    prompt_injection_threshold: float = 0.5

    check_pii: bool = True
    pii_action: str = "sanitize"  # "sanitize" (mask/redact) or "block"
    pii_mask_style: str = "tag"   # "tag" ([REDACTED_EMAIL]), "asterisk" (j***@example.com), "hash"
    pii_entities: List[str] = field(default_factory=lambda: [
        "email", "phone", "ssn", "credit_card", "api_key", "ip_address", "jwt", "password"
    ])
    custom_regex_rules: List[Dict[str, Any]] = field(default_factory=list)

    check_toxicity: bool = True
    toxicity_action: str = "block"  # "block" or "sanitize"

    allowed_topics: List[str] = field(default_factory=list)
    blocked_topics: List[str] = field(default_factory=list)

    # --- Tool & Agent Execution Guardrails ---
    check_dangerous_commands: bool = True
    blocked_shell_commands: List[str] = field(default_factory=lambda: [
        "rm -rf", "rmdir /s", "mkfs", "dd if=", ":(){ :|:& };:", "drop database", "drop table",
        "format c:", "del /f /s /q", "curl.*\\|.*bash", "wget.*\\|.*bash", "powershell.*-enc",
        "chmod -r 777", "chmod 777", "shutdown", "reboot", "init 0"
    ])
    check_path_traversal: bool = True
    blocked_paths: List[str] = field(default_factory=lambda: [
        "/etc/shadow", "/etc/passwd", "system32", ".env", "id_rsa", "authorized_keys",
        ".aws/credentials", ".git/config"
    ])
    max_tool_loop_iterations: int = 15
    require_human_approval_tools: List[str] = field(default_factory=list)

    # --- Output Guardrails ---
    check_secret_leaks: bool = True
    output_secret_action: str = "sanitize"  # "sanitize" (redact secret) or "block"
    system_prompt: Optional[str] = None  # If set, detects leakage of system prompt
    system_prompt_similarity_threshold: float = 0.75
    enforce_json: bool = False
    json_schema: Optional[Dict[str, Any]] = None
    check_hallucination: bool = False
    grounding_context: Optional[str] = None

    # --- Governance & Rate Limits ---
    max_requests_per_minute: Optional[int] = None
    max_tokens_budget: Optional[int] = None

    # --- Optional LLM-as-a-Judge ---
    llm_judge_enabled: bool = False
    llm_judge_api_key: Optional[str] = None
    llm_judge_base_url: Optional[str] = None
    llm_judge_model: str = "gpt-4o-mini"

    # --- Callbacks & Observability ---
    on_violation: Optional[Callable[[Any], None]] = None
    log_audit: bool = True

    @classmethod
    def from_preset(cls, preset_name: str = "strict", **overrides: Any) -> "PrahariConfig":
        """
        Instantiate config from a well-known security preset:
        - 'strict': Maximum security. Blocks on high/medium injection risks, masks all PII, blocks dangerous tools.
        - 'moderate': Balanced security. Masks PII, blocks blatant injections and shell destruction.
        - 'customer_support': Tailored for customer chatbots: tight topic boundaries, strict PII redaction, friendly fallbacks.
        - 'code_agent': Allows shell/code execution but blocks dangerous rm/formatting/secrets, protects .env/keys.
        - 'financial': Strict PII (PCI-DSS & SSN), strict audit, human-in-the-loop for transactions.
        """
        preset_name = preset_name.lower()

        if preset_name == "strict":
            base = cls(
                check_prompt_injection=True,
                prompt_injection_threshold=0.35,
                prompt_injection_action="block",
                check_pii=True,
                pii_action="sanitize",
                check_toxicity=True,
                check_dangerous_commands=True,
                check_path_traversal=True,
                check_secret_leaks=True,
                max_tool_loop_iterations=10,
            )
        elif preset_name == "moderate":
            base = cls(
                check_prompt_injection=True,
                prompt_injection_threshold=0.6,
                prompt_injection_action="block",
                check_pii=True,
                pii_action="sanitize",
                check_toxicity=True,
                check_dangerous_commands=True,
                check_path_traversal=True,
                check_secret_leaks=True,
                max_tool_loop_iterations=20,
            )
        elif preset_name == "customer_support":
            base = cls(
                check_prompt_injection=True,
                prompt_injection_threshold=0.45,
                check_pii=True,
                pii_action="sanitize",
                check_toxicity=True,
                check_dangerous_commands=True,
                check_secret_leaks=True,
                max_tool_loop_iterations=8,
            )
        elif preset_name == "code_agent":
            base = cls(
                check_prompt_injection=True,
                prompt_injection_threshold=0.6,
                check_pii=True,
                pii_entities=["api_key", "password", "jwt"],  # Allow emails/IPs commonly in code
                check_toxicity=False,
                check_dangerous_commands=True,
                check_path_traversal=True,
                check_secret_leaks=True,
                max_tool_loop_iterations=30,
            )
        elif preset_name == "financial":
            base = cls(
                check_prompt_injection=True,
                prompt_injection_threshold=0.35,
                check_pii=True,
                pii_action="sanitize",
                check_dangerous_commands=True,
                check_secret_leaks=True,
                max_tool_loop_iterations=10,
                require_human_approval_tools=["transfer_funds", "execute_payment", "modify_account"],
            )
        else:
            base = cls()

        for key, val in overrides.items():
            if hasattr(base, key):
                setattr(base, key, val)
            else:
                raise ValueError(f"Unknown PrahariConfig parameter: '{key}'")

        return base
