"""
AgentPrahari Example 2: Agent Tool Execution Safety.
Demonstrates:
  - Intercepting dangerous agent tool calls (e.g. rm -rf, drop database, format disk)
  - Blocking path traversal attacks (../../etc/passwd)
  - Detecting agent infinite loops
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentprahari import AgentPrahari, DangerousToolCallError

def main():
    print("\n" + "="*60)
    print("AgentPrahari: Safe Agent Tool Execution Demo")
    print("="*60 + "\n")

    shield = AgentPrahari.from_preset("strict")

    # Define a simulated agent tool
    def execute_terminal(cmd: str) -> str:
        return f"Simulated output of running: {cmd}"

    # Wrap the tool with AgentPrahari
    safe_terminal = shield.wrap_tool(execute_terminal, name="execute_terminal")

    # 1. Safe command execution
    print("[Test 1: Safe Tool Execution]")
    try:
        res = safe_terminal(cmd="ls -la /home/user/documents")
        print(f"[PASSED] Success: {res}")
    except DangerousToolCallError as e:
        print(f"[BLOCKED]: {e}")

    # 2. Destructive command blocked
    print("\n[Test 2: Malicious Destructive Command Attempt]")
    try:
        safe_terminal(cmd="rm -rf / --no-preserve-root")
        print("[FAIL] Unexpectedly allowed!")
    except DangerousToolCallError as e:
        print(f"[BLOCKED DANGEROUS TOOL CALL]: {e}")

    # 3. Path traversal blocked
    print("\n[Test 3: Path Traversal Attempt]")
    try:
        safe_terminal(cmd="cat ../../../etc/shadow")
        print("[FAIL] Unexpectedly allowed!")
    except DangerousToolCallError as e:
        print(f"[BLOCKED DANGEROUS TOOL CALL]: {e}")

    # 4. SQL data wipe blocked
    print("\n[Test 4: SQL Table Wipe Attempt]")
    try:
        safe_terminal(cmd="psql -U admin -c 'DROP DATABASE production;'")
        print("[FAIL] Unexpectedly allowed!")
    except DangerousToolCallError as e:
        print(f"[BLOCKED DANGEROUS TOOL CALL]: {e}")

    print("\n" + "="*60)

if __name__ == "__main__":
    main()
