import sys
import os

# Add the parent directory to sys.path so we can import logic_guard
sys.path.append(os.getcwd())

# Mock the DefenseManager class structure directly to avoid sandbox/__init__.py triggers
# We will import the LogicGuard class properly though.

from sandbox.defense.logic_guard.guard import LogicGuard
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json


@dataclass
class DefenseResult:
    is_attack: bool = False
    should_block: bool = False
    final_score: float = 0.0
    reason: str = ""
    attack_types: List[str] = field(default_factory=list)
    method_results: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseConfig:
    enabled: bool = False
    mode: str = "warn"


class DefenseManager:
    def __init__(self, config: DefenseConfig = None):
        self.config = config or DefenseConfig()
        self.logic_guard = LogicGuard()

    def verify_tool_call(
        self, tool_name: str, arguments: Dict[str, Any], context: str = ""
    ) -> DefenseResult:
        if not self.config.enabled:
            return DefenseResult(is_attack=False, should_block=False)

        is_safe, reason = self.logic_guard.check(
            prompt=context, tool_name=tool_name, args=arguments
        )

        if not is_safe:
            return DefenseResult(
                is_attack=True,
                should_block=True,
                reason=reason,
                final_score=1.0,
                attack_types=["logic_violation"],
            )

        return DefenseResult(is_attack=False, should_block=False)


def test_logic_guard():
    print("Testing LogicGuard (Standalone)...")

    config = DefenseConfig(enabled=True)
    manager = DefenseManager(config=config)

    # Test Case 1: Normal Transfer
    print("\n[Test 1] Normal Transfer (Amount: 500)")
    result = manager.verify_tool_call(
        "transfer", {"amount": 500, "account_id": "user123"}
    )
    if not result.is_attack:
        print("PASS: Correctly allowed.")
    else:
        print(f"FAIL: Blocked. {result.reason}")

    # Test Case 2: Negative Amount
    print("\n[Test 2] Negative Amount")
    result = manager.verify_tool_call("transfer", {"amount": -100})
    if result.is_attack:
        print(f"PASS: Correctly blocked. {result.reason}")
    else:
        print("FAIL: Allowed negative amount.")

    # Test Case 3: Admin Access
    print("\n[Test 3] Admin Access")
    result = manager.verify_tool_call("check_balance", {"account_id": "admin"})
    if result.is_attack:
        print(f"PASS: Correctly blocked. {result.reason}")
    else:
        print("FAIL: Allowed admin access.")


if __name__ == "__main__":
    test_logic_guard()
