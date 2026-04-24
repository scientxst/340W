import sys
import os

# Add the parent directory to sys.path so we can import modules
sys.path.append(os.getcwd())

from sandbox.defense.defense_manager import DefenseManager, DefenseConfig


def test_logic_guard():
    print("Testing LogicGuard Integration...")

    # 1. Enable Defense
    config = DefenseConfig(enabled=True)
    manager = DefenseManager(config=config)

    # Test Case 1: Normal Transfer (Safe)
    print("\n[Test 1] Normal Transfer (Amount: 500)")
    result = manager.verify_tool_call(
        tool_name="transfer", arguments={"amount": 500, "account_id": "user123"}
    )
    if not result.is_attack:
        print("PASS: Correctly allowed.")
    else:
        print(f"FAIL: Blocked unexpectedly. Reason: {result.reason}")

    # Test Case 2: Negative Amount (Unsafe)
    print("\n[Test 2] Negative Amount (Amount: -100)")
    result = manager.verify_tool_call(
        tool_name="transfer", arguments={"amount": -100, "account_id": "user123"}
    )
    if result.is_attack:
        print(f"PASS: Correctly blocked. Reason: {result.reason}")
    else:
        print("FAIL: Allowed negative amount.")

    # Test Case 3: Over Limit (Unsafe)
    print("\n[Test 3] Transfer Over Limit (Amount: 2,000,000)")
    result = manager.verify_tool_call(
        tool_name="transfer", arguments={"amount": 2000000, "account_id": "user123"}
    )
    if result.is_attack:
        print(f"PASS: Correctly blocked. Reason: {result.reason}")
    else:
        print("FAIL: Allowed amount over limit.")

    # Test Case 4: Admin Access (Unsafe)
    print("\n[Test 4] Unauthorized Admin Access")
    result = manager.verify_tool_call(
        tool_name="check_balance", arguments={"account_id": "admin"}
    )
    if result.is_attack:
        print(f"PASS: Correctly blocked. Reason: {result.reason}")
    else:
        print("FAIL: Allowed admin access.")


if __name__ == "__main__":
    test_logic_guard()
