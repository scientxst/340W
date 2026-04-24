import sys
import os

# Add parent directory to path to import sandbox modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from sandbox.defense.logic_guard.guard import LogicGuard


def test_logic_guard():
    guard = LogicGuard()
    print("Testing LogicGuard...")

    # Test 1: Valid Transfer
    is_safe, reason = guard.check("prompt", "transfer", {"amount": 500, "to": "user2"})
    assert is_safe, f"Test 1 Failed: Valid transfer blocked. Reason: {reason}"
    print("Test 1 Passed: Valid Transfer")

    # Test 2: Negative Amount (General Rule)
    is_safe, reason = guard.check("prompt", "transfer", {"amount": -100})
    assert not is_safe, "Test 2 Failed: Negative transfer allowed."
    print("Test 2 Passed: Negative Amount Blocked")

    # Test 3: Excessive Transfer (Specific Rule)
    is_safe, reason = guard.check("prompt", "transfer", {"amount": 2000000})
    assert not is_safe, "Test 3 Failed: Excessive transfer allowed."
    print("Test 3 Passed: Excessive Transfer Blocked")

    # Test 4: Valid Withdraw
    is_safe, reason = guard.check("prompt", "withdraw", {"amount": 100})
    assert is_safe, f"Test 4 Failed: Valid withdraw blocked. Reason: {reason}"
    print("Test 4 Passed: Valid Withdraw")

    # Test 5: Invalid Withdraw (Zero/Negative)
    is_safe, reason = guard.check("prompt", "withdraw", {"amount": 0})
    assert not is_safe, "Test 5 Failed: Zero withdrawal allowed."
    print("Test 5 Passed: Zero Withdrawal Blocked")

    # Test 6: Unauthorized Account
    is_safe, reason = guard.check("prompt", "get_balance", {"account_id": "admin"})
    assert not is_safe, "Test 6 Failed: Admin access allowed."
    print("Test 6 Passed: Unauthorized Access Blocked")

    # Test 7: Valid Deposit
    is_safe, reason = guard.check("prompt", "deposit", {"amount": 5000})
    assert is_safe, f"Test 7 Failed: Valid deposit blocked. Reason: {reason}"
    print("Test 7 Passed: Valid Deposit")

    # Test 8: Excessive Deposit Blocked (AML rule)
    is_safe, reason = guard.check("prompt", "deposit", {"amount": 600000})
    assert not is_safe, "Test 8 Failed: Excessive deposit allowed."
    print("Test 8 Passed: Excessive Deposit Blocked")

    # Test 9: Valid Payment
    is_safe, reason = guard.check(
        "prompt", "payment", {"amount": 200, "payee": "electric_company"}
    )
    assert is_safe, f"Test 9 Failed: Valid payment blocked. Reason: {reason}"
    print("Test 9 Passed: Valid Payment")

    # Test 10: Blocklisted Payee Payment Blocked
    is_safe, reason = guard.check(
        "prompt", "payment", {"amount": 1500, "payee": "crypto_exchange"}
    )
    assert not is_safe, "Test 10 Failed: Payment to blocklisted payee allowed."
    print("Test 10 Passed: Blocklisted Payee Payment Blocked")


if __name__ == "__main__":
    try:
        test_logic_guard()
        print("\nAll LogicGuard tests passed successfully!")
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)
