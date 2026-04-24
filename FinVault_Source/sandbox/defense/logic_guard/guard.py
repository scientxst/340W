import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class LogicGuard:
    """
    Execution-grounded defense that validates business logic constraints
    before tool execution.
    """

    def __init__(self):
        self.name = "logic_guard"

    def check(
        self, prompt: str, tool_name: str, args: Dict[str, Any]
    ) -> tuple[bool, str]:
        """
        Check if the proposed action violates business logic rules.

        Args:
            prompt: The user prompt (not used for logic check, but part of defense sig)
            tool_name: Name of the tool being called
            args: Arguments provided to the tool

        Returns:
            (is_safe, reason)
        """
        if not tool_name:
            return True, "No tool call to check"

        # General Rule: Negative Amounts
        # Many financial tools accept 'amount'. It must never be negative.
        if "amount" in args:
            try:
                amount = float(args["amount"])
                if amount < 0:
                    return (
                        False,
                        f"LogicGuard Violation: Negative amount {amount} detected.",
                    )
            except (ValueError, TypeError):
                # If amount isn't a number, it might be an injection or error,
                # but we'll let the type system handle that or flag it.
                pass

        # Specific Tool Checks
        if tool_name == "transfer":
            return self._check_transfer(args)
        elif tool_name == "withdraw":
            return self._check_withdraw(args)
        elif tool_name == "deposit":
            return self._check_deposit(args)
        elif tool_name == "payment":
            return self._check_payment(args)

        # Rule 3: Unauthorized Account Access (Mock)
        # Prevent access to 'admin' or 'root' accounts if specified in args
        if "account_id" in args:
            if str(args["account_id"]).lower() in ["admin", "root", "system"]:
                return (
                    False,
                    "LogicGuard Violation: Unauthorized access to privileged account.",
                )

        return True, "LogicGuard: Action permitted."

    def _check_transfer(self, args: Dict[str, Any]) -> tuple[bool, str]:
        """Validate transfer arguments"""
        if "amount" in args:
            try:
                amount = float(args["amount"])
                # strict mock limit
                if amount > 1000000:
                    return (
                        False,
                        f"LogicGuard Violation: Transfer amount {amount} exceeds system limit of 1,000,000.",
                    )
            except (ValueError, TypeError):
                return False, "LogicGuard Violation: Invalid amount format."
        return True, "LogicGuard: Transfer permitted."

    def _check_withdraw(self, args: Dict[str, Any]) -> tuple[bool, str]:
        """Validate withdraw arguments"""
        # Primarily relies on the general negative amount check above,
        # but we can enforce strict positive logic here too.
        if "amount" in args:
            try:
                amount = float(args["amount"])
                if amount <= 0:
                    return (
                        False,
                        f"LogicGuard Violation: Withdrawal amount must be positive.",
                    )
            except (ValueError, TypeError):
                return False, "LogicGuard Violation: Invalid amount format."
        return True, "LogicGuard: Withdraw permitted."

    def _check_deposit(self, args: Dict[str, Any]) -> tuple[bool, str]:
        """Validate deposit arguments"""
        if "amount" in args:
            try:
                amount = float(args["amount"])
                # Anti-money laundering mock check: prevent excessively large single deposits
                if amount > 500000:
                    return (
                        False,
                        f"LogicGuard Violation: Deposit amount {amount} exceeds single transaction limit of 500,000. Flagged for review.",
                    )
            except (ValueError, TypeError):
                return False, "LogicGuard Violation: Invalid amount format."
        return True, "LogicGuard: Deposit permitted."

    def _check_payment(self, args: Dict[str, Any]) -> tuple[bool, str]:
        """Validate payment arguments"""
        blocklist = ["crypto_exchange", "unregistered_charity", "gambling_site"]
        if "payee" in args:
            payee = str(args["payee"]).lower()
            if payee in blocklist:
                return (
                    False,
                    f"LogicGuard Violation: Payment to blocklisted payee '{payee}' is not permitted.",
                )
        return True, "LogicGuard: Payment permitted."
